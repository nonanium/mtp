use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

enum Capability {
    Pending(mtp_pipes::PipeHandle<mtp_native::Sender, mtp_native::NativeRecvStream>),
    Writer(mtp_native::PipeWriter),
    Reader(mtp_native::PipeReader),
    EncryptedWriter(mtp_pipes::EncryptedPipeWriter<mtp_native::PipeWriter>),
    EncryptedReader(mtp_pipes::EncryptedPipeReader<mtp_native::PipeReader>),
}

type PipeCapability = Arc<Mutex<Option<Capability>>>;
type PipeOffers = HashMap<
    (String, u32),
    mtp_pipes::PipeRequest<mtp_native::Sender, mtp_native::Receiver, mtp_native::NativeRecvStream>,
>;

#[derive(Default)]
pub struct Pipes {
    handles: Mutex<HashMap<(String, String), PipeCapability>>,
    offers: Mutex<PipeOffers>,
    cancellations: Mutex<HashMap<(String, String), Arc<tokio::sync::Notify>>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipeInfo {
    pub handle: String,
    pub pipe_id: u32,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl Pipes {
    pub async fn invalidate(&self, name: &str) {
        self.handles
            .lock()
            .await
            .retain(|(owner, _), _| owner != name);
        self.cancellations
            .lock()
            .await
            .retain(|(owner, _), notify| {
                if owner == name {
                    notify.notify_one();
                    false
                } else {
                    true
                }
            });
        let mut offers = self.offers.lock().await;
        let ids: Vec<_> = offers
            .keys()
            .filter(|(owner, _)| owner == name)
            .cloned()
            .collect();
        for id in ids {
            if let Some(offer) = offers.remove(&id) {
                let _ = offer.deny().await;
            }
        }
    }
    pub async fn encrypt_writer(
        &self,
        name: &str,
        info: &PipeInfo,
        keys: &mtp_crypto::Keyring,
        sender: u64,
        options: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let entry = self.lookup(name, &info.handle).await?;
        let mut entry = entry.lock().await;
        let Some(Capability::Writer(writer)) = entry.take() else {
            return Err("pipe is not a writer".into());
        };
        let recipient = crate::protected_commands::integer(options, "recipientId")?;
        let purpose = options
            .get("purpose")
            .map(|_| crate::protected_commands::purpose(options, "purpose"))
            .transpose()?
            .unwrap_or(0x40);
        let direction = options
            .get("direction")
            .map(|_| crate::protected_commands::purpose(options, "direction"))
            .transpose()?
            .unwrap_or(0);
        let mut session_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        session_id.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        let params = mtp_pipes::PipeSessionParameters::new_id(
            session_id,
            mtp_common::PipeId::new(info.pipe_id).ok_or("invalid pipe ID")?,
            sender,
            recipient,
            purpose,
            direction,
        )
        .map_err(|e| e.to_string())?;
        let recipients = crate::protected_commands::bundles(options, "recipientPublicKeys")?;
        let dual = match options
            .get("signatureSuite")
            .and_then(|v| v.as_str())
            .unwrap_or("ed25519")
        {
            "ed25519" => false,
            "dual" => true,
            _ => return Err("invalid signature suite".into()),
        };
        let writer = mtp_pipes::initiate_group_pipe_session_with_suite(
            writer,
            params,
            keys,
            &recipients,
            dual,
        )
        .await
        .map_err(|e| e.to_string())?;
        let context = context_value(writer.context());
        *entry = Some(Capability::EncryptedWriter(writer));
        Ok(context)
    }
    pub async fn encrypt_reader(
        &self,
        name: &str,
        info: &PipeInfo,
        keys: &mtp_crypto::Keyring,
        recipient: u64,
        options: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let entry = self.lookup(name, &info.handle).await?;
        let mut entry = entry.lock().await;
        let Some(Capability::Reader(reader)) = entry.take() else {
            return Err("pipe is not a reader".into());
        };
        let sender = crate::protected_commands::integer(options, "senderId")?;
        let purpose = options
            .get("purpose")
            .map(|_| crate::protected_commands::purpose(options, "purpose"))
            .transpose()?
            .unwrap_or(0x40);
        let direction = options
            .get("direction")
            .map(|_| crate::protected_commands::purpose(options, "direction"))
            .transpose()?
            .unwrap_or(0);
        let public = crate::protected_commands::bundles(options, "senderPublicKeys")?;
        let reader = mtp_pipes::accept_pipe_session_auto(
            reader,
            mtp_common::PipeId::new(info.pipe_id).ok_or("invalid pipe ID")?,
            sender,
            recipient,
            purpose,
            direction,
            keys,
            &public,
            crate::protected_commands::policy(options)?,
        )
        .await
        .map_err(|e| e.to_string())?;
        let context = context_value(reader.context());
        *entry = Some(Capability::EncryptedReader(reader));
        Ok(context)
    }
    pub async fn write_record(&self, name: &str, handle: &str, bytes: &[u8]) -> Result<(), String> {
        let entry = self.lookup(name, handle).await?;
        let mut entry = entry.lock().await;
        let Some(Capability::EncryptedWriter(writer)) = entry.as_mut() else {
            return Err("pipe is not an encrypted writer".into());
        };
        if let Err(error) = writer.write_record(bytes).await {
            entry.take();
            return Err(error.to_string());
        }
        Ok(())
    }
    pub async fn read_record(&self, name: &str, handle: &str) -> Result<Option<Vec<u8>>, String> {
        let entry = self.lookup(name, handle).await?;
        let mut entry = entry.lock().await;
        let Some(Capability::EncryptedReader(reader)) = entry.as_mut() else {
            return Err("pipe is not an encrypted reader".into());
        };
        match reader.read_record().await {
            Ok(value) => Ok(value),
            Err(error) => {
                entry.take();
                Err(error.to_string())
            }
        }
    }
    async fn insert(
        &self,
        name: &str,
        capability: Capability,
        pipe_id: u32,
        description: String,
    ) -> PipeInfo {
        let handle = uuid::Uuid::new_v4().to_string();
        self.handles.lock().await.insert(
            (name.into(), handle.clone()),
            Arc::new(Mutex::new(Some(capability))),
        );
        self.cancellations.lock().await.insert(
            (name.into(), handle.clone()),
            Arc::new(tokio::sync::Notify::new()),
        );
        PipeInfo {
            handle,
            pipe_id,
            description,
            context: None,
        }
    }
    async fn lookup(
        &self,
        name: &str,
        handle: &str,
    ) -> Result<Arc<Mutex<Option<Capability>>>, String> {
        self.handles
            .lock()
            .await
            .get(&(name.into(), handle.into()))
            .cloned()
            .ok_or("invalid or foreign pipe handle".into())
    }
    pub async fn offer(
        &self,
        name: &str,
        offer: mtp_pipes::PipeRequest<
            mtp_native::Sender,
            mtp_native::Receiver,
            mtp_native::NativeRecvStream,
        >,
    ) {
        let mut offers = self.offers.lock().await;
        if offers.len() >= 128 {
            drop(offers);
            let _ = offer.deny().await;
            return;
        }
        offers.insert((name.into(), offer.id().get()), offer);
    }
    pub async fn create(
        &self,
        name: &str,
        session: &crate::Session,
        description: String,
    ) -> Result<PipeInfo, String> {
        let pending = session
            .connection()
            .create_pipe(&description)
            .await
            .map_err(|e| e.to_string())?;
        let id = pending.pipe_id_value().get();
        Ok(self
            .insert(name, Capability::Pending(pending), id, description)
            .await)
    }
    pub async fn wait(&self, name: &str, handle: &str) -> Result<Option<PipeInfo>, String> {
        let entry = self.lookup(name, handle).await?;
        let mut entry = entry.lock().await;
        let Some(Capability::Pending(pending)) = entry.take() else {
            return Err("pipe is not pending".into());
        };
        let pipe_id = pending.pipe_id_value().get();
        let description = pending.description().to_owned();
        let cancellation = self
            .cancellations
            .lock()
            .await
            .get(&(name.into(), handle.into()))
            .cloned()
            .ok_or("released pipe handle")?;
        let accepted = tokio::select! {
            result = pending.wait() => result.map_err(|e| e.to_string())?,
            _ = cancellation.notified() => return Err("pipe negotiation cancelled".into()),
        };
        match accepted {
            Some(writer) => {
                *entry = Some(Capability::Writer(writer));
                Ok(Some(PipeInfo {
                    handle: handle.into(),
                    pipe_id,
                    description,
                    context: None,
                }))
            }
            None => Ok(None),
        }
    }
    pub async fn accept(&self, name: &str, id: u32) -> Result<PipeInfo, String> {
        let offer = self
            .offers
            .lock()
            .await
            .remove(&(name.into(), id))
            .ok_or("unknown pipe offer")?;
        let description = offer.description().to_owned();
        let reader = offer.accept().await.map_err(|e| e.to_string())?;
        Ok(self
            .insert(name, Capability::Reader(reader), id, description)
            .await)
    }
    pub async fn deny(&self, name: &str, id: u32) -> Result<(), String> {
        self.offers
            .lock()
            .await
            .remove(&(name.into(), id))
            .ok_or("unknown pipe offer")?
            .deny()
            .await
            .map_err(|e| e.to_string())
    }
    pub async fn write(&self, name: &str, handle: &str, bytes: &[u8]) -> Result<(), String> {
        let entry = self.lookup(name, handle).await?;
        let mut entry = entry.lock().await;
        let Some(Capability::Writer(writer)) = entry.as_mut() else {
            return Err("pipe is not a raw writer".into());
        };
        if let Err(error) = writer.write_all(bytes).await {
            entry.take();
            return Err(error.to_string());
        }
        Ok(())
    }
    pub async fn read(&self, name: &str, handle: &str) -> Result<Option<Vec<u8>>, String> {
        let entry = self.lookup(name, handle).await?;
        let mut entry = entry.lock().await;
        let Some(Capability::Reader(reader)) = entry.as_mut() else {
            return Err("pipe is not a raw reader".into());
        };
        let mut bytes = vec![0; 64 * 1024];
        match reader.read(&mut bytes).await {
            Ok(0) => {
                entry.take();
                Ok(None)
            }
            Ok(count) => {
                bytes.truncate(count);
                Ok(Some(bytes))
            }
            Err(error) => {
                entry.take();
                Err(error.to_string())
            }
        }
    }
    pub async fn close(&self, name: &str, handle: &str, abort: bool) -> Result<(), String> {
        if let Some(cancellation) = self
            .cancellations
            .lock()
            .await
            .remove(&(name.into(), handle.into()))
        {
            cancellation.notify_one();
        }
        let entry = self
            .handles
            .lock()
            .await
            .remove(&(name.into(), handle.into()))
            .ok_or("invalid or foreign pipe handle")?;
        match entry.lock().await.take() {
            Some(Capability::EncryptedWriter(writer)) if !abort => {
                writer.finish().await.map_err(|e| e.to_string())
            }
            Some(Capability::Pending(pending)) => pending.cancel().await.map_err(|e| e.to_string()),
            Some(Capability::Writer(mut writer)) if abort => {
                writer.abort().map_err(|e| e.to_string())
            }
            Some(Capability::Writer(writer)) => writer.finish().await.map_err(|e| e.to_string()),
            _ => Ok(()),
        }
    }
}

fn context_value(context: &mtp_pipes::PipeProtectionContext) -> serde_json::Value {
    serde_json::json!({"sessionId": context.session_id(), "purpose": context.purpose(), "direction": context.direction(), "transcriptHash": context.transcript_hash().as_slice()})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_forged_and_foreign_handles() {
        let pipes = Pipes::default();
        assert!(pipes.lookup("account", "forged").await.is_err());
        let handle = uuid::Uuid::new_v4().to_string();
        pipes.handles.lock().await.insert(
            ("account".into(), handle.clone()),
            Arc::new(Mutex::new(None)),
        );
        assert!(pipes.lookup("other", &handle).await.is_err());
        assert!(pipes.lookup("account", &handle).await.is_ok());
        pipes.close("account", &handle, true).await.unwrap();
        assert!(pipes.lookup("account", &handle).await.is_err());
    }
}
