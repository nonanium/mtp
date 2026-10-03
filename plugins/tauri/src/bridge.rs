use std::{collections::HashMap, sync::Arc};

use tauri::{
    Emitter, Manager as _, Runtime, State,
    plugin::{Builder, TauriPlugin},
};
use tokio::sync::Mutex;

use crate::Manager;

async fn frame_limits(state: &Bridge, name: &str) -> Result<mtp_codec::DecodeLimits, String> {
    let entries = state.identities.entries.lock().await;
    let identity = entries.get(name).ok_or("identity is not initialized")?;
    let options = serde_json::json!({"limits": identity.options.receive_limits.clone().unwrap_or_else(|| serde_json::json!({}))});
    Ok(crate::protected_commands::limits(&options)?.0.intersection(
        mtp_codec::DecodeLimits::for_transport_message_size(
            identity
                .options
                .max_message_size
                .unwrap_or(16 * 1024 * 1024),
        ),
    ))
}

#[tauri::command]
async fn mtp_request(
    name: String,
    bytes: Vec<u8>,
    response_type: Option<String>,
    deadline_ms: u64,
    state: State<'_, Bridge>,
) -> Result<Vec<u8>, crate::BridgeError> {
    if deadline_ms == 0 {
        return Err("invalid request deadline".into());
    }
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("frame exceeds bridge limit".into());
    }
    let frame = mtp_codec::CommunicationValue::from_bytes_with_limits(
        &bytes,
        frame_limits(&state, &name).await?,
    )
    .map_err(|e| e.to_string())?;
    let expected = response_type
        .map(|name| {
            mtp_codec::CommunicationType::from_name(&name)
                .ok_or_else(|| format!("unknown response type {name}"))
        })
        .transpose()?;
    state
        .manager
        .registry
        .attach(&name)
        .await
        .ok_or("connection is not initialized")?
        .request(
            frame,
            expected,
            std::time::Duration::from_millis(deadline_ms),
        )
        .await
        .map_err(crate::BridgeError::from)?
        .to_bytes()
        .map_err(|e| crate::BridgeError::from(e.to_string()))
}

#[tauri::command]
async fn mtp_send(
    name: String,
    bytes: Vec<u8>,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("frame exceeds bridge limit".into());
    }
    let frame = mtp_codec::CommunicationValue::from_bytes_with_limits(
        &bytes,
        frame_limits(&state, &name).await?,
    )
    .map_err(|e| e.to_string())?;
    let session = state
        .manager
        .registry
        .attach(&name)
        .await
        .ok_or("connection is not initialized")?;
    session.send(&frame).await.map_err(crate::BridgeError::from)
}

struct Bridge {
    #[cfg(all(feature = "mobile", target_os = "android"))]
    service: Box<dyn Fn(bool) -> Result<(), String> + Send + Sync>,
    #[cfg(all(feature = "mobile", target_os = "android"))]
    android: Box<
        dyn Fn(Vec<crate::lifecycle::BackgroundConnection>) -> Result<(), String> + Send + Sync,
    >,
    persistence: Mutex<()>,
    manager: Arc<Manager>,
    attachments: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    views: Arc<Mutex<AttachedViews>>,
    pipes: Arc<crate::Pipes>,
    identities: Arc<crate::identities::Identities>,
    relays: Mutex<HashMap<(String, String), RelayCapability>>,
}

type AttachedViews = HashMap<String, std::collections::HashSet<(String, String)>>;
type RelayCapability = (
    mtp_codec::VerifiedRelayMetadata,
    Vec<mtp_crypto::PublicKeyBundle>,
    mtp_codec::ProtectionPolicy,
);

#[tauri::command]
async fn mtp_set_background_enabled(
    enabled: bool,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    #[cfg(all(feature = "mobile", target_os = "android"))]
    return (state.service)(enabled).map_err(Into::into);
    #[cfg(not(all(feature = "mobile", target_os = "android")))]
    {
        let _ = (enabled, state);
        Err("background service is only available on Android".into())
    }
}

#[tauri::command]
async fn mtp_create_encrypted_pipe(
    name: String,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<Option<crate::PipeInfo>, crate::BridgeError> {
    let session = state
        .manager
        .registry
        .attach(&name)
        .await
        .ok_or("connection is not initialized")?;
    let description = options
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("encrypted pipe")
        .to_owned();
    let pending = state.pipes.create(&name, &session, description).await?;
    let Some(mut info) = state.pipes.wait(&name, &pending.handle).await? else {
        return Ok(None);
    };
    let (keys, id) = operation_identity(&state, &name, &serde_json::json!({}), "identity").await?;
    match state
        .pipes
        .encrypt_writer(&name, &info, &keys, id, &options)
        .await
    {
        Ok(context) => info.context = Some(context),
        Err(error) => {
            let _ = state.pipes.close(&name, &info.handle, true).await;
            return Err(error.into());
        }
    }
    Ok(Some(info))
}
#[tauri::command]
async fn mtp_accept_encrypted_pipe(
    name: String,
    request: serde_json::Value,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<crate::PipeInfo, crate::BridgeError> {
    let id = request
        .get("pipeId")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("invalid pipe ID")?;
    let mut info = state.pipes.accept(&name, id).await?;
    let (keys, recipient) =
        operation_identity(&state, &name, &serde_json::json!({}), "recipient").await?;
    match state
        .pipes
        .encrypt_reader(&name, &info, &keys, recipient, &options)
        .await
    {
        Ok(context) => info.context = Some(context),
        Err(error) => {
            let _ = state.pipes.close(&name, &info.handle, true).await;
            return Err(error.into());
        }
    }
    Ok(info)
}
#[tauri::command]
async fn mtp_pipe_write_record(
    name: String,
    handle: String,
    bytes: Vec<u8>,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    state
        .pipes
        .write_record(&name, &handle, &bytes)
        .await
        .map_err(Into::into)
}
#[tauri::command]
async fn mtp_pipe_read_record(
    name: String,
    handle: String,
    state: State<'_, Bridge>,
) -> Result<Option<Vec<u8>>, crate::BridgeError> {
    state
        .pipes
        .read_record(&name, &handle)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn mtp_export_credentials(
    name: String,
    state: State<'_, Bridge>,
) -> Result<crate::identities::ImportedCredentials, crate::BridgeError> {
    if !state.manager.credential_export_allowed() {
        return Err("credential export disabled by host".into());
    }
    let entries = state.identities.entries.lock().await;
    let identity = entries.get(&name).ok_or("identity is not initialized")?;
    Ok(crate::identities::ImportedCredentials {
        client_id: identity.client_id.map(|id| id.to_string()),
        keyring: identity
            .keys
            .try_to_bytes()
            .map_err(|e| e.to_string())?
            .to_vec(),
        host_public_key: identity.options.host_public_key.clone(),
    })
}

#[tauri::command]
async fn mtp_build_relay(
    name: String,
    r#type: String,
    content: Vec<u8>,
    metadata: Option<Vec<u8>>,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<Vec<u8>, crate::BridgeError> {
    let (keys, id) = operation_identity(&state, &name, &options, "identity").await?;
    crate::protected_commands::build_relay(
        &keys,
        id,
        &r#type,
        &content,
        metadata.as_deref(),
        &options,
    )
    .map_err(Into::into)
}

#[tauri::command]
async fn mtp_relay_claimed_signer(
    name: String,
    bytes: Vec<u8>,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<String, crate::BridgeError> {
    let (keys, _) = operation_identity(&state, &name, &options, "recipient").await?;
    let history = crate::protected_commands::key_history(&keys, &options)?;
    let keyrings: Vec<_> = history.iter().collect();
    let (decode, _, protected) = crate::protected_commands::limits(&options)?;
    mtp_codec::relay_metadata_claimed_signer_id_with_options(
        &mtp_codec::CommunicationValue::from_bytes_with_limits(&bytes, decode)
            .map_err(|e| e.to_string())?,
        &keyrings,
        decode,
        protected,
    )
    .map(|id| id.to_string())
    .map_err(|e| crate::BridgeError::from(e.to_string()))
}

#[tauri::command]
async fn mtp_open_relay_metadata(
    name: String,
    bytes: Vec<u8>,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<serde_json::Value, crate::BridgeError> {
    let (keys, _) = operation_identity(&state, &name, &options, "recipient").await?;
    let signer = crate::protected_commands::integer(&options, "signerId")?;
    if options.get("expectedSignerId").is_some()
        && crate::protected_commands::integer(&options, "expectedSignerId")? != signer
    {
        return Err("unexpected relay signer".into());
    }
    let public = crate::protected_commands::bundles(&options, "signerPublicKeys")?;
    let policy = crate::protected_commands::policy(&options)?;
    let history = crate::protected_commands::key_history(&keys, &options)?;
    let keyrings: Vec<_> = history.iter().collect();
    let open_options = crate::protected_commands::relay_options(&options, policy)?;
    let metadata = mtp_codec::open_relay_metadata_with_limits_without_replay(
        &mtp_codec::CommunicationValue::from_bytes_with_limits(&bytes, open_options.decode_limits)
            .map_err(|e| e.to_string())?,
        &keyrings,
        Some(signer),
        |_| Some(public.clone()),
        open_options,
    )
    .map_err(|e| e.to_string())?;
    let handle = uuid::Uuid::new_v4().to_string();
    let result = serde_json::json!({"handle": handle, "relayVersion": metadata.relay_version().to_string(), "signerId": metadata.signer_id().to_string(), "finalRecipientId": metadata.final_recipient_id().to_string(), "messageId": metadata.message_id().get().to_string(), "createdAt": metadata.created_at().to_string(), "metadata": metadata.metadata().map(|v| v.to_bytes()).transpose().map_err(|e| e.to_string())?, "encryptedContent": metadata.encrypted_content().to_bytes().map_err(|e| e.to_string())?, "matchedSignerKeyIndex": metadata.matched_signer_key_index()});
    let mut relays = state.relays.lock().await;
    if relays.len() >= 128 {
        return Err("relay capability limit exceeded".into());
    }
    relays.insert((name, handle), (metadata, public, policy));
    Ok(result)
}

#[tauri::command]
async fn mtp_open_relay_content(
    name: String,
    handle: String,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<serde_json::Value, crate::BridgeError> {
    let (keys, _) = operation_identity(&state, &name, &options, "recipient").await?;
    let relays = state.relays.lock().await;
    let (metadata, public, policy) = relays
        .get(&(name, handle))
        .ok_or("invalid or foreign relay handle")?;
    if options.get("expectedSignerId").is_some()
        && crate::protected_commands::integer(&options, "expectedSignerId")? != metadata.signer_id()
    {
        return Err("unexpected relay signer".into());
    }
    let recipient = options
        .get("expectedFinalRecipientId")
        .map(|_| crate::protected_commands::integer(&options, "expectedFinalRecipientId"))
        .transpose()?;
    let history = crate::protected_commands::key_history(&keys, &options)?;
    let keyrings: Vec<_> = history.iter().collect();
    if options.get("signaturePolicy").is_some()
        && crate::protected_commands::policy(&options)? != *policy
    {
        return Err("relay signature policy changed".into());
    }
    if options.get("signerPublicKeys").is_some() {
        let supplied = crate::protected_commands::bundles(&options, "signerPublicKeys")?;
        let encode = |keys: &[mtp_crypto::PublicKeyBundle]| {
            keys.iter()
                .map(|key| key.try_as_bytes().map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()
        };
        if encode(&supplied)? != encode(public)? {
            return Err("relay signer key history changed".into());
        }
    }
    let content = mtp_codec::open_relay_content_with_limits_without_replay(
        metadata,
        &keyrings,
        public,
        recipient,
        crate::protected_commands::relay_options(&options, *policy)?,
    )
    .map_err(|e| e.to_string())?;
    Ok(
        serde_json::json!({"type": content.message_type.to_string(), "content": content.content.to_bytes().map_err(|e| e.to_string())?, "signerId": content.signer_id.to_string(), "finalRecipientId": content.final_recipient_id.to_string()}),
    )
}

#[tauri::command]
async fn mtp_release_relay(
    name: String,
    handle: String,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    state.relays.lock().await.remove(&(name, handle));
    Ok(())
}

async fn operation_identity(
    state: &Bridge,
    name: &str,
    options: &serde_json::Value,
    field: &str,
) -> Result<(Arc<mtp_crypto::Keyring>, u64), String> {
    if let Some(identity) = options.get(field) {
        let keys = mtp_crypto::Keyring::from_bytes(&crate::protected_commands::bytes(
            identity.get("keyring").ok_or("identity keyring missing")?,
        )?)
        .map_err(|e| e.to_string())?;
        let id = if field == "identity" {
            crate::protected_commands::integer(identity, "signerId")?
        } else {
            identity
                .get("id")
                .map(|_| crate::protected_commands::integer(identity, "id"))
                .transpose()?
                .unwrap_or(0)
        };
        return Ok((Arc::new(keys), id));
    }
    let entries = state.identities.entries.lock().await;
    let identity = entries.get(name).ok_or("identity is not initialized")?;
    let keys = identity.keys.clone();
    let id = identity.client_id.unwrap_or(0);
    drop(entries);
    let id = state
        .manager
        .registry
        .attach(name)
        .await
        .map_or(id, |session| session.connection().client_id);
    Ok((keys, id))
}

#[tauri::command]
async fn mtp_build_protected(
    name: String,
    r#type: String,
    content: Vec<u8>,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<Vec<u8>, crate::BridgeError> {
    let (keys, id) = operation_identity(&state, &name, &options, "identity").await?;
    crate::protected_commands::build(&keys, id, &r#type, &content, &options).map_err(Into::into)
}
#[tauri::command]
async fn mtp_open_protected(
    name: String,
    bytes: Vec<u8>,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<serde_json::Value, crate::BridgeError> {
    let (keys, _) = operation_identity(&state, &name, &options, "recipient").await?;
    crate::protected_commands::open(&keys, &bytes, &options).map_err(Into::into)
}
#[tauri::command]
async fn mtp_protected_claimed_signer(
    name: String,
    bytes: Vec<u8>,
    options: serde_json::Value,
    state: State<'_, Bridge>,
) -> Result<String, crate::BridgeError> {
    let (keys, _) = operation_identity(&state, &name, &options, "recipient").await?;
    let history = crate::protected_commands::key_history(&keys, &options)?;
    let keyrings: Vec<_> = history.iter().collect();
    let (decode, _, protected) = crate::protected_commands::limits(&options)?;
    mtp_codec::protected_claimed_signer_id_with_options(
        &mtp_codec::CommunicationValue::from_bytes_with_limits(&bytes, decode)
            .map_err(|e| e.to_string())?,
        &keyrings,
        mtp_codec::ProtectionPurpose(crate::protected_commands::purpose(
            &options,
            "encryptionPurpose",
        )?),
        decode,
        protected,
    )
    .map(|id| id.to_string())
    .map_err(|e| crate::BridgeError::from(e.to_string()))
}

#[tauri::command]
async fn mtp_initialize(
    name: String,
    options: crate::identities::InitializeOptions,
    state: State<'_, Bridge>,
) -> Result<crate::identities::IdentityInfo, crate::BridgeError> {
    state
        .identities
        .initialize(&name, options)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn mtp_connect(
    name: String,
    mode: String,
    state: State<'_, Bridge>,
) -> Result<serde_json::Value, crate::BridgeError> {
    let _persistence = state.persistence.lock().await;
    let id = state
        .identities
        .connect(&name, &mode, &state.manager.registry)
        .await?;
    #[cfg(all(feature = "mobile", target_os = "android"))]
    (state.android)(state.identities.durable_configuration().await?)?;
    state.manager.persist(&state.identities).await?;
    #[cfg(feature = "mobile")]
    let supervised = crate::mobile::lifecycle().is_some();
    #[cfg(not(feature = "mobile"))]
    let supervised = false;
    if !supervised && let Some(session) = state.manager.registry.attach(&name).await {
        state.manager.observe(&name, session).await;
    }
    Ok(serde_json::json!({"clientId": id.to_string(), "state": 2}))
}

#[tauri::command]
async fn mtp_clear_credentials(
    name: String,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    let _persistence = state.persistence.lock().await;
    #[cfg(feature = "mobile")]
    if let Some(owner) = crate::mobile::lifecycle() {
        owner.remove(&name).await;
    }
    state.manager.stop(&name).await;
    state.pipes.invalidate(&name).await;
    state
        .relays
        .lock()
        .await
        .retain(|(owner, _), _| owner != &name);
    state.views.lock().await.remove(&name);
    if let Some(task) = state.attachments.lock().await.remove(&name) {
        task.abort();
    }
    state.identities.entries.lock().await.remove(&name);
    #[cfg(all(feature = "mobile", target_os = "android"))]
    (state.android)(state.identities.durable_configuration().await?)?;
    state.manager.persist(&state.identities).await?;
    Ok(())
}

#[tauri::command]
async fn mtp_create_pipe(
    name: String,
    description: String,
    state: State<'_, Bridge>,
) -> Result<crate::PipeInfo, crate::BridgeError> {
    let session = state
        .manager
        .registry
        .attach(&name)
        .await
        .ok_or("connection is not initialized")?;
    state
        .pipes
        .create(&name, &session, description)
        .await
        .map_err(Into::into)
}
#[tauri::command]
async fn mtp_pipe_wait(
    name: String,
    handle: String,
    state: State<'_, Bridge>,
) -> Result<Option<crate::PipeInfo>, crate::BridgeError> {
    state.pipes.wait(&name, &handle).await.map_err(Into::into)
}
#[tauri::command]
async fn mtp_accept_pipe(
    name: String,
    pipe_id: u32,
    state: State<'_, Bridge>,
) -> Result<crate::PipeInfo, crate::BridgeError> {
    state.pipes.accept(&name, pipe_id).await.map_err(Into::into)
}
#[tauri::command]
async fn mtp_deny_pipe(
    name: String,
    pipe_id: u32,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    state.pipes.deny(&name, pipe_id).await.map_err(Into::into)
}
#[tauri::command]
async fn mtp_pipe_write(
    name: String,
    handle: String,
    bytes: Vec<u8>,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    state
        .pipes
        .write(&name, &handle, &bytes)
        .await
        .map_err(Into::into)
}
#[tauri::command]
async fn mtp_pipe_read(
    name: String,
    handle: String,
    state: State<'_, Bridge>,
) -> Result<Option<Vec<u8>>, crate::BridgeError> {
    state.pipes.read(&name, &handle).await.map_err(Into::into)
}
#[tauri::command]
async fn mtp_pipe_close(
    name: String,
    handle: String,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    state
        .pipes
        .close(&name, &handle, false)
        .await
        .map_err(Into::into)
}
#[tauri::command]
async fn mtp_pipe_abort(
    name: String,
    handle: String,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    state
        .pipes
        .close(&name, &handle, true)
        .await
        .map_err(Into::into)
}
#[tauri::command]
async fn mtp_pipe_cancel(
    name: String,
    handle: String,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    state
        .pipes
        .close(&name, &handle, true)
        .await
        .map_err(Into::into)
}

#[tauri::command]
async fn mtp_status(name: String, state: State<'_, Bridge>) -> Result<bool, crate::BridgeError> {
    Ok(state.manager.registry.attach(&name).await.is_some())
}

#[tauri::command]
async fn mtp_stop(name: String, state: State<'_, Bridge>) -> Result<(), crate::BridgeError> {
    #[cfg(feature = "mobile")]
    if let Some(owner) = crate::mobile::lifecycle() {
        owner.remove(&name).await;
    }
    state.manager.stop(&name).await;
    state.pipes.invalidate(&name).await;
    state
        .relays
        .lock()
        .await
        .retain(|(owner, _), _| owner != &name);
    state.views.lock().await.remove(&name);
    if let Some(task) = state.attachments.lock().await.remove(&name) {
        task.abort();
    }
    Ok(())
}

#[tauri::command]
async fn mtp_detach<R: Runtime>(
    name: String,
    attachment_id: String,
    window: tauri::WebviewWindow<R>,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    let mut attachments = state.attachments.lock().await;
    let mut views = state.views.lock().await;
    if let Some(attached) = views.get_mut(&name) {
        attached.remove(&(window.label().into(), attachment_id));
        if !attached.is_empty() {
            return Ok(());
        }
    }
    views.remove(&name);
    if let Some(task) = attachments.remove(&name) {
        task.abort();
    }
    Ok(())
}

#[tauri::command]
async fn mtp_attach<R: Runtime>(
    name: String,
    attachment_id: String,
    app: tauri::AppHandle<R>,
    window: tauri::WebviewWindow<R>,
    state: State<'_, Bridge>,
) -> Result<(), crate::BridgeError> {
    let _session = state
        .manager
        .registry
        .attach(&name)
        .await
        .ok_or("connection is not initialized")?;
    let mut attachments = state.attachments.lock().await;
    state
        .views
        .lock()
        .await
        .entry(name.clone())
        .or_default()
        .insert((window.label().into(), attachment_id));
    if attachments
        .get(&name)
        .is_some_and(|task| !task.is_finished())
    {
        return Ok(());
    }
    let mut sessions = state.manager.registry.watch(&name).await;
    let event_name = name.clone();
    let pipes = state.pipes.clone();
    let views = state.views.clone();
    attachments.insert(
        name,
        tokio::spawn(async move {
            loop {
                let session = sessions.borrow_and_update().clone();
                let Some(session) = session else {
                    if sessions.changed().await.is_err() { break; }
                    continue;
                };
                let mut subscription = session.subscribe(32).await;
                let mut pipe_offers = session.subscribe_pipes(32).await;
                loop {
                tokio::select! {
                    _ = sessions.changed() => { break; }
                    frame = subscription.receive() => {
                        let Some(frame) = frame else {
                            let _ = sessions.changed().await;
                            break;
                        };
                        if let Ok(bytes) = frame.to_bytes() {
                            let attached = views.lock().await;
                            if let Some(windows) = attached.get(&event_name) {
                                let labels: std::collections::HashSet<_> = windows.iter().map(|(label, _)| label).collect();
                                for label in labels {
                                    let _ = app.emit_to(label.as_str(), "mtp://event", (&event_name, &bytes));
                                }
                            }
                        }
                    }
                    offer = pipe_offers.recv() => {
                        let Some(offer) = offer else {
                            let _ = sessions.changed().await;
                            break;
                        };
                        #[derive(Clone, serde::Serialize)]
                        #[serde(rename_all = "camelCase")]
                        struct Offer { pipe_id: u32, description: String }
                        let payload = Offer { pipe_id: offer.id().get(), description: offer.description().into() };
                        pipes.offer(&event_name, offer).await;
                        let attached = views.lock().await;
                        if let Some(windows) = attached.get(&event_name) {
                            let labels: std::collections::HashSet<_> = windows.iter().map(|(label, _)| label).collect();
                            for label in labels {
                                let _ = app.emit_to(label.as_str(), "mtp://event", (&event_name, &payload));
                            }
                        }
                    }
                }
                }
            }
        }),
    );
    Ok(())
}

pub fn init<R: Runtime>(manager: Arc<Manager>) -> TauriPlugin<R> {
    Builder::new("mtp")
        .on_event(|app, event| {
            if let tauri::RunEvent::WindowEvent {
                label,
                event: tauri::WindowEvent::Destroyed,
                ..
            } = event
            {
                let app = app.clone();
                let label = label.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<Bridge>();
                    let mut attachments = state.attachments.lock().await;
                    let mut views = state.views.lock().await;
                    views.retain(|name, attached| {
                        attached.retain(|(window, _)| window != &label);
                        if attached.is_empty() {
                            if let Some(task) = attachments.remove(name) {
                                task.abort();
                            }
                            false
                        } else {
                            true
                        }
                    });
                });
            }
        })
        .invoke_handler(tauri::generate_handler![
            mtp_status,
            mtp_set_background_enabled,
            mtp_create_encrypted_pipe,
            mtp_accept_encrypted_pipe,
            mtp_pipe_write_record,
            mtp_pipe_read_record,
            mtp_export_credentials,
            mtp_build_relay,
            mtp_relay_claimed_signer,
            mtp_open_relay_metadata,
            mtp_open_relay_content,
            mtp_release_relay,
            mtp_build_protected,
            mtp_open_protected,
            mtp_protected_claimed_signer,
            mtp_initialize,
            mtp_connect,
            mtp_clear_credentials,
            mtp_stop,
            mtp_attach,
            mtp_detach,
            mtp_request,
            mtp_send,
            mtp_create_pipe,
            mtp_pipe_wait,
            mtp_accept_pipe,
            mtp_deny_pipe,
            mtp_pipe_write,
            mtp_pipe_read,
            mtp_pipe_close,
            mtp_pipe_abort,
            mtp_pipe_cancel
        ])
        .setup(move |app, _api| {
            #[cfg(all(feature = "mobile", target_os = "android"))]
            let android = crate::mobile::register(&_api)?;
            #[cfg(feature = "mobile")]
            if let Some(owner) = crate::mobile::lifecycle()
                && !Arc::ptr_eq(&manager, &owner.manager)
            {
                return Err("Tauri and mobile must use the same MTP manager".into());
            }
            #[cfg(feature = "mobile")]
            let identities = crate::mobile::lifecycle()
                .map(|owner| owner.identities.clone())
                .unwrap_or_default();
            #[cfg(not(feature = "mobile"))]
            let identities = Arc::new(crate::identities::Identities::default());
            app.manage(Bridge {
                #[cfg(all(feature = "mobile", target_os = "android"))]
                service: {
                    let android = android.clone();
                    Box::new(move |enabled| {
                        android
                            .run_mobile_plugin::<()>(
                                if enabled { "enable" } else { "disable" },
                                serde_json::json!({}),
                            )
                            .map_err(|e| e.to_string())
                    })
                },
                #[cfg(all(feature = "mobile", target_os = "android"))]
                android: Box::new(move |connections| {
                    let command = if connections.is_empty() {
                        "clear"
                    } else {
                        "configure"
                    };
                    android.run_mobile_plugin::<()>(command, serde_json::json!({
                        "config": serde_json::to_string(&connections).map_err(|e| e.to_string())?
                    })).map_err(|e| e.to_string())
                }),
                persistence: Mutex::new(()),
                manager,
                attachments: Mutex::new(HashMap::new()),
                views: Arc::new(Mutex::new(HashMap::new())),
                pipes: Arc::new(crate::Pipes::default()),
                identities,
                relays: Mutex::new(HashMap::new()),
            });
            Ok(())
        })
        .build()
}
