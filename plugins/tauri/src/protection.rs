use std::sync::Arc;

use mtp_codec::{
    CommunicationType, CommunicationValue, DataValue, InMemoryReplayGuard, ProtectedMessageBuilder,
    ProtectedOpenOptions, ProtectionPolicy, ProtectionPurpose, VerifiedProtectedMessage,
    open_protected_checked,
};
use mtp_crypto::{DualSigner, Keyring, PublicKeyBundle};
use tokio::sync::Mutex;

/// Native key ownership. JavaScript cannot turn credential export on.
pub struct NativeIdentity {
    pub id: u64,
    keys: Arc<Keyring>,
    export_allowed: bool,
    replay: Mutex<InMemoryReplayGuard>,
}

impl NativeIdentity {
    pub fn temporary(id: u64) -> Self {
        Self::new(id, Keyring::generate())
    }

    pub fn enrollment_request(
        &self,
        message_type: CommunicationType,
        content: DataValue,
        iota_id: u64,
        pinned_iota: PublicKeyBundle,
    ) -> Result<CommunicationValue, String> {
        self.protect(
            message_type,
            content,
            iota_id,
            vec![pinned_iota],
            0x72,
            0x73,
        )
    }

    pub async fn enrollment_response(
        &self,
        frame: &CommunicationValue,
        iota_id: u64,
        pinned_iota: &PublicKeyBundle,
    ) -> Result<VerifiedProtectedMessage, String> {
        self.open(frame, iota_id, pinned_iota, 0x74, 0x75).await
    }

    /// The permanent identity signs, while the temporary Contact receives.
    pub fn provision_contact(
        &self,
        message_type: CommunicationType,
        content: DataValue,
        temporary_contact_id: u64,
        temporary_contact: PublicKeyBundle,
    ) -> Result<CommunicationValue, String> {
        self.protect(
            message_type,
            content,
            temporary_contact_id,
            vec![temporary_contact],
            0x76,
            0x77,
        )
    }

    pub fn new(id: u64, keys: Keyring) -> Self {
        Self {
            id,
            keys: Arc::new(keys),
            export_allowed: false,
            replay: Mutex::new(InMemoryReplayGuard::new(4096)),
        }
    }

    pub fn allow_export(mut self, allowed: bool) -> Self {
        self.export_allowed = allowed;
        self
    }

    pub fn public_keys(&self) -> PublicKeyBundle {
        self.keys.public_key_bundle()
    }

    pub fn export(&self, permission_granted: bool) -> Result<Vec<u8>, String> {
        if !self.export_allowed || !permission_granted {
            return Err("credential export is disabled".into());
        }
        self.keys
            .try_to_bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|e| e.to_string())
    }

    pub fn protect(
        &self,
        message_type: CommunicationType,
        content: DataValue,
        receiver: u64,
        recipients: Vec<PublicKeyBundle>,
        signature_purpose: u8,
        encryption_purpose: u8,
    ) -> Result<CommunicationValue, String> {
        let signer = DualSigner::new(
            &self.keys.sig_cl_secret_key,
            &self.keys.sig_pq_secret_key,
            &self.keys.sig_pq_public_key,
        )
        .map_err(|e| e.to_string())?;
        ProtectedMessageBuilder::new(
            message_type,
            content,
            self.id,
            receiver,
            &signer,
            ProtectionPurpose(signature_purpose),
            ProtectionPurpose(encryption_purpose),
        )
        .recipients(recipients)
        .message_id(uuid::Uuid::new_v4().as_u128())
        .created_at(mtp_common::unix_time_millis().map_err(|e| e.to_string())?)
        .build()
        .map_err(|e| e.to_string())
    }

    pub async fn open(
        &self,
        frame: &CommunicationValue,
        expected_signer: u64,
        pinned_signer: &PublicKeyBundle,
        signature_purpose: u8,
        encryption_purpose: u8,
    ) -> Result<VerifiedProtectedMessage, String> {
        let options = ProtectedOpenOptions::new(
            Some(self.id),
            ProtectionPurpose(signature_purpose),
            ProtectionPurpose(encryption_purpose),
            ProtectionPolicy::dual(),
        );
        open_protected_checked(
            frame,
            &self.keys,
            expected_signer,
            pinned_signer,
            options,
            &mut *self.replay.lock().await,
        )
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_requires_both_host_and_permission() {
        let identity = NativeIdentity::temporary(1);
        assert!(identity.export(false).is_err());
        assert!(identity.export(true).is_err());
        let identity = identity.allow_export(true);
        assert!(identity.export(false).is_err());
        assert!(identity.export(true).is_ok());
    }

    #[test]
    fn temporary_identities_have_distinct_keys() {
        let first = NativeIdentity::temporary(1)
            .public_keys()
            .try_as_bytes()
            .unwrap();
        let second = NativeIdentity::temporary(1)
            .public_keys()
            .try_as_bytes()
            .unwrap();
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn enrollment_and_provisioning_bind_purposes_and_destinations() {
        let account = NativeIdentity::temporary(7);
        let iota = NativeIdentity::temporary(8);
        let contact = NativeIdentity::temporary(9);
        let request = account
            .enrollment_request(
                CommunicationType::ProtectedMessage,
                DataValue::BoolTrue,
                iota.id,
                iota.public_keys(),
            )
            .unwrap();
        assert!(
            iota.open(&request, account.id, &account.public_keys(), 0x72, 0x73)
                .await
                .is_ok()
        );
        let response = iota
            .protect(
                CommunicationType::ProtectedMessage,
                DataValue::BoolTrue,
                account.id,
                vec![account.public_keys()],
                0x74,
                0x75,
            )
            .unwrap();
        assert!(
            account
                .enrollment_response(&response, iota.id + 1, &iota.public_keys())
                .await
                .is_err()
        );
        assert!(
            account
                .enrollment_response(&response, iota.id, &contact.public_keys())
                .await
                .is_err()
        );
        assert!(
            account
                .enrollment_response(&response, iota.id, &iota.public_keys())
                .await
                .is_ok()
        );
        let provision = account
            .provision_contact(
                CommunicationType::ProtectedMessage,
                DataValue::Bytes(vec![1, 2, 3]),
                contact.id,
                contact.public_keys(),
            )
            .unwrap();
        assert!(
            contact
                .open(&provision, account.id, &account.public_keys(), 0x74, 0x75)
                .await
                .is_err()
        );
        assert!(
            contact
                .open(&provision, account.id, &account.public_keys(), 0x76, 0x77)
                .await
                .is_ok()
        );
    }
}
