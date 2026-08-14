pub mod communication_value;
pub mod data_value;
#[cfg(feature = "crypto")]
pub mod protected;
#[cfg(feature = "crypto")]
pub mod relay;

pub use communication_value::CommunicationValue;
#[cfg(feature = "crypto")]
pub use data_value::{
    ApplicationProtectionPurpose, EncryptedValue, MtpProtectionPurpose, ProtectionError,
    ProtectionPolicy, ProtectionPurpose, ProtectionPurposeError, SignaturePolicy, SignedValue,
};
pub use data_value::{DataKind, DataValue, DecodeLimits};
pub use mtp_common::{CodecError, TimeError, unix_time_millis};
#[cfg(feature = "crypto")]
pub use protected::{
    CURRENT_PROTECTED_VERSION, InMemoryReplayGuard, ProtectedError, ProtectedMessageBuilder,
    ProtectedOpenOptions, ReplayError, ReplayGuard, VerifiedProtectedMessage, open_protected,
    open_protected_with, open_protected_with_keys, protected_claimed_signer_id,
};
#[cfg(feature = "crypto")]
pub use relay::{
    CURRENT_RELAY_VERSION, RelayError, SealedRelayBuilder, VerifiedRelayContent,
    VerifiedRelayMetadata, forward_relay_frame, open_relay_content,
    open_relay_content_with_keyrings, open_relay_content_with_keys, open_relay_metadata,
    open_relay_metadata_with, open_relay_metadata_with_keys, relay_metadata_claimed_signer_id,
};

pub use mtp_type_map::{
    CommunicationType, CommunicationTypeId, DataType, DataTypeId, PROTOCOL_VERSION, TypeMap,
    Version,
};

pub(crate) fn rand_u32() -> u32 {
    loop {
        let value = rand::random();
        if value != 0 {
            return value;
        }
    }
}

#[cfg(feature = "registry")]
pub mod registry;
