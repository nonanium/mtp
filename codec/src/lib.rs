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
pub use data_value::{
    DEFAULT_TRANSPORT_ALLOCATION_FACTOR, DataKind, DataValue, DecodeError, DecodeLimits,
    EncodeLimits,
};
pub use mtp_common::{CodecError, TimeError, unix_time_millis};
#[cfg(feature = "crypto")]
#[allow(deprecated)]
pub use protected::{
    CURRENT_PROTECTED_VERSION, InMemoryReplayGuard, ProtectedError, ProtectedLimits,
    ProtectedMessageBuilder, ProtectedOpenOptions, ReplayError, ReplayGuard,
    VerifiedProtectedMessage, open_protected_checked, open_protected_with_checked,
    open_protected_with_keys_checked, open_protected_with_keys_without_replay,
    open_protected_with_without_replay, open_protected_without_replay, protected_claimed_signer_id,
    protected_claimed_signer_id_with_limits, protected_claimed_signer_id_with_options,
};
#[cfg(feature = "crypto")]
#[allow(deprecated)]
pub use relay::{
    CURRENT_RELAY_VERSION, RelayError, RelayOpenOptions, SealedRelayBuilder, VerifiedRelayContent,
    VerifiedRelayMetadata, forward_relay_frame, open_relay_content,
    open_relay_content_with_keyrings, open_relay_content_with_keyrings_and_limits,
    open_relay_content_with_keys, open_relay_content_with_limits,
    open_relay_content_with_limits_without_replay, open_relay_metadata_checked,
    open_relay_metadata_with_checked, open_relay_metadata_with_limits_checked,
    open_relay_metadata_with_limits_without_replay, open_relay_metadata_with_without_replay,
    open_relay_metadata_without_replay, relay_metadata_claimed_signer_id,
    relay_metadata_claimed_signer_id_with_limits, relay_metadata_claimed_signer_id_with_options,
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
