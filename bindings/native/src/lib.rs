mod adapter;
pub mod client;
pub mod connection;
pub mod connection_handle;
pub mod pinning;

#[cfg(feature = "pipes")]
pub mod encrypted_pipe;
#[cfg(feature = "pipes")]
pub mod pipe;

pub use connection::{
    DecodeRejectionClass, DecodeRejectionCounters, DecodeRejectionCounts, Policy, Receiver,
    SendMode, Sender, classify_decode_error,
};
pub use mtp_common::{PingId, PipeId, RequestId};
pub use mtp_core;
pub use mtp_core::{GenericReceiver, GenericSender};

#[cfg(feature = "pipes")]
pub use connection::TransportEvent;
#[cfg(feature = "pipes")]
pub use encrypted_pipe::{
    EncryptedPipeError, EncryptedPipeReader, EncryptedPipeWriter, MAX_ENCRYPTED_PIPE_RECORD,
    MAX_PIPE_SESSION_OFFER, PIPE_SESSION_ENCRYPTION_PURPOSE, PIPE_SESSION_SIGNATURE_PURPOSE,
    PipeProtectionContext, PipeSessionError, PipeSessionParameters,
    accept_forward_secure_pipe_session, accept_forward_secure_pipe_session_with_key_history,
    accept_pipe_session, accept_pipe_session_with_key_history, accept_pipe_session_with_policy,
    initiate_forward_secure_pipe_session, initiate_group_pipe_session, initiate_pipe_session,
};
#[cfg(feature = "pipes")]
pub use pipe::{PipeReader, PipeWriter};

pub use adapter::{NativeConnection, NativeRecvStream, NativeSendStream};
pub use client::{ClientConfig, connect, connect_with_config};
pub use connection_handle::ConnectionHandle;
pub use mtp_core::{TransportConnection, TransportRecvStream, TransportSendStream};

#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "host")]
pub use host::{Host, HostConfig, host, host_with_config};
