mod adapter;
pub mod client;
pub mod connection;
pub mod connection_handle;
pub mod pinning;

#[cfg(feature = "pipes")]
pub mod pipe;
#[cfg(feature = "pipes")]
mod pipe_protocol;

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
pub use pipe::{PipeReader, PipeWriter};

pub use adapter::{NativeConnection, NativeRecvStream, NativeSendStream};
pub use client::{ClientConfig, connect, connect_with_config};
pub use connection_handle::ConnectionHandle;
pub use mtp_core::{TransportConnection, TransportRecvStream, TransportSendStream};

#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "host")]
pub use host::{Host, HostConfig, host, host_with_config};
