//! Platform-independent transport policy and protocol decisions.

pub use mtp_common::{PingId, PipeId, RequestId};

mod adapter;
mod connection;
mod framing;
mod policy;

pub use adapter::{TransportConnection, TransportRecvStream, TransportSendStream};
#[cfg(feature = "pipes")]
pub use connection::TransportEvent;
pub use connection::{
    DecodeRejectionCounters, DecodeRejectionCounts, GenericReceiver, GenericSender,
};
#[cfg(feature = "pipes")]
pub use pipe::{PipeReader, PipeWriter};

pub use framing::{
    DecodeRejectionClass, RetryDisposition, classify_decode_error, classify_retry,
    decode_frame_length, encode_frame,
};
pub use policy::{Policy, RuntimePolicy, SendMode};

#[cfg(feature = "pipes")]
mod pipe;

#[cfg(feature = "test-helpers")]
#[doc(hidden)]
pub mod testing {
    pub use crate::decode_frame_length;
}
