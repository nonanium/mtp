//! Dependency-light types shared by every MTP package.

mod error;
mod expiring_set;
mod handshake;
mod id;
mod ping;
#[cfg(feature = "pipes")]
mod pipe;
mod request;
mod stream;
mod time;

pub use error::{CodecError, CommunicationError};
pub use expiring_set::ExpiringSet;
pub use handshake::{HandshakeOutcome, RejectionReason};
pub use id::{MessageId, PingId, PipeId, RequestId, ZeroIdError};
pub use ping::PingTracker;
#[cfg(feature = "pipes")]
pub use pipe::PipeError;
pub use request::{RequestTracker, RouteResult};
pub use stream::{FirstFrameDisposition, classify_first_frame};
pub use time::{TimeError, unix_time_millis};

#[cfg(feature = "test-helpers")]
#[doc(hidden)]
pub mod testing {
    pub use crate::time::duration_to_unix_time_millis;
}
