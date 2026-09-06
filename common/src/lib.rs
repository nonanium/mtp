//! Dependency-light types shared by every MTP package.

mod error;
mod handshake;
#[cfg(feature = "pipes")]
mod pipe;
mod stream;
mod time;

pub use error::{CodecError, CommunicationError};
pub use handshake::{HandshakeOutcome, RejectionReason};
#[cfg(feature = "pipes")]
pub use pipe::PipeError;
pub use stream::{FirstFrameDisposition, classify_first_frame};
pub use time::{TimeError, unix_time_millis};

#[cfg(feature = "test-helpers")]
#[doc(hidden)]
pub mod testing {
    pub use crate::time::duration_to_unix_time_millis;
}
