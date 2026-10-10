//! Shared pipe negotiation, cancellation and authenticated records.
//!
//! Bindings supply transport streams. Protocol operations accept async byte
//! streams without requiring `Send`, including browser-local futures.

#[cfg(target_arch = "wasm32")]
mod tokio {
    pub use ::tokio::io;
    pub use tokio_with_wasm::{sync, time};
}

use mtp_core::{PlatformSend, PlatformSync};

mod negotiation;
pub use negotiation::{
    PendingCreation, PendingCreationGuard, PipeDispatcher, PipeHandle, PipeReceiver, PipeRequest,
    PipeSender, TransportEvent, expire_pending_creation, fail_pending_creations,
    fail_pending_pipes, is_expired_creation, run_dispatcher,
};

#[cfg(feature = "encrypted")]
mod handshake;
#[cfg(feature = "encrypted")]
mod policy;
#[cfg(feature = "encrypted")]
mod record;
#[cfg(feature = "encrypted")]
pub use handshake::{
    MAX_PIPE_SESSION_OFFER, PIPE_SESSION_ENCRYPTION_PURPOSE, PIPE_SESSION_SIGNATURE_PURPOSE,
    PipeProtectionContext, PipeSessionError, PipeSessionParameters,
    accept_forward_secure_pipe_session, accept_forward_secure_pipe_session_auto,
    accept_forward_secure_pipe_session_with_key_history, accept_pipe_session,
    accept_pipe_session_auto, accept_pipe_session_with_key_history,
    accept_pipe_session_with_policy, initiate_forward_secure_pipe_session,
    initiate_group_pipe_session, initiate_group_pipe_session_with_suite, initiate_pipe_session,
};
#[cfg(feature = "encrypted")]
pub use policy::pipe_session_signing_keys;
#[cfg(feature = "encrypted")]
pub use record::{
    EncryptedPipeError, EncryptedPipeReader, EncryptedPipeWriter, MAX_ENCRYPTED_PIPE_RECORD,
};
