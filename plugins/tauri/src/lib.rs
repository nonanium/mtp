//! Shared native connection ownership for the Android Tauri bridge.
//!
//! Native identities, live fanout, protected frames and Android lifecycle.
#[cfg(feature = "tauri")]
mod bridge;
mod error;
pub mod identities;
mod manager;
mod pipes;
pub mod protected_commands;
mod protection;
pub use error::BridgeError;
pub use pipes::{PipeInfo, Pipes};
pub mod lifecycle;
#[cfg(feature = "mobile")]
pub mod mobile;
mod session;

#[cfg(feature = "tauri")]
pub use bridge::init;
pub use manager::{ConnectionOptions, Endpoint, HostCallbacks, Manager};
pub use protection::NativeIdentity;
pub use session::{ConnectionRegistry, Session, Subscription};
