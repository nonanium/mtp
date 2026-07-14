pub mod client;
pub mod connection;
pub mod connection_handle;

#[cfg(feature = "pipes")]
pub mod pipe;

pub use connection::{Policy, Receiver, SendMode, Sender};

#[cfg(feature = "pipes")]
pub use connection::TransportEvent;
#[cfg(feature = "pipes")]
pub use pipe::{PipeReader, PipeWriter};

pub use client::connect;
pub use connection_handle::ConnectionHandle;

#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "host")]
pub use host::{Host, host};
