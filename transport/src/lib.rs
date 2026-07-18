pub mod client;
pub mod connection;
pub mod connection_handle;
mod framing;
pub mod generic_connection;
pub mod pinning;
pub mod transport_traits;

#[cfg(feature = "pipes")]
pub mod pipe;

pub use connection::{Policy, Receiver, SendMode, Sender};
pub use generic_connection::{GenericReceiver, GenericSender};

#[cfg(feature = "pipes")]
pub use connection::TransportEvent;
#[cfg(feature = "pipes")]
pub use pipe::{PipeReader, PipeWriter};

pub use client::{ClientConfig, connect, connect_with_config};
pub use connection_handle::ConnectionHandle;
pub use transport_traits::{TransportConnection, TransportRecvStream, TransportSendStream};

#[cfg(feature = "host")]
pub mod host;
#[cfg(feature = "host")]
pub use host::{Host, HostConfig, host, host_with_config};
