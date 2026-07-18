//! HTTP/3 routing primitives and the combined MTP web-server API.
//!
//! The public routing API is transport-independent.  The HTTP/3 driver is
//! intentionally kept behind the crate's implementation boundary so callers
//! do not need to depend on a particular QUIC implementation.

mod error;
mod router;
mod server;
mod stream;
mod transport;

pub use error::WebServerError;
pub use router::{HttpHandler, Router, RouterError};
pub use server::{MTPWebServer, WebServerConfig, WebServerMetrics};
pub use stream::{Http3Request, Http3Response};
pub use transport::{
    H3TransportConnection, H3TransportReceiver, H3TransportSender, WebMTPConnection,
    WebMtpReceiver, WebMtpSender,
};
