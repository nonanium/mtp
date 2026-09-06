//! HTTP routing primitives and the combined MTP web-server API.
//!
//! The public routing API is transport-independent.  The HTTP/3 driver is
//! intentionally kept behind the crate's implementation boundary so callers
//! do not need to depend on a particular QUIC implementation.

mod error;
mod h3;
mod http;
mod router;
mod server;
mod stream;
mod tcp;
mod transport;

pub use error::WebServerError;
pub use mtp_h3::{H3TransportConnection, H3TransportReceiver, H3TransportSender};
#[cfg(feature = "pipes")]
pub use mtp_native::TransportEvent;
pub use router::{DynamicHttpHandler, HttpHandler, RouteParams, Router, RouterError};
pub use server::{MTPWebServer, WebServerConfig, WebServerMetrics};
#[allow(deprecated)]
pub use stream::{Http3Request, Http3Response, HttpRequest, HttpResponse};
pub use transport::{WebMTPConnection, WebMtpReceiver, WebMtpSender};
