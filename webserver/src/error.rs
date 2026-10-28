use mtp_common::CommunicationError;
use std::fmt;

/// Unified error type for the webserver transport adapter.
#[derive(Debug)]
pub enum WebServerError {
    Transport(CommunicationError),
    WebTransport(String),
    Tls(String),
    Http(String),
    BadRequest(String),
    HandlerTimeout,
    PayloadTooLarge,
    NotFound(String),
}

impl WebServerError {
    pub fn status_code(&self) -> http::StatusCode {
        use http::StatusCode;
        match self {
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::HandlerTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Transport(_) | Self::WebTransport(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Tls(_) | Self::Http(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl fmt::Display for WebServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::WebTransport(msg) => write!(f, "webtransport error: {msg}"),
            Self::Tls(msg) => write!(f, "TLS error: {msg}"),
            Self::Http(msg) => write!(f, "HTTP error: {msg}"),
            Self::BadRequest(msg) => write!(f, "invalid HTTP request: {msg}"),
            Self::HandlerTimeout => write!(
                f,
                "request handler timed out; operation outcome may be uncertain"
            ),
            Self::PayloadTooLarge => write!(f, "HTTP request body is too large"),
            Self::NotFound(route) => write!(f, "route not found: {route}"),
        }
    }
}

impl std::error::Error for WebServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CommunicationError> for WebServerError {
    fn from(e: CommunicationError) -> Self {
        Self::Transport(e)
    }
}
