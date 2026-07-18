use mtp_common::CommunicationError;
use std::fmt;

/// Unified error type for the webserver transport adapter.
#[derive(Debug)]
pub enum WebServerError {
    Transport(CommunicationError),
    WebTransport(String),
    Http(String),
    NotFound(String),
}

impl fmt::Display for WebServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::WebTransport(msg) => write!(f, "webtransport error: {msg}"),
            Self::Http(msg) => write!(f, "HTTP error: {msg}"),
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
