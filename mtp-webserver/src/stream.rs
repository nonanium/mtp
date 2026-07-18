use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use tokio::sync::mpsc;

/// An owned HTTP/3 request passed to a route handler.
#[derive(Clone, Debug)]
pub struct Http3Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
}

/// A buffered HTTP/3 response returned from a route handler.
pub struct Http3Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<Bytes>,
    pub(crate) stream: Option<mpsc::Receiver<Bytes>>,
}

impl Http3Response {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Vec::new(),
            stream: None,
        }
    }

    pub fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        match (key.parse::<HeaderName>(), value.parse::<HeaderValue>()) {
            (Ok(key), Ok(value)) => {
                self.headers.insert(key, value);
            }
            (Err(error), _) => {
                tracing::warn!(%error, key, "discarding invalid HTTP response header")
            }
            (_, Err(error)) => {
                tracing::warn!(%error, key, "discarding invalid HTTP response header")
            }
        }
        self
    }
    pub fn try_header(mut self, key: &str, value: &str) -> Result<Self, String> {
        let key = key.parse::<HeaderName>().map_err(|e| e.to_string())?;
        let value = value.parse::<HeaderValue>().map_err(|e| e.to_string())?;
        self.headers.insert(key, value);
        Ok(self)
    }

    pub fn body(mut self, chunk: impl Into<Bytes>) -> Self {
        self.body.push(chunk.into());
        self
    }
    /// Stream response chunks as they become available instead of buffering them.
    pub fn stream(mut self, chunks: mpsc::Receiver<Bytes>) -> Self {
        self.stream = Some(chunks);
        self
    }
}

impl Default for Http3Response {
    fn default() -> Self {
        Self::new(StatusCode::OK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_collects_headers_and_body_chunks() {
        let response = Http3Response::new(StatusCode::CREATED)
            .header("content-type", "text/plain")
            .body("hello")
            .body(" world");
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.headers["content-type"], "text/plain");
        assert_eq!(
            response.body,
            vec![Bytes::from("hello"), Bytes::from(" world")]
        );
    }
}
