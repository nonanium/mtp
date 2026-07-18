use crate::{Http3Request, Http3Response};
use http::Method;
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

/// An asynchronous HTTP/3 route handler.
pub type HttpHandler = Arc<
    dyn Fn(Http3Request, Http3Response) -> Pin<Box<dyn Future<Output = Http3Response> + Send>>
        + Send
        + Sync,
>;

/// Errors returned by [`Router`] route registration.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("duplicate route registration for {0}")]
    DuplicateRoute(String),

    #[error("a router fallback is already registered")]
    DuplicateFallback,
}

/// Exact-path HTTP route table used by [`MTPWebServer`](crate::MTPWebServer).
#[derive(Clone, Default)]
pub struct Router {
    routes: HashMap<(Option<Method>, String), HttpHandler>,
    fallback: Option<HttpHandler>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn route<F, Fut>(self, path: impl Into<String>, handler: F) -> Result<Self, RouterError>
    where
        F: Fn(Http3Request, Http3Response) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Http3Response> + Send + 'static,
    {
        self.route_inner(
            None,
            path.into(),
            Arc::new(move |request, response| Box::pin(handler(request, response))),
        )
    }

    pub fn route_method<F, Fut>(
        self,
        method: Method,
        path: impl Into<String>,
        handler: F,
    ) -> Result<Self, RouterError>
    where
        F: Fn(Http3Request, Http3Response) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Http3Response> + Send + 'static,
    {
        self.route_inner(
            Some(method),
            path.into(),
            Arc::new(move |request, response| Box::pin(handler(request, response))),
        )
    }

    pub fn fallback<F, Fut>(mut self, handler: F) -> Result<Self, RouterError>
    where
        F: Fn(Http3Request, Http3Response) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Http3Response> + Send + 'static,
    {
        if self.fallback.is_some() {
            return Err(RouterError::DuplicateFallback);
        }
        self.fallback = Some(Arc::new(move |request, response| {
            Box::pin(handler(request, response))
        }));
        Ok(self)
    }

    fn route_inner(
        mut self,
        method: Option<Method>,
        path: String,
        handler: HttpHandler,
    ) -> Result<Self, RouterError> {
        if self
            .routes
            .insert((method, path.clone()), handler)
            .is_some()
        {
            return Err(RouterError::DuplicateRoute(path));
        }
        Ok(self)
    }

    pub(crate) fn handler(&self, method: &Method, path: &str) -> Option<HttpHandler> {
        self.routes
            .get(&(Some(method.clone()), path.to_string()))
            .or_else(|| self.routes.get(&(None, path.to_string())))
            .cloned()
    }
    pub(crate) fn fallback_handler(&self) -> Option<HttpHandler> {
        self.fallback.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Method, StatusCode, Uri};

    #[tokio::test]
    async fn route_dispatches_an_exact_path() {
        let router = Router::new()
            .route("/health", |_, response| async move {
                response.status(StatusCode::NO_CONTENT)
            })
            .unwrap();
        let request = Http3Request {
            method: Method::GET,
            uri: Uri::from_static("/health"),
            headers: Default::default(),
            body: Some(Bytes::new()),
        };
        let response =
            router.handler(&Method::GET, "/health").unwrap()(request, Http3Response::default())
                .await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        assert!(router.handler(&Method::GET, "/missing").is_none());
    }
}
