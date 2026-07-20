use crate::{HttpRequest, HttpResponse};
use http::Method;
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

/// Values captured from a parameterized route.
pub type RouteParams = HashMap<String, String>;

/// An asynchronous HTTP route handler.
pub type HttpHandler = Arc<
    dyn Fn(HttpRequest, HttpResponse) -> Pin<Box<dyn Future<Output = HttpResponse> + Send>>
        + Send
        + Sync,
>;

/// An asynchronous handler for a parameterized HTTP route.
pub type DynamicHttpHandler = Arc<
    dyn Fn(
            HttpRequest,
            HttpResponse,
            RouteParams,
        ) -> Pin<Box<dyn Future<Output = HttpResponse> + Send>>
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

    #[error("invalid route pattern: {0}")]
    InvalidPattern(String),
}

#[derive(Clone)]
struct PatternRoute {
    method: Option<Method>,
    pattern: String,
    segments: Vec<PatternSegment>,
    static_segments: usize,
    handler: DynamicHttpHandler,
}

#[derive(Clone)]
enum PatternSegment {
    Static(String),
    Parameter(String),
}

/// HTTP route table used by [`MTPWebServer`](crate::MTPWebServer).
#[derive(Clone, Default)]
pub struct Router {
    routes: HashMap<(Option<Method>, String), HttpHandler>,
    pattern_routes: Vec<PatternRoute>,
    fallback: Option<HttpHandler>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn route<F, Fut>(self, path: impl Into<String>, handler: F) -> Result<Self, RouterError>
    where
        F: Fn(HttpRequest, HttpResponse) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HttpResponse> + Send + 'static,
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
        F: Fn(HttpRequest, HttpResponse) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HttpResponse> + Send + 'static,
    {
        self.route_inner(
            Some(method),
            path.into(),
            Arc::new(move |request, response| Box::pin(handler(request, response))),
        )
    }

    /// Register a route containing named single-segment parameters such as
    /// `/api/get/{userid}/profile.json`.
    pub fn route_pattern<F, Fut>(
        self,
        pattern: impl Into<String>,
        handler: F,
    ) -> Result<Self, RouterError>
    where
        F: Fn(HttpRequest, HttpResponse, RouteParams) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HttpResponse> + Send + 'static,
    {
        self.route_pattern_inner(
            None,
            pattern.into(),
            Arc::new(move |request, response, params| Box::pin(handler(request, response, params))),
        )
    }

    /// Register a method-specific route containing named single-segment
    /// parameters.
    pub fn route_pattern_method<F, Fut>(
        self,
        method: Method,
        pattern: impl Into<String>,
        handler: F,
    ) -> Result<Self, RouterError>
    where
        F: Fn(HttpRequest, HttpResponse, RouteParams) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HttpResponse> + Send + 'static,
    {
        self.route_pattern_inner(
            Some(method),
            pattern.into(),
            Arc::new(move |request, response, params| Box::pin(handler(request, response, params))),
        )
    }

    pub fn fallback<F, Fut>(mut self, handler: F) -> Result<Self, RouterError>
    where
        F: Fn(HttpRequest, HttpResponse) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HttpResponse> + Send + 'static,
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

    fn route_pattern_inner(
        mut self,
        method: Option<Method>,
        pattern: String,
        handler: DynamicHttpHandler,
    ) -> Result<Self, RouterError> {
        let segments = parse_pattern(&pattern)?;
        if self
            .pattern_routes
            .iter()
            .any(|route| route.method == method && route.pattern == pattern)
        {
            return Err(RouterError::DuplicateRoute(pattern));
        }
        let static_segments = segments
            .iter()
            .filter(|segment| matches!(segment, PatternSegment::Static(_)))
            .count();
        self.pattern_routes.push(PatternRoute {
            method,
            pattern,
            segments,
            static_segments,
            handler,
        });
        Ok(self)
    }

    pub(crate) fn handler(&self, method: &Method, path: &str) -> Option<HttpHandler> {
        self.routes
            .get(&(Some(method.clone()), path.to_string()))
            .or_else(|| self.routes.get(&(None, path.to_string())))
            .cloned()
    }

    pub(crate) fn pattern_handler(
        &self,
        method: &Method,
        path: &str,
    ) -> Option<(DynamicHttpHandler, RouteParams)> {
        self.pattern_routes
            .iter()
            .filter(|route| route.method.is_none() || route.method.as_ref() == Some(method))
            .filter_map(|route| match_pattern(&route.segments, path).map(|params| (route, params)))
            .max_by_key(|(route, _)| (route.method.is_some(), route.static_segments))
            .map(|(route, params)| (route.handler.clone(), params))
    }
    pub(crate) fn fallback_handler(&self) -> Option<HttpHandler> {
        self.fallback.clone()
    }
}

fn parse_pattern(pattern: &str) -> Result<Vec<PatternSegment>, RouterError> {
    let path = pattern.strip_prefix('/').unwrap_or(pattern);
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.is_empty() {
        return Ok(Vec::new());
    }
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') || segment.ends_with('}') {
                if segment.len() < 3 || !segment.starts_with('{') || !segment.ends_with('}') {
                    return Err(RouterError::InvalidPattern(pattern.to_string()));
                }
                let name = &segment[1..segment.len() - 1];
                if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    || name.chars().next().is_some_and(|c| c.is_ascii_digit())
                {
                    return Err(RouterError::InvalidPattern(pattern.to_string()));
                }
                Ok(PatternSegment::Parameter(name.to_string()))
            } else if segment.contains('{') || segment.contains('}') {
                Err(RouterError::InvalidPattern(pattern.to_string()))
            } else {
                Ok(PatternSegment::Static(segment.to_string()))
            }
        })
        .collect()
}

fn match_pattern(segments: &[PatternSegment], path: &str) -> Option<RouteParams> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let path = path.strip_suffix('/').unwrap_or(path);
    let actual: Vec<&str> = if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    };
    if actual.len() != segments.len() {
        return None;
    }
    let mut params = RouteParams::new();
    for (segment, value) in segments.iter().zip(actual) {
        match segment {
            PatternSegment::Static(expected) if expected != value => return None,
            PatternSegment::Static(_) => {}
            PatternSegment::Parameter(name) => {
                params.insert(name.clone(), percent_decode(value)?);
            }
        }
    }
    Some(params)
}

fn percent_decode(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let raw = value.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' {
            if index + 2 >= raw.len() {
                return None;
            }
            let high = hex_digit(raw[index + 1])?;
            let low = hex_digit(raw[index + 2])?;
            bytes.push(high * 16 + low);
            index += 3;
        } else {
            bytes.push(raw[index]);
            index += 1;
        }
    }
    String::from_utf8(bytes).ok()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
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
        let request = HttpRequest {
            method: Method::GET,
            uri: Uri::from_static("/health"),
            headers: Default::default(),
            body: Some(Bytes::new()),
            remote_addr: "127.0.0.1:4433".parse().unwrap(),
        };
        let response =
            router.handler(&Method::GET, "/health").unwrap()(request, HttpResponse::default())
                .await;
        assert_eq!(response.status, StatusCode::NO_CONTENT);
        assert!(router.handler(&Method::GET, "/missing").is_none());
    }

    #[tokio::test]
    async fn route_pattern_extracts_decoded_parameters() {
        let router = Router::new()
            .route_pattern_method(
                Method::GET,
                "/api/get/{userid}/profile.json",
                |_, response, params| async move {
                    response.body(params.get("userid").unwrap().clone())
                },
            )
            .unwrap();
        let (handler, params) = router
            .pattern_handler(&Method::GET, "/api/get/user%2D123/profile.json")
            .unwrap();
        let request = HttpRequest {
            method: Method::GET,
            uri: Uri::from_static("/api/get/user%2D123/profile.json"),
            headers: Default::default(),
            body: Some(Bytes::new()),
            remote_addr: "127.0.0.1:4433".parse().unwrap(),
        };
        let response = handler(request, HttpResponse::default(), params).await;
        assert_eq!(response.body, vec![Bytes::from("user-123")]);
    }

    #[test]
    fn route_pattern_rejects_invalid_patterns_and_extra_segments() {
        assert!(matches!(
            Router::new()
                .route_pattern("/users/{user-id}", |_, response, _| async move { response }),
            Err(RouterError::InvalidPattern(_))
        ));
        let router = Router::new()
            .route_pattern("/users/{userid}", |_, response, _| async move { response })
            .unwrap();
        assert!(
            router
                .pattern_handler(&Method::GET, "/users/alex/details")
                .is_none()
        );
    }

    #[tokio::test]
    async fn method_specific_and_static_routes_win() {
        let router = Router::new()
            .route_pattern(
                "/api/{resource}/profile.json",
                |_, response, _| async move { response.status(StatusCode::ACCEPTED) },
            )
            .unwrap()
            .route_pattern_method(
                Method::GET,
                "/api/users/profile.json",
                |_, response, _| async move { response.status(StatusCode::CREATED) },
            )
            .unwrap();
        let (handler, params) = router
            .pattern_handler(&Method::GET, "/api/users/profile.json")
            .unwrap();
        let request = HttpRequest {
            method: Method::GET,
            uri: Uri::from_static("/api/users/profile.json"),
            headers: Default::default(),
            body: None,
            remote_addr: "127.0.0.1:4433".parse().unwrap(),
        };
        let response = handler(request, HttpResponse::default(), params).await;
        assert_eq!(response.status, StatusCode::CREATED);
    }
}
