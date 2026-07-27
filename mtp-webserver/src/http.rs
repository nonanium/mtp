use crate::{HttpRequest, HttpResponse, Router, WebServerError, WebServerMetrics};
use http::StatusCode;
use std::{future::Future, sync::Arc, time::Duration};

pub(crate) async fn dispatch_request(request: HttpRequest, router: &Router) -> HttpResponse {
    let path = request.uri.path();
    if let Some(handler) = router.handler(&request.method, path) {
        return handler(request, HttpResponse::default()).await;
    }
    if let Some((handler, params)) = router.pattern_handler(&request.method, path) {
        return handler(request, HttpResponse::default(), params).await;
    }
    if let Some(handler) = router.fallback_handler() {
        return handler(request, HttpResponse::default()).await;
    }
    HttpResponse::new(StatusCode::NOT_FOUND)
}

pub(crate) async fn run_request<F>(
    path: &str,
    timeout: Duration,
    metrics: Option<&Arc<dyn WebServerMetrics>>,
    future: F,
) -> HttpResponse
where
    F: Future<Output = Result<HttpResponse, WebServerError>>,
{
    if let Some(metrics) = metrics {
        metrics.request_started(path);
    }
    let started = std::time::Instant::now();
    let response = match tokio::time::timeout(timeout, future).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let status = if matches!(error, WebServerError::PayloadTooLarge) {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            if let Some(metrics) = metrics {
                metrics.error_occurred(&error);
            }
            HttpResponse::new(status)
        }
        Err(_) => {
            let error = WebServerError::Http("request handler timed out".into());
            if let Some(metrics) = metrics {
                metrics.error_occurred(&error);
            }
            HttpResponse::new(StatusCode::REQUEST_TIMEOUT)
        }
    };
    if let Some(metrics) = metrics {
        metrics.request_completed(path, response.status.as_u16(), started.elapsed());
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Uri};

    fn request(method: Method, uri: &'static str) -> HttpRequest {
        HttpRequest {
            method,
            uri: Uri::from_static(uri),
            headers: Default::default(),
            body: None,
            remote_addr: "127.0.0.1:1".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn shared_dispatch_preserves_precedence_and_ignores_query() {
        let router = Router::new()
            .route("/items", |_, response| async move {
                response.status(StatusCode::ACCEPTED)
            })
            .unwrap()
            .route_pattern("/{name}", |_, response, _| async move {
                response.status(StatusCode::CREATED)
            })
            .unwrap()
            .fallback(|_, response| async move { response.status(StatusCode::IM_A_TEAPOT) })
            .unwrap();
        assert_eq!(
            dispatch_request(request(Method::GET, "/items?q=1"), &router)
                .await
                .status,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            dispatch_request(request(Method::GET, "/other"), &router)
                .await
                .status,
            StatusCode::CREATED
        );
    }

    #[tokio::test]
    async fn dispatch_matches_terminal_slashes_for_exact_and_pattern_routes() {
        let router = Router::new()
            .route("/api", |_, response| async move {
                response.status(StatusCode::ACCEPTED)
            })
            .unwrap()
            .route_pattern("/api/test/{id}", |_, response, _| async move {
                response.status(StatusCode::CREATED)
            })
            .unwrap()
            .fallback(|_, response| async move { response.status(StatusCode::IM_A_TEAPOT) })
            .unwrap();

        for uri in ["/api", "/api/"] {
            assert_eq!(
                dispatch_request(request(Method::GET, uri), &router)
                    .await
                    .status,
                StatusCode::ACCEPTED
            );
        }
        for uri in ["/api/test/1", "/api/test/1/"] {
            assert_eq!(
                dispatch_request(request(Method::GET, uri), &router)
                    .await
                    .status,
                StatusCode::CREATED
            );
        }
    }
}
