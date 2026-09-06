use mtp::webserver::{HttpRequest, HttpResponse, RouteParams, WebServerConfig};
use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};

async fn health(request: HttpRequest, response: HttpResponse) -> HttpResponse {
    response
        .header("content-type", "text/plain; charset=utf-8")
        .body(format!("OK\nclient: {}\n", request.remote_addr))
}

async fn profile(
    request: HttpRequest,
    response: HttpResponse,
    params: RouteParams,
) -> HttpResponse {
    let Some(user) = params.get("user") else {
        return response.body("missing user");
    };
    let body = serde_json::json!({
        "user": user,
        "remote_addr": request.remote_addr.to_string(),
        "profile": { "display_name": format!("Example user {user}"), "status": "active" }
    });
    response
        .header("content-type", "application/json; charset=utf-8")
        .body(body.to_string())
}

pub fn config() -> Result<WebServerConfig, mtp::webserver::RouterError> {
    let root = Arc::new(web_client_dist());
    if root.is_none() {
        eprintln!(
            "Web client build not found; requests will show setup instructions. Run `pnpm --dir tests/fixtures/example/web-client build`."
        );
    }
    WebServerConfig::new()
        .route("/health", health)?
        .route_pattern("/api/get/{user}/profile", profile)?
        .fallback(move |request, response| {
            let root = Arc::clone(&root);
            async move { static_assets(request, response, root).await }
        })
}

fn web_client_dist() -> Option<PathBuf> {
    [
        PathBuf::from("web-client/dist"),
        PathBuf::from("tests/fixtures/example/web-client/dist"),
    ]
    .into_iter()
    .find(|path| path.join("index.html").is_file())
}

async fn static_assets(
    request: HttpRequest,
    response: HttpResponse,
    root: Arc<Option<PathBuf>>,
) -> HttpResponse {
    if request.method != http::Method::GET && request.method != http::Method::HEAD {
        return response.status(http::StatusCode::METHOD_NOT_ALLOWED);
    }
    let Some(root) = root.as_ref() else {
        return response
            .status(http::StatusCode::SERVICE_UNAVAILABLE)
            .header("content-type", "text/html; charset=utf-8")
            .body("<!doctype html><title>MTP web client not built</title><p>Run <code>pnpm --dir tests/fixtures/example/web-client build</code>.</p>");
    };
    let relative = request.uri.path().trim_start_matches('/');
    let path = Path::new(relative);
    if relative.contains('\\')
        || path.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return response
            .status(http::StatusCode::BAD_REQUEST)
            .body("Invalid path");
    }
    let requested = if relative.is_empty() {
        root.join("index.html")
    } else {
        root.join(path)
    };
    let file = if requested.is_file() {
        requested
    } else if path.extension().is_none() {
        root.join("index.html")
    } else {
        return response
            .status(http::StatusCode::NOT_FOUND)
            .body("Not found");
    };
    match tokio::fs::read(&file).await {
        Ok(body) => {
            let response = response.header("content-type", content_type(&file));
            if request.method == http::Method::HEAD {
                response.header("content-length", &body.len().to_string())
            } else {
                response.body(body)
            }
        }
        Err(_) => response
            .status(http::StatusCode::NOT_FOUND)
            .body("Not found"),
    }
}

fn content_type(file: &Path) -> &'static str {
    match file.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("json" | "map") => "application/json",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}
