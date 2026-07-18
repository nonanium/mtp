use mtp::webserver::{Http3Request, Http3Response, WebServerConfig};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

async fn ok(_request: Http3Request, response: Http3Response) -> Http3Response {
    response
        .header("content-type", "text/plain; charset=utf-8")
        .body("OK")
}

pub fn config() -> Result<WebServerConfig, mtp::webserver::RouterError> {
    WebServerConfig::new().route("/", ok)
}

/// Starts the conventional HTTPS side of the example host. WebTransport uses
/// UDP/QUIC on the same port; browsers still need TCP/TLS to navigate to a URL.
pub async fn spawn_https(
    address: SocketAddr,
    certificate_pem: &[u8],
    key_pem: &[u8],
) -> io::Result<JoinHandle<()>> {
    // The TCP listener is created before the QUIC endpoint, so it must select
    // rustls' process-wide provider itself.
    mtp::crypto::ensure_crypto_provider();
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(io::Error::other)?;
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(io::Error::other)?;
    let listener = TcpListener::bind(address).await?;
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let asset_root = web_client_dist();
    match &asset_root {
        Some(_) => println!(
            "HTTPS web client available at https://localhost:{}",
            address.port()
        ),
        None => eprintln!(
            "Web client build not found; HTTPS will show setup instructions. Run `pnpm --dir example/web-client build`."
        ),
    }
    Ok(tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let asset_root = asset_root.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = serve_https_request(&mut stream, &asset_root).await;
            });
        }
    }))
}

fn web_client_dist() -> Option<PathBuf> {
    [
        PathBuf::from("web-client/dist"),
        PathBuf::from("example/web-client/dist"),
    ]
    .into_iter()
    .find(|path| path.join("index.html").is_file())
}

async fn serve_https_request<S>(stream: &mut S, asset_root: &Option<PathBuf>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = [0; 16 * 1024];
    let size = stream.read(&mut request).await?;
    let request = std::str::from_utf8(&request[..size]).unwrap_or_default();
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    let (status, content_type, body) = match asset_root {
        Some(asset_root) => {
            let relative = path.trim_start_matches('/');
            let candidate = asset_root.join(relative);
            let file = if relative.is_empty() || !candidate.is_file() || relative.contains("..") {
                asset_root.join("index.html")
            } else {
                candidate
            };
            let content_type = content_type(&file);
            match tokio::fs::read(&file).await {
                Ok(body) => ("200 OK", content_type, body),
                Err(_) => ("404 Not Found", "text/plain; charset=utf-8", b"Not found".to_vec()),
            }
        }
        None => (
            "503 Service Unavailable",
            "text/html; charset=utf-8",
            b"<!doctype html><title>MTP web client not built</title><p>Run <code>pnpm --dir example/web-client build</code>.</p>".to_vec(),
        ),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

fn content_type(file: &Path) -> &'static str {
    match file.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}
