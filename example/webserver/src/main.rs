use http::StatusCode;
use mtp::{
    host::HostConfig,
    webserver::{Http3Request, Http3Response, MTPWebServer, WebServerConfig},
};

async fn health(_request: Http3Request, response: Http3Response) -> Http3Response {
    response
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(r#"{"status":"ok"}"#)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = HostConfig::new(
        "0.0.0.0".parse()?,
        4433,
        std::fs::read("cert.pem")?,
        std::fs::read("key.pem")?,
    );
    let web = WebServerConfig::new().route("/health", health)?.mtp_path("/mtp");
    let mut server = MTPWebServer::new(config, web).await?;
    println!("listening on {}", server.local_addr());

    while let Some(connection) = server.accept().await? {
        println!(
            "MTP client connected: path={}, version={}, description={:?}",
            connection.path, connection.version, connection.description
        );
        tokio::spawn(async move {
            while let Ok(message) = connection.receiver.receive().await {
                println!("received MTP message {}", message.get_id());
            }
        });
    }
    Ok(())
}
