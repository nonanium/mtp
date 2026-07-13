use std::net::{IpAddr, Ipv4Addr};

use mtp_client::{ClientConfig, MTPClient};
use mtp_host::{HostConfig, MTPHost};

fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem.into_bytes(), key_pem.into_bytes())
}

async fn start_host(send_pongs: bool) -> (MTPHost, Vec<u8>) {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let host = MTPHost::new(
        HostConfig::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, cert_pem.clone(), key_pem)
            .with_pongs(send_pongs),
    )
    .await
    .unwrap();
    (host, cert_pem)
}

#[tokio::test]
async fn test_ping_rtt_and_missed_ping_teardown() {
    let (mut host, cert_pem) = start_host(true).await;
    let url = format!("https://127.0.0.1:{}", host.local_addr().port());

    let client = MTPClient::connect(
        ClientConfig::new(url)
            .with_pinned_pem(cert_pem)
            .with_ping_interval(std::time::Duration::from_millis(25))
            .with_max_missed_pings(3),
    )
    .await
    .unwrap();

    let _accepted = host.accept().await.unwrap().unwrap();

    let ping = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(ping) = client.get_ping() {
                return ping;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    assert!(ping > std::time::Duration::ZERO);

    let (mut silent_host, silent_cert_pem) = start_host(false).await;
    let silent_url = format!("https://127.0.0.1:{}", silent_host.local_addr().port());
    let silent_client = MTPClient::connect(
        ClientConfig::new(silent_url)
            .with_pinned_pem(silent_cert_pem)
            .with_ping_interval(std::time::Duration::from_millis(25))
            .with_max_missed_pings(2),
    )
    .await
    .unwrap();

    let _accepted = silent_host.accept().await.unwrap().unwrap();

    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if silent_client.sender.is_closed() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;

    assert!(closed.is_ok(), "client should close after missed pings");
}
