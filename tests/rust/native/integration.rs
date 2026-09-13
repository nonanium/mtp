use std::net::{IpAddr, Ipv4Addr};

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use mtp_native::{
    ClientConfig as TransportClientConfig, Host, HostConfig as TransportHostConfig, Policy,
    Receiver, Sender, connect, connect_with_config, host, host_with_config,
};

fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().expect("failed to generate self-signed key pair");
    let params = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
        .expect("failed to build self-signed certificate params");
    let cert = params
        .self_signed(&key_pair)
        .expect("failed to self-sign certificate");
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem.into_bytes(), key_pem.into_bytes())
}

async fn start_test_host(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
) -> Result<Host, Box<dyn std::error::Error>> {
    Ok(host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem,
        key_pem,
        Policy::default(),
    )
    .await?)
}

async fn connect_to_host(
    h: &Host,
    cert_pem: Vec<u8>,
) -> Result<(Sender, Receiver), Box<dyn std::error::Error>> {
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    Ok(connect(&url, Some(cert_pem), Policy::default()).await?)
}

async fn connected_pair()
-> Result<(Host, Sender, Receiver, Sender, Receiver), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = start_test_host(cert_pem.clone(), key_pem).await?;
    let (client_tx, client_rx) = connect_to_host(&h, cert_pem).await?;
    let (host_tx, host_rx) = h.next().await.ok_or("host did not accept connection")?;
    Ok((h, client_tx, client_rx, host_tx, host_rx))
}

fn numbered_message(comm_type: CommunicationType, value: u128, tm: &TypeMap) -> CommunicationValue {
    CommunicationValue::new(comm_type)
        .add_data(
            DataType::PqSignature
                .try_to_id(tm)
                .expect("test type must be mapped"),
            DataValue::UnsignedNumber(value),
        )
        .expect("numbered message must have a container payload")
}

fn assert_numbered_message(
    message: &CommunicationValue,
    comm_type: CommunicationType,
    value: u128,
    tm: &TypeMap,
) {
    assert_eq!(
        message.get_type(),
        comm_type.try_to_id(tm).expect("test type must be mapped")
    );
    assert_eq!(
        message.get_data(DataType::PqSignature),
        Some(&DataValue::UnsignedNumber(value))
    );
}

#[tokio::test]
async fn test_host_start_and_stop() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let h = start_test_host(cert_pem, key_pem).await?;
    let addr = h.local_addr();
    // Port should be non-zero (OS-assigned)
    assert!(addr.port() > 0);
    Ok(())
}

#[tokio::test]
async fn test_explicit_development_tls() -> Result<(), Box<dyn std::error::Error>> {
    // The insecure-tls feature requires MTP_INSECURE_TLS=1 at runtime.
    // SAFETY: test is single-threaded; no concurrent readers of this env var.
    unsafe {
        std::env::set_var("MTP_INSECURE_TLS", "1");
    }

    let mut h = host_with_config(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        TransportHostConfig::self_signed(Policy::default()),
    )
    .await?;
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    let client_config =
        TransportClientConfig::new(Policy::default()).with_insecure_certificate_verification();

    let (client_tx, _client_rx) = connect_with_config(&url, client_config).await?;
    let (_host_tx, _host_rx) = h.next().await.ok_or("host did not accept connection")?;

    client_tx.close().await;
    h.shutdown(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .await;
    Ok(())
}

#[tokio::test]
async fn test_send_receive_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let (_h, client_tx, client_rx, host_tx, host_rx) = connected_pair().await?;

    let tm = TypeMap::latest();

    // Client sends a simple message
    let msg = numbered_message(CommunicationType::Ping, 42, &tm);
    client_tx.send(&msg).await?;

    // Host receives it
    let received = host_rx.receive().await?;
    assert_numbered_message(&received, CommunicationType::Ping, 42, &tm);

    // Host sends a response
    let resp = numbered_message(CommunicationType::BadRequest, 99, &tm);
    host_tx.send(&resp).await?;

    // Client receives it
    let client_received = client_rx.receive().await?;
    assert_numbered_message(&client_received, CommunicationType::BadRequest, 99, &tm);

    // Close both sides
    client_tx.close().await;
    host_tx.close().await;
    Ok(())
}

#[tokio::test]
async fn test_generic_payload_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let (_h, client_tx, _client_rx, host_tx, host_rx) = connected_pair().await?;
    let payload = DataValue::Array(vec![
        DataValue::Str("generic payload".into()),
        DataValue::Bytes(vec![1, 2, 3]),
    ]);
    let message =
        CommunicationValue::new(CommunicationType::BadRequest).with_payload(payload.clone());

    client_tx.send(&message).await?;
    let received = host_rx.receive().await?;

    assert_eq!(received.into_payload(), payload);
    client_tx.close().await;
    host_tx.close().await;
    Ok(())
}

#[tokio::test]
async fn test_concurrent_messages() -> Result<(), Box<dyn std::error::Error>> {
    let (_h, client_tx, _client_rx, _host_tx, host_rx) = connected_pair().await?;

    let tm = TypeMap::latest();

    // Send 5 messages in sequence
    for i in 0..5u128 {
        let msg = numbered_message(CommunicationType::Ping, i, &tm);
        client_tx.send(&msg).await?;
    }

    // Receive all 5 in order
    for i in 0..5u128 {
        let received = host_rx.receive().await?;
        assert_numbered_message(&received, CommunicationType::Ping, i, &tm);
    }

    // Send 3 responses back
    for i in 0..3u128 {
        let msg = numbered_message(CommunicationType::BadRequest, i * 10, &tm);
        client_tx.send(&msg).await?;
    }

    for i in 0..3u128 {
        let received = host_rx.receive().await?;
        assert_numbered_message(&received, CommunicationType::BadRequest, i * 10, &tm);
    }

    client_tx.close().await;
    Ok(())
}

#[tokio::test]
async fn test_close_detection() -> Result<(), Box<dyn std::error::Error>> {
    let (_h, client_tx, _client_rx, _host_tx, host_rx) = connected_pair().await?;

    // Send a message then close
    let msg = CommunicationValue::new(CommunicationType::Ping);
    client_tx.send(&msg).await?;

    // Host should still receive the message
    let tm = TypeMap::latest();
    let received = host_rx.receive().await?;
    assert_eq!(
        received.get_type(),
        CommunicationType::Ping
            .try_to_id(&tm)
            .expect("test type must be mapped")
    );

    client_tx.close().await;

    // Host should get an error or closed signal on next receive
    let result = host_rx.receive().await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn test_host_shutdown_stops_accepting() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = start_test_host(cert_pem.clone(), key_pem).await?;
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());

    // A connection succeeds while the host is accepting.
    let (_c_tx, _c_rx) = connect(&url, Some(cert_pem.clone()), Policy::default()).await?;
    let _accepted = h.next().await.ok_or("host did not accept connection")?;

    // After shutdown the accept task is aborted and its endpoint is dropped, so
    // new connections no longer succeed. Guard with a timeout so a hung connect
    // still fails the assertion rather than blocking the test.
    h.shutdown(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .await;

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connect(&url, Some(cert_pem), Policy::default()),
    )
    .await;
    assert!(
        matches!(result, Err(_) | Ok(Err(_))),
        "connect should not succeed after host shutdown"
    );
    Ok(())
}

#[tokio::test]
async fn test_drop_receiver_keeps_sender_alive() -> Result<(), Box<dyn std::error::Error>> {
    let (_h, client_tx, client_rx, host_tx, host_rx) = connected_pair().await?;

    // Client sends a message the host receives.
    let msg = CommunicationValue::new(CommunicationType::Ping);
    client_tx.send(&msg).await?;
    let _ = host_rx.receive().await?;

    // Dropping the host Receiver aborts only its accept task; the Sender shares
    // the same connection and must keep working.
    drop(host_rx);

    let tm = TypeMap::latest();

    let resp = numbered_message(CommunicationType::BadRequest, 7, &tm);
    host_tx.send(&resp).await?;

    let got = client_rx.receive().await?;
    assert_numbered_message(&got, CommunicationType::BadRequest, 7, &tm);

    client_tx.close().await;
    host_tx.close().await;
    Ok(())
}

#[tokio::test]
async fn test_persistent_stream_reopens_after_local_finish()
-> Result<(), Box<dyn std::error::Error>> {
    let (_h, client_tx, client_rx, host_tx, host_rx) = connected_pair().await?;

    let tm = TypeMap::latest();
    let msg1 = numbered_message(CommunicationType::Ping, 11, &tm);
    client_tx.send(&msg1).await?;
    let received1 = host_rx.receive().await?;
    assert_numbered_message(&received1, CommunicationType::Ping, 11, &tm);

    client_tx.finish_stream().await?;

    let msg2 = numbered_message(CommunicationType::BadRequest, 22, &tm);
    client_tx.send(&msg2).await?;
    let received2 = host_rx.receive().await?;
    assert_numbered_message(&received2, CommunicationType::BadRequest, 22, &tm);

    client_tx.close().await;
    host_tx.close().await;
    drop(client_rx);
    Ok(())
}

#[tokio::test]
async fn test_receiver_backpressure_with_small_queue() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = start_test_host(cert_pem.clone(), key_pem).await?;
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    let policy = Policy::default().with_receiver_queue_capacity(1);
    let (client_tx, client_rx) = connect(&url, Some(cert_pem), policy).await?;
    let (_host_tx, host_rx) = h.next().await.ok_or("host did not accept connection")?;

    let tm = TypeMap::latest();
    for i in 0..8u128 {
        client_tx
            .send(&numbered_message(CommunicationType::Ping, i, &tm))
            .await?;
    }

    for i in 0..8u128 {
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), host_rx.receive()).await??;
        assert_numbered_message(&received, CommunicationType::Ping, i, &tm);
    }

    client_tx.close().await;
    drop(client_rx);
    h.shutdown(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .await;
    Ok(())
}

#[tokio::test]
async fn test_max_frames_per_stream_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let policy = Policy::default().with_max_frames_per_stream(Some(1));
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        policy,
    )
    .await?;
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    let (client_tx, _client_rx) = connect(&url, Some(cert_pem), Policy::default()).await?;
    let (_host_tx, host_rx) = h.next().await.ok_or("host did not accept connection")?;

    let tm = TypeMap::latest();
    client_tx
        .send(&numbered_message(CommunicationType::Ping, 1, &tm))
        .await
        .expect("first frame should be sent");
    let first = host_rx
        .receive()
        .await
        .expect("first frame should be received");
    assert_numbered_message(&first, CommunicationType::Ping, 1, &tm);

    let _ = client_tx
        .send(&numbered_message(CommunicationType::Ping, 2, &tm))
        .await;
    let second = host_rx.receive().await;
    assert!(second.is_err(), "stream should be closed after frame limit");

    client_tx.close().await;
    h.shutdown(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .await;
    Ok(())
}

#[tokio::test]
async fn test_semaphore_saturation_with_concurrent_streams()
-> Result<(), Box<dyn std::error::Error>> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let policy = Policy::default()
        .with_send_mode(mtp_native::SendMode::SingleStreamPerMessage)
        .with_receiver_queue_capacity(1)
        .with_max_concurrent_stream_tasks(1);
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        policy,
    )
    .await?;
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    let (client_tx, _client_rx) = connect(&url, Some(cert_pem), Policy::default()).await?;
    let (_host_tx, host_rx) = h.next().await.ok_or("host did not accept connection")?;

    let tm = TypeMap::latest();
    let mut joins = Vec::new();
    for i in 0..6u128 {
        let tx = client_tx.clone();
        let msg = numbered_message(CommunicationType::Ping, i, &tm);
        joins.push(tokio::spawn(async move { tx.send(&msg).await }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    for join in joins {
        join.await??;
    }

    let mut received_ids = std::collections::BTreeSet::new();
    for _ in 0..6 {
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), host_rx.receive()).await??;
        assert!(received.is_type(CommunicationType::Ping));
        match received.get_data(DataType::PqSignature) {
            Some(DataValue::UnsignedNumber(id)) => assert!(received_ids.insert(*id)),
            other => panic!("received Ping without its numeric test payload: {other:?}"),
        }
    }
    assert_eq!(received_ids, (0..6).collect());

    client_tx.close().await;
    h.shutdown(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
        .await;
    Ok(())
}
