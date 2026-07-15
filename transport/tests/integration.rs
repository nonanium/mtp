use std::net::{IpAddr, Ipv4Addr};

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};
use mtp_transport::{Host, Policy, Receiver, Sender, connect, host};

fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem.into_bytes(), key_pem.into_bytes())
}

async fn start_test_host(cert_pem: Vec<u8>, key_pem: Vec<u8>) -> Host {
    host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem,
        key_pem,
        Policy::default(),
    )
    .await
    .unwrap()
}

async fn connect_to_host(h: &Host, cert_pem: Vec<u8>) -> (Sender, Receiver) {
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    connect(&url, Some(cert_pem), Policy::default())
        .await
        .unwrap()
}

async fn connected_pair() -> (Host, Sender, Receiver, Sender, Receiver) {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = start_test_host(cert_pem.clone(), key_pem).await;
    let (client_tx, client_rx) = connect_to_host(&h, cert_pem).await;
    let (host_tx, host_rx) = h.next().await.unwrap();
    (h, client_tx, client_rx, host_tx, host_rx)
}

fn numbered_message(comm_type: CommunicationType, value: u128, tm: &TypeMap) -> CommunicationValue {
    CommunicationValue::new(comm_type).add_data(
        DataType::PqSignature.to_id(tm),
        DataValue::UnsignedNumber(value),
    )
}

fn assert_numbered_message(
    message: &CommunicationValue,
    comm_type: CommunicationType,
    value: u128,
    tm: &TypeMap,
) {
    assert_eq!(message.get_type(), comm_type.to_id(tm));
    assert_eq!(
        message.get_data(DataType::PqSignature).clone(),
        DataValue::UnsignedNumber(value)
    );
}

#[tokio::test]
async fn test_host_start_and_stop() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let h = start_test_host(cert_pem, key_pem).await;
    let addr = h.local_addr();
    // Port should be non-zero (OS-assigned)
    assert!(addr.port() > 0);
}

#[tokio::test]
async fn test_send_receive_roundtrip() {
    let (_h, client_tx, client_rx, host_tx, host_rx) = connected_pair().await;

    let tm = TypeMap::latest();

    // Client sends a simple message
    let msg = numbered_message(CommunicationType::Ping, 42, &tm);
    client_tx.send(&msg).await.unwrap();

    // Host receives it
    let received = host_rx.receive().await.unwrap();
    assert_numbered_message(&received, CommunicationType::Ping, 42, &tm);

    // Host sends a response
    let resp = numbered_message(CommunicationType::Pong, 99, &tm);
    host_tx.send(&resp).await.unwrap();

    // Client receives it
    let client_received = client_rx.receive().await.unwrap();
    assert_numbered_message(&client_received, CommunicationType::Pong, 99, &tm);

    // Close both sides
    client_tx.close();
    host_tx.close();
}

#[tokio::test]
async fn test_concurrent_messages() {
    let (_h, client_tx, _client_rx, _host_tx, host_rx) = connected_pair().await;

    let tm = TypeMap::latest();

    // Send 5 messages in sequence
    for i in 0..5u128 {
        let msg = numbered_message(CommunicationType::Ping, i, &tm);
        client_tx.send(&msg).await.unwrap();
    }

    // Receive all 5 in order
    for i in 0..5u128 {
        let received = host_rx.receive().await.unwrap();
        assert_numbered_message(&received, CommunicationType::Ping, i, &tm);
    }

    // Send 3 responses back
    for i in 0..3u128 {
        let msg = numbered_message(CommunicationType::Pong, i * 10, &tm);
        client_tx.send(&msg).await.unwrap();
    }

    for i in 0..3u128 {
        let received = host_rx.receive().await.unwrap();
        assert_numbered_message(&received, CommunicationType::Pong, i * 10, &tm);
    }

    client_tx.close();
}

#[tokio::test]
async fn test_close_detection() {
    let (_h, client_tx, _client_rx, _host_tx, host_rx) = connected_pair().await;

    // Send a message then close
    let msg = CommunicationValue::new(CommunicationType::Ping);
    client_tx.send(&msg).await.unwrap();
    client_tx.close();

    // Host should still receive the message
    let tm = TypeMap::latest();
    let received = host_rx.receive().await.unwrap();
    assert_eq!(received.get_type(), CommunicationType::Ping.to_id(&tm));

    // Host should get an error or closed signal on next receive
    let result = host_rx.receive().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_host_shutdown_stops_accepting() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = start_test_host(cert_pem.clone(), key_pem).await;
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());

    // A connection succeeds while the host is accepting.
    let (_c_tx, _c_rx) = connect(&url, Some(cert_pem.clone()), Policy::default())
        .await
        .unwrap();
    let _accepted = h.next().await.unwrap();

    // After shutdown the accept task is aborted and its endpoint is dropped, so
    // new connections no longer succeed. Guard with a timeout so a hung connect
    // still fails the assertion rather than blocking the test.
    h.shutdown();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connect(&url, Some(cert_pem), Policy::default()),
    )
    .await;
    assert!(
        matches!(result, Err(_) | Ok(Err(_))),
        "connect should not succeed after host shutdown"
    );
}

#[tokio::test]
async fn test_drop_receiver_keeps_sender_alive() {
    let (_h, client_tx, client_rx, host_tx, host_rx) = connected_pair().await;

    // Client sends a message the host receives.
    let msg = CommunicationValue::new(CommunicationType::Ping);
    client_tx.send(&msg).await.unwrap();
    let _ = host_rx.receive().await.unwrap();

    // Dropping the host Receiver aborts only its accept task; the Sender shares
    // the same connection and must keep working.
    drop(host_rx);

    let tm = TypeMap::latest();

    let resp = numbered_message(CommunicationType::Pong, 7, &tm);
    host_tx.send(&resp).await.unwrap();

    let got = client_rx.receive().await.unwrap();
    assert_numbered_message(&got, CommunicationType::Pong, 7, &tm);

    client_tx.close();
    host_tx.close();
}

#[tokio::test]
async fn test_persistent_stream_reopens_after_local_finish() {
    let (_h, client_tx, client_rx, host_tx, host_rx) = connected_pair().await;

    let tm = TypeMap::latest();
    let msg1 = numbered_message(CommunicationType::Ping, 11, &tm);
    client_tx.send(&msg1).await.unwrap();
    let received1 = host_rx.receive().await.unwrap();
    assert_numbered_message(&received1, CommunicationType::Ping, 11, &tm);

    client_tx.finish_stream().await.unwrap();

    let msg2 = numbered_message(CommunicationType::Pong, 22, &tm);
    client_tx.send(&msg2).await.unwrap();
    let received2 = host_rx.receive().await.unwrap();
    assert_numbered_message(&received2, CommunicationType::Pong, 22, &tm);

    client_tx.close();
    host_tx.close();
    drop(client_rx);
}

#[tokio::test]
async fn test_receiver_backpressure_with_small_queue() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = start_test_host(cert_pem.clone(), key_pem).await;
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    let policy = Policy::default().with_receiver_queue_capacity(1);
    let (client_tx, client_rx) = connect(&url, Some(cert_pem), policy).await.unwrap();
    let (_host_tx, host_rx) = h.next().await.unwrap();

    let tm = TypeMap::latest();
    for i in 0..8u128 {
        client_tx
            .send(&numbered_message(CommunicationType::Ping, i, &tm))
            .await
            .unwrap();
    }

    for i in 0..8u128 {
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), host_rx.receive())
            .await
            .unwrap()
            .unwrap();
        assert_numbered_message(&received, CommunicationType::Ping, i, &tm);
    }

    client_tx.close();
    drop(client_rx);
    h.shutdown();
}

#[tokio::test]
async fn test_max_frames_per_stream_enforced() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let policy = Policy::default().with_max_frames_per_stream(Some(1));
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        policy,
    )
    .await
    .unwrap();
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    let (client_tx, _client_rx) = connect(&url, Some(cert_pem), Policy::default())
        .await
        .unwrap();
    let (_host_tx, host_rx) = h.next().await.unwrap();

    let tm = TypeMap::latest();
    client_tx
        .send(&numbered_message(CommunicationType::Ping, 1, &tm))
        .await
        .unwrap();
    let first = host_rx.receive().await.unwrap();
    assert_numbered_message(&first, CommunicationType::Ping, 1, &tm);

    client_tx
        .send(&numbered_message(CommunicationType::Ping, 2, &tm))
        .await
        .unwrap();
    let second = host_rx.receive().await;
    assert!(second.is_err(), "stream should be closed after frame limit");

    client_tx.close();
    h.shutdown();
}

#[tokio::test]
async fn test_semaphore_saturation_with_concurrent_streams() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let policy = Policy::default()
        .with_send_mode(mtp_transport::SendMode::SingleStreamPerMessage)
        .with_receiver_queue_capacity(1)
        .with_max_concurrent_stream_tasks(1);
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        policy,
    )
    .await
    .unwrap();
    let url = format!("https://127.0.0.1:{}", h.local_addr().port());
    let (client_tx, _client_rx) = connect(&url, Some(cert_pem), Policy::default())
        .await
        .unwrap();
    let (_host_tx, host_rx) = h.next().await.unwrap();

    let tm = TypeMap::latest();
    let mut joins = Vec::new();
    for i in 0..6u128 {
        let tx = client_tx.clone();
        let msg = numbered_message(CommunicationType::Ping, i, &tm);
        joins.push(tokio::spawn(async move { tx.send(&msg).await }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    for join in joins {
        join.await.unwrap().unwrap();
    }

    for i in 0..6u128 {
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), host_rx.receive())
            .await
            .unwrap()
            .unwrap();
        assert_numbered_message(&received, CommunicationType::Ping, i, &tm);
    }

    client_tx.close();
    h.shutdown();
}
