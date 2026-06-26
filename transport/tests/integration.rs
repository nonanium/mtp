use std::net::{IpAddr, Ipv4Addr};

use mtp_codec::{CommunicationType, DataType, TypeMap};
use mtp_transport::{Policy, connect, host};

fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    (cert_pem.into_bytes(), key_pem.into_bytes())
}

#[tokio::test]
async fn test_host_start_and_stop() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem,
        key_pem,
        Policy::default(),
    )
    .await
    .unwrap();
    let addr = h.local_addr();
    // Port should be non-zero (OS-assigned)
    assert!(addr.port() > 0);
}

#[tokio::test]
async fn test_send_receive_roundtrip() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        Policy::default(),
    )
    .await
    .unwrap();
    let addr = h.local_addr();

    let url = format!("https://127.0.0.1:{}", addr.port());
    let (client_tx, client_rx) = connect(&url, Some(cert_pem), Policy::default())
        .await
        .unwrap();

    // Accept on host side
    let (host_tx, host_rx) = h.next().await.unwrap();

    let tm = TypeMap::latest();

    // Client sends a simple message
    let msg = mtp_codec::CommunicationValue::new(CommunicationType::Ping).add_data(
        DataType::PqSignature.to_id(&tm),
        mtp_codec::DataValue::UnsignedNumber(42),
    );
    client_tx.send(&msg).await.unwrap();

    // Host receives it
    let received = host_rx.receive().await.unwrap();
    assert_eq!(received.get_type(), CommunicationType::Ping.to_id(&tm));
    let val = received.get_data(DataType::PqSignature.to_id(&tm)).clone();
    assert_eq!(val, mtp_codec::DataValue::UnsignedNumber(42));

    // Host sends a response
    let resp = mtp_codec::CommunicationValue::new(CommunicationType::Pong).add_data(
        DataType::PqSignature.to_id(&tm),
        mtp_codec::DataValue::UnsignedNumber(99),
    );
    host_tx.send(&resp).await.unwrap();

    // Client receives it
    let client_received = client_rx.receive().await.unwrap();
    assert_eq!(
        client_received.get_type(),
        CommunicationType::Pong.to_id(&tm)
    );
    let client_val = client_received
        .get_data(DataType::PqSignature.to_id(&tm))
        .clone();
    assert_eq!(client_val, mtp_codec::DataValue::UnsignedNumber(99));

    // Close both sides
    client_tx.close();
    host_tx.close();
}

#[tokio::test]
async fn test_concurrent_messages() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        Policy::default(),
    )
    .await
    .unwrap();
    let addr = h.local_addr();

    let url = format!("https://127.0.0.1:{}", addr.port());
    let (client_tx, _client_rx) = connect(&url, Some(cert_pem), Policy::default())
        .await
        .unwrap();

    let (_host_tx, host_rx) = h.next().await.unwrap();

    let tm = TypeMap::latest();

    // Send 5 messages in sequence
    for i in 0..5u128 {
        let msg = mtp_codec::CommunicationValue::new(CommunicationType::Ping).add_data(
            DataType::PqSignature.to_id(&tm),
            mtp_codec::DataValue::UnsignedNumber(i),
        );
        client_tx.send(&msg).await.unwrap();
    }

    // Receive all 5 in order
    for i in 0..5u128 {
        let received = host_rx.receive().await.unwrap();
        let val = received.get_data(DataType::PqSignature.to_id(&tm)).clone();
        assert_eq!(val, mtp_codec::DataValue::UnsignedNumber(i));
    }

    // Send 3 responses back
    for i in 0..3u128 {
        let msg = mtp_codec::CommunicationValue::new(CommunicationType::Pong).add_data(
            DataType::PqSignature.to_id(&tm),
            mtp_codec::DataValue::UnsignedNumber(i * 10),
        );
        client_tx.send(&msg).await.unwrap();
    }

    for i in 0..3u128 {
        let received = host_rx.receive().await.unwrap();
        let val = received.get_data(DataType::PqSignature.to_id(&tm)).clone();
        assert_eq!(val, mtp_codec::DataValue::UnsignedNumber(i * 10));
    }

    client_tx.close();
}

#[tokio::test]
async fn test_close_detection() {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        Policy::default(),
    )
    .await
    .unwrap();
    let addr = h.local_addr();

    let url = format!("https://127.0.0.1:{}", addr.port());
    let (client_tx, _client_rx) = connect(&url, Some(cert_pem), Policy::default())
        .await
        .unwrap();

    let (_host_tx, host_rx) = h.next().await.unwrap();

    // Send a message then close
    let msg = mtp_codec::CommunicationValue::new(CommunicationType::Ping);
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
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        Policy::default(),
    )
    .await
    .unwrap();
    let addr = h.local_addr();
    let url = format!("https://127.0.0.1:{}", addr.port());

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
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let mut h = host(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        cert_pem.clone(),
        key_pem,
        Policy::default(),
    )
    .await
    .unwrap();
    let addr = h.local_addr();

    let url = format!("https://127.0.0.1:{}", addr.port());
    let (client_tx, client_rx) = connect(&url, Some(cert_pem), Policy::default())
        .await
        .unwrap();

    let (host_tx, host_rx) = h.next().await.unwrap();

    // Client sends a message the host receives.
    let msg = mtp_codec::CommunicationValue::new(CommunicationType::Ping);
    client_tx.send(&msg).await.unwrap();
    let _ = host_rx.receive().await.unwrap();

    // Dropping the host Receiver aborts only its accept task; the Sender shares
    // the same connection and must keep working.
    drop(host_rx);

    let tm = TypeMap::latest();

    let resp = mtp_codec::CommunicationValue::new(CommunicationType::Pong).add_data(
        DataType::PqSignature.to_id(&tm),
        mtp_codec::DataValue::UnsignedNumber(7),
    );
    host_tx.send(&resp).await.unwrap();

    let got = client_rx.receive().await.unwrap();
    assert_eq!(got.get_type(), CommunicationType::Pong.to_id(&tm));
    assert_eq!(
        got.get_data(DataType::PqSignature.to_id(&tm)).clone(),
        mtp_codec::DataValue::UnsignedNumber(7)
    );

    client_tx.close();
    host_tx.close();
}
