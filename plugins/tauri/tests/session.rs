use mtp_client::{ClientConfig, MTPClient};
use mtp_codec::{CommunicationType, CommunicationValue};
use mtp_host::{HostConfig, MTPHost};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
use tauri_plugin_mtp::ConnectionRegistry;

#[tokio::test]
async fn shared_requests_fanout_detach_and_no_replay() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pem = cert.pem().into_bytes();
        let mut host = MTPHost::new(
            HostConfig::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
                pem.clone(),
                key.serialize_pem().into_bytes(),
            )
            .with_pongs(false),
        )
        .await
        .unwrap();
        let mut policy = ClientConfig::new("https://localhost").policy;
        policy.read_timeout = Duration::from_millis(200);
        let config = ClientConfig::new(format!("https://127.0.0.1:{}", host.local_addr().port()))
            .with_policy(policy)
            .with_pinned_pem(pem.clone())
            .with_ping_interval(Duration::ZERO);
        let registry = ConnectionRegistry::default();
        let (session, peer) = tokio::join!(
            registry.attach_or_connect("shared", "fixture", || MTPClient::connect(config)),
            host.accept()
        );
        let session = session.unwrap();
        let peer = peer.unwrap().unwrap();
        let reused = registry
            .attach_or_connect("shared", "fixture", || async {
                panic!("duplicate connection")
            })
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&session, &reused));
        assert!(
            registry
                .attach_or_connect("shared", "conflict", || async {
                    panic!("conflict must fail")
                })
                .await
                .is_err()
        );
        let mut native = session.subscribe(8).await;
        let mut ui = session.subscribe(8).await;
        let frame = CommunicationValue::new(CommunicationType::ProtectedMessage).with_id(99);
        let server = async {
            let first = peer.receive().await.unwrap();
            let second = peer.receive().await.unwrap();
            assert_ne!(first.id(), second.id());
            assert_ne!(first.id(), Some(99));
            for request in [second, first] {
                peer.sender
                    .send(
                        &CommunicationValue::new(CommunicationType::ProtectedMessage)
                            .with_id(request.id().unwrap()),
                    )
                    .await
                    .unwrap();
            }
        };
        let (rust, js, ()) = tokio::join!(
            session.request(
                frame.clone(),
                Some(CommunicationType::ProtectedMessage),
                Duration::from_secs(2)
            ),
            reused.request(
                frame,
                Some(CommunicationType::ProtectedMessage),
                Duration::from_secs(2)
            ),
            server
        );
        assert_ne!(rust.unwrap().id(), js.unwrap().id());
        let expired = session.request(
            CommunicationValue::new(CommunicationType::ProtectedMessage),
            Some(CommunicationType::ProtectedMessage),
            Duration::from_millis(20),
        );
        let late = async {
            let request = peer.receive().await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
            peer.sender
                .send(
                    &CommunicationValue::new(CommunicationType::ProtectedMessage)
                        .with_id(request.id().unwrap()),
                )
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(expired, late);
        assert!(result.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), native.receive())
                .await
                .is_err()
        );
        let live = CommunicationValue::new(CommunicationType::ProtectedMessage);
        peer.sender.send(&live).await.unwrap();
        assert!(native.receive().await.is_some());
        assert!(ui.receive().await.is_some());
        // Established streams may stay idle beyond the frame deadline without
        // terminating the native session or losing its subscribers.
        tokio::time::sleep(Duration::from_millis(500)).await;
        peer.sender.send(&live).await.unwrap();
        assert!(native.receive().await.is_some());
        assert!(ui.receive().await.is_some());
        ui.detach().await;
        peer.sender.send(&live).await.unwrap();
        assert!(native.receive().await.is_some());
        let mut returning = session.subscribe(8).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(30), returning.receive())
                .await
                .is_err()
        );
        peer.sender.send(&live).await.unwrap();
        assert!(native.receive().await.is_some());
        assert!(returning.receive().await.is_some());
        drop(returning);
        assert!(registry.attach("shared").await.is_some());
        // No UI pipe observer: offers are denied and cannot stall RPC dispatch.
        let pending = peer.create_pipe("absent UI").await.unwrap();
        assert!(pending.wait().await.unwrap().is_none());
        let pipes = tauri_plugin_mtp::Pipes::default();
        let pending = pipes
            .create("shared", &session, "cancel during wait".into())
            .await
            .unwrap();
        let (wait, cancel) = tokio::join!(pipes.wait("shared", &pending.handle), async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            pipes.close("shared", &pending.handle, true).await
        });
        assert!(wait.is_err());
        cancel.unwrap();
        let mut lifecycle = registry.watch("shared").await;
        assert!(Arc::ptr_eq(lifecycle.borrow().as_ref().unwrap(), &session));
        registry.disconnect("shared").await;
        lifecycle.changed().await.unwrap();
        assert!(lifecycle.borrow_and_update().is_none());
        let config = ClientConfig::new(format!("https://127.0.0.1:{}", host.local_addr().port()))
            .with_pinned_pem(pem)
            .with_ping_interval(Duration::ZERO);
        let (replacement, peer) = tokio::join!(
            registry.attach_or_connect("shared", "fixture", || MTPClient::connect(config)),
            host.accept()
        );
        let replacement = replacement.unwrap();
        let peer = peer.unwrap().unwrap();
        lifecycle.changed().await.unwrap();
        assert!(Arc::ptr_eq(
            lifecycle.borrow_and_update().as_ref().unwrap(),
            &replacement
        ));
        registry.disconnect_session("shared", &session).await;
        assert!(Arc::ptr_eq(
            &registry.attach("shared").await.unwrap(),
            &replacement
        ));
        let mut native = replacement.subscribe(8).await;
        let ui = replacement.subscribe(8).await;
        ui.detach().await;
        drop(lifecycle);
        peer.sender.send(&live).await.unwrap();
        assert!(native.receive().await.is_some());
        assert!(registry.attach("shared").await.is_some());
        replacement.close().await;
    })
    .await
    .unwrap();
}

#[test]
fn export_is_separate_from_default_permissions_and_host_policy() {
    let default: toml::Value = toml::from_str(include_str!("../permissions/default.toml")).unwrap();
    let permissions = default["default"]["permissions"].as_array().unwrap();
    assert!(
        !permissions
            .iter()
            .any(|value| value.as_str().unwrap().contains("export"))
    );
    let export: toml::Value =
        toml::from_str(include_str!("../permissions/export-credentials.toml")).unwrap();
    assert_eq!(
        export["permission"][0]["commands"]["allow"][0].as_str(),
        Some("mtp_export_credentials")
    );
    let identity = tauri_plugin_mtp::NativeIdentity::temporary(1);
    assert!(identity.export(true).is_err());
    let identity = identity.allow_export(true);
    assert!(identity.export(false).is_err());
    assert!(identity.export(true).is_ok());
}
