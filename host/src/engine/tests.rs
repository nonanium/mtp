use super::*;
use std::sync::Mutex;

#[tokio::test]
async fn guest_generator_accepts_full_width_id_after_collision_check()
-> Result<(), Box<dyn std::error::Error>> {
    let lookups = Arc::new(Mutex::new(Vec::new()));
    let recorded_lookups = Arc::clone(&lookups);

    let mut config = HostConfig::new("127.0.0.1".parse()?, 4433, Vec::new(), Vec::new())
        .with_guest_id_generator(Box::new(|| Box::pin(async { Some(u64::MAX) })));
    config.get_existing_client = Box::new(move |id, description| {
        let recorded_lookups = Arc::clone(&recorded_lookups);
        Box::pin(async move {
            recorded_lookups
                .lock()
                .expect("guest ID lookup mutex should not be poisoned")
                .push((id, description));
            None
        })
    });

    let engine = HandshakeEngine::new(Registry::builtin(), Arc::new(config));

    assert_eq!(engine.assign_guest_id().await?.id, u64::MAX);
    assert_eq!(
        *lookups
            .lock()
            .expect("guest ID lookup mutex should not be poisoned"),
        vec![(u64::MAX, None)]
    );
    Ok(())
}

#[tokio::test]
async fn active_guest_ids_are_unique_and_released() -> Result<(), Box<dyn std::error::Error>> {
    let config = HostConfig::new("127.0.0.1".parse()?, 4433, Vec::new(), Vec::new());
    let engine = HandshakeEngine::new(Registry::builtin(), Arc::new(config));

    let first = engine.try_reserve_guest_id(1).await?.unwrap();
    assert!(engine.try_reserve_guest_id(1).await?.is_none());

    drop(first);
    assert!(engine.try_reserve_guest_id(1).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn zero_is_rejected_as_a_guest_id() -> Result<(), Box<dyn std::error::Error>> {
    let config = HostConfig::new("127.0.0.1".parse()?, 4433, Vec::new(), Vec::new())
        .with_guest_id_generator(Box::new(|| Box::pin(async { Some(0) })));
    let engine = HandshakeEngine::new(Registry::builtin(), Arc::new(config));

    assert!(engine.assign_guest_id().await.is_err());
    Ok(())
}
