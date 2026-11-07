use super::*;
use std::sync::Mutex;

#[derive(Default)]
struct RecordedHandshake {
    sent: Mutex<Vec<CommunicationValue>>,
    closed: std::sync::atomic::AtomicBool,
}

impl HandshakeSender for RecordedHandshake {
    async fn send(&self, message: &CommunicationValue) -> Result<(), CommunicationError> {
        self.sent.lock().unwrap().push(message.clone());
        Ok(())
    }
    async fn finish_stream(&self) -> Result<(), CommunicationError> {
        Ok(())
    }
    fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

struct Opening(Mutex<Option<CommunicationValue>>);
impl HandshakeReceiver for Opening {
    async fn receive(&self) -> Result<CommunicationValue, CommunicationError> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or(CommunicationError::ClosedByPeer)
    }
}

#[tokio::test]
async fn dictionary_mismatch_and_missing_fingerprint_fail_before_identity_lookup() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let lookups = Arc::new(AtomicUsize::new(0));
    let count = lookups.clone();
    let mut config = HostConfig::new("127.0.0.1".parse().unwrap(), 4433, vec![], vec![]);
    config.get_existing_client = Box::new(move |_, _| {
        count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { None })
    });
    let engine = HandshakeEngine::new(Registry::builtin(), Arc::new(config));
    let map = TypeMap::latest();
    for include_wrong_hash in [false, true] {
        let mut frame =
            CommunicationValue::new_with_type_map(CommunicationType::Identification, &map)
                .add_typed_default(
                    DataType::Version,
                    DataValue::Array(vec![DataValue::Str(map.version.to_string())]),
                )
                .add_typed_default(DataType::Id, DataValue::UnsignedNumber(42));
        if include_wrong_hash {
            frame = frame.add_typed_default(
                DataType::DictionaryFingerprint,
                DataValue::Array(vec![DataValue::Bytes(vec![0; 32])]),
            );
        }
        let sender = RecordedHandshake::default();
        let receiver = Opening(Mutex::new(Some(frame)));
        assert!(matches!(
            engine.accept(&sender, &receiver).await,
            Err(AcceptError::Receive(CommunicationError::ProtocolViolation(
                _
            )))
        ));
        assert!(sender.closed.load(Ordering::SeqCst));
        let sent = sender.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].is_type(CommunicationType::ErrorBadVersion));
        assert_eq!(sent[0].get_data(DataType::Error), Some(&DataValue::Str("dictionary_mismatch".into())));
        assert_eq!(
            sent[0].get_data(DataType::Connected),
            Some(&DataValue::BoolFalse)
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
    }
}

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
