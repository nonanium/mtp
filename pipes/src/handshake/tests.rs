use super::*;
use crate::record::derive_record_keys;
use tokio::io::duplex;

#[tokio::test]
async fn cancelled_record_io_cannot_reuse_a_partial_stream() {
    let context = PipeProtectionContext::new(b"cancelled", 0x40, 0).expect("context");
    let (left, right) = duplex(1);
    let mut writer = EncryptedPipeWriter::new(left, [7; 32], context.clone());
    let mut write = Box::pin(writer.write_record(b"partial record"));
    assert!(
        std::future::poll_fn(|cx| { std::task::Poll::Ready(write.as_mut().poll(cx).is_pending()) })
            .await
    );
    drop(write);
    assert!(matches!(
        writer.write_record(b"retry").await,
        Err(EncryptedPipeError::InvalidState)
    ));
    assert!(matches!(
        writer.try_into_inner(),
        Err(EncryptedPipeError::InvalidState)
    ));

    let (mut left, empty) = duplex(16);
    left.write_all(&[0]).await.expect("partial prefix");
    let mut reader = EncryptedPipeReader::new(empty, [7; 32], context);
    let mut read = Box::pin(reader.read_record());
    assert!(
        std::future::poll_fn(|cx| { std::task::Poll::Ready(read.as_mut().poll(cx).is_pending()) })
            .await
    );
    drop(read);
    assert!(matches!(
        reader.read_record().await,
        Err(EncryptedPipeError::InvalidState)
    ));
    assert!(matches!(
        reader.try_into_inner(),
        Err(EncryptedPipeError::InvalidState)
    ));
    drop(right);
}

#[test]
fn application_pipe_context_rejects_mtp_purposes() {
    assert!(matches!(
        PipeProtectionContext::new(b"application", PIPE_SESSION_SIGNATURE_PURPOSE, 0),
        Err(EncryptedPipeError::InvalidContext)
    ));
}

#[tokio::test]
async fn records_roundtrip_and_bind_context() {
    let (left, right) = duplex(4096);
    let context =
        PipeProtectionContext::new(b"pipe-session/client/peer", 0x41, 0).expect("context");
    let writer_context = context.clone();
    let reader_context = context.clone();
    let writer = tokio::spawn(async move {
        let mut writer = EncryptedPipeWriter::new(left, [7u8; 32], writer_context);
        writer.write_record(b"first").await.expect("first record");
        writer.write_record(b"second").await.expect("second record");
        writer.finish().await.expect("finish");
    });

    let mut reader = EncryptedPipeReader::new(right, [7u8; 32], reader_context);
    assert_eq!(
        reader.read_record().await.expect("read").as_deref(),
        Some(b"first".as_slice())
    );
    assert_eq!(
        reader.read_record().await.expect("read").as_deref(),
        Some(b"second".as_slice())
    );
    assert!(reader.read_record().await.expect("eof").is_none());
    writer.await.expect("writer task");
}

#[tokio::test]
async fn wrong_context_fails_authentication() {
    let (left, right) = duplex(4096);
    let writer_context = PipeProtectionContext::new(b"session-a", 1, 0).expect("context");
    let reader_context = PipeProtectionContext::new(b"session-b", 1, 0).expect("context");
    let writer = tokio::spawn(async move {
        let mut writer = EncryptedPipeWriter::new(left, [9u8; 32], writer_context);
        writer.write_record(b"secret").await.expect("write");
    });
    let mut reader = EncryptedPipeReader::new(right, [9u8; 32], reader_context);
    assert!(matches!(
        reader.read_record().await,
        Err(EncryptedPipeError::Crypto(_))
    ));
    assert!(matches!(
        reader.read_record().await,
        Err(EncryptedPipeError::InvalidState)
    ));
    writer.await.expect("writer task");
}

#[tokio::test]
async fn transport_eof_without_final_record_is_truncation() {
    let (left, right) = duplex(4096);
    let context = PipeProtectionContext::new(b"session", 0x40, 0).expect("context");
    let mut writer = EncryptedPipeWriter::new(left, [3u8; 32], context.clone());
    writer.write_record(b"not finished").await.expect("record");
    let stream = writer.try_into_inner().expect("aligned stream");
    drop(stream);

    let mut reader = EncryptedPipeReader::new(right, [3u8; 32], context);
    assert_eq!(
        reader.read_record().await.expect("record").as_deref(),
        Some(b"not finished".as_slice())
    );
    assert!(matches!(
        reader.read_record().await,
        Err(EncryptedPipeError::FinalRecordRequired)
    ));
    assert!(matches!(
        reader.read_record().await,
        Err(EncryptedPipeError::InvalidState)
    ));
}

#[test]
fn record_key_schedule_is_context_and_chain_bound() {
    let context = PipeProtectionContext::new(b"session-a", 1, 0).expect("context");
    let first = derive_record_keys(&[7u8; 32], &context, 0).expect("first keys");
    let second = derive_record_keys(&first.1, &context, 1).expect("second keys");
    let repeated = derive_record_keys(&[7u8; 32], &context, 1).expect("repeated keys");
    let other_context = PipeProtectionContext::new(b"session-b", 1, 0).expect("context");
    let other = derive_record_keys(&first.1, &other_context, 1).expect("other keys");

    assert_ne!(first.0, second.0);
    assert_ne!(second.0, repeated.0);
    assert_ne!(second.0, other.0);
    assert_ne!(second.1, other.1);
}

#[tokio::test]
async fn signed_session_offer_establishes_the_record_layer() {
    let sender = Keyring::generate();
    let recipient = Keyring::generate();
    let sender_public = sender.public_key_bundle();
    let recipient_public = recipient.public_key_bundle();
    let params = PipeSessionParameters::new_id(
        b"session/client/peer/pipe-7",
        PipeId::new(7).unwrap(),
        41,
        99,
        0x40,
        0,
    )
    .expect("parameters");
    let writer_params = params.clone();
    let (left, right) = duplex(128 * 1024);
    let writer_task = tokio::spawn(async move {
        let mut writer = initiate_pipe_session(left, writer_params, &sender, &recipient_public)
            .await
            .expect("session offer");
        writer
            .write_record(b"authenticated pipe data")
            .await
            .expect("record");
        writer.finish().await.expect("finish");
    });

    let mut reader = accept_pipe_session(right, &params, &recipient, &sender_public)
        .await
        .expect("session accept");
    assert_eq!(
        reader.read_record().await.expect("record").as_deref(),
        Some(b"authenticated pipe data".as_slice())
    );
    assert!(reader.read_record().await.expect("eof").is_none());
    writer_task.await.expect("writer task");
}

#[tokio::test]
async fn session_offer_accepts_a_trusted_historical_signing_key() {
    let historical_sender = Keyring::generate();
    let current_sender = Keyring::generate();
    let recipient = Keyring::generate();
    let recipient_public = recipient.public_key_bundle();
    let historical_public = historical_sender.public_key_bundle();
    let current_public = current_sender.public_key_bundle();
    let params = PipeSessionParameters::new_id(
        b"historical-session",
        PipeId::new(8).unwrap(),
        41,
        99,
        0x40,
        0,
    )
    .expect("parameters");
    let writer_params = params.clone();
    let (left, right) = duplex(128 * 1024);
    let writer_task = tokio::spawn(async move {
        initiate_pipe_session(left, writer_params, &historical_sender, &recipient_public).await
    });
    let reader = accept_pipe_session_with_key_history(
        right,
        &params,
        &recipient,
        &[current_public, historical_public],
        ProtectionPolicy::from(mtp_codec::SignaturePolicy::Dual),
    )
    .await
    .expect("historical session offer");
    let writer = writer_task.await.expect("writer task").expect("writer");
    drop(writer);
    // The successful setup is the assertion; no application record is
    // needed to prove that the historical signature key was selected.
    assert_eq!(reader.sequence(), 0);
}

#[tokio::test]
async fn forward_secure_duplex_handshake_accepts_signing_key_history() {
    let historical_sender = Keyring::generate();
    let current_sender = Keyring::generate();
    let recipient = Keyring::generate();
    let historical_public = historical_sender.public_key_bundle();
    let current_public = current_sender.public_key_bundle();
    let recipient_public = recipient.public_key_bundle();
    let params = PipeSessionParameters::new_id(
        b"forward-secure-session",
        PipeId::new(17).unwrap(),
        41,
        99,
        0x40,
        0,
    )
    .expect("parameters");
    let responder_params = params.clone();
    let (left, right) = duplex(256 * 1024);
    let responder = tokio::spawn(async move {
        accept_forward_secure_pipe_session_with_key_history(
            right,
            &responder_params,
            &recipient,
            &[current_public, historical_public],
            ProtectionPolicy::from(mtp_codec::SignaturePolicy::Dual),
        )
        .await
    });
    let mut writer = initiate_forward_secure_pipe_session(
        left,
        params,
        &historical_sender,
        &recipient_public,
        ProtectionPolicy::from(mtp_codec::SignaturePolicy::Dual),
    )
    .await
    .expect("forward-secure initiator");
    writer
        .write_record(b"forward secret")
        .await
        .expect("record");
    writer.finish().await.expect("finish");
    let mut reader = responder.await.expect("responder task").expect("reader");
    assert_eq!(
        reader.read_record().await.expect("record").as_deref(),
        Some(b"forward secret".as_slice())
    );
    assert!(reader.read_record().await.expect("final").is_none());
}

#[test]
fn group_session_offer_is_decryptable_by_each_current_member_only() {
    let sender = Keyring::generate();
    let first = Keyring::generate();
    let second = Keyring::generate();
    let outsider = Keyring::generate();
    let params =
        PipeSessionParameters::new_id(b"group-session", PipeId::new(11).unwrap(), 41, 99, 0x40, 0)
            .expect("parameters");
    let key = [8u8; 32];
    let offer = build_session_offer(
        &params,
        &sender,
        &[first.public_key_bundle(), second.public_key_bundle()],
        key,
    )
    .expect("offer");
    let encrypted = DataValue::from_bytes(&offer).expect("encrypted offer");
    for member in [&first, &second] {
        let opened = encrypted
            .decrypt(
                member,
                ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
            )
            .expect("member decrypt");
        let fields = opened
            .as_signed()
            .and_then(|value| value.value.as_array_slice())
            .expect("signed fields");
        assert_eq!(fields[7].as_bytes_slice(), Some(key.as_slice()));
    }
    assert!(matches!(
        encrypted.decrypt(
            &outsider,
            ProtectionPurpose::from(PIPE_SESSION_ENCRYPTION_PURPOSE),
        ),
        Err(ProtectionError::NoMatchingRecipient)
    ));
}
