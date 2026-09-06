use mtp_common::testing::duration_to_unix_time_millis;
use mtp_common::{
    CodecError, CommunicationError, HandshakeOutcome, PipeError, RejectionReason, TimeError,
};
use std::time::Duration;

#[test]
fn time_and_codec_public_behavior() {
    assert_eq!(
        duration_to_unix_time_millis(Duration::new(1_786_449_600, 123_000_000)),
        Ok(1_786_449_600_123)
    );
    assert_eq!(
        duration_to_unix_time_millis(Duration::new(u64::MAX, 0)),
        Err(TimeError::OutOfRange)
    );
    assert_eq!(CodecError::InvalidEncoding.to_string(), "Invalid encoding");
    assert_eq!(CodecError::UnknownVersion.to_string(), "Unknown version");
    assert_eq!(
        CodecError::InvalidEncoding.clone(),
        CodecError::InvalidEncoding
    );
}

#[test]
fn communication_error_public_behavior() {
    assert_eq!(
        CommunicationError::UseAfterClosed.to_string(),
        "Use after Closed"
    );
    assert_eq!(
        CommunicationError::StreamClosed.to_string(),
        "Stream Closed"
    );
    assert_eq!(CommunicationError::StreamError.to_string(), "Stream Error");
    assert_eq!(
        CommunicationError::UseAfterClosed.clone(),
        CommunicationError::UseAfterClosed
    );
    assert!(
        CommunicationError::AuthenticationFailed("bad key".into())
            .to_string()
            .contains("bad key")
    );
    assert!(
        CommunicationError::Other("custom error".into())
            .to_string()
            .contains("custom error")
    );
    assert!(
        CommunicationError::ConnectingError("refused".into())
            .to_string()
            .contains("refused")
    );
}

#[test]
fn pipe_error_public_behavior() {
    assert_eq!(PipeError::Rejected.to_string(), "pipe request was rejected");
    assert_eq!(
        PipeError::Cancelled.to_string(),
        "pipe request was cancelled"
    );
    assert_eq!(
        PipeError::HandshakeTimeout.to_string(),
        "pipe handshake timed out"
    );
    assert_eq!(
        PipeError::StreamClosed.to_string(),
        "pipe stream closed unexpectedly"
    );
    assert_eq!(PipeError::ConnectionClosed.to_string(), "connection closed");
    assert_eq!(
        PipeError::IoError("boom".into()).to_string(),
        "pipe I/O error: boom"
    );
    assert_eq!(
        PipeError::from(CommunicationError::StreamClosed),
        PipeError::StreamClosed
    );
    assert_eq!(
        PipeError::from(CommunicationError::ConnectionLost),
        PipeError::ConnectionClosed
    );
    assert_eq!(
        PipeError::from(CommunicationError::StreamError),
        PipeError::IoError("Stream Error".into())
    );
}

#[test]
fn handshake_outcome_public_behavior() {
    let accepted = HandshakeOutcome::Accepted {
        version: "1.0".into(),
        assigned_id: 42,
    };
    assert_eq!(accepted.to_string(), "accepted (version=1.0, id=42)");
    assert_eq!(accepted.clone(), accepted);
    let bad_version = HandshakeOutcome::Rejected {
        reason: RejectionReason::BadVersion {
            supported_versions: vec!["1.0".into(), "2.0".into()],
        },
    };
    assert!(bad_version.to_string().contains("1.0"));
    assert!(bad_version.to_string().contains("2.0"));
    assert!(
        RejectionReason::AuthenticationFailed {
            detail: "invalid signature".into()
        }
        .to_string()
        .contains("invalid signature")
    );
    assert_eq!(RejectionReason::RateLimited.to_string(), "rate limited");
    assert_eq!(
        HandshakeOutcome::Rejected {
            reason: RejectionReason::RateLimited
        }
        .to_string(),
        "rejected: rate limited"
    );
}
