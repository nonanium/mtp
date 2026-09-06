use mtp_common::CommunicationError;
use mtp_core::{RetryDisposition, classify_retry};

/// Classifies failures that may be recovered by replacing a persistent
/// application stream. Encoding and frame-size failures are deterministic and
/// must reach the caller without opening more streams.
pub(crate) struct RetryClassifier;

impl RetryClassifier {
    pub(crate) fn retry_persistent_stream(error: &CommunicationError) -> bool {
        classify_retry(error) == RetryDisposition::SafeToRetry
    }
}
