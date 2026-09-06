use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TimeError {
    #[error("system clock is before the Unix epoch")]
    BeforeUnixEpoch,
    #[error("Unix epoch milliseconds exceed the u64 range")]
    OutOfRange,
}

pub fn duration_to_unix_time_millis(duration: Duration) -> Result<u64, TimeError> {
    u64::try_from(duration.as_millis()).map_err(|_| TimeError::OutOfRange)
}

pub fn unix_time_millis() -> Result<u64, TimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TimeError::BeforeUnixEpoch)
        .and_then(duration_to_unix_time_millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_preserves_milliseconds_and_rejects_overflow() {
        assert_eq!(
            duration_to_unix_time_millis(Duration::new(1_786_449_600, 123_000_000)),
            Ok(1_786_449_600_123)
        );
        assert_eq!(
            duration_to_unix_time_millis(Duration::new(u64::MAX, 0)),
            Err(TimeError::OutOfRange)
        );
    }
}
