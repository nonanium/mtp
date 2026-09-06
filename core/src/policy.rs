use std::ops::Deref;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMode {
    PersistentStream,
    SingleStreamPerMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub send_mode: SendMode,
    /// Allow messages sent on separate streams to be written concurrently.
    ///
    /// This applies only to [`SendMode::SingleStreamPerMessage`]. Messages may
    /// be received in a different order from their `send` calls.
    pub parallel_multi_stream_sends: bool,
    pub max_message_size: u64,
    pub handshake_max_message_size: u64,
    pub close_frame_len: u32,
    pub application_close_code: u32,
    pub open_stream_timeout: Duration,
    pub write_timeout: Duration,
    pub accept_stream_timeout: Duration,
    pub read_timeout: Duration,
    /// Maximum time a peer may take to accept or deny a pipe request.
    pub pipe_decision_timeout: Duration,
    /// Maximum time an accepted peer may take to open its pipe stream.
    pub pipe_stream_open_timeout: Duration,
    pub keep_alive_interval: Option<Duration>,
    pub max_idle_timeout: Option<Duration>,
    pub force_close_delay: Duration,
    pub persistent_stream_max_retries: usize,
    pub persistent_stream_retry_backoff: Duration,
    pub receiver_queue_capacity: usize,
    pub max_concurrent_stream_tasks: usize,
    pub max_frames_per_stream: Option<usize>,
    pub request_tombstone_ttl: Duration,
    pub request_tombstone_capacity: usize,
    pub pipe_tombstone_ttl: Duration,
    pub pipe_tombstone_capacity: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            send_mode: SendMode::PersistentStream,
            parallel_multi_stream_sends: true,
            max_message_size: 16 * 1024 * 1024,
            handshake_max_message_size: 64 * 1024,
            close_frame_len: u32::MAX,
            application_close_code: 0,
            open_stream_timeout: Duration::from_millis(2_000),
            write_timeout: Duration::from_millis(2_000),
            accept_stream_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(30_000),
            pipe_decision_timeout: Duration::from_secs(30),
            pipe_stream_open_timeout: Duration::from_secs(30),
            keep_alive_interval: Some(Duration::from_secs(3)),
            max_idle_timeout: Some(Duration::from_secs(30)),
            force_close_delay: Duration::from_millis(300),
            persistent_stream_max_retries: 4,
            persistent_stream_retry_backoff: Duration::from_millis(20),
            receiver_queue_capacity: 1000,
            max_concurrent_stream_tasks: 128,
            max_frames_per_stream: None,
            request_tombstone_ttl: Duration::from_secs(60),
            request_tombstone_capacity: 1024,
            pipe_tombstone_ttl: Duration::from_secs(60),
            pipe_tombstone_capacity: 1024,
        }
    }
}

impl Policy {
    pub fn with_send_mode(mut self, send_mode: SendMode) -> Self {
        self.send_mode = send_mode;
        self
    }

    pub fn with_parallel_multi_stream_sends(mut self, enabled: bool) -> Self {
        self.parallel_multi_stream_sends = enabled;
        self
    }

    pub fn with_max_message_size(mut self, max_message_size: u64) -> Self {
        self.max_message_size = max_message_size;
        self
    }

    pub fn with_handshake_max_message_size(mut self, max_message_size: u64) -> Self {
        self.handshake_max_message_size = max_message_size;
        self
    }

    pub fn with_timeouts(
        mut self,
        open_stream_timeout: Duration,
        write_timeout: Duration,
        read_timeout: Duration,
    ) -> Self {
        self.open_stream_timeout = open_stream_timeout;
        self.write_timeout = write_timeout;
        self.read_timeout = read_timeout;
        self
    }

    pub fn with_keep_alive(mut self, keep_alive_interval: Option<Duration>) -> Self {
        self.keep_alive_interval = keep_alive_interval;
        self
    }

    pub fn with_max_idle_timeout(mut self, max_idle_timeout: Option<Duration>) -> Self {
        self.max_idle_timeout = max_idle_timeout;
        self
    }

    pub fn with_receiver_queue_capacity(mut self, receiver_queue_capacity: usize) -> Self {
        self.receiver_queue_capacity = receiver_queue_capacity;
        self
    }

    pub fn with_persistent_stream_retries(
        mut self,
        persistent_stream_max_retries: usize,
        persistent_stream_retry_backoff: Duration,
    ) -> Self {
        self.persistent_stream_max_retries = persistent_stream_max_retries;
        self.persistent_stream_retry_backoff = persistent_stream_retry_backoff;
        self
    }

    pub fn with_max_concurrent_stream_tasks(mut self, max_concurrent_stream_tasks: usize) -> Self {
        self.max_concurrent_stream_tasks = max_concurrent_stream_tasks;
        self
    }

    pub fn with_max_frames_per_stream(mut self, max_frames_per_stream: Option<usize>) -> Self {
        self.max_frames_per_stream = max_frames_per_stream;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimePolicy(Policy);

impl RuntimePolicy {
    pub fn new(policy: &Policy) -> Self {
        let mut policy = *policy;
        policy.receiver_queue_capacity = policy.receiver_queue_capacity.max(1);
        policy.max_concurrent_stream_tasks = policy.max_concurrent_stream_tasks.max(1);
        policy.request_tombstone_capacity = policy.request_tombstone_capacity.max(1);
        policy.pipe_tombstone_capacity = policy.pipe_tombstone_capacity.max(1);
        Self(policy)
    }
}

impl Deref for RuntimePolicy {
    type Target = Policy;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_multi_stream_sends_are_enabled_by_default_and_configurable() {
        assert!(Policy::default().parallel_multi_stream_sends);
        assert!(
            !Policy::default()
                .with_parallel_multi_stream_sends(false)
                .parallel_multi_stream_sends
        );
    }

    #[test]
    fn tombstone_policy_defaults_and_normalization_are_stable() {
        let defaults = Policy::default();
        assert_eq!(defaults.request_tombstone_ttl, Duration::from_secs(60));
        assert_eq!(defaults.request_tombstone_capacity, 1024);
        assert_eq!(defaults.pipe_tombstone_ttl, Duration::from_secs(60));
        assert_eq!(defaults.pipe_tombstone_capacity, 1024);

        let runtime = RuntimePolicy::new(&Policy {
            request_tombstone_capacity: 0,
            pipe_tombstone_capacity: 0,
            ..defaults
        });
        assert_eq!(runtime.request_tombstone_capacity, 1);
        assert_eq!(runtime.pipe_tombstone_capacity, 1);
    }
}
