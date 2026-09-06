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
    pub max_message_size: u64,
    pub handshake_max_message_size: u64,
    pub close_frame_len: u32,
    pub application_close_code: u32,
    pub open_stream_timeout: Duration,
    pub write_timeout: Duration,
    pub accept_stream_timeout: Duration,
    pub read_timeout: Duration,
    pub keep_alive_interval: Option<Duration>,
    pub max_idle_timeout: Option<Duration>,
    pub force_close_delay: Duration,
    pub persistent_stream_max_retries: usize,
    pub persistent_stream_retry_backoff: Duration,
    pub receiver_queue_capacity: usize,
    pub max_concurrent_stream_tasks: usize,
    pub max_frames_per_stream: Option<usize>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            send_mode: SendMode::PersistentStream,
            max_message_size: 16 * 1024 * 1024,
            handshake_max_message_size: 64 * 1024,
            close_frame_len: u32::MAX,
            application_close_code: 0,
            open_stream_timeout: Duration::from_millis(2_000),
            write_timeout: Duration::from_millis(2_000),
            accept_stream_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(30_000),
            keep_alive_interval: Some(Duration::from_secs(3)),
            max_idle_timeout: Some(Duration::from_secs(30)),
            force_close_delay: Duration::from_millis(300),
            persistent_stream_max_retries: 4,
            persistent_stream_retry_backoff: Duration::from_millis(20),
            receiver_queue_capacity: 1000,
            max_concurrent_stream_tasks: 128,
            max_frames_per_stream: None,
        }
    }
}

impl Policy {
    pub fn with_send_mode(mut self, send_mode: SendMode) -> Self {
        self.send_mode = send_mode;
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
        Self(policy)
    }
}

impl Deref for RuntimePolicy {
    type Target = Policy;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
