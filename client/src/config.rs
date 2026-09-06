use tokio::time::Duration;

pub use mtp_native::Policy;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientTlsConfig {
    SystemRoots,
    PinnedPem(Vec<u8>),
}

pub struct ClientConfig {
    pub url: String,
    pub tls: ClientTlsConfig,
    pub client_id: u64,
    pub description: Option<String>,
    pub policy: Policy,
    pub ping_interval: Duration,
    pub ping_jitter: Option<Duration>,
    pub max_missed_pings: usize,
    pub ping_timestamp: bool,
    pub request_timeout: Duration,
    #[cfg(feature = "crypto")]
    pub auth_timeout: Duration,
    #[cfg(feature = "crypto")]
    pub require_pq: bool,
}

impl ClientConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            tls: ClientTlsConfig::SystemRoots,
            client_id: 0,
            description: None,
            policy: Policy::default(),
            ping_interval: Duration::ZERO,
            ping_jitter: None,
            max_missed_pings: 3,
            ping_timestamp: true,
            request_timeout: Duration::from_secs(30),
            #[cfg(feature = "crypto")]
            auth_timeout: Duration::from_secs(30),
            #[cfg(feature = "crypto")]
            require_pq: true,
        }
    }

    pub fn with_tls(mut self, tls: ClientTlsConfig) -> Self {
        self.tls = tls;
        self
    }

    pub fn with_pinned_pem(self, cert_pem: Vec<u8>) -> Self {
        self.with_tls(ClientTlsConfig::PinnedPem(cert_pem))
    }

    pub fn with_client_id(mut self, client_id: u64) -> Self {
        self.client_id = client_id;
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    pub fn with_ping_jitter(mut self, jitter: Option<Duration>) -> Self {
        self.ping_jitter = jitter;
        self
    }

    pub fn with_max_missed_pings(mut self, max_missed_pings: usize) -> Self {
        self.max_missed_pings = max_missed_pings;
        self
    }

    pub fn with_ping_timestamp(mut self, ping_timestamp: bool) -> Self {
        self.ping_timestamp = ping_timestamp;
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_auth_timeout(mut self, timeout: Duration) -> Self {
        self.auth_timeout = timeout;
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_require_pq(mut self, require_pq: bool) -> Self {
        self.require_pq = require_pq;
        self
    }

    pub(crate) fn server_cert(&self) -> Option<Vec<u8>> {
        match &self.tls {
            ClientTlsConfig::SystemRoots => None,
            ClientTlsConfig::PinnedPem(cert) => Some(cert.clone()),
        }
    }
}
