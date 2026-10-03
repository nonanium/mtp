use std::net::IpAddr;

#[cfg(feature = "crypto")]
use std::cmp::{Ordering, Reverse};
#[cfg(feature = "crypto")]
use std::collections::HashSet;
#[cfg(feature = "crypto")]
use std::collections::VecDeque;
#[cfg(feature = "crypto")]
use std::collections::{BinaryHeap, HashMap};
#[cfg(feature = "crypto")]
use std::pin::Pin;
#[cfg(feature = "crypto")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "crypto")]
use std::time::{Duration as StdDuration, Instant};
#[cfg(feature = "crypto")]
use tokio::time::Duration;

pub use mtp_native::Policy;

/// Callback that looks up a registered client by ID.
///
/// Called during login to retrieve a client's public key bundle for signature
/// verification, and also during guest ID generation to check whether a random
/// candidate collides with a registered client.  When used for collision
/// checking the `description` argument is `None`.
#[cfg(feature = "crypto")]
pub type GetExistingClient = Box<
    dyn Fn(
            u64,
            Option<String>,
        )
            -> Pin<Box<dyn std::future::Future<Output = Option<mtp_crypto::PublicKeyBundle>> + Send>>
        + Send
        + Sync,
>;

/// Callback that assigns a guest (unauthenticated) client ID.
///
/// Return `Some(id)` to accept the guest with the given full-width `u64` ID, or
/// `None` to reject the connection.
///
/// When set to `None` on `HostConfig`, the built-in generator produces a random
/// full-width non-zero ID that avoids collisions with registered clients and
/// currently connected guests.
#[cfg(feature = "crypto")]
pub type GuestIdGenerator =
    Box<dyn Fn() -> Pin<Box<dyn std::future::Future<Output = Option<u64>> + Send>> + Send + Sync>;

#[cfg(feature = "crypto")]
/// Callback that commits a new registration and returns its non-zero ID.
///
/// Applications own registration idempotence and must persist identity
/// assignments when retries can span host restarts.
pub type CompleteRegister = Box<
    dyn Fn(
            mtp_crypto::PublicKeyBundle,
            Option<String>,
        ) -> Pin<Box<dyn std::future::Future<Output = u64> + Send>>
        + Send
        + Sync,
>;

/// Callback that recovers an existing registration by its public identity.
///
/// Returning an ID makes a registration retry idempotent. Returning `None`
/// asks the host to invoke [`CompleteRegister`] for a new registration.
#[cfg(feature = "crypto")]
pub type FindRegisteredClient = Box<
    dyn Fn(
            mtp_crypto::PublicKeyBundle,
            Option<String>,
        ) -> Pin<Box<dyn std::future::Future<Output = Option<u64>> + Send>>
        + Send
        + Sync,
>;

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationPolicy {
    ForceAuthentication,
    AllowAuthentication,
    Unauthenticated,
}

/// Transport-supplied identity used to scope authentication attempt limits.
/// Concrete hosts should populate these fields from the accepted connection;
/// the zero/empty defaults exist only for transport-neutral callers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthenticationContext {
    pub peer_network_identity: Option<IpAddr>,
    pub connection_id: u64,
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationAttempt {
    pub peer_network_identity: Option<IpAddr>,
    pub connection_id: u64,
    pub claimed_client_id: Option<u64>,
    pub registration: bool,
}

#[cfg(feature = "crypto")]
#[derive(Debug, thiserror::Error)]
pub enum AuthenticationLimitError {
    #[error("authentication limiter storage is unavailable")]
    Store,
}

#[cfg(feature = "crypto")]
pub trait AuthenticationAttemptLimiter: Send + Sync {
    fn allow(&self, context: &AuthenticationAttempt) -> Result<bool, AuthenticationLimitError>;
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum AuthenticationLimitKey {
    Peer(IpAddr),
    Connection(u64),
    Client(u64),
    Registration,
    Global,
}

#[cfg(feature = "crypto")]
pub struct InMemoryAuthenticationAttemptLimiter {
    config: AuthenticationLimiterConfig,
    clock: Arc<dyn AuthenticationClock>,
    attempts: Mutex<AuthenticationLimiterState>,
}

#[cfg(feature = "crypto")]
struct AuthenticationLimiterState {
    attempts: HashMap<AuthenticationLimitKey, AuthenticationBucketState>,
    expirations: BinaryHeap<Reverse<AuthenticationExpiry>>,
    dynamic_key_count: usize,
}

#[cfg(feature = "crypto")]
struct AuthenticationBucketState {
    history: VecDeque<Instant>,
    generation: u64,
}

#[cfg(feature = "crypto")]
#[derive(Clone, Eq)]
struct AuthenticationExpiry {
    at: Instant,
    generation: u64,
    key: AuthenticationLimitKey,
}

#[cfg(feature = "crypto")]
impl Ord for AuthenticationExpiry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.at
            .cmp(&other.at)
            .then_with(|| self.generation.cmp(&other.generation))
    }
}

#[cfg(feature = "crypto")]
impl PartialOrd for AuthenticationExpiry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "crypto")]
impl PartialEq for AuthenticationExpiry {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.generation == other.generation
    }
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone)]
pub struct AuthenticationBucketPolicy {
    pub max_attempts: usize,
    pub window: StdDuration,
}

#[cfg(feature = "crypto")]
#[derive(Debug, Clone)]
pub struct AuthenticationLimiterConfig {
    pub peer: Option<AuthenticationBucketPolicy>,
    pub connection: Option<AuthenticationBucketPolicy>,
    pub client: Option<AuthenticationBucketPolicy>,
    pub registration: Option<AuthenticationBucketPolicy>,
    pub global: Option<AuthenticationBucketPolicy>,
    pub max_dynamic_keys: usize,
}

#[cfg(feature = "crypto")]
impl AuthenticationLimiterConfig {
    pub fn with_default_policies(max_attempts: usize, window: StdDuration) -> Self {
        let policy = AuthenticationBucketPolicy {
            max_attempts,
            window,
        };
        Self {
            peer: Some(policy.clone()),
            connection: Some(policy.clone()),
            client: Some(policy.clone()),
            registration: Some(policy),
            global: None,
            max_dynamic_keys: 100_000,
        }
    }
}

#[cfg(feature = "crypto")]
pub trait AuthenticationClock: Send + Sync {
    fn now(&self) -> Instant;
}

#[cfg(feature = "crypto")]
#[derive(Debug, Default)]
pub struct SystemAuthenticationClock;

#[cfg(feature = "crypto")]
impl AuthenticationClock for SystemAuthenticationClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(feature = "crypto")]
impl InMemoryAuthenticationAttemptLimiter {
    pub fn new(config: AuthenticationLimiterConfig) -> Self {
        Self::with_clock(config, Arc::new(SystemAuthenticationClock))
    }

    pub fn with_clock(
        config: AuthenticationLimiterConfig,
        clock: Arc<dyn AuthenticationClock>,
    ) -> Self {
        Self {
            config,
            clock,
            attempts: Mutex::new(AuthenticationLimiterState {
                attempts: HashMap::new(),
                expirations: BinaryHeap::new(),
                dynamic_key_count: 0,
            }),
        }
    }

    fn policy(&self, key: &AuthenticationLimitKey) -> Option<&AuthenticationBucketPolicy> {
        match key {
            AuthenticationLimitKey::Peer(_) => self.config.peer.as_ref(),
            AuthenticationLimitKey::Connection(_) => self.config.connection.as_ref(),
            AuthenticationLimitKey::Client(_) => self.config.client.as_ref(),
            AuthenticationLimitKey::Registration => self.config.registration.as_ref(),
            AuthenticationLimitKey::Global => self.config.global.as_ref(),
        }
    }

    fn is_dynamic_key(key: &AuthenticationLimitKey) -> bool {
        matches!(
            key,
            AuthenticationLimitKey::Peer(_)
                | AuthenticationLimitKey::Connection(_)
                | AuthenticationLimitKey::Client(_)
        )
    }

    fn keys(&self, context: &AuthenticationAttempt) -> Vec<AuthenticationLimitKey> {
        let mut keys = Vec::with_capacity(5);
        if self.config.peer.is_some()
            && let Some(peer) = context.peer_network_identity.as_ref()
        {
            keys.push(AuthenticationLimitKey::Peer(normalize_ip_addr(*peer)));
        }
        if self.config.connection.is_some() && context.connection_id != 0 {
            keys.push(AuthenticationLimitKey::Connection(context.connection_id));
        }
        if self.config.client.is_some()
            && let Some(client_id) = context.claimed_client_id
        {
            keys.push(AuthenticationLimitKey::Client(client_id));
        }
        if self.config.registration.is_some() && context.registration {
            keys.push(AuthenticationLimitKey::Registration);
        }
        if self.config.global.is_some() {
            keys.push(AuthenticationLimitKey::Global);
        }
        keys
    }

    fn schedule_expiry(
        state: &mut AuthenticationLimiterState,
        key: AuthenticationLimitKey,
        first_attempt: Instant,
        generation: u64,
        policy: &AuthenticationBucketPolicy,
    ) {
        let Some(at) = first_attempt.checked_add(policy.window) else {
            return;
        };
        state.expirations.push(Reverse(AuthenticationExpiry {
            at,
            generation,
            key,
        }));
    }

    fn remove_bucket(&self, state: &mut AuthenticationLimiterState, key: &AuthenticationLimitKey) {
        if state.attempts.remove(key).is_some() && Self::is_dynamic_key(key) {
            state.dynamic_key_count -= 1;
        }
    }

    fn expire_buckets(&self, state: &mut AuthenticationLimiterState, now: Instant) {
        while state
            .expirations
            .peek()
            .is_some_and(|entry| entry.0.at <= now)
        {
            let expiry = state.expirations.pop().expect("heap entry disappeared").0;
            let Some(policy) = self.policy(&expiry.key) else {
                self.remove_bucket(state, &expiry.key);
                continue;
            };
            let Some(bucket) = state.attempts.get_mut(&expiry.key) else {
                continue;
            };
            if bucket.generation != expiry.generation {
                continue;
            }

            let cutoff = now.checked_sub(policy.window);
            while bucket
                .history
                .front()
                .is_some_and(|timestamp| cutoff.is_some_and(|cutoff| *timestamp <= cutoff))
            {
                bucket.history.pop_front();
            }
            if bucket.history.is_empty() {
                self.remove_bucket(state, &expiry.key);
            } else {
                bucket.generation = bucket.generation.wrapping_add(1);
                let first_attempt = *bucket.history.front().expect("bucket is nonempty");
                let generation = bucket.generation;
                Self::schedule_expiry(state, expiry.key, first_attempt, generation, policy);
            }
        }
    }
}

#[cfg(feature = "crypto")]
pub fn normalize_ip_addr(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

#[cfg(feature = "crypto")]
impl AuthenticationAttemptLimiter for InMemoryAuthenticationAttemptLimiter {
    fn allow(&self, context: &AuthenticationAttempt) -> Result<bool, AuthenticationLimitError> {
        let now = self.clock.now();
        let keys = self.keys(context);
        let mut attempts = self
            .attempts
            .lock()
            .map_err(|_| AuthenticationLimitError::Store)?;

        self.expire_buckets(&mut attempts, now);

        for key in &keys {
            let policy = self.policy(key).expect("configured key policy");
            if policy.max_attempts == 0 {
                return Ok(false);
            }
            if let Some(bucket) = attempts.attempts.get(key)
                && bucket.history.len() >= policy.max_attempts
            {
                return Ok(false);
            }
        }

        let new_dynamic_keys = keys
            .iter()
            .filter(|key| Self::is_dynamic_key(key) && !attempts.attempts.contains_key(*key))
            .count();
        if attempts.dynamic_key_count + new_dynamic_keys > self.config.max_dynamic_keys {
            return Ok(false);
        }

        for key in keys {
            if let Some(bucket) = attempts.attempts.get_mut(&key) {
                bucket.history.push_back(now);
                continue;
            }

            let policy = self.policy(&key).expect("configured key policy");
            let mut history = VecDeque::new();
            history.push_back(now);
            let bucket = AuthenticationBucketState {
                history,
                generation: 0,
            };
            if Self::is_dynamic_key(&key) {
                attempts.dynamic_key_count += 1;
            }
            Self::schedule_expiry(&mut attempts, key.clone(), now, bucket.generation, policy);
            attempts.attempts.insert(key, bucket);
        }
        Ok(true)
    }
}

pub struct HostConfig {
    pub ip: IpAddr,
    pub port: u16,
    pub tls_fullchain: Vec<u8>,
    pub tls_key: Vec<u8>,

    pub policy: Policy,
    pub send_pongs: bool,
    /// Maximum native transport handshakes admitted at once.
    pub max_transport_handshakes: usize,
    /// Maximum native connections allowed to await application handoff.
    pub max_pending_connections: usize,
    /// Maximum authentication handshakes admitted at once.
    pub max_pending_authentications: usize,

    #[cfg(feature = "crypto")]
    pub authentication_policy: AuthenticationPolicy,
    #[cfg(feature = "crypto")]
    authentication_policy_explicit: bool,
    #[cfg(feature = "crypto")]
    pub auth_timeout: Duration,
    #[cfg(feature = "crypto")]
    pub require_pq: bool,
    #[cfg(feature = "crypto")]
    pub host_keyring: mtp_crypto::Keyring,
    #[cfg(feature = "crypto")]
    pub get_existing_client: GetExistingClient,
    #[cfg(feature = "crypto")]
    pub(crate) active_guest_ids: Arc<Mutex<HashSet<u64>>>,
    #[cfg(feature = "crypto")]
    pub(crate) registration_lock: Arc<tokio::sync::Mutex<()>>,
    #[cfg(feature = "crypto")]
    pub guest_id_generator: Option<GuestIdGenerator>,
    #[cfg(feature = "crypto")]
    pub complete_register: CompleteRegister,
    #[cfg(feature = "crypto")]
    pub find_registered_client: Option<FindRegisteredClient>,
    #[cfg(feature = "crypto")]
    pub auth_limiter: Arc<dyn AuthenticationAttemptLimiter>,
    #[cfg(feature = "crypto")]
    pub conceal_authentication_identities: bool,
}

impl HostConfig {
    pub fn new(ip: IpAddr, port: u16, tls_fullchain: Vec<u8>, tls_key: Vec<u8>) -> Self {
        Self {
            ip,
            port,
            tls_fullchain,
            tls_key,
            policy: Policy::default(),
            send_pongs: true,
            max_transport_handshakes: 64,
            max_pending_connections: 64,
            max_pending_authentications: 64,
            #[cfg(feature = "crypto")]
            authentication_policy: AuthenticationPolicy::Unauthenticated,
            #[cfg(feature = "crypto")]
            authentication_policy_explicit: false,
            #[cfg(feature = "crypto")]
            auth_timeout: Duration::from_secs(30),
            #[cfg(feature = "crypto")]
            require_pq: true,
            #[cfg(feature = "crypto")]
            host_keyring: mtp_crypto::Keyring::new(
                mtp_crypto::KemPublicKey::new(Vec::new()),
                mtp_crypto::KemPrivateKey::new(Vec::new()),
                mtp_crypto::SignaturePqPublicKey::new(Vec::new()),
                mtp_crypto::SignaturePqPrivateKey::new(Vec::new()),
                mtp_crypto::SignaturePublicKey::new(Vec::new()),
                mtp_crypto::SignaturePrivateKey::new(Vec::new()),
            ),
            #[cfg(feature = "crypto")]
            get_existing_client: Box::new(|_, _| Box::pin(async { None })),
            #[cfg(feature = "crypto")]
            active_guest_ids: Arc::new(Mutex::new(HashSet::new())),
            #[cfg(feature = "crypto")]
            registration_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "crypto")]
            guest_id_generator: None,
            #[cfg(feature = "crypto")]
            complete_register: Box::new(|_, _| Box::pin(async { 0 })),
            #[cfg(feature = "crypto")]
            find_registered_client: None,
            #[cfg(feature = "crypto")]
            auth_limiter: Arc::new(InMemoryAuthenticationAttemptLimiter::new(
                AuthenticationLimiterConfig::with_default_policies(32, StdDuration::from_secs(60)),
            )),
            #[cfg(feature = "crypto")]
            conceal_authentication_identities: true,
        }
    }

    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_pongs(mut self, send_pongs: bool) -> Self {
        self.send_pongs = send_pongs;
        self
    }

    pub fn with_max_transport_handshakes(mut self, limit: usize) -> Self {
        self.max_transport_handshakes = limit;
        self
    }

    pub fn with_max_pending_connections(mut self, limit: usize) -> Self {
        self.max_pending_connections = limit;
        self
    }

    pub fn with_max_pending_authentications(mut self, limit: usize) -> Self {
        self.max_pending_authentications = limit;
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_authentication(
        mut self,
        host_keyring: mtp_crypto::Keyring,
        get_existing_client: GetExistingClient,
        complete_register: CompleteRegister,
    ) -> Self {
        if !self.authentication_policy_explicit {
            self.authentication_policy = AuthenticationPolicy::ForceAuthentication;
        }
        self.host_keyring = host_keyring;
        self.get_existing_client = Box::new(get_existing_client);
        self.complete_register = Box::new(complete_register);
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_authentication_policy(mut self, policy: AuthenticationPolicy) -> Self {
        self.authentication_policy = policy;
        self.authentication_policy_explicit = true;
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

    #[cfg(feature = "crypto")]
    pub fn with_guest_id_generator(mut self, generator: GuestIdGenerator) -> Self {
        self.guest_id_generator = Some(generator);
        self
    }

    /// Configure the lookup used to make registration retries idempotent.
    #[cfg(feature = "crypto")]
    pub fn with_registration_lookup(mut self, lookup: FindRegisteredClient) -> Self {
        self.find_registered_client = Some(lookup);
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_authentication_limiter(
        mut self,
        limiter: Arc<dyn AuthenticationAttemptLimiter>,
    ) -> Self {
        self.auth_limiter = limiter;
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_authentication_identity_concealment(mut self, conceal: bool) -> Self {
        self.conceal_authentication_identities = conceal;
        self
    }
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;

    #[test]
    fn authentication_attempt_limiter_rejects_repeated_attempts() {
        let limiter = InMemoryAuthenticationAttemptLimiter::new(AuthenticationLimiterConfig {
            peer: None,
            connection: Some(AuthenticationBucketPolicy {
                max_attempts: 1,
                window: StdDuration::from_secs(60),
            }),
            client: None,
            registration: None,
            global: None,
            max_dynamic_keys: 100,
        });
        let attempt = AuthenticationAttempt {
            peer_network_identity: None,
            connection_id: 9,
            claimed_client_id: Some(42),
            registration: false,
        };

        assert!(limiter.allow(&attempt).expect("first attempt decision"));
        assert!(!limiter.allow(&attempt).expect("second attempt decision"));
    }

    #[test]
    fn authentication_attempt_limiter_can_scope_registration_separately() {
        let limiter = InMemoryAuthenticationAttemptLimiter::new(AuthenticationLimiterConfig {
            peer: None,
            connection: None,
            client: None,
            registration: Some(AuthenticationBucketPolicy {
                max_attempts: 2,
                window: StdDuration::from_secs(60),
            }),
            global: None,
            max_dynamic_keys: 100,
        });
        let login = AuthenticationAttempt {
            peer_network_identity: None,
            connection_id: 1,
            claimed_client_id: None,
            registration: false,
        };
        let registration = AuthenticationAttempt {
            registration: true,
            ..login.clone()
        };

        assert!(limiter.allow(&login).expect("login attempt decision"));
        assert!(
            limiter
                .allow(&registration)
                .expect("first registration decision")
        );
        assert!(
            limiter
                .allow(&registration)
                .expect("second registration decision")
        );
        assert!(
            !limiter
                .allow(&registration)
                .expect("third registration decision")
        );
    }

    fn test_keyring() -> mtp_crypto::Keyring {
        mtp_crypto::Keyring::new(
            mtp_crypto::KemPublicKey::new(Vec::new()),
            mtp_crypto::KemPrivateKey::new(Vec::new()),
            mtp_crypto::SignaturePqPublicKey::new(Vec::new()),
            mtp_crypto::SignaturePqPrivateKey::new(Vec::new()),
            mtp_crypto::SignaturePublicKey::new(Vec::new()),
            mtp_crypto::SignaturePrivateKey::new(Vec::new()),
        )
    }

    fn test_get_existing_client() -> GetExistingClient {
        Box::new(|_, _| Box::pin(async { None }))
    }

    fn test_complete_register() -> CompleteRegister {
        Box::new(|_, _| Box::pin(async { 1 }))
    }

    fn test_config() -> HostConfig {
        HostConfig::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            4433,
            Vec::new(),
            Vec::new(),
        )
    }

    #[test]
    fn with_authentication_defaults_to_force_authentication() {
        let config = test_config().with_authentication(
            test_keyring(),
            test_get_existing_client(),
            test_complete_register(),
        );

        assert_eq!(
            config.authentication_policy,
            AuthenticationPolicy::ForceAuthentication
        );
    }

    #[test]
    fn explicit_authentication_policy_before_with_authentication_is_preserved() {
        let config = test_config()
            .with_authentication_policy(AuthenticationPolicy::AllowAuthentication)
            .with_authentication(
                test_keyring(),
                test_get_existing_client(),
                test_complete_register(),
            );

        assert_eq!(
            config.authentication_policy,
            AuthenticationPolicy::AllowAuthentication
        );
    }

    #[test]
    fn explicit_authentication_policy_after_with_authentication_is_preserved() {
        let config = test_config()
            .with_authentication(
                test_keyring(),
                test_get_existing_client(),
                test_complete_register(),
            )
            .with_authentication_policy(AuthenticationPolicy::AllowAuthentication);

        assert_eq!(
            config.authentication_policy,
            AuthenticationPolicy::AllowAuthentication
        );
    }
}
