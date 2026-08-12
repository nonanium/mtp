use std::net::IpAddr;

#[cfg(feature = "crypto")]
use std::collections::HashMap;
#[cfg(feature = "crypto")]
use std::collections::HashSet;
#[cfg(feature = "crypto")]
use std::pin::Pin;
#[cfg(feature = "crypto")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "crypto")]
use tokio::time::Duration;

pub use mtp_transport::Policy;

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
/// The host serializes registration commits and remembers successful identity
/// assignments for the lifetime of the host. Applications that need retry
/// recovery across a host restart should also configure [`FindRegisteredClient`]
/// to look up the public identity in persistent storage.
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
/// Returning an ID makes a registration retry idempotent: the host can send
/// the same final response when the original response was lost after the
/// application committed the registration. Returning `None` asks the host to
/// invoke [`CompleteRegister`] for a new registration.
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

pub struct HostConfig {
    pub ip: IpAddr,
    pub port: u16,
    pub tls_fullchain: Vec<u8>,
    pub tls_key: Vec<u8>,

    pub policy: Policy,
    pub send_pongs: bool,

    #[cfg(feature = "crypto")]
    pub authentication_policy: AuthenticationPolicy,
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
    pub(crate) registration_ids: Arc<Mutex<HashMap<Vec<u8>, u64>>>,
    #[cfg(feature = "crypto")]
    pub(crate) registration_lock: Arc<tokio::sync::Mutex<()>>,
    #[cfg(feature = "crypto")]
    pub guest_id_generator: Option<GuestIdGenerator>,
    #[cfg(feature = "crypto")]
    pub complete_register: CompleteRegister,
    #[cfg(feature = "crypto")]
    pub find_registered_client: Option<FindRegisteredClient>,
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
            #[cfg(feature = "crypto")]
            authentication_policy: AuthenticationPolicy::Unauthenticated,
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
            registration_ids: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(feature = "crypto")]
            registration_lock: Arc::new(tokio::sync::Mutex::new(())),
            #[cfg(feature = "crypto")]
            guest_id_generator: None,
            #[cfg(feature = "crypto")]
            complete_register: Box::new(|_, _| Box::pin(async { 0 })),
            #[cfg(feature = "crypto")]
            find_registered_client: None,
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

    #[cfg(feature = "crypto")]
    pub fn with_authentication(
        mut self,
        host_keyring: mtp_crypto::Keyring,
        get_existing_client: GetExistingClient,
        complete_register: CompleteRegister,
    ) -> Self {
        self.authentication_policy = AuthenticationPolicy::ForceAuthentication;
        self.host_keyring = host_keyring;
        self.get_existing_client = Box::new(get_existing_client);
        self.complete_register = Box::new(complete_register);
        self
    }

    #[cfg(feature = "crypto")]
    pub fn with_authentication_policy(mut self, policy: AuthenticationPolicy) -> Self {
        self.authentication_policy = policy;
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
}
