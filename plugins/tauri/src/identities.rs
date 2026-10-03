use mtp_client::{ClientConfig, MTPClient};
use mtp_crypto::{Keyring, PublicKeyBundle};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InitializeOptions {
    pub url: String,
    pub descriptor: Option<String>,
    pub host_public_key: Option<Vec<u8>>,
    pub credentials: Option<ImportedCredentials>,
    #[serde(default)]
    pub fresh: bool,
    pub server_certificate_hashes: Option<Vec<Vec<u8>>>,
    pub max_message_size: Option<u64>,
    pub auth_timeout_ms: Option<u64>,
    pub require_pq: Option<bool>,
    pub pings: Option<serde_json::Value>,
    pub receive_limits: Option<serde_json::Value>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedCredentials {
    pub client_id: Option<String>,
    pub keyring: Vec<u8>,
    pub host_public_key: Option<Vec<u8>>,
}

pub struct Identity {
    pub options: InitializeOptions,
    pub keys: Arc<Keyring>,
    pub client_id: Option<u64>,
}
#[derive(Default)]
pub struct Identities {
    pub entries: Mutex<HashMap<String, Identity>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    pub client_id: Option<String>,
    pub public_keys: Vec<u8>,
}

impl Identities {
    /// Host persistence receives serialized keys directly, without JS export.
    pub async fn durable_configuration(
        &self,
    ) -> Result<Vec<crate::lifecycle::BackgroundConnection>, String> {
        let entries = self.entries.lock().await;
        let mut result = Vec::new();
        for (name, identity) in entries.iter() {
            if identity.options.fresh || identity.client_id.is_none_or(|id| id == 0) {
                continue;
            }
            let mut options = identity.options.clone();
            options.host_public_key = options.host_public_key.or_else(|| {
                options
                    .credentials
                    .as_ref()
                    .and_then(|c| c.host_public_key.clone())
            });
            if options.host_public_key.is_none() {
                continue;
            }
            options.credentials = Some(ImportedCredentials {
                client_id: identity.client_id.map(|id| id.to_string()),
                keyring: identity
                    .keys
                    .try_to_bytes()
                    .map_err(|e| e.to_string())?
                    .to_vec(),
                host_public_key: options.host_public_key.clone(),
            });
            result.push(crate::lifecycle::BackgroundConnection {
                name: name.clone(),
                options,
            });
        }
        Ok(result)
    }
    pub async fn initialize(
        &self,
        name: &str,
        options: InitializeOptions,
    ) -> Result<IdentityInfo, String> {
        if name.trim().is_empty() {
            return Err("connection name is empty".into());
        }
        let mut entries = self.entries.lock().await;
        if let Some(identity) = entries.get(name) {
            let mut existing = identity.options.clone();
            let mut requested = options.clone();
            existing.host_public_key = existing.host_public_key.or_else(|| {
                existing
                    .credentials
                    .as_ref()
                    .and_then(|c| c.host_public_key.clone())
            });
            requested.host_public_key = requested.host_public_key.or_else(|| {
                requested
                    .credentials
                    .as_ref()
                    .and_then(|c| c.host_public_key.clone())
            });
            for normalized in [&mut existing, &mut requested] {
                normalized.max_message_size.get_or_insert(16 * 1024 * 1024);
                normalized.auth_timeout_ms.get_or_insert(30_000);
                normalized.require_pq.get_or_insert(true);
                normalized
                    .pings
                    .get_or_insert(serde_json::Value::Bool(true));
            }
            let effective_limits = |options: &InitializeOptions| {
                let (decode, encode, protected) = crate::protected_commands::limits(
                    &serde_json::json!({"limits": options.receive_limits.clone().unwrap_or_else(|| serde_json::json!({}))}),
                )?;
                Ok::<_, String>((
                    decode.intersection(mtp_codec::DecodeLimits::for_transport_message_size(
                        options.max_message_size.unwrap(),
                    )),
                    encode.intersection(mtp_codec::EncodeLimits::for_transport_message_size(
                        options.max_message_size.unwrap(),
                    )),
                    protected,
                ))
            };
            if effective_limits(&existing)? != effective_limits(&requested)? {
                return Err("connection receive limits conflict".into());
            }
            existing.receive_limits = None;
            requested.receive_limits = None;
            // Native restoration imports keys before JS. An ordinary frontend
            // initialization must reuse those keys, not require their export.
            if requested.credentials.is_none() {
                existing.credentials = None;
            }
            if existing != requested {
                return Err("connection configuration conflict".into());
            }
            return Self::info(identity);
        }
        if !options.url.starts_with("https://") {
            return Err("MTP endpoint must use HTTPS".into());
        }
        if options.fresh && options.credentials.is_some() {
            return Err(
                "temporary identities must use fresh native keys, not imported credentials".into(),
            );
        }
        if options.fresh && options.host_public_key.is_none() {
            return Err("temporary identities require pinned host keys".into());
        }
        if let Some(credentials) = &options.credentials
            && let Some(pin) = &credentials.host_public_key
        {
            PublicKeyBundle::from_bytes(pin)
                .map_err(|e| e.to_string())?
                .validate()
                .map_err(|e| e.to_string())?;
            if options
                .host_public_key
                .as_ref()
                .is_some_and(|host| host != pin)
            {
                return Err("imported host pin conflicts with configured host keys".into());
            }
        }
        if options.auth_timeout_ms == Some(0) || options.max_message_size == Some(0) {
            return Err("timeouts and message limits must be positive".into());
        }
        if let Some(pings) = &options.pings
            && !pings.is_boolean()
            && !pings.is_object()
        {
            return Err("pings must be a boolean or object".into());
        }
        if let Some(limits) = &options.receive_limits {
            crate::protected_commands::limits(&serde_json::json!({"limits": limits}))?;
        }
        if let Some(bytes) = &options.host_public_key {
            PublicKeyBundle::from_bytes(bytes)
                .map_err(|e| e.to_string())?
                .validate()
                .map_err(|e| e.to_string())?;
        }
        let keys = match &options.credentials {
            Some(credentials) => {
                Keyring::from_bytes(&credentials.keyring).map_err(|e| e.to_string())?
            }
            None => Keyring::generate(),
        };
        let client_id = options
            .credentials
            .as_ref()
            .and_then(|c| c.client_id.as_ref())
            .map(|id| id.parse::<u64>().map_err(|e| e.to_string()))
            .transpose()?;
        let identity = Identity {
            options,
            keys: Arc::new(keys),
            client_id,
        };
        let info = Self::info(&identity)?;
        entries.insert(name.into(), identity);
        Ok(info)
    }
    fn info(identity: &Identity) -> Result<IdentityInfo, String> {
        Ok(IdentityInfo {
            client_id: identity.client_id.map(|id| id.to_string()),
            public_keys: identity
                .keys
                .public_key_bundle()
                .try_as_bytes()
                .map_err(|e| e.to_string())?,
        })
    }
    pub async fn connect(
        &self,
        name: &str,
        mode: &str,
        registry: &crate::ConnectionRegistry,
    ) -> Result<u64, crate::BridgeError> {
        let mut entries = self.entries.lock().await;
        let identity = entries.get_mut(name).ok_or("identity is not initialized")?;
        let options = &identity.options;
        if options.fresh && matches!(mode, "auth" | "register") {
            return Err("temporary identities cannot authenticate or register permanently".into());
        }
        let mut config =
            ClientConfig::new(&options.url).with_client_id(identity.client_id.unwrap_or(0));
        if let Some(description) = &options.descriptor {
            config = config.with_description(description);
        }
        config = config
            .with_ping_interval(Duration::from_secs(30))
            .with_ping_jitter(Some(Duration::from_secs(5)))
            .with_auth_timeout(Duration::from_millis(
                options.auth_timeout_ms.unwrap_or(30_000),
            ))
            .with_require_pq(options.require_pq.unwrap_or(true));
        if let Some(max) = options.max_message_size {
            config.policy.max_message_size = max;
        }
        if let Some(hashes) = &options.server_certificate_hashes {
            if hashes.len() != 1 {
                return Err("native transport requires exactly one certificate hash".into());
            }
            config = config.with_pinned_spki_sha256(
                hashes[0]
                    .as_slice()
                    .try_into()
                    .map_err(|_| "certificate hash must have 32 bytes")?,
            );
        }
        if options
            .pings
            .as_ref()
            .is_some_and(|v| v != &serde_json::Value::Bool(false))
        {
            config = config.with_ping_interval(Duration::from_secs(30));
        }
        if options.pings == Some(serde_json::Value::Bool(false)) {
            config = config.with_ping_interval(Duration::ZERO);
        }
        if let Some(serde_json::Value::Object(pings)) = &options.pings {
            for field in pings.keys() {
                if !["intervalMs", "jitterMs", "maxMissedPings", "timestamp"]
                    .contains(&field.as_str())
                {
                    return Err(format!("unknown ping option {field}").into());
                }
            }
            if let Some(value) = pings.get("intervalMs") {
                config.ping_interval =
                    Duration::from_millis(value.as_u64().ok_or("invalid ping interval")?);
            }
            if let Some(value) = pings.get("jitterMs") {
                config.ping_jitter = Some(Duration::from_millis(
                    value.as_u64().ok_or("invalid ping jitter")?,
                ));
            }
            if let Some(value) = pings.get("maxMissedPings") {
                config.max_missed_pings = usize::try_from(
                    value
                        .as_u64()
                        .filter(|v| *v > 0)
                        .ok_or("invalid missed ping count")?,
                )
                .map_err(|e| e.to_string())?;
            }
            if let Some(value) = pings.get("timestamp") {
                config.ping_timestamp = value.as_bool().ok_or("invalid ping timestamp option")?;
            }
        }
        let host = options
            .host_public_key
            .as_ref()
            .or_else(|| {
                options
                    .credentials
                    .as_ref()
                    .and_then(|c| c.host_public_key.as_ref())
            })
            .map(|b| PublicKeyBundle::from_bytes(b).map_err(|e| e.to_string()))
            .transpose()?;
        let authenticated = match mode {
            "unauthenticated" => false,
            "connect" => !options.fresh && identity.client_id.is_some() && host.is_some(),
            "auth" | "register" => true,
            _ => return Err("unknown connection mode".into()),
        };
        let registration = mode == "register" || authenticated && identity.client_id.is_none();
        if let Some(existing) = registry.attach(name).await {
            let existing_authenticated =
                existing.connection().auth_state == mtp_client::AuthState::Authenticated;
            if existing_authenticated != authenticated {
                registry.disconnect(name).await;
            }
        }
        let handshake_timeout = config.auth_timeout;
        let keys = identity.keys.clone();
        let session = registry
            .attach_or_connect(name, name, || async {
                tokio::time::timeout(handshake_timeout, async {
                    if authenticated {
                        let host = host.ok_or_else(|| {
                            mtp_common::CommunicationError::Other(
                                "authentication requires pinned host keys".into(),
                            )
                        })?;
                        if registration {
                            MTPClient::auth_register(config, &keys, &host).await
                        } else {
                            MTPClient::auth_connect(config, &keys, &host).await
                        }
                    } else {
                        MTPClient::connect(config).await
                    }
                })
                .await
                .map_err(|_| {
                    mtp_common::CommunicationError::timeout(mtp_common::TransportPhase::Handshake)
                })?
            })
            .await
            .map_err(crate::BridgeError::from)?;
        let id = session.connection().client_id;
        if authenticated || options.fresh {
            identity.client_id = Some(id);
        }
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(url: &str) -> InitializeOptions {
        serde_json::from_value(serde_json::json!({"url": url})).unwrap()
    }

    #[tokio::test]
    async fn initialization_is_idempotent_and_conflicts_fail() {
        let identities = Identities::default();
        let first = identities
            .initialize("test", options("https://localhost:443"))
            .await
            .unwrap();
        let second = identities
            .initialize("test", options("https://localhost:443"))
            .await
            .unwrap();
        assert_eq!(first.public_keys, second.public_keys);
        assert!(
            identities
                .initialize("test", options("https://localhost:444"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn names_own_independent_keys() {
        let identities = Identities::default();
        let first = identities
            .initialize("first", options("https://localhost:443"))
            .await
            .unwrap();
        let second = identities
            .initialize("second", options("https://localhost:443"))
            .await
            .unwrap();
        assert_ne!(first.public_keys, second.public_keys);
    }

    #[tokio::test]
    async fn restored_identity_is_reused_without_js_key_import() {
        let identities = Identities::default();
        let mut saved: InitializeOptions = serde_json::from_value(serde_json::json!({
            "url": "https://localhost", "hostPublicKey": Keyring::generate().public_key_bundle().try_as_bytes().unwrap()
        })).unwrap();
        saved.credentials = Some(ImportedCredentials {
            client_id: Some("42".into()),
            keyring: Keyring::generate().try_to_bytes().unwrap().to_vec(),
            host_public_key: saved.host_public_key.clone(),
        });
        let first = identities
            .initialize("account", saved.clone())
            .await
            .unwrap();
        saved.credentials = None;
        let frontend = identities
            .initialize("account", saved.clone())
            .await
            .unwrap();
        assert_eq!(first.public_keys, frontend.public_keys);
        assert_eq!(frontend.client_id.as_deref(), Some("42"));
        saved.host_public_key = Some(
            Keyring::generate()
                .public_key_bundle()
                .try_as_bytes()
                .unwrap(),
        );
        assert!(identities.initialize("account", saved).await.is_err());
    }

    #[tokio::test]
    async fn temporary_identity_cannot_permanently_authenticate() {
        let identities = Identities::default();
        let mut temporary = options("https://localhost");
        temporary.fresh = true;
        temporary.host_public_key = Some(
            Keyring::generate()
                .public_key_bundle()
                .try_as_bytes()
                .unwrap(),
        );
        identities.initialize("temporary", temporary).await.unwrap();
        let registry = crate::ConnectionRegistry::default();
        for mode in ["auth", "register"] {
            assert!(
                identities
                    .connect("temporary", mode, &registry)
                    .await
                    .unwrap_err()
                    .message
                    .contains("temporary")
            );
        }
    }

    #[tokio::test]
    async fn persistence_roundtrip_keeps_native_keys_and_filters_temporary_identities() {
        let identities = Identities::default();
        let host = Keyring::generate()
            .public_key_bundle()
            .try_as_bytes()
            .unwrap();
        let keys = Keyring::generate().try_to_bytes().unwrap().to_vec();
        let options: InitializeOptions = serde_json::from_value(serde_json::json!({
            "url": "https://localhost:443", "credentials": {
                "clientId": "42", "keyring": keys, "hostPublicKey": host
            }, "serverCertificateHashes": [vec![7u8; 32]], "pings": false
        }))
        .unwrap();
        identities
            .initialize("saved", options.clone())
            .await
            .unwrap();
        identities
            .initialize(
                "temporary",
                serde_json::from_value(
                    serde_json::json!({"url": "https://localhost:443", "fresh": true, "hostPublicKey": Keyring::generate().public_key_bundle().try_as_bytes().unwrap()}),
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let saved = identities.durable_configuration().await.unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(
            saved[0].options.host_public_key,
            options.credentials.as_ref().unwrap().host_public_key
        );
        let encoded = serde_json::to_string(&saved).unwrap();
        let restored: Vec<crate::lifecycle::BackgroundConnection> =
            serde_json::from_str(&encoded).unwrap();
        let cold = Identities::default();
        cold.initialize(&restored[0].name, restored[0].options.clone())
            .await
            .unwrap();
        assert!(cold.durable_configuration().await.unwrap() == saved);
        identities.entries.lock().await.remove("saved");
        assert!(identities.durable_configuration().await.unwrap().is_empty());
    }
}
