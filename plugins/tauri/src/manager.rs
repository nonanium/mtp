use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use mtp_client::{ClientConfig, MTPClient};
use mtp_codec::CommunicationValue;
use mtp_common::CommunicationError;
use mtp_crypto::{Keyring, PublicKeyBundle};
use tokio::sync::Mutex;

use crate::{ConnectionRegistry, Session};

pub struct Endpoint {
    pub config: ClientConfig,
    pub host_key: PublicKeyBundle,
}

/// Host application discovery and background processing run without a webview.
pub trait HostCallbacks: Send + Sync + 'static {
    /// Persist configuration in the host's native secure store. Keys never
    /// cross the frontend bridge. Called after permanent registration/clear.
    fn persist<'a>(
        &'a self,
        _connections: Vec<crate::lifecycle::BackgroundConnection>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn resolve<'a>(
        &'a self,
        name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Endpoint, CommunicationError>> + Send + 'a>>;
    fn message<'a>(
        &'a self,
        name: &'a str,
        session: Arc<Session>,
        frame: CommunicationValue,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

pub struct ConnectionOptions {
    /// An opaque host-provided identity. Never put secret key bytes here.
    pub identity: String,
    pub keyring: Arc<Keyring>,
    pub authenticated: bool,
}

/// Shared ownership for frontend attachments and native consumers.
pub struct Manager {
    pub registry: ConnectionRegistry,
    callbacks: Arc<dyn HostCallbacks>,
    workers: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    export_credentials: std::sync::atomic::AtomicBool,
}

impl Manager {
    pub async fn observe(&self, name: &str, session: Arc<Session>) {
        let mut workers = self.workers.lock().await;
        if workers.get(name).is_some_and(|task| !task.is_finished()) {
            return;
        }
        let mut subscription = session.subscribe(256).await;
        let callbacks = self.callbacks.clone();
        let name_owned = name.to_owned();
        workers.insert(
            name.to_owned(),
            tokio::spawn(async move {
                while let Some(frame) = subscription.receive().await {
                    callbacks.message(&name_owned, session.clone(), frame).await;
                }
            }),
        );
    }
    pub async fn persist(&self, identities: &crate::identities::Identities) -> Result<(), String> {
        self.callbacks
            .persist(identities.durable_configuration().await?)
            .await
    }
    /// Host-only credential export policy. Tauri permissions remain required.
    pub fn set_credential_export(&self, enabled: bool) {
        self.export_credentials
            .store(enabled, std::sync::atomic::Ordering::Release);
    }
    pub fn credential_export_allowed(&self) -> bool {
        self.export_credentials
            .load(std::sync::atomic::Ordering::Acquire)
    }
    pub async fn background_message(
        &self,
        name: &str,
        session: Arc<Session>,
        frame: CommunicationValue,
    ) {
        self.callbacks.message(name, session, frame).await;
    }
    pub fn new(callbacks: Arc<dyn HostCallbacks>) -> Arc<Self> {
        Arc::new(Self {
            registry: ConnectionRegistry::default(),
            callbacks,
            workers: Mutex::new(HashMap::new()),
            export_credentials: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub async fn initialize(
        self: &Arc<Self>,
        name: &str,
        options: ConnectionOptions,
    ) -> Result<Arc<Session>, CommunicationError> {
        let mut workers = self.workers.lock().await;
        let session = self
            .registry
            .attach_or_connect(name, &options.identity, || async {
                let endpoint = self.callbacks.resolve(name).await?;
                if options.authenticated {
                    MTPClient::auth_connect(endpoint.config, &options.keyring, &endpoint.host_key)
                        .await
                } else {
                    MTPClient::connect(endpoint.config).await
                }
            })
            .await?;
        if !workers.contains_key(name) {
            let mut subscription = session.subscribe(32).await;
            let callbacks = self.callbacks.clone();
            let name_owned = name.to_owned();
            let connection = session.clone();
            workers.insert(
                name.to_owned(),
                tokio::spawn(async move {
                    while let Some(frame) = subscription.receive().await {
                        callbacks
                            .message(&name_owned, connection.clone(), frame)
                            .await;
                    }
                }),
            );
        }
        Ok(session)
    }

    pub async fn stop(&self, name: &str) {
        if let Some(worker) = self.workers.lock().await.remove(name) {
            worker.abort();
        }
        self.registry.disconnect(name).await;
    }

    pub async fn request(
        &self,
        name: &str,
        frame: CommunicationValue,
        deadline: Duration,
    ) -> Result<CommunicationValue, CommunicationError> {
        let session = self
            .registry
            .attach(name)
            .await
            .ok_or(CommunicationError::ConnectionLost)?;
        session.request(frame, None, deadline).await
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        for (_, worker) in self.workers.get_mut().drain() {
            worker.abort();
        }
    }
}
