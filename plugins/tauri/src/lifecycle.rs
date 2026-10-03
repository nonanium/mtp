//! Process-wide native ownership, independent of the webview lifetime.
use crate::{
    Manager,
    identities::{Identities, InitializeOptions},
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackgroundConnection {
    pub name: String,
    pub options: InitializeOptions,
}

pub struct Lifecycle {
    pub manager: Arc<Manager>,
    pub identities: Arc<Identities>,
    workers: Mutex<HashMap<String, (BackgroundConnection, tokio::task::JoinHandle<()>)>>,
}

impl Lifecycle {
    pub fn new(manager: Arc<Manager>) -> Arc<Self> {
        Arc::new(Self {
            manager,
            identities: Arc::new(Identities::default()),
            workers: Mutex::new(HashMap::new()),
        })
    }

    /// Only durable authenticated identities can run unattended. Registration
    /// and anonymous sessions must be completed in the foreground first.
    pub async fn start(
        self: &Arc<Self>,
        connections: Vec<BackgroundConnection>,
    ) -> Result<(), String> {
        let mut workers = self.workers.lock().await;
        let mut names = std::collections::HashSet::new();
        for connection in &connections {
            if connection.options.fresh {
                return Err(
                    "temporary identities cannot run as permanent background connections".into(),
                );
            }
            if !names.insert(&connection.name) {
                return Err("duplicate background connection name".into());
            }
            let credentials = connection
                .options
                .credentials
                .as_ref()
                .ok_or("background connection requires persisted credentials")?;
            if credentials
                .client_id
                .as_ref()
                .and_then(|id| id.parse::<u64>().ok())
                .filter(|id| *id != 0)
                .is_none()
            {
                return Err("background connection requires permanent client ID".into());
            }
            if connection
                .options
                .host_public_key
                .as_ref()
                .or(credentials.host_public_key.as_ref())
                .is_none()
            {
                return Err("background authentication requires pinned host keys".into());
            }
            if let Some((existing, _)) = workers.get(&connection.name)
                && existing != connection
            {
                return Err("background connection configuration conflict".into());
            }
        }
        let durable = self.identities.durable_configuration().await?;
        for connection in &connections {
            if let Some(existing) = durable.iter().find(|entry| entry.name == connection.name) {
                if existing != connection {
                    return Err("background identity configuration conflict".into());
                }
            } else {
                self.identities
                    .initialize(&connection.name, connection.options.clone())
                    .await?;
            }
        }
        for connection in connections {
            if workers.contains_key(&connection.name) {
                continue;
            }
            let owner = Arc::downgrade(self);
            let name = connection.name.clone();
            let task = tokio::spawn(async move {
                let mut failures = 0u32;
                loop {
                    let Some(owner) = owner.upgrade() else { break };
                    let result = owner
                        .identities
                        .connect(&name, "auth", &owner.manager.registry)
                        .await;
                    if result.is_ok() {
                        failures = 0;
                        if let Some(session) = owner.manager.registry.attach(&name).await {
                            let mut subscription = session.subscribe(256).await;
                            while let Some(frame) = subscription.receive().await {
                                owner
                                    .manager
                                    .background_message(&name, session.clone(), frame)
                                    .await;
                            }
                            owner
                                .manager
                                .registry
                                .disconnect_session(&name, &session)
                                .await;
                        }
                    }
                    failures = failures.saturating_add(1);
                    let ceiling = (1000u64 << failures.min(6)).min(60_000);
                    let random = uuid::Uuid::new_v4().as_u128() as u64;
                    drop(owner);
                    tokio::time::sleep(Duration::from_millis(ceiling / 2 + random % (ceiling / 2)))
                        .await;
                }
            });
            workers.insert(connection.name.clone(), (connection, task));
        }
        Ok(())
    }

    pub async fn stop(&self) {
        let mut workers = self.workers.lock().await;
        for (name, (_, task)) in workers.drain() {
            task.abort();
            self.manager.stop(&name).await;
        }
    }

    pub async fn remove(&self, name: &str) {
        if let Some((_, task)) = self.workers.lock().await.remove(name) {
            task.abort();
        }
        self.manager.stop(name).await;
    }
}

impl Drop for Lifecycle {
    fn drop(&mut self) {
        for (_, (_, task)) in self.workers.get_mut().drain() {
            task.abort();
        }
    }
}
