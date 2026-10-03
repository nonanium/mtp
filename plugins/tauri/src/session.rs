use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use mtp_client::MTPConnection;
use mtp_codec::{CommunicationType, CommunicationValue};
use mtp_common::CommunicationError;
use tokio::sync::{Mutex, mpsc, watch};

/// One owner of the application receive queue. Requests use the connection's
/// existing response dispatcher, while independent subscribers receive copies.
pub struct Session {
    closed: AtomicBool,
    connection: Arc<MTPConnection>,
    next_request_id: AtomicU64,
    subscribers: Mutex<HashMap<u64, mpsc::Sender<CommunicationValue>>>,
    next_subscription_id: AtomicU64,
    receive_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pipe_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pipe_subscriber: Mutex<
        Option<
            mpsc::Sender<
                mtp_pipes::PipeRequest<
                    mtp_native::Sender,
                    mtp_native::Receiver,
                    mtp_native::NativeRecvStream,
                >,
            >,
        >,
    >,
}

pub struct Subscription {
    id: u64,
    session: Arc<Session>,
    receiver: mpsc::Receiver<CommunicationValue>,
}

impl Subscription {
    pub async fn receive(&mut self) -> Option<CommunicationValue> {
        self.receiver.recv().await
    }

    /// Detaching an observer does not disconnect native consumers.
    pub async fn detach(self) {
        self.session.subscribers.lock().await.remove(&self.id);
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // Dropping the receiver closes the sender immediately, even if no more
        // frames arrive to trigger subscriber cleanup.
        self.receiver.close();
    }
}

impl Session {
    pub fn connection(&self) -> &MTPConnection {
        &self.connection
    }
    pub async fn new(connection: MTPConnection) -> Arc<Self> {
        let session = Arc::new(Self {
            closed: AtomicBool::new(false),
            connection: Arc::new(connection),
            next_request_id: AtomicU64::new(1),
            subscribers: Mutex::new(HashMap::new()),
            next_subscription_id: AtomicU64::new(1),
            receive_task: Mutex::new(None),
            pipe_task: Mutex::new(None),
            pipe_subscriber: Mutex::new(None),
        });
        let weak = Arc::downgrade(&session);
        let connection = session.connection.clone();
        let task = tokio::spawn(async move {
            while let Ok(frame) = connection.receive().await {
                let Some(session) = weak.upgrade() else {
                    break;
                };
                // Slow subscribers are detached rather than accumulating an
                // unbounded event history or blocking background consumers.
                session
                    .subscribers
                    .lock()
                    .await
                    .retain(|_, sender| sender.try_send(frame.clone()).is_ok());
            }
            if let Some(session) = weak.upgrade() {
                session.closed.store(true, Ordering::Release);
                session.subscribers.lock().await.clear();
            }
        });
        *session.receive_task.lock().await = Some(task);
        let weak = Arc::downgrade(&session);
        let connection = session.connection.clone();
        *session.pipe_task.lock().await = Some(tokio::spawn(async move {
            while let Ok(offer) = connection.receive_pipe().await {
                let Some(session) = weak.upgrade() else { break };
                let subscriber = session.pipe_subscriber.lock().await;
                let offer = match subscriber.as_ref() {
                    Some(sender) => match sender.try_send(offer) {
                        Ok(()) => continue,
                        Err(error) => error.into_inner(),
                    },
                    None => offer,
                };
                drop(subscriber);
                let _ = offer.deny().await;
            }
        }));
        session
    }

    /// Offers have one native owner and no detached UI history.
    pub async fn subscribe_pipes(
        &self,
        capacity: usize,
    ) -> mpsc::Receiver<
        mtp_pipes::PipeRequest<
            mtp_native::Sender,
            mtp_native::Receiver,
            mtp_native::NativeRecvStream,
        >,
    > {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        *self.pipe_subscriber.lock().await = Some(sender);
        receiver
    }

    pub async fn subscribe(self: &Arc<Self>, capacity: usize) -> Subscription {
        let id = self.next_subscription_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        let mut subscribers = self.subscribers.lock().await;
        if !self.closed.load(Ordering::Acquire) {
            subscribers.insert(id, sender);
        }
        Subscription {
            id,
            session: self.clone(),
            receiver,
        }
    }

    /// All native and bridge requests must enter here. Caller-supplied IDs are
    /// overwritten so independently initialized callers cannot collide.
    pub async fn request(
        &self,
        frame: CommunicationValue,
        expected: Option<CommunicationType>,
        deadline: Duration,
    ) -> Result<CommunicationValue, CommunicationError> {
        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let Ok(id) = u32::try_from(id) else {
            self.close().await;
            return Err(CommunicationError::Other(
                "request ID space exhausted; reconnect before sending".into(),
            ));
        };
        let frame = frame.with_id(id);
        tokio::time::timeout(
            deadline,
            self.connection
                .request_with_timeout(&frame, expected, deadline),
        )
        .await
        .map_err(|_| CommunicationError::timeout(mtp_common::TransportPhase::WaitResponse))?
    }

    pub async fn send(&self, frame: &CommunicationValue) -> Result<(), CommunicationError> {
        self.connection.sender.send(frame).await
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.connection.sender.close().await;
        if let Some(task) = self.receive_task.lock().await.take() {
            task.abort();
        }
        self.subscribers.lock().await.clear();
        self.pipe_subscriber.lock().await.take();
        if let Some(task) = self.pipe_task.lock().await.take() {
            task.abort();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(task) = self.receive_task.get_mut().take() {
            task.abort();
        }
        if let Some(task) = self.pipe_task.get_mut().take() {
            task.abort();
        }
    }
}

/// Registration is serialized, including connection establishment. Identical
/// configuration attaches to the existing session; conflicts fail explicitly.
#[derive(Default)]
pub struct ConnectionRegistry {
    sessions: Mutex<HashMap<String, (String, Arc<Session>)>>,
    observers: Mutex<HashMap<String, watch::Sender<Option<Arc<Session>>>>>,
}

impl ConnectionRegistry {
    /// Watches live session replacements without retaining application events.
    pub async fn watch(&self, name: &str) -> watch::Receiver<Option<Arc<Session>>> {
        let sessions = self.sessions.lock().await;
        let mut observers = self.observers.lock().await;
        observers
            .entry(name.into())
            .or_insert_with(|| {
                watch::channel(sessions.get(name).map(|(_, session)| session.clone())).0
            })
            .subscribe()
    }

    pub async fn attach_or_connect<F, Fut>(
        &self,
        name: &str,
        configuration_identity: &str,
        connect: F,
    ) -> Result<Arc<Session>, CommunicationError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<MTPConnection, CommunicationError>>,
    {
        if name.is_empty() {
            return Err(CommunicationError::Other("connection name is empty".into()));
        }
        let mut sessions = self.sessions.lock().await;
        if let Some((identity, session)) = sessions.get(name) {
            if identity != configuration_identity {
                return Err(CommunicationError::Other(format!(
                    "connection {name:?} already has a different configuration"
                )));
            }
            if !session.closed.load(Ordering::Acquire) {
                return Ok(session.clone());
            }
            let session = session.clone();
            sessions.remove(name);
            session.close().await;
        }
        let session = Session::new(connect().await?).await;
        sessions.insert(
            name.into(),
            (configuration_identity.into(), session.clone()),
        );
        if let Some(observer) = self.observers.lock().await.get(name) {
            observer.send_replace(Some(session.clone()));
        }
        Ok(session)
    }

    pub async fn attach(&self, name: &str) -> Option<Arc<Session>> {
        self.sessions
            .lock()
            .await
            .get(name)
            .filter(|(_, session)| !session.closed.load(Ordering::Acquire))
            .map(|(_, session)| session.clone())
    }

    pub async fn disconnect(&self, name: &str) {
        let mut sessions = self.sessions.lock().await;
        if let Some((_, session)) = sessions.remove(name) {
            session.close().await;
        }
        if let Some(observer) = self.observers.lock().await.get(name) {
            observer.send_replace(None);
        }
    }

    /// A closing supervisor must not disconnect a replacement attached meanwhile.
    pub async fn disconnect_session(&self, name: &str, expected: &Arc<Session>) {
        let mut sessions = self.sessions.lock().await;
        if sessions
            .get(name)
            .is_some_and(|(_, session)| Arc::ptr_eq(session, expected))
        {
            sessions.remove(name);
            expected.close().await;
            if let Some(observer) = self.observers.lock().await.get(name) {
                observer.send_replace(None);
            }
        }
    }
}
