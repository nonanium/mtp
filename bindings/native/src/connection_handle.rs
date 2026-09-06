use mtp_common::CommunicationError;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::sync::watch;

#[derive(Debug)]
pub struct ConnectionHandle {
    connection_id: u64,
    closed: AtomicBool,
    close_tx: watch::Sender<Option<CommunicationError>>,
    close_rx: watch::Receiver<Option<CommunicationError>>,
    remote_addr: Option<SocketAddr>,
}

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

impl ConnectionHandle {
    pub fn new() -> Self {
        let (close_tx, close_rx) = watch::channel(None);
        Self {
            connection_id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed).max(1),
            closed: AtomicBool::new(false),
            close_tx,
            close_rx,
            remote_addr: None,
        }
    }

    pub fn with_remote_addr(remote_addr: SocketAddr) -> Self {
        let mut handle = Self::new();
        handle.remote_addr = Some(remote_addr);
        handle
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Stable process-local identifier for authentication-rate-limit scopes.
    pub fn connection_id(&self) -> u64 {
        self.connection_id
    }

    pub fn is_open(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub fn close(&self, reason: Option<CommunicationError>) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            let _ = self.close_tx.send(reason);
        }
    }

    pub fn close_reason(&self) -> Option<CommunicationError> {
        self.close_rx.borrow().clone()
    }

    pub fn subscribe_close(&self) -> watch::Receiver<Option<CommunicationError>> {
        self.close_rx.clone()
    }

    pub fn close_with_error(&self, error: CommunicationError) {
        self.close(Some(error));
    }

    pub async fn wait_closed(self: Arc<Self>) -> Option<CommunicationError> {
        let mut rx = self.subscribe_close();
        if self.is_closed() {
            return rx.borrow().clone();
        }
        rx.changed().await.ok()?;
        rx.borrow().clone()
    }
}

impl Default for ConnectionHandle {
    fn default() -> Self {
        Self::new()
    }
}
