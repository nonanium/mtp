use mtp_common::CommunicationError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::watch;

#[derive(Debug)]
pub struct ConnectionHandle {
    closed: AtomicBool,
    close_tx: watch::Sender<Option<CommunicationError>>,
    close_rx: watch::Receiver<Option<CommunicationError>>,
}

impl ConnectionHandle {
    pub fn new() -> Self {
        let (close_tx, close_rx) = watch::channel(None);
        Self {
            closed: AtomicBool::new(false),
            close_tx,
            close_rx,
        }
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
        let _ = rx.changed().await.ok()?;
        rx.borrow().clone()
    }
}

impl Default for ConnectionHandle {
    fn default() -> Self {
        Self::new()
    }
}
