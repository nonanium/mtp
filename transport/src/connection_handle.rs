use mtp_common::CommunicationError;
use std::net::SocketAddr;
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
    remote_addr: Option<SocketAddr>,
}

impl ConnectionHandle {
    pub fn new() -> Self {
        let (close_tx, close_rx) = watch::channel(None);
        Self {
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

/* ================================ TESTS ================================ */
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_is_open() {
        let h = ConnectionHandle::new();
        assert!(h.is_open());
        assert!(!h.is_closed());
    }

    #[test]
    fn test_close_transitions_state() {
        let h = ConnectionHandle::new();
        h.close(Some(CommunicationError::StreamClosed));
        assert!(!h.is_open());
        assert!(h.is_closed());
    }

    #[test]
    fn test_close_reason_some() {
        let h = ConnectionHandle::new();
        h.close(Some(CommunicationError::UseAfterClosed));
        assert!(h.close_reason().is_some());
    }

    #[test]
    fn test_close_reason_none() {
        let h = ConnectionHandle::new();
        h.close(None);
        assert!(h.close_reason().is_none());
    }

    #[test]
    fn test_default_is_new() {
        let h = ConnectionHandle::default();
        assert!(h.is_open());
    }

    #[test]
    fn test_close_with_error() {
        let h = ConnectionHandle::new();
        h.close_with_error(CommunicationError::MessageTooLarge);
        assert!(h.is_closed());
        assert!(h.close_reason().is_some());
    }

    #[test]
    fn test_multiple_close_first_wins() {
        let h = ConnectionHandle::new();
        h.close(Some(CommunicationError::StreamClosed));
        h.close(Some(CommunicationError::UseAfterClosed));
        // First close reason is preserved
        assert!(h.close_reason().is_some());
    }

    #[test]
    fn test_close_sends_reason() {
        let h = ConnectionHandle::new();
        let mut rx = h.subscribe_close();
        h.close(Some(CommunicationError::ClosedLocally));
        // After close, the watch channel is updated
        assert!(rx.borrow_and_update().is_some());
    }
}
