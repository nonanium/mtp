use rand::RngExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, Instant};

use mtp_codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp_transport::{Receiver, Sender};

pub(crate) struct PingSession {
    pub(crate) last_ping: Arc<Mutex<Option<Duration>>>,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

impl PingSession {
    pub(crate) fn get_ping(&self) -> Option<Duration> {
        self.last_ping.try_lock().ok().and_then(|ping| *ping)
    }
}

impl Drop for PingSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn start_ping_session(
    config: &crate::config::ClientConfig,
    sender: Sender,
    receiver: &Receiver,
) -> Option<PingSession> {
    if config.ping_interval.is_zero() {
        return None;
    }

    let (pong_tx, mut pong_rx) = mpsc::unbounded_channel();
    receiver.observe_pongs(pong_tx);
    let last_ping = Arc::new(Mutex::new(None));
    let ping_state = last_ping.clone();
    let interval = config.ping_interval;
    let ping_jitter = config.ping_jitter;
    let max_missed_pings = config.max_missed_pings;
    let ping_timestamp = config.ping_timestamp;
    let mut close_rx = receiver.handle().subscribe_close();

    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        let mut pending = HashMap::new();

        loop {
            tokio::select! {
                _ = close_rx.changed() => {
                    if close_rx.borrow().is_some() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if max_missed_pings > 0 && !pending.is_empty() && pending.len() >= max_missed_pings {
                        sender.close().await;
                        break;
                    }

                    if let Some(jitter) = ping_jitter && !jitter.is_zero() {
                        let max_ms = jitter.as_millis() as u64;
                        let extra = rand::rng().random_range(0..=max_ms);
                        tokio::time::sleep(Duration::from_millis(extra)).await;
                    }

                    let mut ping = CommunicationValue::new(CommunicationType::Ping);
                    if ping_timestamp {
                        let sent_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis();
                        ping = ping.add_typed_default(
                            DataType::Timestamp,
                            DataValue::UnsignedNumber(sent_at),
                        );
                    }
                    let id = ping.get_id();
                    if sender.send(&ping).await.is_err() {
                        sender.close().await;
                        break;
                    }
                    pending.insert(id, Instant::now());
                }
                pong = pong_rx.recv() => match pong {
                    Some(pong) => {
                        if let Some(sent_at) = pending.remove(&pong.get_id()) {
                            let mut last_ping = ping_state.lock().await;
                            *last_ping = Some(sent_at.elapsed());
                        }
                    }
                    None => break,
                },
            }
        }
    });

    Some(PingSession { last_ping, task })
}
