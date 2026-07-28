use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_session_id() -> String {
    let ts = now_epoch_secs();
    let rand_part: u32 = rand::random();
    format!("{ts}-{rand_part:08x}")
}

// ---------------------------------------------------------------------------
// Persisted data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionRecord {
    pub session_id: String,
    pub client_id: u64,
    pub description: String,
    pub start_time: u64,
    pub end_time: u64,
    pub duration_secs: f64,
    pub messages_received: u64,
    pub messages_ok: u64,
    pub messages_failed: u64,
    pub pipes_handled: u64,
    pub pipe_bytes_copied: u64,
    pub pipe_denials: u64,
    pub send_errors: u64,
    pub avg_message_latency_ms: f64,
    pub max_message_latency_ms: f64,
    pub exit_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregateStats {
    pub total_connections: u64,
    pub total_messages: u64,
    pub total_messages_ok: u64,
    pub total_messages_failed: u64,
    pub total_pipes: u64,
    pub total_pipe_bytes: u64,
    pub total_pipe_denials: u64,
    pub total_send_errors: u64,
    pub total_accept_errors: u64,
    pub avg_session_duration_secs: f64,
    pub avg_messages_per_session: f64,
    pub avg_pipes_per_session: f64,
    pub avg_message_latency_ms: f64,
    pub max_message_latency_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overview {
    pub total_sessions: u64,
    pub first_session_timestamp: u64,
    pub last_session_timestamp: u64,
    pub aggregate: AggregateStats,
    pub connection_versions: HashMap<String, u64>,
    pub sessions: Vec<SessionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerMetricsFile {
    pub total_connections: u64,
    pub total_messages: u64,
    pub total_messages_ok: u64,
    pub total_messages_failed: u64,
    pub total_pipes: u64,
    pub total_pipe_bytes: u64,
    pub total_pipe_denials: u64,
    pub total_send_errors: u64,
    pub total_accept_errors: u64,
    pub connection_versions: HashMap<String, u64>,
    pub sessions: Vec<SessionRecord>,
}

// ---------------------------------------------------------------------------
// Live metrics state
// ---------------------------------------------------------------------------

struct Inner {
    total_connections: u64,
    total_messages: u64,
    total_messages_ok: u64,
    total_messages_failed: u64,
    total_pipes: u64,
    total_pipe_bytes: u64,
    total_pipe_denials: u64,
    total_send_errors: u64,
    total_accept_errors: u64,
    connection_versions: HashMap<String, u64>,
    active_connections: u64,
    completed_sessions: Vec<SessionRecord>,
}

pub struct ServerMetrics {
    inner: Mutex<Inner>,
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                total_connections: 0,
                total_messages: 0,
                total_messages_ok: 0,
                total_messages_failed: 0,
                total_pipes: 0,
                total_pipe_bytes: 0,
                total_pipe_denials: 0,
                total_send_errors: 0,
                total_accept_errors: 0,
                connection_versions: HashMap::new(),
                active_connections: 0,
                completed_sessions: Vec::new(),
            }),
        }
    }

    pub fn load(path: &str) -> Self {
        let file = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<ServerMetricsFile>(&s).ok());

        let mut inner = Inner {
            total_connections: 0,
            total_messages: 0,
            total_messages_ok: 0,
            total_messages_failed: 0,
            total_pipes: 0,
            total_pipe_bytes: 0,
            total_pipe_denials: 0,
            total_send_errors: 0,
            total_accept_errors: 0,
            connection_versions: HashMap::new(),
            active_connections: 0,
            completed_sessions: Vec::new(),
        };

        if let Some(data) = file {
            inner.total_connections = data.total_connections;
            inner.total_messages = data.total_messages;
            inner.total_messages_ok = data.total_messages_ok;
            inner.total_messages_failed = data.total_messages_failed;
            inner.total_pipes = data.total_pipes;
            inner.total_pipe_bytes = data.total_pipe_bytes;
            inner.total_pipe_denials = data.total_pipe_denials;
            inner.total_send_errors = data.total_send_errors;
            inner.total_accept_errors = data.total_accept_errors;
            inner.connection_versions = data.connection_versions;
            inner.completed_sessions = data.sessions;
        }

        Self {
            inner: Mutex::new(inner),
        }
    }

    pub fn save(&self, path: &str) {
        let inner = self.inner.lock().unwrap();
        let data = self.to_file(&inner);
        if let Some(parent) = Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&data).unwrap_or_default();
        let _ = std::fs::write(path, json);
    }

    fn to_file(&self, inner: &Inner) -> ServerMetricsFile {
        ServerMetricsFile {
            total_connections: inner.total_connections,
            total_messages: inner.total_messages,
            total_messages_ok: inner.total_messages_ok,
            total_messages_failed: inner.total_messages_failed,
            total_pipes: inner.total_pipes,
            total_pipe_bytes: inner.total_pipe_bytes,
            total_pipe_denials: inner.total_pipe_denials,
            total_send_errors: inner.total_send_errors,
            total_accept_errors: inner.total_accept_errors,
            connection_versions: inner.connection_versions.clone(),
            sessions: inner.completed_sessions.clone(),
        }
    }

    pub fn start_session(&self, client_id: u64, description: String) -> SessionHandle<'_> {
        let session_id = generate_session_id();
        let start = Instant::now();
        let start_time = now_epoch_secs();

        self.inner.lock().unwrap().total_connections += 1;
        self.inner.lock().unwrap().active_connections += 1;

        SessionHandle {
            metrics: self,
            session_id,
            client_id,
            description,
            start,
            start_time,
            messages_received: 0,
            messages_ok: 0,
            messages_failed: 0,
            pipes_handled: 0,
            pipe_bytes: 0,
            pipe_denials: 0,
            send_errors: 0,
            latencies: Vec::new(),
        }
    }

    pub fn snapshot(&self) -> ServerMetricsFile {
        let inner = self.inner.lock().unwrap();
        self.to_file(&inner)
    }

    pub fn record_accept_error(&self) {
        self.inner.lock().unwrap().total_accept_errors += 1;
    }

    pub fn record_connection_version(&self, version: &str) {
        *self
            .inner
            .lock()
            .unwrap()
            .connection_versions
            .entry(version.to_string())
            .or_insert(0) += 1;
    }

    pub fn build_overview(&self, overview_path: &str) {
        let inner = self.inner.lock().unwrap();
        let sessions = &inner.completed_sessions;
        let total = sessions.len() as u64;

        if total == 0 {
            let overview = Overview {
                total_sessions: 0,
                first_session_timestamp: 0,
                last_session_timestamp: 0,
                aggregate: AggregateStats::default(),
                connection_versions: HashMap::new(),
                sessions: Vec::new(),
            };
            if let Some(parent) = Path::new(overview_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let json = serde_json::to_string_pretty(&overview).unwrap_or_default();
            let _ = std::fs::write(overview_path, json);
            return;
        }

        let first_ts = sessions.first().map(|s| s.start_time).unwrap_or(0);
        let last_ts = sessions.last().map(|s| s.end_time).unwrap_or(0);

        let total_duration: f64 = sessions.iter().map(|s| s.duration_secs).sum();
        let total_msgs: u64 = sessions.iter().map(|s| s.messages_received).sum();
        let total_pipes: u64 = sessions.iter().map(|s| s.pipes_handled).sum();

        let mut max_latency: f64 = 0.0;
        let mut latency_sum: f64 = 0.0;
        let mut latency_count: u64 = 0;
        for s in sessions {
            if s.avg_message_latency_ms > 0.0 {
                latency_sum += s.avg_message_latency_ms * s.messages_ok as f64;
                latency_count += s.messages_ok;
            }
            if s.max_message_latency_ms > max_latency {
                max_latency = s.max_message_latency_ms;
            }
        }

        let aggregate = AggregateStats {
            total_connections: inner.total_connections,
            total_messages: inner.total_messages,
            total_messages_ok: inner.total_messages_ok,
            total_messages_failed: inner.total_messages_failed,
            total_pipes: inner.total_pipes,
            total_pipe_bytes: inner.total_pipe_bytes,
            total_pipe_denials: inner.total_pipe_denials,
            total_send_errors: inner.total_send_errors,
            total_accept_errors: inner.total_accept_errors,
            avg_session_duration_secs: total_duration / total as f64,
            avg_messages_per_session: total_msgs as f64 / total as f64,
            avg_pipes_per_session: total_pipes as f64 / total as f64,
            avg_message_latency_ms: if latency_count > 0 {
                latency_sum / latency_count as f64
            } else {
                0.0
            },
            max_message_latency_ms: max_latency,
        };

        let overview = Overview {
            total_sessions: total,
            first_session_timestamp: first_ts,
            last_session_timestamp: last_ts,
            aggregate,
            connection_versions: inner.connection_versions.clone(),
            sessions: sessions.clone(),
        };

        if let Some(parent) = Path::new(overview_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&overview).unwrap_or_default();
        let _ = std::fs::write(overview_path, json);
    }

    fn finish_session(&self, record: SessionRecord) {
        let mut inner = self.inner.lock().unwrap();
        inner.active_connections -= 1;
        inner.total_messages += record.messages_received;
        inner.total_messages_ok += record.messages_ok;
        inner.total_messages_failed += record.messages_failed;
        inner.total_pipes += record.pipes_handled;
        inner.total_pipe_bytes += record.pipe_bytes_copied;
        inner.total_pipe_denials += record.pipe_denials;
        inner.total_send_errors += record.send_errors;
        inner.completed_sessions.push(record);
    }
}

// ---------------------------------------------------------------------------
// Session handle — local accumulators, no mutex contention during connection
// ---------------------------------------------------------------------------

pub struct SessionHandle<'a> {
    metrics: &'a ServerMetrics,
    session_id: String,
    client_id: u64,
    description: String,
    start: Instant,
    start_time: u64,
    messages_received: u64,
    messages_ok: u64,
    messages_failed: u64,
    pipes_handled: u64,
    pipe_bytes: u64,
    pipe_denials: u64,
    send_errors: u64,
    latencies: Vec<f64>,
}

impl<'a> SessionHandle<'a> {
    pub fn messages_received(&self) -> u64 {
        self.messages_received
    }

    pub fn record_message(&mut self, latency: Duration, ok: bool) {
        self.messages_received += 1;
        if ok {
            self.messages_ok += 1;
        } else {
            self.messages_failed += 1;
        }
        self.latencies.push(latency.as_secs_f64() * 1000.0);
    }

    pub fn record_pipe(&mut self, bytes: u64) {
        self.pipes_handled += 1;
        self.pipe_bytes += bytes;
    }

    pub fn record_pipe_denial(&mut self) {
        self.pipe_denials += 1;
    }

    pub fn record_send_error(&mut self) {
        self.send_errors += 1;
    }

    pub fn finish(self, exit_reason: String) -> SessionRecord {
        let elapsed = self.start.elapsed();
        let end_time = self.start_time + elapsed.as_secs();

        let avg_latency = if self.latencies.is_empty() {
            0.0
        } else {
            self.latencies.iter().sum::<f64>() / self.latencies.len() as f64
        };
        let max_latency = self.latencies.iter().copied().fold(0.0_f64, f64::max);

        let record = SessionRecord {
            session_id: self.session_id,
            client_id: self.client_id,
            description: self.description,
            start_time: self.start_time,
            end_time,
            duration_secs: elapsed.as_secs_f64(),
            messages_received: self.messages_received,
            messages_ok: self.messages_ok,
            messages_failed: self.messages_failed,
            pipes_handled: self.pipes_handled,
            pipe_bytes_copied: self.pipe_bytes,
            pipe_denials: self.pipe_denials,
            send_errors: self.send_errors,
            avg_message_latency_ms: avg_latency,
            max_message_latency_ms: max_latency,
            exit_reason,
        };

        self.metrics.finish_session(record.clone());
        record
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tmp_path(name: &str) -> String {
        let dir = std::env::temp_dir().join("mtp_server_metrics_test");
        let _ = std::fs::create_dir_all(&dir);
        dir.join(name).to_str().unwrap().to_string()
    }

    #[test]
    fn test_session_record_roundtrip() {
        let record = SessionRecord {
            session_id: "test-123".into(),
            client_id: 1000,
            description: "test session".into(),
            start_time: 1000,
            end_time: 1010,
            duration_secs: 10.0,
            messages_received: 5,
            messages_ok: 4,
            messages_failed: 1,
            pipes_handled: 2,
            pipe_bytes_copied: 4096,
            pipe_denials: 0,
            send_errors: 0,
            avg_message_latency_ms: 1.5,
            max_message_latency_ms: 3.0,
            exit_reason: "normal".into(),
        };

        let json = serde_json::to_string(&record).unwrap();
        let decoded: SessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn test_metrics_file_roundtrip() {
        let file = ServerMetricsFile {
            total_connections: 10,
            total_messages: 50,
            total_messages_ok: 48,
            total_messages_failed: 2,
            total_pipes: 5,
            total_pipe_bytes: 20480,
            total_pipe_denials: 1,
            total_send_errors: 0,
            total_accept_errors: 3,
            connection_versions: HashMap::from([("2.0".into(), 8), ("1.0".into(), 2)]),
            sessions: vec![
                SessionRecord {
                    session_id: "s1".into(),
                    client_id: 1000,
                    description: "first".into(),
                    start_time: 100,
                    end_time: 110,
                    duration_secs: 10.0,
                    messages_received: 3,
                    messages_ok: 3,
                    messages_failed: 0,
                    pipes_handled: 1,
                    pipe_bytes_copied: 1024,
                    pipe_denials: 0,
                    send_errors: 0,
                    avg_message_latency_ms: 0.5,
                    max_message_latency_ms: 1.0,
                    exit_reason: "normal".into(),
                },
                SessionRecord {
                    session_id: "s2".into(),
                    client_id: 1001,
                    description: "second".into(),
                    start_time: 200,
                    end_time: 230,
                    duration_secs: 30.0,
                    messages_received: 7,
                    messages_ok: 6,
                    messages_failed: 1,
                    pipes_handled: 4,
                    pipe_bytes_copied: 19456,
                    pipe_denials: 1,
                    send_errors: 0,
                    avg_message_latency_ms: 2.0,
                    max_message_latency_ms: 5.0,
                    exit_reason: "idle timeout".into(),
                },
            ],
        };

        let json = serde_json::to_string_pretty(&file).unwrap();
        let decoded: ServerMetricsFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file.total_connections, decoded.total_connections);
        assert_eq!(file.sessions.len(), decoded.sessions.len());
        assert_eq!(file.sessions[0], decoded.sessions[0]);
        assert_eq!(file.sessions[1], decoded.sessions[1]);
    }

    #[test]
    fn test_session_handle_lifecycle() {
        let metrics = ServerMetrics::new();
        let mut session = metrics.start_session(1000, "test".into());

        session.record_message(Duration::from_millis(1), true);
        session.record_message(Duration::from_millis(3), true);
        session.record_message(Duration::from_millis(2), false);
        session.record_pipe(512);

        let record = session.finish("test exit".into());

        assert_eq!(record.client_id, 1000);
        assert_eq!(record.messages_received, 3);
        assert_eq!(record.messages_ok, 2);
        assert_eq!(record.messages_failed, 1);
        assert_eq!(record.pipes_handled, 1);
        assert_eq!(record.pipe_bytes_copied, 512);
        assert!(record.avg_message_latency_ms > 0.0);
        assert_eq!(record.max_message_latency_ms, 3.0);
        assert_eq!(record.exit_reason, "test exit");

        let snap = metrics.snapshot();
        assert_eq!(snap.total_connections, 1);
        assert_eq!(snap.total_messages, 3);
        assert_eq!(snap.total_messages_ok, 2);
        assert_eq!(snap.total_messages_failed, 1);
        assert_eq!(snap.total_pipes, 1);
        assert_eq!(snap.total_pipe_bytes, 512);
        assert_eq!(snap.sessions.len(), 1);
    }

    #[test]
    fn test_overview_generation() {
        let metrics = ServerMetrics::new();

        for i in 0..3 {
            let mut session = metrics.start_session(1000 + i as u64, format!("session {i}"));
            for _ in 0..(i + 1) * 2 {
                session.record_message(Duration::from_millis(1 + i), true);
            }
            session.record_pipe((i as u64 + 1) * 1000);
            session.finish(format!("exit {i}"));
        }

        let overview_path = tmp_path("overview_test.json");
        metrics.build_overview(&overview_path);

        let json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: Overview = serde_json::from_str(&json).unwrap();

        assert_eq!(overview.total_sessions, 3);
        assert!(overview.first_session_timestamp > 0);
        assert!(overview.last_session_timestamp >= overview.first_session_timestamp);
        assert_eq!(overview.aggregate.total_connections, 3);
        assert_eq!(overview.aggregate.total_messages, 12); // 2+4+6
        assert_eq!(overview.aggregate.total_pipes, 3);
        assert_eq!(overview.aggregate.total_pipe_bytes, 6000); // 1000+2000+3000
        assert!(overview.aggregate.avg_session_duration_secs >= 0.0);
        assert_eq!(overview.sessions.len(), 3);

        let _ = std::fs::remove_file(&overview_path);
    }

    #[test]
    fn test_load_missing_file() {
        let metrics = ServerMetrics::load("/nonexistent/path/metrics.json");
        let snap = metrics.snapshot();
        assert_eq!(snap.total_connections, 0);
        assert!(snap.sessions.is_empty());
    }

    #[test]
    fn test_multiple_sessions_accumulate() {
        let path = tmp_path("accumulate_test.json");
        let metrics = ServerMetrics::load(&path);

        for i in 0..5 {
            let mut session = metrics.start_session(1000, format!("s{i}"));
            session.record_message(Duration::from_millis(1), true);
            session.record_pipe(100);
            session.finish(format!("done {i}"));
        }

        metrics.save(&path);

        let metrics2 = ServerMetrics::load(&path);
        let snap = metrics2.snapshot();
        assert_eq!(snap.total_connections, 5);
        assert_eq!(snap.total_messages, 5);
        assert_eq!(snap.total_messages_ok, 5);
        assert_eq!(snap.total_pipes, 5);
        assert_eq!(snap.total_pipe_bytes, 500);
        assert_eq!(snap.sessions.len(), 5);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_overview_latencies() {
        let metrics = ServerMetrics::new();

        let mut s1 = metrics.start_session(1000, "s1".into());
        s1.record_message(Duration::from_millis(2), true);
        s1.record_message(Duration::from_millis(4), true);
        s1.finish("done".into());

        let mut s2 = metrics.start_session(1001, "s2".into());
        s2.record_message(Duration::from_millis(1), true);
        s2.finish("done".into());

        let overview_path = tmp_path("latency_overview.json");
        metrics.build_overview(&overview_path);
        let json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: Overview = serde_json::from_str(&json).unwrap();

        // s1 avg = 3.0, s2 avg = 1.0
        // weighted avg = (3*2 + 1*1) / 3 = 7/3 ≈ 2.333
        assert!(
            (overview.aggregate.avg_message_latency_ms - 7.0 / 3.0).abs() < 0.01,
            "avg latency: {}",
            overview.aggregate.avg_message_latency_ms
        );
        assert_eq!(overview.aggregate.max_message_latency_ms, 4.0);

        let _ = std::fs::remove_file(&overview_path);
    }

    #[test]
    fn test_overview_empty() {
        let metrics = ServerMetrics::new();
        let overview_path = tmp_path("empty_overview.json");
        metrics.build_overview(&overview_path);

        let json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: Overview = serde_json::from_str(&json).unwrap();
        assert_eq!(overview.total_sessions, 0);
        assert!(overview.sessions.is_empty());

        let _ = std::fs::remove_file(&overview_path);
    }

    // -----------------------------------------------------------------------
    // Integration-style tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_session_lifecycle() {
        let path = tmp_path("lifecycle.json");
        let overview_path = tmp_path("lifecycle_overview.json");

        let metrics = ServerMetrics::load(&path);

        let mut s1 = metrics.start_session(1000, "first".into());
        s1.record_message(Duration::from_millis(1), true);
        s1.record_message(Duration::from_millis(2), true);
        let r1 = s1.finish("normal".into());

        let mut s2 = metrics.start_session(1001, "second".into());
        s2.record_message(Duration::from_millis(5), true);
        s2.record_message(Duration::from_millis(3), false);
        s2.record_pipe(2048);
        s2.record_pipe(4096);
        let r2 = s2.finish("idle timeout".into());

        let mut s3 = metrics.start_session(1002, "third".into());
        s3.record_pipe(1024);
        let r3 = s3.finish("normal".into());

        assert_eq!(r1.client_id, 1000);
        assert_eq!(r1.messages_received, 2);
        assert_eq!(r1.messages_ok, 2);
        assert_eq!(r1.pipes_handled, 0);

        assert_eq!(r2.client_id, 1001);
        assert_eq!(r2.messages_received, 2);
        assert_eq!(r2.messages_ok, 1);
        assert_eq!(r2.messages_failed, 1);
        assert_eq!(r2.pipes_handled, 2);
        assert_eq!(r2.pipe_bytes_copied, 6144);
        assert_eq!(r2.exit_reason, "idle timeout");

        assert_eq!(r3.client_id, 1002);
        assert_eq!(r3.messages_received, 0);
        assert_eq!(r3.pipes_handled, 1);
        assert_eq!(r3.pipe_bytes_copied, 1024);

        let snap = metrics.snapshot();
        assert_eq!(snap.total_connections, 3);
        assert_eq!(snap.total_messages, 4);
        assert_eq!(snap.total_messages_ok, 3);
        assert_eq!(snap.total_messages_failed, 1);
        assert_eq!(snap.total_pipes, 3);
        assert_eq!(snap.total_pipe_bytes, 7168);
        assert_eq!(snap.sessions.len(), 3);

        metrics.save(&path);
        let metrics2 = ServerMetrics::load(&path);
        let snap2 = metrics2.snapshot();
        assert_eq!(snap2.total_connections, 3);
        assert_eq!(snap2.total_messages, 4);
        assert_eq!(snap2.sessions.len(), 3);
        assert_eq!(snap2.sessions[1].exit_reason, "idle timeout");

        metrics2.build_overview(&overview_path);
        let overview_json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: Overview = serde_json::from_str(&overview_json).unwrap();
        assert_eq!(overview.total_sessions, 3);
        assert_eq!(overview.aggregate.total_connections, 3);
        assert_eq!(overview.aggregate.total_messages, 4);
        assert_eq!(overview.aggregate.total_messages_ok, 3);
        assert_eq!(overview.aggregate.total_messages_failed, 1);
        assert_eq!(overview.aggregate.total_pipes, 3);
        assert_eq!(overview.aggregate.total_pipe_bytes, 7168);
        assert!(overview.aggregate.avg_session_duration_secs >= 0.0);
        assert!(overview.aggregate.avg_messages_per_session > 0.0);
        assert_eq!(overview.sessions.len(), 3);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&overview_path);
    }

    #[test]
    fn test_overview_rebuild_accuracy() {
        let path = tmp_path("accuracy.json");
        let overview_path = tmp_path("accuracy_overview.json");

        let metrics = ServerMetrics::load(&path);

        for i in 0..10u32 {
            let mut session = metrics.start_session(1000 + i as u64, format!("session {i}"));
            let msg_count = (i + 1) * 2;
            for j in 0..msg_count {
                session.record_message(Duration::from_millis((j + 1) as u64), j % 3 != 0);
            }
            session.record_pipe((i as u64 + 1) * 512);
            session.finish(format!("exit {i}"));
        }

        metrics.save(&path);
        let metrics2 = ServerMetrics::load(&path);
        metrics2.build_overview(&overview_path);

        let overview_json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: Overview = serde_json::from_str(&overview_json).unwrap();

        assert_eq!(overview.total_sessions, 10);
        assert_eq!(overview.aggregate.total_connections, 10);
        assert_eq!(overview.aggregate.total_messages, 110);
        assert_eq!(overview.aggregate.total_pipes, 10);
        assert_eq!(overview.aggregate.total_pipe_bytes, 28160);
        assert!(overview.aggregate.avg_session_duration_secs >= 0.0);
        assert!((overview.aggregate.avg_messages_per_session - 11.0).abs() < 0.01);
        assert!((overview.aggregate.avg_pipes_per_session - 1.0).abs() < 0.01);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&overview_path);
    }

    #[test]
    fn test_persistence_across_instances() {
        let path = tmp_path("persistence.json");
        let overview_path = tmp_path("persistence_overview.json");

        {
            let metrics = ServerMetrics::load(&path);
            let mut s1 = metrics.start_session(1000, "inst1-s1".into());
            s1.record_message(Duration::from_millis(10), true);
            s1.record_pipe(100);
            s1.finish("done".into());

            let mut s2 = metrics.start_session(1001, "inst1-s2".into());
            s2.record_message(Duration::from_millis(20), true);
            s2.finish("done".into());

            metrics.save(&path);
            metrics.build_overview(&overview_path);
        }

        {
            let metrics = ServerMetrics::load(&path);
            let snap = metrics.snapshot();
            assert_eq!(snap.sessions.len(), 2);
            assert_eq!(snap.total_connections, 2);

            let mut s3 = metrics.start_session(1002, "inst2-s1".into());
            s3.record_message(Duration::from_millis(5), true);
            s3.record_pipe(200);
            s3.record_pipe(300);
            s3.finish("done".into());

            metrics.save(&path);
            metrics.build_overview(&overview_path);
        }

        let metrics = ServerMetrics::load(&path);
        let snap = metrics.snapshot();
        assert_eq!(snap.sessions.len(), 3);
        assert_eq!(snap.total_connections, 3);
        assert_eq!(snap.total_messages, 3);
        assert_eq!(snap.total_messages_ok, 3);
        assert_eq!(snap.total_pipes, 3);
        assert_eq!(snap.total_pipe_bytes, 600);

        let overview_json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: Overview = serde_json::from_str(&overview_json).unwrap();
        assert_eq!(overview.total_sessions, 3);
        assert_eq!(overview.sessions[0].description, "inst1-s1");
        assert_eq!(overview.sessions[1].description, "inst1-s2");
        assert_eq!(overview.sessions[2].description, "inst2-s1");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&overview_path);
    }

    #[test]
    fn test_accept_errors_and_versions() {
        let path = tmp_path("accept_errors.json");
        let overview_path = tmp_path("accept_errors_overview.json");

        let metrics = ServerMetrics::load(&path);

        // Simulate 5 accept errors
        for _ in 0..5 {
            metrics.record_accept_error();
        }

        // Simulate connection versions
        metrics.record_connection_version("2.0");
        metrics.record_connection_version("2.0");
        metrics.record_connection_version("1.0");

        // A normal session with pipe denials and send errors
        let mut s1 = metrics.start_session(1000, "normal".into());
        s1.record_message(Duration::from_millis(1), true);
        s1.record_pipe_denial();
        s1.record_send_error();
        s1.record_send_error();
        s1.finish("done".into());

        metrics.save(&path);
        let metrics2 = ServerMetrics::load(&path);
        let snap = metrics2.snapshot();
        assert_eq!(snap.total_accept_errors, 5);
        assert_eq!(snap.connection_versions["2.0"], 2);
        assert_eq!(snap.connection_versions["1.0"], 1);
        assert_eq!(snap.total_pipe_denials, 1);
        assert_eq!(snap.total_send_errors, 2);
        assert_eq!(snap.sessions.len(), 1);
        assert_eq!(snap.sessions[0].pipe_denials, 1);
        assert_eq!(snap.sessions[0].send_errors, 2);

        metrics2.build_overview(&overview_path);
        let overview_json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: Overview = serde_json::from_str(&overview_json).unwrap();
        assert_eq!(overview.aggregate.total_accept_errors, 5);
        assert_eq!(overview.aggregate.total_pipe_denials, 1);
        assert_eq!(overview.aggregate.total_send_errors, 2);
        assert_eq!(overview.connection_versions["2.0"], 2);
        assert_eq!(overview.connection_versions["1.0"], 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&overview_path);
    }
}
