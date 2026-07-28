use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
pub struct PipeResult {
    pub size: usize,
    pub iteration: usize,
    pub total_ms: f64,
    pub data_only_ms: f64,
    pub bytes_matched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientSessionRecord {
    pub session_id: String,
    pub timestamp: u64,
    pub auth_method: String,
    pub auth_duration_ms: f64,
    pub error: Option<String>,
    pub message_roundtrip_ms: f64,
    pub pipe_results: Vec<PipeResult>,
    pub total_pipe_bytes: u64,
    pub overall_pipe_avg_total_ms: f64,
    pub overall_pipe_avg_data_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientAggregateStats {
    pub total_sessions: u64,
    pub auth_failures: u64,
    pub avg_auth_duration_ms: f64,
    pub avg_message_roundtrip_ms: f64,
    pub avg_pipe_total_ms: f64,
    pub avg_pipe_data_ms: f64,
    pub total_pipe_bytes: u64,
    pub avg_pipe_throughput_mbps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientOverview {
    pub total_sessions: u64,
    pub aggregate: ClientAggregateStats,
    pub sessions: Vec<ClientSessionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientMetricsFile {
    pub sessions: Vec<ClientSessionRecord>,
}

// ---------------------------------------------------------------------------
// Live metrics state
// ---------------------------------------------------------------------------

pub struct ClientMetrics {
    sessions: Vec<ClientSessionRecord>,
}

impl ClientMetrics {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    pub fn load(path: &str) -> Self {
        let file = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str::<ClientMetricsFile>(&s).ok());

        Self {
            sessions: file.map(|f| f.sessions).unwrap_or_default(),
        }
    }

    pub fn save(&self, path: &str) {
        let data = ClientMetricsFile {
            sessions: self.sessions.clone(),
        };
        if let Some(parent) = Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&data).unwrap_or_default();
        let _ = std::fs::write(path, json);
    }

    pub fn record_session(&mut self, record: ClientSessionRecord) {
        self.sessions.push(record);
    }

    pub fn build_overview(&self, overview_path: &str) {
        let total = self.sessions.len() as u64;

        if total == 0 {
            let overview = ClientOverview {
                total_sessions: 0,
                aggregate: ClientAggregateStats::default(),
                sessions: Vec::new(),
            };
            if let Some(parent) = Path::new(overview_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let json = serde_json::to_string_pretty(&overview).unwrap_or_default();
            let _ = std::fs::write(overview_path, json);
            return;
        }

        let mut auth_sum: f64 = 0.0;
        let mut msg_sum: f64 = 0.0;
        let mut pipe_total_sum: f64 = 0.0;
        let mut pipe_data_sum: f64 = 0.0;
        let mut total_pipe_bytes: u64 = 0;
        let mut total_pipe_duration_secs: f64 = 0.0;
        let mut auth_failures: u64 = 0;
        let mut success_count: u64 = 0;

        for s in &self.sessions {
            if s.error.is_some() {
                auth_failures += 1;
            } else {
                success_count += 1;
                auth_sum += s.auth_duration_ms;
                msg_sum += s.message_roundtrip_ms;
                pipe_total_sum += s.overall_pipe_avg_total_ms;
                pipe_data_sum += s.overall_pipe_avg_data_ms;
                total_pipe_bytes += s.total_pipe_bytes;
                for pr in &s.pipe_results {
                    total_pipe_duration_secs += pr.total_ms / 1000.0;
                }
            }
        }

        let divisor = if success_count > 0 { success_count } else { 1 };

        let aggregate = ClientAggregateStats {
            total_sessions: total,
            auth_failures,
            avg_auth_duration_ms: auth_sum / divisor as f64,
            avg_message_roundtrip_ms: msg_sum / divisor as f64,
            avg_pipe_total_ms: pipe_total_sum / divisor as f64,
            avg_pipe_data_ms: pipe_data_sum / divisor as f64,
            total_pipe_bytes,
            avg_pipe_throughput_mbps: if total_pipe_duration_secs > 0.0 {
                (total_pipe_bytes as f64 / 1_048_576.0) / total_pipe_duration_secs
            } else {
                0.0
            },
        };

        let overview = ClientOverview {
            total_sessions: total,
            aggregate,
            sessions: self.sessions.clone(),
        };

        if let Some(parent) = Path::new(overview_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&overview).unwrap_or_default();
        let _ = std::fs::write(overview_path, json);
    }
}

// ---------------------------------------------------------------------------
// Builder for constructing a session record piece by piece
// ---------------------------------------------------------------------------

pub struct SessionBuilder {
    session_id: String,
    timestamp: u64,
    auth_method: String,
    auth_duration_ms: f64,
    error: Option<String>,
    message_roundtrip_ms: f64,
    pipe_results: Vec<PipeResult>,
}

impl SessionBuilder {
    pub fn new(auth_method: &str, auth_duration: Duration) -> Self {
        Self {
            session_id: generate_session_id(),
            timestamp: now_epoch_secs(),
            auth_method: auth_method.to_string(),
            auth_duration_ms: auth_duration.as_secs_f64() * 1000.0,
            error: None,
            message_roundtrip_ms: 0.0,
            pipe_results: Vec::new(),
        }
    }

    pub fn set_error(&mut self, error: String) {
        self.error = Some(error);
    }

    pub fn set_message_roundtrip(&mut self, duration: Duration) {
        self.message_roundtrip_ms = duration.as_secs_f64() * 1000.0;
    }

    pub fn add_pipe_result(&mut self, result: PipeResult) {
        self.pipe_results.push(result);
    }

    pub fn build(self) -> ClientSessionRecord {
        let total_pipe_bytes: u64 = self
            .pipe_results
            .iter()
            .map(|r| r.size as u64)
            .sum();

        let overall_pipe_avg_total_ms = if self.pipe_results.is_empty() {
            0.0
        } else {
            self.pipe_results.iter().map(|r| r.total_ms).sum::<f64>()
                / self.pipe_results.len() as f64
        };

        let overall_pipe_avg_data_ms = if self.pipe_results.is_empty() {
            0.0
        } else {
            self.pipe_results.iter().map(|r| r.data_only_ms).sum::<f64>()
                / self.pipe_results.len() as f64
        };

        ClientSessionRecord {
            session_id: self.session_id,
            timestamp: self.timestamp,
            auth_method: self.auth_method,
            auth_duration_ms: self.auth_duration_ms,
            error: self.error,
            message_roundtrip_ms: self.message_roundtrip_ms,
            pipe_results: self.pipe_results,
            total_pipe_bytes,
            overall_pipe_avg_total_ms,
            overall_pipe_avg_data_ms,
        }
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
        let dir = std::env::temp_dir().join("mtp_client_metrics_test");
        let _ = std::fs::create_dir_all(&dir);
        dir.join(name).to_str().unwrap().to_string()
    }

    #[test]
    fn test_pipe_result_roundtrip() {
        let pr = PipeResult {
            size: 1024,
            iteration: 0,
            total_ms: 5.5,
            data_only_ms: 3.2,
            bytes_matched: true,
        };
        let json = serde_json::to_string(&pr).unwrap();
        let decoded: PipeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(pr, decoded);
    }

    #[test]
    fn test_client_session_roundtrip() {
        let record = ClientSessionRecord {
            session_id: "test-session".into(),
            timestamp: 12345,
            auth_method: "connect".into(),
            auth_duration_ms: 42.5,
            error: None,
            message_roundtrip_ms: 10.3,
            pipe_results: vec![
                PipeResult {
                    size: 64,
                    iteration: 0,
                    total_ms: 1.0,
                    data_only_ms: 0.5,
                    bytes_matched: true,
                },
                PipeResult {
                    size: 256,
                    iteration: 0,
                    total_ms: 2.0,
                    data_only_ms: 1.0,
                    bytes_matched: true,
                },
            ],
            total_pipe_bytes: 320,
            overall_pipe_avg_total_ms: 1.5,
            overall_pipe_avg_data_ms: 0.75,
        };

        let json = serde_json::to_string(&record).unwrap();
        let decoded: ClientSessionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn test_client_metrics_load_missing() {
        let metrics = ClientMetrics::load("/nonexistent/path.json");
        assert!(metrics.sessions.is_empty());
    }

    #[test]
    fn test_multiple_client_sessions() {
        let path = tmp_path("multi_session.json");
        let mut metrics = ClientMetrics::load(&path);

        for i in 0..3 {
            let mut builder = SessionBuilder::new("connect", Duration::from_millis(10 + i));
            builder.set_message_roundtrip(Duration::from_millis(5 + i));
            builder.add_pipe_result(PipeResult {
                size: 64,
                iteration: 0,
                total_ms: 1.0 + i as f64,
                data_only_ms: 0.5 + i as f64 * 0.5,
                bytes_matched: true,
            });
            metrics.record_session(builder.build());
        }

        metrics.save(&path);

        let metrics2 = ClientMetrics::load(&path);
        assert_eq!(metrics2.sessions.len(), 3);
        assert_eq!(metrics2.sessions[0].auth_method, "connect");
        assert_eq!(metrics2.sessions[1].pipe_results[0].size, 64);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_client_overview_stats() {
        let mut metrics = ClientMetrics::new();

        for i in 0..4 {
            let mut builder = SessionBuilder::new("connect", Duration::from_millis(20));
            builder.set_message_roundtrip(Duration::from_millis(10 + i as u64));
            builder.add_pipe_result(PipeResult {
                size: 256,
                iteration: 0,
                total_ms: 2.0,
                data_only_ms: 1.0,
                bytes_matched: true,
            });
            metrics.record_session(builder.build());
        }

        let overview_path = tmp_path("client_overview.json");
        metrics.build_overview(&overview_path);

        let json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: ClientOverview = serde_json::from_str(&json).unwrap();

        assert_eq!(overview.total_sessions, 4);
        assert_eq!(overview.aggregate.avg_auth_duration_ms, 20.0);
        assert_eq!(overview.aggregate.avg_message_roundtrip_ms, 11.5);
        assert_eq!(overview.aggregate.avg_pipe_total_ms, 2.0);
        assert_eq!(overview.aggregate.avg_pipe_data_ms, 1.0);
        assert_eq!(overview.aggregate.total_pipe_bytes, 1024);
        assert!(overview.aggregate.avg_pipe_throughput_mbps > 0.0);
        assert_eq!(overview.sessions.len(), 4);

        let _ = std::fs::remove_file(&overview_path);
    }

    #[test]
    fn test_client_overview_empty() {
        let metrics = ClientMetrics::new();
        let overview_path = tmp_path("client_empty_overview.json");
        metrics.build_overview(&overview_path);

        let json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: ClientOverview = serde_json::from_str(&json).unwrap();
        assert_eq!(overview.total_sessions, 0);
        assert!(overview.sessions.is_empty());

        let _ = std::fs::remove_file(&overview_path);
    }

    #[test]
    fn test_auth_failure_recording() {
        let path = tmp_path("auth_failure.json");
        let overview_path = tmp_path("auth_failure_overview.json");

        let mut metrics = ClientMetrics::load(&path);

        // Successful session
        let mut b1 = SessionBuilder::new("connect", Duration::from_millis(42));
        b1.set_message_roundtrip(Duration::from_millis(10));
        metrics.record_session(b1.build());

        // Failed auth session
        let mut b2 = SessionBuilder::new("connect", Duration::from_millis(5000));
        b2.set_error("authentication timed out".into());
        metrics.record_session(b2.build());

        // Another successful session
        let mut b3 = SessionBuilder::new("register", Duration::from_millis(100));
        b3.set_message_roundtrip(Duration::from_millis(8));
        metrics.record_session(b3.build());

        metrics.save(&path);
        let metrics2 = ClientMetrics::load(&path);
        assert_eq!(metrics2.sessions.len(), 3);
        assert!(metrics2.sessions[0].error.is_none());
        assert_eq!(
            metrics2.sessions[1].error.as_deref(),
            Some("authentication timed out")
        );
        assert!(metrics2.sessions[2].error.is_none());

        metrics2.build_overview(&overview_path);
        let overview_json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: ClientOverview = serde_json::from_str(&overview_json).unwrap();

        assert_eq!(overview.total_sessions, 3);
        assert_eq!(overview.aggregate.auth_failures, 1);
        // Averages should only count successful sessions
        assert!((overview.aggregate.avg_auth_duration_ms - 71.0).abs() < 0.01); // (42+100)/2
        assert!((overview.aggregate.avg_message_roundtrip_ms - 9.0).abs() < 0.01); // (10+8)/2

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&overview_path);
    }

    // -----------------------------------------------------------------------
    // Integration-style tests
    // -----------------------------------------------------------------------

    fn make_pr(size: usize, iteration: usize, total_ms: f64, data_only_ms: f64) -> PipeResult {
        PipeResult {
            size,
            iteration,
            total_ms,
            data_only_ms,
            bytes_matched: true,
        }
    }

    #[test]
    fn test_full_client_lifecycle() {
        let path = tmp_path("client_lifecycle.json");
        let overview_path = tmp_path("client_lifecycle_overview.json");

        let mut metrics = ClientMetrics::load(&path);

        let mut b1 = SessionBuilder::new("connect", Duration::from_millis(42));
        b1.set_message_roundtrip(Duration::from_millis(10));
        b1.add_pipe_result(make_pr(64, 0, 1.5, 0.8));
        b1.add_pipe_result(make_pr(256, 0, 2.5, 1.2));
        metrics.record_session(b1.build());

        let mut b2 = SessionBuilder::new("register", Duration::from_millis(150));
        b2.set_message_roundtrip(Duration::from_millis(15));
        b2.add_pipe_result(make_pr(64, 0, 2.0, 1.0));
        b2.add_pipe_result(make_pr(1024, 0, 5.0, 3.0));
        metrics.record_session(b2.build());

        metrics.save(&path);
        let metrics2 = ClientMetrics::load(&path);
        assert_eq!(metrics2.sessions.len(), 2);

        let s1 = &metrics2.sessions[0];
        assert_eq!(s1.auth_method, "connect");
        assert!((s1.auth_duration_ms - 42.0).abs() < 0.01);
        assert!((s1.message_roundtrip_ms - 10.0).abs() < 0.01);
        assert_eq!(s1.pipe_results.len(), 2);
        assert_eq!(s1.total_pipe_bytes, 320);
        assert!((s1.overall_pipe_avg_total_ms - 2.0).abs() < 0.01);
        assert!((s1.overall_pipe_avg_data_ms - 1.0).abs() < 0.01);

        let s2 = &metrics2.sessions[1];
        assert_eq!(s2.auth_method, "register");
        assert_eq!(s2.pipe_results.len(), 2);
        assert_eq!(s2.total_pipe_bytes, 1088);

        metrics2.build_overview(&overview_path);
        let overview_json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: ClientOverview = serde_json::from_str(&overview_json).unwrap();
        assert_eq!(overview.total_sessions, 2);
        assert!((overview.aggregate.avg_auth_duration_ms - 96.0).abs() < 0.01);
        assert!((overview.aggregate.avg_message_roundtrip_ms - 12.5).abs() < 0.01);
        assert_eq!(overview.aggregate.total_pipe_bytes, 1408);
        assert!(overview.aggregate.avg_pipe_throughput_mbps > 0.0);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&overview_path);
    }

    #[test]
    fn test_cross_session_accumulation() {
        let path = tmp_path("client_accumulate.json");
        let overview_path = tmp_path("client_accumulate_overview.json");

        {
            let mut metrics = ClientMetrics::load(&path);
            let mut b = SessionBuilder::new("connect", Duration::from_millis(30));
            b.set_message_roundtrip(Duration::from_millis(8));
            b.add_pipe_result(make_pr(64, 0, 1.0, 0.5));
            metrics.record_session(b.build());
            metrics.save(&path);
        }

        {
            let mut metrics = ClientMetrics::load(&path);
            assert_eq!(metrics.sessions.len(), 1);
            let mut b = SessionBuilder::new("register", Duration::from_millis(200));
            b.set_message_roundtrip(Duration::from_millis(12));
            b.add_pipe_result(make_pr(1024, 0, 4.0, 2.5));
            metrics.record_session(b.build());
            metrics.save(&path);
        }

        let metrics = ClientMetrics::load(&path);
        assert_eq!(metrics.sessions.len(), 2);
        assert_eq!(metrics.sessions[0].auth_method, "connect");
        assert_eq!(metrics.sessions[1].auth_method, "register");

        metrics.build_overview(&overview_path);
        let overview_json = std::fs::read_to_string(&overview_path).unwrap();
        let overview: ClientOverview = serde_json::from_str(&overview_json).unwrap();
        assert_eq!(overview.total_sessions, 2);
        assert!((overview.aggregate.avg_auth_duration_ms - 115.0).abs() < 0.01);
        assert!((overview.aggregate.avg_message_roundtrip_ms - 10.0).abs() < 0.01);
        assert_eq!(overview.aggregate.total_pipe_bytes, 1088);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&overview_path);
    }
}
