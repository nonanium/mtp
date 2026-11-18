//! Bounded, process-wide usage aggregates. Never pass payloads or runtime identifiers here.
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Mutex, OnceLock},
};
use web_time::Instant;

pub const MAX_BYTES: usize = 1536 * 1024;
pub const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
static SAMPLER: OnceLock<fn()> = OnceLock::new();
pub fn set_sampler(sampler: fn()) {
    let _ = SAMPLER.set(sampler);
}

const MAX_METRICS: usize = 512;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Aggregate {
    pub count: u64,
    pub total: u64,
    pub max: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Bucket {
    pub timestamp_unix_ms: u64,
    pub process_started_unix_ms: u64,
    pub elapsed_ms: u64,
    pub metrics: BTreeMap<String, Aggregate>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub timestamp_unix_ms: u64,
    pub process_started_unix_ms: u64,
    pub elapsed_ms: u64,
    pub sequence: u64,
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u8,
    pub enabled: bool,
    pub mtp_version: String,
    #[serde(default)]
    pub storage_available: bool,
    pub buckets: VecDeque<Bucket>,
    #[serde(default)]
    pub events: VecDeque<RuntimeEvent>,
}

struct Collector {
    snapshot: Snapshot,
    started: Instant,
    started_unix_ms: u64,
    last_checkpoint: Instant,
    sequence: u64,
    #[cfg(not(target_arch = "wasm32"))]
    persisted_hash: Option<u64>,
    #[cfg(not(target_arch = "wasm32"))]
    path: Option<std::path::PathBuf>,
}

fn collector() -> &'static Mutex<Collector> {
    static COLLECTOR: OnceLock<Mutex<Collector>> = OnceLock::new();
    COLLECTOR.get_or_init(|| {
        Mutex::new(Collector {
            snapshot: Snapshot {
                schema_version: 1,
                enabled: true,
                mtp_version: env!("CARGO_PKG_VERSION").into(),
                storage_available: false,
                buckets: VecDeque::new(),
                events: VecDeque::new(),
            },
            started: Instant::now(),
            last_checkpoint: Instant::now(),
            sequence: 0,
            #[cfg(not(target_arch = "wasm32"))]
            persisted_hash: None,
            started_unix_ms: crate::unix_time_millis().unwrap_or(0),
            #[cfg(not(target_arch = "wasm32"))]
            path: None,
        })
    })
}

impl Collector {
    fn prune(&mut self) {
        let now = crate::unix_time_millis().unwrap_or(0);
        self.snapshot.buckets.retain(|bucket| {
            bucket.timestamp_unix_ms <= now
                && now.saturating_sub(bucket.timestamp_unix_ms) < RETENTION_MS
        });
        self.snapshot.events.retain(|event| {
            event.timestamp_unix_ms <= now
                && now.saturating_sub(event.timestamp_unix_ms) < RETENTION_MS
        });
        while self.snapshot.events.len() > 1024 {
            self.snapshot.events.pop_front();
        }
        while self.snapshot.buckets.len() > 1440 {
            self.snapshot.buckets.pop_front();
        }
        while serde_json::to_vec(&self.snapshot).map_or(usize::MAX, |bytes| bytes.len()) > MAX_BYTES
        {
            if self.snapshot.buckets.pop_front().is_none()
                && self.snapshot.events.pop_front().is_none()
            {
                break;
            }
        }
    }

    fn persist(&mut self) {
        self.prune();
        self.last_checkpoint = Instant::now();
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(path) = &self.path {
            use std::hash::{Hash, Hasher};
            self.snapshot.storage_available = true;
            let Ok(bytes) = serde_json::to_vec(&self.snapshot) else {
                return;
            };
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut hasher);
            let hash = hasher.finish();
            if self.persisted_hash == Some(hash) {
                return;
            }
            let temporary = path.with_extension("tmp");
            self.snapshot.storage_available = std::fs::write(&temporary, bytes)
                .and_then(|_| std::fs::rename(&temporary, path))
                .is_ok();
            if self.snapshot.storage_available {
                self.persisted_hash = Some(hash);
            }
        }
    }
}

// Names must come from source-controlled protocol enums or literal operation names.
pub fn record(name: &'static str, value: u64) {
    record_key(name, value);
}

pub fn frame(direction: &'static str, kind: &'static str, bytes: usize) {
    record_key(&format!("frame.{direction}.{kind}.bytes"), bytes as u64);
}

fn record_key(name: &str, value: u64) {
    let Ok(mut state) = collector().lock() else {
        return;
    };
    if !state.snapshot.enabled {
        if state.last_checkpoint.elapsed().as_secs() >= 60 {
            state.persist();
        }
        return;
    }
    let elapsed_ms = state.started.elapsed().as_millis() as u64;
    let minute = elapsed_ms / 60_000;
    let fresh = state.snapshot.buckets.back().is_none_or(|bucket| {
        bucket.process_started_unix_ms != state.started_unix_ms
            || bucket.elapsed_ms / 60_000 != minute
    });
    if fresh {
        // Checkpoint completed minutes on existing activity, without another wakeup timer.
        state.persist();
        let bucket = Bucket {
            timestamp_unix_ms: crate::unix_time_millis().unwrap_or(0),
            process_started_unix_ms: state.started_unix_ms,
            elapsed_ms,
            metrics: BTreeMap::new(),
        };
        state.snapshot.buckets.push_back(bucket);
    }
    let bucket = state
        .snapshot
        .buckets
        .back_mut()
        .expect("diagnostic bucket exists");
    if bucket.metrics.len() >= MAX_METRICS && !bucket.metrics.contains_key(name) {
        return;
    }
    let metric = bucket.metrics.entry(name.into()).or_default();
    metric.count = metric.count.saturating_add(1);
    metric.total = metric.total.saturating_add(value);
    metric.max = metric.max.max(value);
    drop(state);
    if fresh && let Some(sample) = SAMPLER.get() {
        sample();
    }
}

pub fn snapshot() -> Snapshot {
    let mut state = collector()
        .lock()
        .expect("diagnostic collector unavailable");
    state.persist();
    state.snapshot.clone()
}

pub fn set_enabled(enabled: bool) {
    let mut state = collector()
        .lock()
        .expect("diagnostic collector unavailable");
    state.snapshot.enabled = enabled;
    state.persist();
}

pub fn clear() {
    let mut state = collector()
        .lock()
        .expect("diagnostic collector unavailable");
    state.snapshot.buckets.clear();
    state.snapshot.events.clear();
    state.persist();
}

pub fn restore(json: &str) -> bool {
    if json.len() > MAX_BYTES {
        return false;
    }
    let Ok(snapshot) = serde_json::from_str::<Snapshot>(json) else {
        return false;
    };
    if snapshot.schema_version != 1
        || snapshot.buckets.len() > 1440
        || snapshot.events.len() > 1024
        || snapshot
            .events
            .iter()
            .any(|event| runtime_event_name(&event.name).is_none())
        || snapshot.buckets.iter().any(|bucket| {
            bucket.metrics.len() > MAX_METRICS
                || bucket.metrics.keys().any(|key| {
                    key.len() > 100
                        || !key.bytes().all(|c| {
                            c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-'
                        })
                })
        })
    {
        return false;
    }
    let mut state = collector()
        .lock()
        .expect("diagnostic collector unavailable");
    state.snapshot.enabled = snapshot.enabled;
    state.snapshot.buckets = snapshot.buckets;
    state.snapshot.events = snapshot.events;
    state.prune();
    true
}

#[cfg(not(target_arch = "wasm32"))]
pub fn configure(path: std::path::PathBuf) {
    if let Ok(metadata) = std::fs::metadata(&path)
        && metadata.len() <= MAX_BYTES as u64
        && let Ok(json) = std::fs::read_to_string(&path)
    {
        restore(&json);
    }
    let mut state = collector()
        .lock()
        .expect("diagnostic collector unavailable");
    state.path = Some(path);
    state.persist();
}

pub fn connection_failure(code: &str, phase: Option<&str>) {
    let code = match code {
        "timeout" => "connection.failure.timeout",
        "certificate" => "connection.failure.certificate",
        "authentication-failed" => "connection.failure.authentication",
        "connection-lost" => "connection.failure.lost",
        "transport" => "connection.failure.transport",
        _ => "connection.failure.other",
    };
    record(code, 1);
    if let Some(phase) = phase {
        let phase = match phase {
            "connect" => "error.phase.connect",
            "handshake" => "error.phase.handshake",
            "wait-response" => "error.phase.wait-response",
            _ => "error.phase.other",
        };
        record(phase, 1);
    }
}

pub fn error(context: &'static str, error: &crate::CommunicationError) {
    record_key(&format!("{context}.{}", error.code().as_str()), 1);
    if let Some(phase) = error.phase() {
        record_key(&format!("error.phase.{}", phase.as_str()), 1);
    }
}

fn runtime_event_name(event: &str) -> Option<&'static str> {
    Some(match event {
        "foreground" => "runtime.foreground",
        "background" => "runtime.background",
        "online" => "runtime.online",
        "offline" => "runtime.offline",
        "memory_bytes" => "runtime.js_heap_bytes",
        "app_memory_bytes" => "runtime.app_memory_bytes",
        "app_cpu_total_ms" => "runtime.app_cpu_total_ms",
        "long_task_ms" => "runtime.long_task_ms",
        "sync_duration_ms" => "sync.duration_ms",
        "sync_start" => "sync.start",
        "sync_success" => "sync.success",
        "sync_failure" => "sync.failure",
        "connection_start" => "renderer.connection_start",
        "connection_success" => "renderer.connection_success",
        "connection_failure" => "renderer.connection_failure",
        "startup_shown" => "startup_shown",
        "onboarding_shown" => "onboarding_shown",
        "app_shown" => "app_shown",
        "startup_duration_ms" => "startup_duration_ms",
        "onboarding_duration_ms" => "onboarding_duration_ms",
        "app_duration_ms" => "app_duration_ms",
        "startup_connection_ready" => "startup_connection_ready",
        "startup_session_established" => "startup_session_established",
        "startup_settings_loaded" => "startup_settings_loaded",
        "startup_flags_loaded" => "startup_flags_loaded",
        "onboarding_finish_start" => "onboarding_finish_start",
        "onboarding_finish_success" => "onboarding_finish_success",
        "onboarding_finish_failure" => "onboarding_finish_failure",
        "diagnostics_shown" => "diagnostics_shown",
        "diagnostics_export_start" => "diagnostics_export_start",
        "diagnostics_export_success" => "diagnostics_export_success",
        "diagnostics_export_cancel" => "diagnostics_export_cancel",
        "diagnostics_export_failure" => "diagnostics_export_failure",
        _ => return None,
    })
}

pub fn runtime_event(event: &str, value: u64) {
    let Some(name) = runtime_event_name(event) else {
        return;
    };
    record(name, value);
    // Keep a bounded timeline for lifecycle changes, not high-frequency resource samples.
    if name.ends_with("_ms") || name.ends_with("_bytes") {
        return;
    }
    let Ok(mut state) = collector().lock() else {
        return;
    };
    if !state.snapshot.enabled {
        return;
    }
    state.sequence = state.sequence.saturating_add(1);
    let event = RuntimeEvent {
        timestamp_unix_ms: crate::unix_time_millis().unwrap_or(0),
        process_started_unix_ms: state.started_unix_ms,
        elapsed_ms: state.started.elapsed().as_millis() as u64,
        sequence: state.sequence,
        name: event.into(),
        value,
    };
    state.snapshot.events.push_back(event);
    if state.snapshot.events.len() > 1024 {
        state.snapshot.events.pop_front();
    }
}

pub struct DurationGuard {
    name: &'static str,
    started: Instant,
}
impl DurationGuard {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            started: Instant::now(),
        }
    }
}
impl Drop for DurationGuard {
    fn drop(&mut self) {
        record(
            self.name,
            self.started.elapsed().as_micros().min(u64::MAX as u128) as u64,
        );
    }
}
