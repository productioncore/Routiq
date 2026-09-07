//! Config sync agent (hybrid delivery: snapshot → SSE → reconcile).
//!
//! Lifecycle:
//!   1. Fetch `GET /config` snapshot → validate → atomic write → activate.
//!      (The Rust worker hot-swaps it via mtime watch — never restarted.)
//!   2. Open `GET /config/stream` (SSE) with `Last-Event-ID`; on
//!      `config_changed`/`config_stale`, re-fetch the snapshot (metadata-only
//!      events — full state transfer, no delta-merge risk).
//!   3. Reconcile every `CONFIG_RECONCILE_SECS` via `GET /config/version`
//!      (ETag) independently of the stream.
//!   4. Serve traffic on last-known-good config through any CP outage;
//!      reconnect with backoff + jitter (no reconnect storms).

mod metrics;
mod sse;

use sse::{decide_revision, drain_frames, RevisionDecision};
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread};

/// True when the polled version differs and is non-empty.
pub fn should_update_config(current_version: &str, new_version: &str) -> bool {
    !new_version.is_empty() && new_version != current_version
}

/// Write `data` to `temp_path` then rename onto `target_path` (atomic on POSIX).
pub fn write_config_atomically(
    temp_path: &Path,
    target_path: &Path,
    data: &[u8],
) -> Result<(), String> {
    fs::write(temp_path, data).map_err(|e| format!("write {:?}: {e}", temp_path))?;
    fs::rename(temp_path, target_path)
        .map_err(|e| format!("rename {:?} -> {:?}: {e}", temp_path, target_path))
}

/// Backoff after consecutive failures: base, doubling per failure, capped.
/// A fixed short retry during an outage/throttle keeps the failure permanent
/// (and log-spammy) — back off instead, reset on success.
pub fn backoff_secs(consecutive_failures: u32, base_secs: u64, cap_secs: u64) -> u64 {
    if consecutive_failures == 0 {
        return base_secs;
    }
    let shift = consecutive_failures.min(6);
    base_secs.saturating_mul(1u64 << shift).min(cap_secs)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate a snapshot body before activation. Never replace a valid config
/// with an invalid one — callers keep the current file on `Err`.
/// Returns (revision, version). Revision 0 = server predates revisions.
pub fn validate_snapshot(
    json: &serde_json::Value,
) -> Result<(u64, String), String> {
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if version.is_empty() {
        return Err("snapshot missing version".to_string());
    }
    match json.get("routes").and_then(|r| r.as_array()) {
        Some(routes) if !routes.is_empty() => {}
        _ => return Err("snapshot has no routes".to_string()),
    }
    match json.get("services").and_then(|s| s.as_object()) {
        Some(services) if !services.is_empty() => {}
        _ => return Err("snapshot has no services".to_string()),
    }
    let revision = json.get("revision").and_then(|r| r.as_u64()).unwrap_or(0);
    Ok((revision, version.to_string()))
}

#[derive(Debug, Default, Clone)]
struct SyncState {
    current_revision: u64,
    last_version: String,
}

#[derive(Clone)]
struct AgentConfig {
    base_url: String,
    target_path: PathBuf,
    temp_path: PathBuf,
    token: Option<String>,
    edge_id: String,
    reconcile_secs: u64,
}

fn snapshot_client() -> ureq::Agent {
    ureq::builder()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30))
        .build()
}

fn stream_client() -> ureq::Agent {
    ureq::builder()
        .timeout_connect(Duration::from_secs(15))
        // Heartbeats arrive every ~25s; 70s without a byte = dead stream.
        .timeout_read(Duration::from_secs(70))
        .build()
}

/// Fetch + validate + atomically activate the snapshot.
/// Returns the applied (revision, version) on change, or Ok(None) when the
/// snapshot matches what is already active.
fn fetch_and_apply(
    agent: &ureq::Agent,
    cfg: &AgentConfig,
    state: &Arc<Mutex<SyncState>>,
    reason: &str,
) -> Result<Option<(u64, String)>, String> {
    metrics::inc_polls();
    let mut req = agent.get(&format!("{}/config", cfg.base_url));
    if let Some(ref token) = cfg.token {
        req = req.set("X-Config-Read-Token", token);
    }
    let response = req.call().map_err(|e| match e {
        // Diagnostic: capture WHO emits throttling (Render page? proxy?
        // app?). Body snippet names the emitter; never log the token.
        ureq::Error::Status(429, resp) => {
            let body = resp.into_string().unwrap_or_default();
            let snippet: String = body.chars().take(300).collect();
            format!("snapshot fetch throttled (429) body={snippet:?}")
        }
        other => format!("snapshot fetch failed: {other}"),
    })?;
    let json: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("snapshot is not JSON: {e}"))?;
    let (revision, version) =
        validate_snapshot(&json).map_err(|e| {
            metrics::inc_validation_failures();
            format!("snapshot rejected ({reason}): {e}")
        })?;

    let mut st = state.lock().map_err(|_| "sync state lock poisoned".to_string())?;
    let up_to_date = if st.current_revision == 0 && st.last_version.is_empty() {
        false // nothing active yet — first activation
    } else if revision == 0 {
        version == st.last_version // pre-revision server: compare versions
    } else {
        revision <= st.current_revision // stale or duplicate
    };
    if up_to_date {
        metrics::set_cp_revision(revision);
        return Ok(None);
    }

    let data = serde_json::to_string(&json).map_err(|e| format!("serialize: {e}"))?;
    write_config_atomically(&cfg.temp_path, &cfg.target_path, data.as_bytes())?;
    st.current_revision = revision;
    st.last_version = version.clone();
    drop(st);

    metrics::inc_updates();
    metrics::set_current_revision(revision);
    metrics::set_cp_revision(revision);
    metrics::set_last_sync_unix(now_unix());
    println!("Config activated: revision={revision} version={version} ({reason})");
    Ok(Some((revision, version)))
}

/// Reconciliation: cheap version check, snapshot fetch only on drift.
fn reconcile(agent: &ureq::Agent, cfg: &AgentConfig, state: &Arc<Mutex<SyncState>>) {
    metrics::inc_reconciles();
    let current = state
        .lock()
        .map(|s| s.current_revision)
        .unwrap_or(0);
    let mut req = agent.get(&format!("{}/config/version", cfg.base_url));
    if current > 0 {
        req = req.set("If-None-Match", &format!("W/\"rev-{current}\""));
    }
    if let Some(ref token) = cfg.token {
        req = req.set("X-Config-Read-Token", token);
    }
    let response = match req.call() {
        // ureq surfaces empty-body 304s as Ok — check status either way.
        Ok(r) if r.status() == 304 => return, // in sync — nothing to do
        Ok(r) => r,
        Err(ureq::Error::Status(304, _)) => return, // in sync — nothing to do
        Err(e) => {
            eprintln!("Reconcile failed: {e}");
            metrics::inc_errors();
            return;
        }
    };
    let info: serde_json::Value = match response.into_json() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Reconcile: bad version body: {e}");
            metrics::inc_errors();
            return;
        }
    };
    let rev = info.get("revision").and_then(|r| r.as_u64()).unwrap_or(0);
    metrics::set_cp_revision(rev);
    if rev != current {
        metrics::inc_reconcile_drifts();
        println!("Reconcile drift: local={current} control-plane={rev} — fetching snapshot");
        if let Err(e) = fetch_and_apply(agent, cfg, state, "reconcile") {
            eprintln!("Reconcile fetch failed: {e}");
            metrics::inc_errors();
        }
    }
}

/// Long-lived SSE stream. Returns when the stream ends so the caller can
/// reconnect with backoff. Ok(successes) counts applied updates this session.
fn run_stream(
    agent: &ureq::Agent,
    cfg: &AgentConfig,
    state: &Arc<Mutex<SyncState>>,
) -> Result<u64, String> {
    let current = state.lock().map(|s| s.current_revision).unwrap_or(0);
    let url = format!("{}/config/stream?edge_id={}", cfg.base_url, cfg.edge_id);
    let mut req = agent
        .get(&url)
        .set("Accept", "text/event-stream")
        .set("Last-Event-ID", &current.to_string());
    if let Some(ref token) = cfg.token {
        req = req.set("X-Config-Read-Token", token);
    }
    let response = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(401, _)) => {
            return Err("stream rejected (401) — check CONFIG_READ_TOKEN".to_string());
        }
        Err(ureq::Error::Status(429, _)) => {
            return Err("stream throttled (429) — backing off".to_string());
        }
        Err(e) => return Err(format!("stream connect failed: {e}")),
    };
    if response.status() != 200 {
        return Err(format!("stream bad status: {}", response.status()));
    }

    metrics::set_sse_connected(true);
    println!("SSE connected (last_id={current})");
    let mut applied: u64 = 0;
    let mut buf = String::new();
    let mut reader = std::io::BufReader::new(response.into_reader());
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                println!("SSE closed by server — reconnecting");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("SSE read failed ({e}) — reconnecting");
                break;
            }
        }
        buf.push_str(&line);
        // Bound memory if a sender never terminates a frame.
        if buf.len() > 256 * 1024 {
            buf.clear();
        }
        for ev in drain_frames(&mut buf) {
            match ev.event.as_str() {
                "heartbeat" => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&ev.data) {
                        if let Some(r) = v.get("latestRevision").and_then(|r| r.as_u64()) {
                            metrics::set_cp_revision(r);
                        }
                    }
                }
                "config_stale" => {
                    println!("SSE signalled stale ({}), fetching snapshot", ev.data);
                    match fetch_and_apply(agent, cfg, state, "sse-stale") {
                        Ok(Some(_)) => applied += 1,
                        Ok(None) => {}
                        Err(e) => {
                            eprintln!("{e}");
                            metrics::inc_errors();
                        }
                    }
                }
                "config_changed" => {
                    let rev = ev
                        .id
                        .or_else(|| {
                            serde_json::from_str::<serde_json::Value>(&ev.data)
                                .ok()
                                .and_then(|v| v.get("revision").and_then(|r| r.as_u64()))
                        })
                        .unwrap_or(0);
                    let current = state.lock().map(|s| s.current_revision).unwrap_or(0);
                    metrics::set_cp_revision(rev.max(current));
                    match decide_revision(current, rev) {
                        RevisionDecision::Ignore => {
                            println!("SSE ignoring stale/duplicate revision {rev} (current {current})");
                        }
                        RevisionDecision::Fetch => {
                            println!("SSE change at revision {rev} (current {current}) — fetching snapshot");
                            match fetch_and_apply(agent, cfg, state, "sse-event") {
                                Ok(Some(_)) => applied += 1,
                                Ok(None) => {}
                                Err(e) => {
                                    eprintln!("{e}");
                                    metrics::inc_errors();
                                }
                            }
                        }
                    }
                }
                other => {
                    println!("SSE ignoring unknown event type: {other}");
                }
            }
        }
    }
    metrics::set_sse_connected(false);
    Ok(applied)
}

fn sanitize_edge_id(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect();
    let clean = clean.trim_matches(|c| c == '.' || c == '-').to_string();
    if clean.is_empty() {
        "edge-local".to_string()
    } else {
        clean.chars().take(64).collect()
    }
}

fn main() {
    println!("Starting Config Sync Agent (snapshot → SSE → reconcile)...");

    let base_url = std::env::var("CONTROL_PLANE_URL")
        .unwrap_or_else(|_| "http://control-plane:8081".to_string())
        .trim_end_matches('/')
        .to_string();

    // Must match the gateway's GATEWAY_CONFIG_PATH so the data plane sees writes.
    let target_path = match std::env::var("GATEWAY_CONFIG_PATH") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => std::env::temp_dir().join("gateway_config.json"),
    };
    // Atomic replace: write a sibling temp file, then rename onto the target.
    let temp_path = target_path.with_extension("json.tmp");

    let reconcile_secs: u64 = std::env::var("CONFIG_RECONCILE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 30)
        .unwrap_or(300);

    // METRICS_PORT=0 disables the scrape server (use on Render — avoids port 9092
    // being auto-detected as the web service port before OpenResty binds 8080).
    let metrics_port: u16 = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9092);
    if metrics_port > 0 {
        let bind = std::env::var("METRICS_BIND").unwrap_or_else(|_| "0.0.0.0".to_string());
        metrics::spawn_metrics_server(&bind, metrics_port);
    }

    let token = std::env::var("CONFIG_READ_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());

    let edge_id = sanitize_edge_id(
        &std::env::var("EDGE_ID").unwrap_or_else(|_| "edge-local".to_string()),
    );

    println!(
        "Sync agent: base={base_url} target={} edge={edge_id} reconcile_every={reconcile_secs}s read-token={}",
        target_path.display(),
        if token.is_some() { "configured" } else { "MISSING (reads will 401)" },
    );

    let cfg = AgentConfig {
        base_url,
        target_path,
        temp_path,
        token,
        edge_id,
        reconcile_secs,
    };
    let state = Arc::new(Mutex::new(SyncState::default()));
    let fetch_agent = snapshot_client();

    // Phase 1 — initial snapshot. The start script waits on the target file;
    // keep retrying with backoff until the first activation lands.
    let mut failures: u32 = 0;
    loop {
        match fetch_and_apply(&fetch_agent, &cfg, &state, "initial-snapshot") {
            Ok(_) => break,
            Err(e) => {
                failures += 1;
                eprintln!("Initial snapshot failed ({e}) — retrying");
                metrics::inc_errors();
                thread::sleep(Duration::from_secs(backoff_secs(failures, 5, 120)));
            }
        }
    }

    // Phase 3 — periodic reconciliation runs independently of the stream.
    {
        let cfg = cfg.clone();
        let state = state.clone();
        thread::spawn(move || {
            let agent = snapshot_client();
            loop {
                thread::sleep(Duration::from_secs(cfg.reconcile_secs));
                reconcile(&agent, &cfg, &state);
            }
        });
    }

    // Phase 2 — SSE change stream with reconnect. Failures back off with
    // jitter so fleet reconnects never stampede the control plane.
    let stream_agent = stream_client();
    let mut stream_failures: u32 = 0;
    loop {
        match run_stream(&stream_agent, &cfg, &state) {
            Ok(n) => {
                stream_failures = 0;
                if n > 0 {
                    println!("SSE session applied {n} update(s)");
                }
            }
            Err(e) => {
                stream_failures += 1;
                eprintln!("SSE error ({e}) — reconnect #{stream_failures}");
                metrics::inc_errors();
            }
        }
        metrics::inc_reconnects();
        let wait = backoff_secs(stream_failures, 5, 300) + u64::from(stream_failures % 7);
        thread::sleep(Duration::from_secs(wait));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_update_when_version_changes() {
        assert!(should_update_config("v1", "v2"));
        assert!(!should_update_config("v2", "v2"));
        assert!(!should_update_config("v1", ""));
    }

    #[test]
    fn atomic_write_replaces_target() {
        let dir = std::env::temp_dir().join("config_sidecar_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.json");
        let temp = dir.join("config.json.tmp");
        write_config_atomically(&temp, &target, br#"{"version":"v1"}"#).unwrap();
        let contents = fs::read_to_string(&target).unwrap();
        assert!(contents.contains("v1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_leaves_no_partial_target_on_bad_rename() {
        let dir = std::env::temp_dir().join("config_sidecar_test2");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("config.json");
        let temp = dir.join("config.json.tmp");
        // Target is a directory — rename should fail.
        fs::create_dir(&target).unwrap();
        assert!(write_config_atomically(&temp, &target, b"x").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backoff_starts_at_base_then_doubles_and_caps() {
        assert_eq!(backoff_secs(0, 5, 300), 5);
        assert_eq!(backoff_secs(1, 5, 300), 10);
        assert_eq!(backoff_secs(2, 5, 300), 20);
        assert_eq!(backoff_secs(3, 5, 300), 40);
        assert_eq!(backoff_secs(10, 5, 300), 300);
        assert_eq!(backoff_secs(10, 5, 30), 30);
    }

    #[test]
    fn validate_snapshot_accepts_good_body() {
        let v: serde_json::Value = serde_json::json!({
            "version": "v1.0.4",
            "revision": 106,
            "routes": [{ "path_prefix": "/", "service_name": "s" }],
            "services": { "s": {} },
        });
        assert_eq!(
            validate_snapshot(&v).unwrap(),
            (106, "v1.0.4".to_string())
        );
    }

    #[test]
    fn validate_snapshot_rejects_bad_bodies() {
        assert!(validate_snapshot(&serde_json::json!({})).is_err()); // no version
        assert!(validate_snapshot(&serde_json::json!({
            "version": "v1", "routes": [], "services": {"s": {}},
        }))
        .is_err()); // empty routes
        assert!(validate_snapshot(&serde_json::json!({
            "version": "v1",
            "routes": [{ "path_prefix": "/" }],
            "services": {},
        }))
        .is_err()); // empty services
    }

    #[test]
    fn validate_snapshot_defaults_revision_to_zero() {
        let v: serde_json::Value = serde_json::json!({
            "version": "v1",
            "routes": [{ "path_prefix": "/" }],
            "services": { "s": {} },
        });
        assert_eq!(validate_snapshot(&v).unwrap().0, 0);
    }

    #[test]
    fn sanitize_edge_id_strips_unsafe_chars() {
        assert_eq!(sanitize_edge_id("edge-1_2.x"), "edge-1_2.x");
        assert_eq!(sanitize_edge_id("a/b?c=d&e"), "abcde");
        assert_eq!(sanitize_edge_id(""), "edge-local");
        assert_eq!(sanitize_edge_id("..."), "edge-local");
    }
}
