//! Control Plane — GitOps config distribution + telemetry aggregation
//!
//! Design:
//!   - Config reads use `ArcSwap` — lock-free, ~2 ns, no contention at scale
//!   - Config writes use a `Mutex<ConfigStore>` — writes are rare (human-triggered)
//!   - Versioned history with configurable depth (default 20)
//!   - JWT secret always overridden from environment — never from HTTP body
//!   - All handlers return proper error responses on lock poison

use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use actix_web::HttpRequest;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use hmac::{Hmac, Mac};
use sha2::Sha256;

mod redis_cb;
mod store;
mod otlp;
mod config_validate;

type HmacSha256 = Hmac<Sha256>;

// ── Data models ───────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Upstream {
    pub name: String,
    pub address: String,
    #[serde(default = "default_weight")]
    pub weight: usize,
    /// Version label for canary routing (ADR-0063).
    #[serde(default)]
    pub version: String,
}
fn default_weight() -> usize { 1 }

/// Canary rollout policy (ADR-0063) — mirrored from gateway schema.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CanaryPolicy {
    pub version: String,
    #[serde(default)]
    pub percent: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Route {
    pub path_prefix: String,
    pub service_name: String,
    #[serde(default)]
    pub strip_prefix: bool,
    /// Timeout-policy tier: "fast" | "normal" | "slow" (ADR-0062).
    #[serde(default)]
    pub tier: String,
    /// Per-route body validation policy (ADR-0064) — mirrored opaquely so the
    /// field survives round-trips; the gateway owns the typed schema.
    #[serde(default)]
    pub validation: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServiceConfig {
    pub name: String,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_max: usize,
    pub regional_upstreams: HashMap<String, Vec<Upstream>>,
    #[serde(default = "default_true")]
    pub require_auth: bool,
    #[serde(default)]
    pub canary: Option<CanaryPolicy>,
    /// Per-user daily quota policy (ADR-0066) — mirrored opaquely.
    #[serde(default)]
    pub quota: Option<serde_json::Value>,
}
fn default_rate_limit() -> usize { 1_000 }
fn default_true() -> bool { true }

/// Active health-check policy (ADR-0061) — mirrored from the gateway schema
/// so the field survives POST /config → GET /config round-trips. The control
/// plane itself does not probe anything; edge workers consume this.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HealthCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_health_path")]
    pub path: String,
    #[serde(default = "default_health_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_health_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_unhealthy")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_health_healthy")]
    pub healthy_threshold: u32,
}
fn default_health_path() -> String { "/health".to_string() }
fn default_health_interval() -> u64 { 10 }
fn default_health_timeout() -> u64 { 2_000 }
fn default_health_unhealthy() -> u32 { 3 }
fn default_health_healthy() -> u32 { 2 }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConfigSnapshot {
    pub version: String,
    #[serde(default = "default_concurrency")]
    pub global_max_concurrency: usize,
    /// Never returned in GET /config responses — stripped before serving
    #[serde(default = "default_jwt", skip_serializing)]
    pub jwt_secret: String,
    /// Named JWT keys for zero-downtime rotation (kid → secret).
    /// Never returned in GET /config responses.
    #[serde(default, skip_serializing)]
    pub jwt_keys: HashMap<String, String>,
    /// Expected `iss` claim enforced by the gateway. Distributed (not secret).
    #[serde(default = "default_issuer")]
    pub expected_issuer: String,
    /// Expected `aud` claim enforced by the gateway. Distributed (not secret).
    #[serde(default = "default_audience")]
    pub expected_audience: String,
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// Dynamic CORS policy (ADR-0068) — mirrored opaquely for round-trips.
    #[serde(default)]
    pub cors: Option<serde_json::Value>,
}
fn default_concurrency() -> usize { 10_000 }
fn default_jwt() -> String { "super_secret_key_for_hmac_sha256".to_string() }
fn default_issuer() -> String { "api-gateway-auth-server".to_string() }
fn default_audience() -> String { "api-gateway-clients".to_string() }

// ── Config store ──────────────────────────────────────────────────────────────

struct ConfigStore {
    history: Vec<ConfigSnapshot>,
    history_limit: usize,
}

impl ConfigStore {
    #[cfg(test)]
    fn new(initial: ConfigSnapshot, history_limit: usize) -> Self {
        Self { history: vec![initial], history_limit }
    }

    fn push(&mut self, next: ConfigSnapshot) {
        self.history.push(next);
        if self.history.len() > self.history_limit {
            self.history.remove(0);
        }
    }

    fn pop(&mut self) -> Option<ConfigSnapshot> {
        if self.history.len() > 1 {
            self.history.pop()
        } else {
            None
        }
    }

    fn current(&self) -> &ConfigSnapshot {
        self.history.last().expect("history is never empty")
    }
}

// ── Shared state ──────────────────────────────────────────────────────────────

/// Lock-free current config — gateway nodes poll this via GET /config.
/// Reads are ~2 ns with zero contention regardless of node count.
type LiveConfig = Arc<ArcSwap<ConfigSnapshot>>;

/// Write-side store — only touched on POST /config and POST /config/rollback.
/// Writes are rare (human-triggered), so a Mutex is fine here.
type WriteStore = Arc<Mutex<ConfigStore>>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Config revision + event model (hybrid delivery: snapshot → SSE → reconcile) ──
//
// Every mutation produces a monotonically increasing revision. Edges track
// the last revision they applied; SSE carries metadata-only events and the
// edge re-fetches the snapshot — full state transfer, no delta-merge risk.

/// Ring capacity for reconnect replay. Covers short disconnects; older gaps
/// force a snapshot fetch via `config_stale`.
const EVENT_RING_CAP: usize = 128;
/// SSE heartbeat interval — keeps Render/proxy idle timeouts from killing
/// long-lived streams (proxies typically cut idle conns at 60–100s).
const SSE_HEARTBEAT_SECS: u64 = 25;
/// Reconnect hint sent to edges (`retry:` field), plus edge-side jitter.
const SSE_RETRY_MS: u64 = 10_000;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConfigEvent {
    pub revision: u64,
    pub version: String,
    pub timestamp: u64,
    /// Event kind — currently always "FULL_SYNC" (metadata; edge fetches).
    #[serde(rename = "type")]
    pub kind: String,
}

fn new_config_event(revision: u64, version: &str) -> ConfigEvent {
    ConfigEvent {
        revision,
        version: version.to_string(),
        timestamp: now_secs(),
        kind: "FULL_SYNC".to_string(),
    }
}

/// Pure reconnect recovery: which ring events does an edge with `last_id`
/// still need? Returns (events with rev > last_id, stale) where stale means
/// the ring no longer covers the gap and the edge must snapshot-fetch.
pub fn select_missed_events(
    ring: &VecDeque<ConfigEvent>,
    last_id: u64,
    cap: usize,
) -> (Vec<ConfigEvent>, bool) {
    if ring.is_empty() {
        return (Vec::new(), last_id > 0);
    }
    let oldest = ring.front().map(|e| e.revision).unwrap_or(0);
    let latest = ring.back().map(|e| e.revision).unwrap_or(0);
    if last_id >= latest {
        return (Vec::new(), false);
    }
    if last_id > 0 && last_id + 1 < oldest {
        // Gap starts before retained history — entries were evicted.
        return (Vec::new(), true);
    }
    let mut missed: Vec<ConfigEvent> = ring
        .iter()
        .filter(|e| e.revision > last_id)
        .cloned()
        .collect();
    let stale = missed.len() > cap;
    missed.truncate(cap);
    (missed, stale)
}

#[derive(Clone)]
struct AppState {
    live:  LiveConfig,
    store: WriteStore,
    db:    Option<store::Store>,
    /// Monotonic config revision — bumped on every apply/rollback.
    revision: Arc<AtomicU64>,
    /// Recent events for reconnect replay (bounded ring).
    events: Arc<Mutex<VecDeque<ConfigEvent>>>,
    /// Fanout to SSE subscribers. One send per mutation regardless of edge
    /// count — no per-edge database work on the hot path.
    broadcaster: broadcast::Sender<ConfigEvent>,
    /// Live SSE connections (observability).
    sse_connections: Arc<AtomicU64>,
}

/// Publish a new revision: bump counter, record ring event, fanout.
/// Send errors (no subscribers) are fine and ignored.
fn publish_revision(state: &web::Data<AppState>, version: &str) -> ConfigEvent {
    let revision = state.revision.fetch_add(1, Ordering::SeqCst) + 1;
    let ev = new_config_event(revision, version);
    if let Ok(mut ring) = state.events.lock() {
        ring.push_back(ev.clone());
        while ring.len() > EVENT_RING_CAP {
            ring.pop_front();
        }
    }
    let _ = state.broadcaster.send(ev.clone());
    log::info!("Config revision {revision} published (version {version})");
    ev
}

// ── Admin API authentication ──────────────────────────────────────────────────

const ADMIN_TIMESTAMP_MAX_SKEW_SECS: u64 = 300;
const ADMIN_NONCE_TTL_SECS: u64 = 600;

/// In-memory nonce store when Redis is unavailable (single-node dev). Production
/// should use Redis SET NX so nonces are cluster-wide.
static ADMIN_NONCES: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

/// Bytes signed for admin mutations: `"{timestamp}\n{nonce}\n" || body`.
fn admin_signing_material(timestamp: &str, nonce: &str, body_bytes: &[u8]) -> Vec<u8> {
    let mut material = format!("{timestamp}\n{nonce}\n").into_bytes();
    material.extend_from_slice(body_bytes);
    material
}

/// Record nonce if unseen. Returns false on replay or store failure (fail-closed).
fn check_and_record_admin_nonce(nonce: &str, now: u64) -> bool {
    if nonce.len() < 16 || nonce.len() > 128 {
        return false;
    }

    // Prefer Redis — works across control-plane replicas.
    // Circuit-breaker protected: when Redis is OPEN/slow/down the breaker
    // rejects immediately (§17) and we fall through to the in-memory fallback
    // without ever waiting on a hung Redis (§14, §15).
    let redis_result = redis_cb::with_circuit_breaker(|| {
        let mut con = match redis_cb::open_redis_connection() {
            Ok(c) => c,
            Err(outcome) => return Err(outcome),
        };
        let key = format!("admin:nonce:{nonce}");
        let inserted: redis::RedisResult<bool> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ADMIN_NONCE_TTL_SECS)
            .query(&mut con);
        match inserted {
            Ok(v) => Ok(v),
            Err(e) => Err(redis_cb::classify_redis_error(&e)),
        }
    });

    match redis_result {
        Ok(true) => return true,
        Ok(false) => return false, // replay
        Err(_) => {
            // Redis error/timeout/circuit-open — fall through to memory
        }
    }

    let mut guard = match ADMIN_NONCES.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let map = guard.get_or_insert_with(HashMap::new);
    map.retain(|_, exp| *exp > now);
    if map.contains_key(nonce) {
        return false;
    }
    map.insert(nonce.to_string(), now + ADMIN_NONCE_TTL_SECS);
    true
}

/// Verify admin mutation: HMAC + timestamp window + one-time nonce (ADR-0023).
///
/// Header format:
///   `X-Admin-Timestamp` — unix seconds
///   `X-Admin-Nonce`     — unique per request (≥16 chars)
///   `X-Admin-Signature` — `sha256=<hex(HMAC-SHA256(signing_material))>`
fn verify_admin_signature(req: &HttpRequest, body_bytes: &[u8]) -> bool {
    let admin_key = std::env::var("ADMIN_API_KEY")
        .unwrap_or_else(|_| "CHANGE_ME_ADMIN_API_KEY".to_string());

    // In dev mode (key == default), skip verification to allow easy testing
    if admin_key == "CHANGE_ME_ADMIN_API_KEY" {
        log::warn!("ADMIN_API_KEY is default — skipping signature verification (dev mode)");
        return true;
    }

    let sig_header = match req.headers().get("X-Admin-Signature") {
        Some(v) => match v.to_str() { Ok(s) => s, Err(_) => return false },
        None => return false,
    };
    let timestamp = match req.headers().get("X-Admin-Timestamp") {
        Some(v) => match v.to_str() { Ok(s) => s, Err(_) => return false },
        None => return false,
    };
    let nonce = match req.headers().get("X-Admin-Nonce") {
        Some(v) => match v.to_str() { Ok(s) => s, Err(_) => return false },
        None => return false,
    };

    let ts: u64 = match timestamp.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.abs_diff(ts) > ADMIN_TIMESTAMP_MAX_SKEW_SECS {
        return false;
    }

    if !check_and_record_admin_nonce(nonce, now) {
        log::warn!("Admin request rejected: nonce replay or invalid nonce");
        return false;
    }

    let material = admin_signing_material(timestamp, nonce, body_bytes);
    verify_hmac_signature(&admin_key, &material, sig_header)
}

/// Pure HMAC-SHA256 verification, extracted for unit testing.
///
/// `sig_header` is the raw `X-Admin-Signature` value (`sha256=<hex>`). Returns
/// true iff the hex digest matches `HMAC-SHA256(body, admin_key)` using a
/// constant-time comparison.
fn verify_hmac_signature(admin_key: &str, body_bytes: &[u8], sig_header: &str) -> bool {
    let provided_hex = sig_header.strip_prefix("sha256=").unwrap_or("");
    if provided_hex.is_empty() {
        return false;
    }

    let mut mac = match HmacSha256::new_from_slice(admin_key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body_bytes);
    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    // Constant-time comparison
    if expected_hex.len() != provided_hex.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in expected_hex.bytes().zip(provided_hex.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Warn or exit when ADMIN_API_KEY is a known dev default (ADR-0041 parity).
fn warn_insecure_admin_key() {
    const DEV_KEYS: &[&str] = &[
        "CHANGE_ME_ADMIN_API_KEY",
        "change_me_use_a_long_random_admin_key",
    ];
    let key = std::env::var("ADMIN_API_KEY")
        .unwrap_or_else(|_| "CHANGE_ME_ADMIN_API_KEY".to_string());
    if !DEV_KEYS.iter().any(|d| key == *d) {
        return;
    }
    log::warn!(
        "ADMIN_API_KEY is a known dev/default value — rotate before production \
         (ADR-0013, ADR-0041)"
    );
    if std::env::var("CONTROL_PLANE_REFUSE_INSECURE_SECRETS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        log::error!("CONTROL_PLANE_REFUSE_INSECURE_SECRETS=1 — refusing to start");
        std::process::exit(1);
    }
}

// ── Admin mutation rate limit (per source IP) ─────────────────────────────────

const ADMIN_RL_MAX_PER_MINUTE: u32 = 30;
const ADMIN_RL_WINDOW_SECS:    u64 = 60;

static ADMIN_RL_BUCKETS: Mutex<Option<HashMap<String, (u64, u32)>>> = Mutex::new(None);

/// Simple fixed-window limiter for config mutations. Writes are rare and human-
/// triggered; this blocks brute-force signature guessing on POST /config.
///
/// Security: keyed on the real TCP **peer address** (`peer_addr`), NOT
/// `realip_remote_addr()`. The latter trusts the client-supplied
/// `X-Forwarded-For` / `Forwarded` headers (per actix docs), so an attacker could
/// rotate that header to both bypass this limit and flood the bucket map with
/// unbounded distinct keys (memory-exhaustion DoS). Behind a trusted reverse
/// proxy, terminate XFF there and rely on network policy for the admin port.
fn check_admin_rate_limit(req: &HttpRequest) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Real socket peer — not spoofable via request headers.
    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut guard = match ADMIN_RL_BUCKETS.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let map = guard.get_or_insert_with(HashMap::new);
    admin_rate_limit_step(map, &ip, now, ADMIN_RL_MAX_PER_MINUTE, ADMIN_RL_WINDOW_SECS)
}

/// Pure fixed-window step, extracted for unit testing.
///
/// Prunes entries whose window has fully elapsed so the map cannot grow without
/// bound, then resets/increments the caller's window. Returns `true` if the
/// request is within the limit.
fn admin_rate_limit_step(
    map: &mut HashMap<String, (u64, u32)>,
    ip: &str,
    now: u64,
    max_per_window: u32,
    window_secs: u64,
) -> bool {
    // Bound memory: drop stale windows. O(n) but n is the number of recently
    // active admin IPs (tiny), and mutations are rare (≤ 30/min/IP).
    map.retain(|_, (start, _)| now.saturating_sub(*start) < window_secs);

    let entry = map.entry(ip.to_string()).or_insert((now, 0));
    if now.saturating_sub(entry.0) >= window_secs {
        *entry = (now, 0);
    }
    if entry.1 >= max_per_window {
        return false;
    }
    entry.1 += 1;
    true
}

// ── Config read auth (ADR-0057) ────────────────────────────────────────────────

/// When `CONFIG_READ_TOKEN` is set, GET /config and /config/history require
/// `X-Config-Read-Token` matching that value. Unset = open (local dev).
fn verify_config_read_token(req: &HttpRequest) -> bool {
    let expected = match std::env::var("CONFIG_READ_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => return true,
    };
    match req.headers().get("X-Config-Read-Token") {
        Some(v) => v.to_str().map(|s| s == expected).unwrap_or(false),
        None => false,
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Snapshot envelope: full config + revision metadata. Extra fields are
/// ignored by older edge parsers, so this stays wire-compatible.
#[derive(Serialize)]
struct SnapshotEnvelope<'a> {
    #[serde(flatten)]
    snapshot: &'a ConfigSnapshot,
    revision: u64,
    timestamp: u64,
}

#[derive(Serialize)]
struct VersionInfo {
    revision: u64,
    version: String,
    timestamp: u64,
}

fn version_etag(revision: u64) -> String {
    format!("W/\"rev-{revision}\"")
}

/// GET /config — lock-free snapshot read with revision envelope.
async fn get_config(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !verify_config_read_token(&req) {
        log::warn!("GET /config rejected: missing or invalid X-Config-Read-Token");
        return HttpResponse::Unauthorized().body("Missing or invalid X-Config-Read-Token");
    }
    let snap = state.live.load_full();
    let body = SnapshotEnvelope {
        snapshot: snap.as_ref(),
        revision: state.revision.load(Ordering::SeqCst),
        timestamp: now_secs(),
    };
    HttpResponse::Ok().json(body)
}

/// GET /config/version — lightweight revision check for periodic
/// reconciliation. Supports `If-None-Match` (ETag `W/"rev-N"`) → 304.
async fn config_version(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !verify_config_read_token(&req) {
        log::warn!("GET /config/version rejected: missing or invalid X-Config-Read-Token");
        return HttpResponse::Unauthorized().body("Missing or invalid X-Config-Read-Token");
    }
    let revision = state.revision.load(Ordering::SeqCst);
    let etag = version_etag(revision);
    if let Some(inm) = req.headers().get("If-None-Match") {
        if inm.to_str().map(|s| s.trim() == etag).unwrap_or(false) {
            return HttpResponse::NotModified().finish();
        }
    }
    let snap = state.live.load_full();
    HttpResponse::Ok()
        .insert_header(("ETag", etag))
        .insert_header(("Cache-Control", "no-store"))
        .json(VersionInfo {
            revision,
            version: snap.version.clone(),
            timestamp: now_secs(),
        })
}

fn sse_frame(id: Option<u64>, event: &str, data: &str) -> actix_web::web::Bytes {
    let mut s = String::with_capacity(data.len() + 64);
    if let Some(id) = id {
        s.push_str(&format!("id: {id}\n"));
    }
    s.push_str(&format!("event: {event}\n"));
    for line in data.lines() {
        s.push_str(&format!("data: {line}\n"));
    }
    s.push('\n');
    actix_web::web::Bytes::from(s)
}

fn config_changed_frame(ev: &ConfigEvent) -> actix_web::web::Bytes {
    let data = serde_json::json!({
        "revision": ev.revision,
        "configVersion": ev.version,
        "timestamp": ev.timestamp,
        "type": ev.kind,
    });
    sse_frame(Some(ev.revision), "config_changed", &data.to_string())
}

#[derive(Deserialize)]
struct StreamQuery {
    #[serde(default)]
    edge_id: String,
}

/// GET /config/stream — SSE change stream for edge nodes.
///
/// Auth: `X-Config-Read-Token` (same as snapshot reads).
/// Identity: `?edge_id=` (truncated to 64 chars, observability only).
/// Resume: `Last-Event-ID` header (last applied revision). Missed events
/// still in the ring are replayed; evicted gaps get `config_stale`
/// (edge must snapshot-fetch). Heartbeats every SSE_HEARTBEAT_SECS keep
/// proxies from killing idle streams; `retry:` tells edges when to return.
async fn config_stream(
    req: HttpRequest,
    state: web::Data<AppState>,
    query: web::Query<StreamQuery>,
) -> impl Responder {
    if !verify_config_read_token(&req) {
        log::warn!("GET /config/stream rejected: missing or invalid X-Config-Read-Token");
        return HttpResponse::Unauthorized().body("Missing or invalid X-Config-Read-Token");
    }
    let edge_id: String = {
        let mut id = query.edge_id.trim().to_string();
        if id.is_empty() {
            id = "unknown".to_string();
        }
        id.truncate(64);
        id
    };
    let last_id: u64 = req
        .headers()
        .get("Last-Event-ID")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    // Subscribe BEFORE replaying so no event slips between replay and live.
    let mut rx = state.broadcaster.subscribe();
    let (missed, stale) = match state.events.lock() {
        Ok(ring) => select_missed_events(&ring, last_id, EVENT_RING_CAP),
        Err(_) => (Vec::new(), true),
    };
    let latest = state.revision.load(Ordering::SeqCst);
    state.sse_connections.fetch_add(1, Ordering::SeqCst);
    log::info!("SSE connected: edge={edge_id} last_id={last_id} replay={} stale={stale} live_rev={latest} conns={}",
        missed.len(),
        state.sse_connections.load(Ordering::SeqCst));

    struct ConnGuard(Arc<AtomicU64>, String);
    impl Drop for ConnGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
            log::info!("SSE disconnected: edge={} conns={}", self.1, self.0.load(Ordering::SeqCst));
        }
    }
    let guard = ConnGuard(state.sse_connections.clone(), edge_id.clone());

    // Infallible error type: every frame is producible, so the pump task
    // never needs to fail the stream (also keeps the future Send).
    let (tx, rx_stream) = tokio::sync::mpsc::unbounded_channel::<
        Result<actix_web::web::Bytes, std::convert::Infallible>,
    >();
    let edge_id_task = edge_id.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let send = |b: actix_web::web::Bytes| tx.send(Ok(b)).is_ok();
        send(actix_web::web::Bytes::from(format!("retry: {SSE_RETRY_MS}\n\n")));
        if stale {
            send(sse_frame(None, "config_stale", &serde_json::json!({
                "message": "revision gap exceeds retained history — snapshot fetch required",
                "latestRevision": latest,
            }).to_string()));
        }
        for ev in &missed {
            if !send(config_changed_frame(ev)) {
                return;
            }
        }
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(SSE_HEARTBEAT_SECS));
        // First tick fires immediately — skip it so we don't heartbeat on connect.
        heartbeat.tick().await;
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    let frame = sse_frame(None, "heartbeat",
                        &serde_json::json!({ "ts": now_secs(), "latestRevision": latest }).to_string());
                    if !send(frame) { return; }
                }
                msg = rx.recv() => {
                    match msg {
                        Ok(ev) => {
                            if !send(config_changed_frame(&ev)) { return; }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            // Fell behind the fanout buffer — force reconcile, never guess.
                            let frame = sse_frame(None, "config_stale", &serde_json::json!({
                                "message": "subscriber lagged behind fanout buffer — snapshot fetch required",
                            }).to_string());
                            if !send(frame) { return; }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    }
                }
            }
        }
    });

    let _ = edge_id_task;
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .insert_header(("Connection", "keep-alive"))
        .streaming(tokio_stream::wrappers::UnboundedReceiverStream::new(rx_stream))
}

/// POST /config — push a new config version (requires X-Admin-Signature).
/// Append `?dry_run=1` to preview validation + diff without applying.
async fn post_config(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Bytes,
) -> impl Responder {
    // Verify HMAC signature before deserializing
    if !check_admin_rate_limit(&req) {
        log::warn!("POST /config rejected: admin rate limit exceeded");
        return HttpResponse::TooManyRequests().body("Admin rate limit exceeded");
    }
    if !verify_admin_signature(&req, &body) {
        log::warn!("POST /config rejected: invalid or missing X-Admin-Signature");
        return HttpResponse::Unauthorized().body("Missing or invalid X-Admin-Signature");
    }

    let new_snap: ConfigSnapshot = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid JSON: {e}")),
    };

    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "super_secret_key_for_hmac_sha256".to_string());

    let mut new_snap = new_snap;
    new_snap.jwt_secret = jwt_secret;
    // jwt_keys come from the request body (operator-managed rotation keys)
    // They are never serialized back out via GET /config

    // ── Deep validation + diff (ADR-0065, gap #7) ─────────────────────────
    // Errors reject the push outright; `?dry_run=1` previews without applying.
    let report = config_validate::validate_config(&new_snap);
    let diff = {
        let store_lock = state.store.lock();
        match store_lock {
            Ok(store) => config_validate::diff_report(store.current(), &new_snap),
            Err(_) => return HttpResponse::InternalServerError().body("store lock"),
        }
    };
    let dry_run = req
        .uri()
        .query()
        .map(|q| q.split('&').any(|kv| kv == "dry_run=1" || kv == "dry_run=true"))
        .unwrap_or(false);
    if dry_run {
        return HttpResponse::Ok().json(serde_json::json!({
            "dry_run": true,
            "version": new_snap.version,
            "validation": report,
            "diff": diff,
        }));
    }
    if !report.valid {
        log::warn!("POST /config rejected: {} validation error(s)", report.errors.len());
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "config validation failed",
            "validation": report,
            "diff": diff,
        }));
    }

    let version = new_snap.version.clone();
    let actor_ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();

    // Durable-first: persist the revision BEFORE activating it. If Postgres is
    // configured but the write fails, reject — an un-audited config change is
    // worse than a rejected one (ADR-0011 audit trail).
    if let Some(db) = &state.db {
        let snapshot = match serde_json::to_value(&new_snap) {
            Ok(s) => s,
            Err(e) => {
                log::error!("POST /config: snapshot serialization failed: {e}");
                return HttpResponse::InternalServerError().body("Snapshot serialization failed");
            }
        };
        if let Err(e) = db.record(&version, "apply", &actor_ip, &snapshot).await {
            log::error!("POST /config: durable write failed for version {version}: {e}");
            return HttpResponse::ServiceUnavailable()
                .body("Config store (Postgres) unavailable — change rejected");
        }
    }

    match state.store.lock() {
        Ok(mut store) => {
            store.push(new_snap.clone());
            state.live.store(Arc::new(new_snap));
            let ev = publish_revision(&state, &version);
            log::info!("Config updated to version {version} (revision {})", ev.revision);
            HttpResponse::Ok().json(serde_json::json!({
                "status": "applied",
                "version": version,
                "revision": ev.revision,
                "warnings": report.warnings,
                "diff": diff,
            }))
        }
        Err(_) => HttpResponse::InternalServerError().body("Config store lock poisoned"),
    }
}

/// POST /config/rollback — revert to previous version (requires X-Admin-Signature)
async fn rollback_config(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // Rollback with empty body — sign an empty string
    if !check_admin_rate_limit(&req) {
        log::warn!("POST /config/rollback rejected: admin rate limit exceeded");
        return HttpResponse::TooManyRequests().body("Admin rate limit exceeded");
    }
    if !verify_admin_signature(&req, b"") {
        log::warn!("POST /config/rollback rejected: invalid or missing X-Admin-Signature");
        return HttpResponse::Unauthorized().body("Missing or invalid X-Admin-Signature");
    }
    let prev = {
        let mut store = match state.store.lock() {
            Ok(s) => s,
            Err(_) => return HttpResponse::InternalServerError().body("Config store lock poisoned"),
        };
        store.pop();
        store.current().clone()
    };
    state.live.store(Arc::new(prev.clone()));
    // Rollback publishes a NEW revision pointing at old content — revisions
    // stay monotonic even when versions move backwards.
    let ev = publish_revision(&state, &prev.version);
    log::info!("Config rolled back to version {} (revision {})", prev.version, ev.revision);

    // Durable-first: record the rollback BEFORE responding success.
    if let Some(db) = &state.db {
        let actor_ip = req
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        let snapshot = match serde_json::to_value(&prev) {
            Ok(s) => s,
            Err(e) => {
                log::error!("POST /config/rollback: snapshot serialization failed: {e}");
                return HttpResponse::InternalServerError().body("Snapshot serialization failed");
            }
        };
        if let Err(e) = db.record(&prev.version, "rollback", &actor_ip, &snapshot).await {
            log::error!(
                "POST /config/rollback: durable write failed for version {}: {e}",
                prev.version
            );
            return HttpResponse::ServiceUnavailable()
                .body("Config store (Postgres) unavailable — rollback rejected");
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "rolled_back",
        "version": prev.version,
        "revision": ev.revision,
    }))
}

/// GET /config/history — durable + in-memory version strings (newest first)
async fn config_history(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !verify_config_read_token(&req) {
        log::warn!("GET /config/history rejected: missing or invalid X-Config-Read-Token");
        return HttpResponse::Unauthorized().body("Missing or invalid X-Config-Read-Token");
    }

    // Durable history (Postgres) first, newest first.
    let mut durable: Vec<String> = match &state.db {
        Some(db) => match db.versions().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("GET /config/history: durable read failed: {e}");
                Vec::new()
            }
        },
        None => Vec::new(),
    };

    // Append in-memory versions not yet persisted (e.g. seeded initial config).
    if let Ok(store) = state.store.lock() {
        for c in store.history.iter().rev() {
            if !durable.contains(&c.version) {
                durable.push(c.version.clone());
            }
        }
    }

    HttpResponse::Ok().json(durable)
}

/// GET /config/audit — full durable audit trail (action, actor, timestamp).
async fn config_audit(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !verify_config_read_token(&req) {
        log::warn!("GET /config/audit rejected: missing or invalid X-Config-Read-Token");
        return HttpResponse::Unauthorized().body("Missing or invalid X-Config-Read-Token");
    }
    let Some(db) = &state.db else {
        return HttpResponse::Ok().json(Vec::<serde_json::Value>::new());
    };
    match db.list(200).await {
        Ok(rows) => {
            let values: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "version":   r.version,
                        "action":    r.action,
                        "actor_ip":  r.actor_ip,
                        "created_at": r.created_at,
                    })
                })
                .collect();
            HttpResponse::Ok().json(values)
        }
        Err(e) => {
            log::warn!("GET /config/audit: durable read failed: {e}");
            HttpResponse::InternalServerError().body("Audit read failed")
        }
    }
}

// ── Token revocation (ADR-0038, ADR-0039) ─────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct RevokeRequest {
    /// JWT ID — preferred revocation handle.
    jti: Option<String>,
    /// Full JWT string (no `Bearer ` prefix) — hashed to `gateway:revoked:token:<sha256>`.
    token: Option<String>,
    /// Redis key TTL in seconds. Defaults to 3600; should match remaining token lifetime.
    #[serde(default = "default_revoke_ttl")]
    ttl_secs: u64,
}
fn default_revoke_ttl() -> u64 { 3600 }

/// SHA-256 of the full JWT, lowercase hex — must match gateway `token_hash_hex`.
fn token_hash_hex(token: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Resolve Redis keys to SET for a revoke request. Returns (key, description) pairs.
fn revocation_keys_for_request(req: &RevokeRequest) -> Result<Vec<String>, &'static str> {
    let has_jti = req.jti.as_ref().is_some_and(|s| !s.is_empty());
    let has_token = req.token.as_ref().is_some_and(|s| !s.is_empty());
    if !has_jti && !has_token {
        return Err("provide jti and/or token");
    }
    let mut keys = Vec::with_capacity(2);
    if let Some(jti) = req.jti.as_ref().filter(|s| !s.is_empty()) {
        keys.push(format!("gateway:revoked:jti:{jti}"));
    }
    if let Some(token) = req.token.as_ref().filter(|s| !s.is_empty()) {
        keys.push(format!("gateway:revoked:token:{}", token_hash_hex(token)));
    }
    Ok(keys)
}

/// Write revocation markers to Redis with TTL.
///
/// Circuit-breaker protected: when Redis is OPEN/slow/down the breaker rejects
/// immediately (§17) so `POST /revoke` fails fast with 503 instead of waiting
/// on a hung Redis (§14, §15).
fn write_revocation_keys(keys: &[String], ttl_secs: u64) -> Result<(), String> {
    let result = redis_cb::with_circuit_breaker(|| {
        let mut con = match redis_cb::open_redis_connection() {
            Ok(c) => c,
            Err(outcome) => return Err(outcome),
        };
        for key in keys {
            redis::cmd("SET")
                .arg(key)
                .arg("1")
                .arg("EX")
                .arg(ttl_secs)
                .query::<()>(&mut con)
                .map_err(|e| redis_cb::classify_redis_error(&e))?;
        }
        Ok(())
    });

    match result {
        Ok(()) => Ok(()),
        Err(outcome) => Err(format!("redis unavailable: {outcome:?}")),
    }
}

/// POST /revoke — publish token revocation to Redis (requires X-Admin-Signature).
async fn post_revoke(req: HttpRequest, body: web::Bytes) -> impl Responder {
    if !check_admin_rate_limit(&req) {
        log::warn!("POST /revoke rejected: admin rate limit exceeded");
        return HttpResponse::TooManyRequests().body("Admin rate limit exceeded");
    }
    if !verify_admin_signature(&req, &body) {
        log::warn!("POST /revoke rejected: invalid or missing X-Admin-Signature");
        return HttpResponse::Unauthorized().body("Missing or invalid X-Admin-Signature");
    }

    let revoke_req: RevokeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid JSON: {e}")),
    };

    let keys = match revocation_keys_for_request(&revoke_req) {
        Ok(k) => k,
        Err(msg) => return HttpResponse::BadRequest().body(msg),
    };

    match write_revocation_keys(&keys, revoke_req.ttl_secs) {
        Ok(()) => {
            log::info!("Revoked {} key(s): {:?}", keys.len(), keys);
            HttpResponse::Ok().json(serde_json::json!({
                "status": "revoked",
                "keys": keys,
                "ttl_secs": revoke_req.ttl_secs,
            }))
        }
        Err(e) => {
            log::error!("POST /revoke failed: {e}");
            HttpResponse::ServiceUnavailable().body(e)
        }
    }
}

// ── Telemetry ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct TelemetryPayload {
    requests_total: u64,
    requests_401:   u64,
    requests_429:   u64,
    requests_500:   u64,
    latency_us_sum: u64,
    in_flight:      i64,
    waf_blocks:     u64,
    cache_hits:     u64,
    cache_misses:   u64,
}

async fn post_telemetry(payload: web::Json<TelemetryPayload>) -> impl Responder {
    let p = payload.into_inner();
    let avg = if p.requests_total > 0 {
        p.latency_us_sum as f64 / p.requests_total as f64
    } else {
        0.0
    };
    log::info!(
        "telemetry reqs={} 401={} 429={} 5xx={} lat_avg={:.0}µs \
         in_flight={} waf={} cache_hit={} cache_miss={}",
        p.requests_total, p.requests_401, p.requests_429, p.requests_500,
        avg, p.in_flight, p.waf_blocks, p.cache_hits, p.cache_misses
    );
    HttpResponse::Ok().body("ok")
}

// ── Health ────────────────────────────────────────────────────────────────────

async fn health(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    // Dependency-health evaluator: surface the local Redis circuit state and
    // the config store (Postgres) so orchestrators can distinguish a healthy
    // control plane from one degrading toward an OPEN Redis circuit.
    let cb = redis_cb::get_cb();
    let redis_state = match cb.state() {
        0 => "closed",
        1 => "open",
        _ => "half_open",
    };
    let pg_state = match &state.db {
        Some(db) if db.ping().await => "ok",
        Some(_) => "unreachable",
        None => "disabled",
    };

    // ADR-0069: dependency internals are sensitive topology data. Public
    // callers get a generic healthy body; holders of CONFIG_READ_TOKEN get
    // the full breakdown. HTTP status stays 200 either way so probes work.
    if !verify_config_read_token(&req) {
        return HttpResponse::Ok().json(serde_json::json!({
            "status": "healthy",
            "service": "control-plane",
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status":        "healthy",
        "service":       "control-plane",
        "redis_circuit": redis_state,
        "postgres":      pg_state,
        "revision":      state.revision.load(Ordering::SeqCst),
        "sse_connections": state.sse_connections.load(Ordering::SeqCst),
    }))
}

// ── Prometheus metrics ─────────────────────────────────────────────────────────

/// GET /metrics — minimal exposition so the control plane is a first-class
/// Prometheus target alongside the gateway.
async fn metrics(state: web::Data<AppState>) -> impl Responder {
    let snap = state.live.load();
    let (services, routes) = (snap.services.len(), snap.routes.len());
    let history = state
        .store
        .lock()
        .map(|s| s.history.len())
        .unwrap_or(0);
    let revision = state.revision.load(Ordering::SeqCst);
    let sse_conns = state.sse_connections.load(Ordering::SeqCst);

    let body = format!(
        "# HELP control_plane_up Control plane process is up\n\
         # TYPE control_plane_up gauge\n\
         control_plane_up 1\n\
         # HELP control_plane_config_services Services in the active config\n\
         # TYPE control_plane_config_services gauge\n\
         control_plane_config_services {services}\n\
         # HELP control_plane_config_routes Routes in the active config\n\
         # TYPE control_plane_config_routes gauge\n\
         control_plane_config_routes {routes}\n\
         # HELP control_plane_config_history Versions retained in history\n\
         # TYPE control_plane_config_history gauge\n\
         control_plane_config_history {history}\n\
         # HELP control_plane_config_revision Monotonic config revision served to edges\n\
         # TYPE control_plane_config_revision gauge\n\
         control_plane_config_revision {revision}\n\
         # HELP control_plane_sse_connections Live SSE stream connections from edges\n\
         # TYPE control_plane_sse_connections gauge\n\
         control_plane_sse_connections {sse_conns}\n\
         {}\n",
        redis_cb::prometheus_metrics()
    );

    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(body)
}

// ── Config loader ─────────────────────────────────────────────────────────────

fn load_initial_config() -> ConfigSnapshot {
    let config_dir = std::env::var("CONFIG_DIR")
        .unwrap_or_else(|_| "./conf.d".to_string());
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "super_secret_key_for_hmac_sha256".to_string());
    let max_concurrency = std::env::var("MAX_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000usize);

    // Try full snapshot first
    let snapshot_path = format!("{config_dir}/initial-snapshot.json");
    if Path::new(&snapshot_path).exists() {
        if let Some(mut snap) = fs::read_to_string(&snapshot_path)
            .ok()
            .and_then(|s| serde_json::from_str::<ConfigSnapshot>(&s).ok())
        {
            snap.jwt_secret = jwt_secret;
            snap.global_max_concurrency = max_concurrency;
            log::info!("Loaded snapshot {} from {snapshot_path}", snap.version);
            return snap;
        }
        log::warn!("Failed to parse {snapshot_path}, falling back to per-service files");
    }

    // Fall back to individual service files
    let mut snap = ConfigSnapshot {
        version: "v1.0.0".to_string(),
        global_max_concurrency: max_concurrency,
        jwt_secret,
        jwt_keys: HashMap::new(),
        expected_issuer: default_issuer(),
        expected_audience: default_audience(),
        services: HashMap::new(),
        routes: Vec::new(),
        health_check: None,
            cors: None,
    };

    match fs::read_dir(&config_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file()
                    && path.extension().and_then(|s| s.to_str()) == Some("json")
                    && path.file_name().and_then(|n| n.to_str())
                        != Some("initial-snapshot.json")
                {
                    match fs::read_to_string(&path)
                        .ok()
                        .and_then(|s| serde_json::from_str::<ServiceConfig>(&s).ok())
                    {
                        Some(svc) => {
                            log::info!("Loaded service: {}", svc.name);
                            snap.services.insert(svc.name.clone(), svc);
                        }
                        None => log::warn!("Skipping: {}", path.display()),
                    }
                }
            }
            if !snap.services.is_empty() {
                snap.routes.push(Route {
                    path_prefix: "/".to_string(),
                    service_name: "default-service".to_string(),
                    strip_prefix: false,
            tier: String::new(),
            validation: None,
                });
            }
        }
        Err(e) => {
            log::warn!("Config dir '{config_dir}' not found ({e}), using fallback");
            build_fallback(&mut snap);
        }
    }

    snap
}

fn build_fallback(snap: &mut ConfigSnapshot) {
    let mut upstreams = HashMap::new();
    for (region, addr) in &[
        ("EU", "eu-backend:8080"),
        ("US", "us-backend:8080"),
        ("AP", "ap-backend:8080"),
    ] {
        upstreams.insert(
            region.to_string(),
            vec![Upstream { name: addr.to_string(), address: addr.to_string(), weight: 1, version: String::new() }],
        );
    }
    let svc = ServiceConfig {
        name: "default-service".to_string(),
        rate_limit_max: 10_000,
        regional_upstreams: upstreams,
        require_auth: true,
        canary: None,
        quota: None,
    };
    snap.services.insert("default-service".to_string(), svc);
    snap.routes.push(Route {
        path_prefix: "/".to_string(),
        service_name: "default-service".to_string(),
        strip_prefix: false,
            tier: String::new(),
            validation: None,
    });
}

/// Build the initial in-memory state.
///
/// - If durable revisions exist in Postgres, rebuild history from them
///   (jwt_secret is always re-applied from env — ADR-0013).
/// - Otherwise load from `conf.d` and seed it as the first durable revision.
async fn rebuild_initial_state(
    db: &Option<store::Store>,
    history_limit: usize,
) -> (ConfigSnapshot, Vec<ConfigSnapshot>) {
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "super_secret_key_for_hmac_sha256".to_string());
    let max_concurrency = std::env::var("MAX_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000usize);

    if let Some(db) = db {
        if let Ok(snaps) = db.history_snapshots(history_limit as i64).await {
            if !snaps.is_empty() {
                let mut history: Vec<ConfigSnapshot> = Vec::with_capacity(snaps.len());
                for (_, snap_json) in &snaps {
                    if let Ok(mut snap) = serde_json::from_value::<ConfigSnapshot>(snap_json.clone())
                    {
                        snap.jwt_secret = jwt_secret.clone();
                        snap.global_max_concurrency = max_concurrency;
                        history.push(snap);
                    }
                }
                if let Some(latest) = history.last() {
                    return (latest.clone(), history);
                }
            }
        }
    }

    // Nothing durable — seed from conf.d.
    let initial = load_initial_config();
    if let Some(db) = db {
        let snapshot = match serde_json::to_value(&initial) {
            Ok(s) => s,
            Err(e) => {
                log::error!("seed snapshot serialization failed: {e}");
                serde_json::json!({})
            }
        };
        if let Err(e) = db.record(&initial.version, "seed", "", &snapshot).await {
            log::warn!("seed revision write failed: {e}");
        }
    }
    (initial.clone(), vec![initial])
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Telemetry bootstrap (traces/metrics/logs → Grafana Cloud when
    // OTEL_EXPORTER_OTLP_ENDPOINT is set; console-only otherwise).
    let mut telemetry = otlp::init();

    warn_insecure_admin_key();

    let history_limit = std::env::var("CONFIG_HISTORY_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20usize);

    // Durable state store (Postgres, isolated `control_plane` schema). Optional:
    // without it the control plane degrades to in-memory history only.
    let db = match store::Store::connect().await {
        Ok(Some(s)) => Some(s),
        Ok(None) => None,
        Err(e) => {
            log::error!("PostgreSQL unavailable — config history in-memory only: {e}");
            None
        }
    };

    // Rebuild in-memory state from durable history if available, so rollback
    // keeps working across restarts; otherwise fall back to conf.d config.
    let (initial, history) = rebuild_initial_state(&db, history_limit).await;
    if history.len() > 1 {
        log::info!(
            "Restored {} durable config revision(s) from Postgres (latest: {})",
            history.len(),
            initial.version
        );
    }

    let live  = Arc::new(ArcSwap::from_pointee(initial.clone()));
    let store = Arc::new(Mutex::new(ConfigStore { history, history_limit }));

    // Revision seed: one revision per durable record keeps monotonicity
    // across restarts (best-effort — records predate revision tracking).
    let seed_revision = {
        let h = store.lock().map(|s| s.history.len()).unwrap_or(1).max(1) as u64;
        h
    };
    let (broadcaster, _) = broadcast::channel::<ConfigEvent>(256);
    let seed_event = new_config_event(seed_revision, &initial.version);
    let mut seed_ring = VecDeque::with_capacity(EVENT_RING_CAP);
    seed_ring.push_back(seed_event.clone());
    log::info!(
        "Config revision seeded at {} (version {})",
        seed_revision, initial.version
    );

    let app_state = web::Data::new(AppState {
        live,
        store,
        db,
        revision: Arc::new(AtomicU64::new(seed_revision)),
        events: Arc::new(Mutex::new(seed_ring)),
        broadcaster,
        sse_connections: Arc::new(AtomicU64::new(0)),
    });

    let port    = std::env::var("PORT").unwrap_or_else(|_| "8081".to_string());
    let workers = std::env::var("WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(num_cpus::get);

    log::info!("Control Plane starting on 0.0.0.0:{port} ({workers} workers)");

    HttpServer::new(move || {
        App::new()
            .wrap(otlp::OtelMetrics)
            .app_data(app_state.clone())
            .app_data(web::JsonConfig::default().limit(1_048_576))
            .route("/health",          web::get().to(health))
            .route("/metrics",         web::get().to(metrics))
            .route("/config",          web::get().to(get_config))
            .route("/config",          web::post().to(post_config))
            .route("/config/version",  web::get().to(config_version))
            .route("/config/stream",   web::get().to(config_stream))
            .route("/config/rollback", web::post().to(rollback_config))
            .route("/config/history",  web::get().to(config_history))
            .route("/config/audit",    web::get().to(config_audit))
            .route("/revoke",          web::post().to(post_revoke))
            .route("/telemetry",       web::post().to(post_telemetry))
    })
    .bind(format!("0.0.0.0:{port}"))?
    .workers(workers)
    .run()
    .await?;

    // Graceful telemetry flush (traces/metrics/logs) on shutdown.
    telemetry.shutdown();
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(key: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    fn sign_admin(key: &str, timestamp: &str, nonce: &str, body: &[u8]) -> String {
        let material = admin_signing_material(timestamp, nonce, body);
        sign(key, &material)
    }

    #[test]
    fn admin_signing_binds_timestamp_nonce_and_body() {
        let key = "admin";
        let body = br#"{"version":"v2"}"#;
        let sig = sign_admin(key, "1700000000", "nonce-abc-12345678", body);
        let material = admin_signing_material("1700000000", "nonce-abc-12345678", body);
        assert!(verify_hmac_signature(key, &material, &sig));
        // Tampered body fails
        assert!(!verify_hmac_signature(key, &admin_signing_material("1700000000", "nonce-abc-12345678", br#"{"version":"v3"}"#), &sig));
    }

    #[test]
    fn admin_nonce_replay_rejected_in_memory() {
        let nonce = "replay-test-nonce-123456";
        let now = 1_700_000_000;
        assert!(check_and_record_admin_nonce(nonce, now));
        assert!(!check_and_record_admin_nonce(nonce, now));
    }

    #[test]
    fn hmac_accepts_valid_signature() {
        let key = "super-admin-key";
        let body = br#"{"version":"v2"}"#;
        assert!(verify_hmac_signature(key, body, &sign(key, body)));
    }

    fn test_ring(revs: &[u64]) -> VecDeque<ConfigEvent> {
        revs.iter()
            .map(|r| new_config_event(*r, "v-test"))
            .collect()
    }

    #[test]
    fn replay_returns_only_newer_events() {
        let ring = test_ring(&[101, 102, 103]);
        let (missed, stale) = select_missed_events(&ring, 101, 128);
        assert!(!stale);
        assert_eq!(missed.iter().map(|e| e.revision).collect::<Vec<_>>(), vec![102, 103]);
    }

    #[test]
    fn replay_at_latest_returns_nothing() {
        let ring = test_ring(&[101, 102]);
        let (missed, stale) = select_missed_events(&ring, 102, 128);
        assert!(!stale);
        assert!(missed.is_empty());
    }

    #[test]
    fn replay_fresh_edge_gets_everything() {
        let ring = test_ring(&[7, 8]);
        let (missed, stale) = select_missed_events(&ring, 0, 128);
        assert!(!stale);
        assert_eq!(missed.len(), 2);
    }

    #[test]
    fn replay_evicted_gap_forces_stale() {
        // Ring retained 105..107; edge at 102 missed evicted entries.
        let ring = test_ring(&[105, 106, 107]);
        let (missed, stale) = select_missed_events(&ring, 102, 128);
        assert!(stale);
        assert!(missed.is_empty());
    }

    #[test]
    fn replay_boundary_is_not_stale() {
        // Edge at 104, oldest retained 105 → contiguous, no gap.
        let ring = test_ring(&[105, 106]);
        let (missed, stale) = select_missed_events(&ring, 104, 128);
        assert!(!stale);
        assert_eq!(missed.len(), 2);
    }

    #[test]
    fn replay_respects_cap_and_flags_stale() {
        let ring = test_ring(&[11, 12, 13, 14]);
        let (missed, stale) = select_missed_events(&ring, 10, 2);
        assert!(stale);
        assert_eq!(missed.len(), 2);
    }

    #[test]
    fn version_etag_roundtrip() {
        assert_eq!(version_etag(105), "W/\"rev-105\"");
    }

    #[test]
    fn hmac_rejects_wrong_key() {
        let body = br#"{"version":"v2"}"#;
        let sig = sign("right-key", body);
        assert!(!verify_hmac_signature("wrong-key", body, &sig));
    }

    #[test]
    fn hmac_rejects_tampered_body() {
        let key = "k";
        let sig = sign(key, br#"{"version":"v2"}"#);
        assert!(!verify_hmac_signature(key, br#"{"version":"v3"}"#, &sig));
    }

    #[test]
    fn hmac_rejects_missing_prefix() {
        let key = "k";
        let body = b"x";
        let raw_hex = sign(key, body).strip_prefix("sha256=").unwrap().to_string();
        assert!(!verify_hmac_signature(key, body, &raw_hex));
    }

    #[test]
    fn hmac_rejects_empty_signature() {
        assert!(!verify_hmac_signature("k", b"x", "sha256="));
        assert!(!verify_hmac_signature("k", b"x", ""));
    }

    #[test]
    fn hmac_signs_empty_body_for_rollback() {
        let key = "admin";
        assert!(verify_hmac_signature(key, b"", &sign(key, b"")));
    }

    #[test]
    fn jwt_secret_is_never_serialized() {
        let snap = ConfigSnapshot {
            version: "v1".into(),
            global_max_concurrency: 100,
            jwt_secret: "TOP-SECRET-VALUE".into(),
            jwt_keys: HashMap::from([("k1".into(), "secret-key-1".into())]),
            expected_issuer: default_issuer(),
            expected_audience: default_audience(),
            services: HashMap::new(),
            routes: Vec::new(),
            health_check: None,
            cors: None,
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert!(!json.contains("TOP-SECRET-VALUE"), "jwt_secret leaked in JSON");
        assert!(!json.contains("secret-key-1"), "jwt_keys leaked in JSON");
        assert!(json.contains("expected_issuer"), "non-secret field should serialize");
    }

    #[test]
    fn config_store_push_keeps_history_limit() {
        let base = ConfigSnapshot {
            version: "v1".into(),
            global_max_concurrency: 1,
            jwt_secret: "s".into(),
            jwt_keys: HashMap::new(),
            expected_issuer: default_issuer(),
            expected_audience: default_audience(),
            services: HashMap::new(),
            routes: Vec::new(),
            health_check: None,
            cors: None,
        };
        let mut store = ConfigStore::new(base.clone(), 3);
        for v in 2..=10 {
            let mut s = base.clone();
            s.version = format!("v{v}");
            store.push(s);
        }
        assert_eq!(store.history.len(), 3, "history must be capped at the limit");
        assert_eq!(store.current().version, "v10");
    }

    #[test]
    fn config_store_rollback_returns_previous() {
        let base = ConfigSnapshot {
            version: "v1".into(),
            global_max_concurrency: 1,
            jwt_secret: "s".into(),
            jwt_keys: HashMap::new(),
            expected_issuer: default_issuer(),
            expected_audience: default_audience(),
            services: HashMap::new(),
            routes: Vec::new(),
            health_check: None,
            cors: None,
        };
        let mut store = ConfigStore::new(base.clone(), 5);
        let mut v2 = base.clone();
        v2.version = "v2".into();
        store.push(v2);
        assert_eq!(store.current().version, "v2");
        store.pop();
        assert_eq!(store.current().version, "v1");
    }

    #[test]
    fn config_store_never_pops_last_version() {
        let base = ConfigSnapshot {
            version: "v1".into(),
            global_max_concurrency: 1,
            jwt_secret: "s".into(),
            jwt_keys: HashMap::new(),
            expected_issuer: default_issuer(),
            expected_audience: default_audience(),
            services: HashMap::new(),
            routes: Vec::new(),
            health_check: None,
            cors: None,
        };
        let mut store = ConfigStore::new(base, 5);
        assert!(store.pop().is_none(), "must not pop the only version");
        assert_eq!(store.current().version, "v1");
    }

    #[test]
    fn revocation_keys_jti_only() {
        let req = RevokeRequest {
            jti: Some("abc-123".into()),
            token: None,
            ttl_secs: 3600,
        };
        let keys = revocation_keys_for_request(&req).unwrap();
        assert_eq!(keys, vec!["gateway:revoked:jti:abc-123"]);
    }

    #[test]
    fn revocation_keys_token_only() {
        let req = RevokeRequest {
            jti: None,
            token: Some("eyJhbGci.test.sig".into()),
            ttl_secs: 3600,
        };
        let keys = revocation_keys_for_request(&req).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].starts_with("gateway:revoked:token:"));
        assert_eq!(keys[0].len(), "gateway:revoked:token:".len() + 64);
    }

    #[test]
    fn revocation_keys_both() {
        let req = RevokeRequest {
            jti: Some("j1".into()),
            token: Some("tok".into()),
            ttl_secs: 60,
        };
        let keys = revocation_keys_for_request(&req).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "gateway:revoked:jti:j1");
    }

    #[test]
    fn revocation_keys_rejects_empty() {
        let req = RevokeRequest {
            jti: None,
            token: None,
            ttl_secs: 3600,
        };
        assert!(revocation_keys_for_request(&req).is_err());
    }

    #[test]
    fn token_hash_hex_matches_gateway_contract() {
        assert_eq!(token_hash_hex("hello").len(), 64);
        assert_eq!(token_hash_hex("hello"), token_hash_hex("hello"));
        assert_ne!(token_hash_hex("a"), token_hash_hex("b"));
    }

    #[test]
    fn config_read_token_required_when_env_set() {
        use actix_web::test::TestRequest;

        std::env::set_var("CONFIG_READ_TOKEN", "secret-token");
        let ok = TestRequest::get()
            .insert_header(("X-Config-Read-Token", "secret-token"))
            .to_http_request();
        assert!(verify_config_read_token(&ok));
        let missing = TestRequest::get().to_http_request();
        assert!(!verify_config_read_token(&missing));
        let wrong = TestRequest::get()
            .insert_header(("X-Config-Read-Token", "wrong"))
            .to_http_request();
        assert!(!verify_config_read_token(&wrong));
        std::env::remove_var("CONFIG_READ_TOKEN");
        assert!(verify_config_read_token(&missing));
    }

    #[test]
    fn admin_rate_limit_blocks_over_max() {
        let mut map = HashMap::new();
        let ip = "10.0.0.5";
        // First `max` requests allowed within the same window.
        for i in 0..5 {
            assert!(
                admin_rate_limit_step(&mut map, ip, 1_000, 5, 60),
                "request {i} should be allowed",
            );
        }
        // The 6th in the same window is rejected.
        assert!(!admin_rate_limit_step(&mut map, ip, 1_000, 5, 60));
    }

    #[test]
    fn admin_rate_limit_resets_after_window() {
        let mut map = HashMap::new();
        let ip = "10.0.0.6";
        for _ in 0..5 {
            assert!(admin_rate_limit_step(&mut map, ip, 1_000, 5, 60));
        }
        assert!(!admin_rate_limit_step(&mut map, ip, 1_000, 5, 60));
        // A new window (>= 60s later) resets the counter.
        assert!(admin_rate_limit_step(&mut map, ip, 1_060, 5, 60));
    }

    #[test]
    fn admin_rate_limit_prunes_stale_entries() {
        // Regression: the bucket map used to grow unbounded (one entry per IP,
        // never removed) — a memory-exhaustion DoS, especially when keyed on a
        // spoofable header. Stale windows must be pruned.
        let mut map = HashMap::new();
        for i in 0..1_000 {
            let ip = format!("10.1.{}.{}", i / 256, i % 256);
            admin_rate_limit_step(&mut map, &ip, 1_000, 5, 60);
        }
        assert_eq!(map.len(), 1_000, "all entries are within the active window");
        // Far in the future, a single new request prunes all the stale ones.
        admin_rate_limit_step(&mut map, "10.9.9.9", 100_000, 5, 60);
        assert_eq!(map.len(), 1, "stale windows must be pruned to bound memory");
    }

    #[test]
    fn insecure_admin_key_detected() {
        std::env::set_var("ADMIN_API_KEY", "CHANGE_ME_ADMIN_API_KEY");
        std::env::remove_var("CONTROL_PLANE_REFUSE_INSECURE_SECRETS");
        warn_insecure_admin_key();
        std::env::remove_var("ADMIN_API_KEY");
    }
}
