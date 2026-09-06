//! Config sync — local file watch, fed by the per-node config sidecar.
//!
//! Why a file watch (not per-worker HTTP polling)?
//!   - Each NGINX worker runs this watcher, but they only `stat()` a local file
//!     once per second — effectively free (served from the OS dentry cache).
//!   - A single per-node `config-sidecar` is the only process that talks to the
//!     control plane over HTTP. With N nodes × W workers, the control plane sees
//!     N requests/interval instead of N×W — no thundering herd at fleet scale.
//!   - The sidecar writes atomically (temp file + rename), so a worker never
//!     observes a half-written config.
//!
//! See: docs/decisions/0012-config-distribution-sidecar-file-watch.md
//!
//! Secrets are NEVER distributed through this file. The control plane strips
//! `jwt_secret`/`jwt_keys` from its API responses; the gateway sources them from
//! its own environment / secret manager. See:
//! docs/decisions/0013-secrets-via-environment-not-config-wire.md

use arc_swap::ArcSwap;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

// ── Data types ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Upstream {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub weight: usize,
    /// Version label for canary routing (ADR-0063), e.g. "canary" | "stable".
    #[serde(default)]
    pub version: String,
}

/// Canary rollout policy (ADR-0063). Absent = whole pool treated as stable.
/// Stickiness convention: header `X-Canary` or cookie `gateway_canary` set to
/// the policy version pins that client to canary members.
#[derive(Debug, Deserialize, Clone)]
pub struct CanaryPolicy {
    pub version: String,
    #[serde(default)]
    pub percent: u32,
}
impl CanaryPolicy {
    pub fn effective_percent(&self) -> u32 { self.percent.min(100) }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    pub path_prefix: String,
    pub service_name: String,
    #[serde(default)]
    pub strip_prefix: bool,
    /// Timeout-policy tier (ADR-0062): "fast" | "normal" | "slow".
    #[serde(default)]
    pub tier: String,
    /// Per-route body validation policy (ADR-0064). Absent = no validation.
    #[serde(default)]
    pub validation: Option<crate::validate::ValidationConfig>,
}

impl Route {
    pub fn effective_tier(&self) -> &str {
        match self.tier.as_str() {
            "fast" | "slow" => self.tier.as_str(),
            _ => "normal",
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub rate_limit_max: usize,
    pub regional_upstreams: HashMap<String, Vec<Upstream>>,
    pub require_auth: bool,
    #[serde(default)]
    pub canary: Option<CanaryPolicy>,
    /// Per-user daily quota (ADR-0066). Absent = unlimited.
    #[serde(default)]
    pub quota: Option<QuotaPolicy>,
}

/// Daily per-user request ceiling (ADR-0066).
#[derive(Debug, Deserialize, Clone)]
pub struct QuotaPolicy {
    pub daily_limit: u64,
    /// Grace borrowing (ADR-0073): allow up to this % of the daily limit as
    /// borrowed requests once the limit is exhausted, instead of hard-429ing.
    /// 0 = strict cut-off. Borrowed usage is counted in QUOTA_BORROWED_TOTAL.
    #[serde(default)]
    pub borrow_percent: u32,
}

/// Dynamic CORS policy (ADR-0068) — distributed via config hot-reload so
/// origins change without redeploying the gateway.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CorsConfig {
    /// Exact origins, or "*" for wildcard. Empty list = deny all CORS.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "ct_true")]
    pub allow_credentials: bool,
    #[serde(default = "ct_methods")]
    pub allowed_methods: String,
    #[serde(default = "ct_headers")]
    pub allowed_headers: String,
    #[serde(default = "ct_max_age")]
    pub max_age: u32,
}
fn ct_true() -> bool { true }
fn ct_methods() -> String { "GET, POST, PUT, PATCH, DELETE, OPTIONS".to_string() }
fn ct_headers() -> String {
    "Content-Type, Authorization, X-Requested-With, Accept, Origin, X-CSRF-Token, X-Canary, X-Request-ID, traceparent".to_string()
}
fn ct_max_age() -> u32 { 600 }

/// Active health-check policy (ADR-0061). Absent = disabled.
#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheckConfig {
    #[serde(default = "hc_true")]
    pub enabled: bool,
    #[serde(default = "hc_path")]
    pub path: String,
    #[serde(default = "hc_interval")]
    pub interval_secs: u64,
    #[serde(default = "hc_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "hc_unhealthy")]
    pub unhealthy_threshold: u32,
    #[serde(default = "hc_healthy")]
    pub healthy_threshold: u32,
}
fn hc_true() -> bool { true }
fn hc_path() -> String { "/health".to_string() }
fn hc_interval() -> u64 { 10 }
fn hc_timeout() -> u64 { 2_000 }
fn hc_unhealthy() -> u32 { 3 }
fn hc_healthy() -> u32 { 2 }

#[derive(Debug, Deserialize, Clone)]
pub struct GatewayConfig {
    pub version: String,
    pub global_max_concurrency: usize,

    /// Primary JWT secret (used when a token has no `kid` header).
    ///
    /// Sourced from the `JWT_SECRET` environment variable at load time — the
    /// control plane never serves this over the wire. The `serde(default)`
    /// exists only so configs that omit the field (i.e. every config served by
    /// the control plane) still deserialize cleanly.
    #[serde(default = "default_secret")]
    pub jwt_secret: String,

    /// Named JWT keys for zero-downtime rotation (kid → HMAC-SHA256 secret).
    /// Tokens carrying a `kid` header are validated against this map.
    #[serde(default)]
    pub jwt_keys: HashMap<String, String>,

    /// Expected `iss` claim. Tokens with a different issuer are rejected.
    #[serde(default = "default_issuer")]
    pub expected_issuer: String,

    /// Expected `aud` claim. Tokens with a different audience are rejected.
    #[serde(default = "default_audience")]
    pub expected_audience: String,

    pub services: HashMap<String, ServiceConfig>,
    pub routes: Vec<Route>,

    /// Active upstream health probing (ADR-0061). None = disabled.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    /// Dynamic CORS policy (ADR-0068). None = edge emits no CORS headers.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
}

fn default_secret() -> String { "default_secret".to_string() }
fn default_issuer() -> String { "api-gateway-auth-server".to_string() }
fn default_audience() -> String { "api-gateway-clients".to_string() }

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            version: "v0".to_string(),
            global_max_concurrency: 10_000,
            jwt_secret: default_secret(),
            jwt_keys: HashMap::new(),
            expected_issuer: default_issuer(),
            expected_audience: default_audience(),
            services: HashMap::new(),
            routes: Vec::new(),
            health_check: None,
            cors: None,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_CONFIG: ArcSwap<GatewayConfig> =
        ArcSwap::from_pointee(GatewayConfig::default());
}

/// Path to the config file written by the per-node config sidecar.
/// Override with `GATEWAY_CONFIG_PATH` (defaults to `<tmp>/gateway_config.json`).
fn config_path() -> std::path::PathBuf {
    match std::env::var("GATEWAY_CONFIG_PATH") {
        Ok(p) if !p.is_empty() => std::path::PathBuf::from(p),
        _ => std::env::temp_dir().join("gateway_config.json"),
    }
}

/// Inject runtime secrets that are deliberately absent from the distributed
/// config. The control plane never serves `jwt_secret` / `jwt_keys`, so the
/// gateway pulls them from its own environment here.
///
/// `jwt_keys` (for `kid`-based zero-downtime rotation) MUST also come from the
/// environment — without this they would always be empty and every token
/// carrying a `kid` header would be rejected (auth.rs looks the kid up here).
fn apply_secret_overrides(cfg: &mut GatewayConfig) {
    if let Ok(secret) = std::env::var("JWT_SECRET") {
        if !secret.is_empty() {
            cfg.jwt_secret = secret;
        }
    }
    if let Ok(keys_json) = std::env::var("JWT_KEYS") {
        if let Some(keys) = parse_jwt_keys(&keys_json) {
            cfg.jwt_keys = keys;
        }
    }
    // CORS_ALLOWED_ORIGINS: comma-separated list of origins to allow.
    // Merges with (or creates) the cors section from the control plane config.
    // Example: CORS_ALLOWED_ORIGINS=https://app1.com,https://app2.com
    if let Ok(origins_csv) = std::env::var("CORS_ALLOWED_ORIGINS") {
        let env_origins: Vec<String> = origins_csv
            .split(',')
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty())
            .collect();
        if !env_origins.is_empty() {
            match cfg.cors.as_mut() {
                Some(cors) => {
                    for origin in &env_origins {
                        if !cors.allowed_origins.iter().any(|o| o.eq_ignore_ascii_case(origin)) {
                            cors.allowed_origins.push(origin.clone());
                        }
                    }
                }
                None => {
                    cfg.cors = Some(CorsConfig {
                        allowed_origins: env_origins,
                        allow_credentials: true,
                        allowed_methods: "GET, POST, PUT, PATCH, DELETE, OPTIONS".to_string(),
                        allowed_headers: "Content-Type, Authorization, X-Requested-With, Accept, Origin, X-CSRF-Token, X-Canary, X-Request-ID, traceparent".to_string(),
                        max_age: 600,
                    });
                }
            }
        }
    }
    // UPSTREAM_<SERVICE>: override upstream addresses per service.
    // In Docker Compose the control plane uses internal DNS names (uam-backend:8080).
    // In production (Render, K8s) each service has a public URL.
    // Set UPSTREAM_UAM_AUTH=https://uam-backend.onrender.com:443 to redirect
    // all uam-auth traffic to that URL. Applies to ALL regions for the service.
    // Example: UPSTREAM_UAM_AUTH=https://uam-backend.onrender.com:443
    for (service_name, service) in cfg.services.iter_mut() {
        let env_key = format!("UPSTREAM_{}", service_name.to_uppercase().replace('-', "_"));
        if let Ok(upstream_url) = std::env::var(&env_key) {
            if !upstream_url.is_empty() {
                for (_region, upstreams) in service.regional_upstreams.iter_mut() {
                    for upstream in upstreams.iter_mut() {
                        upstream.address = upstream_url.clone();
                    }
                }
                eprintln!("[config] upstream override: {} → {}", service_name, upstream_url);
            }
        }
    }
}

/// Parse the `JWT_KEYS` env var: a JSON object mapping `kid` → HMAC secret,
/// e.g. `{"2026-q1":"secret-a","2026-q2":"secret-b"}`.
///
/// Returns `None` for empty/blank input or invalid JSON (caller keeps existing
/// keys) so a malformed value can never crash a worker — it just disables
/// rotation, which is a loud, safe failure (kid tokens get rejected) rather than
/// a silent acceptance.
fn parse_jwt_keys(raw: &str) -> Option<HashMap<String, String>> {
    if raw.trim().is_empty() {
        return None;
    }
    match serde_json::from_str::<HashMap<String, String>>(raw) {
        Ok(keys) if !keys.is_empty() => Some(keys),
        Ok(_) => None,
        Err(_) => {
            eprintln!("[config] JWT_KEYS is not a valid JSON object of kid→secret; ignoring");
            None
        }
    }
}

/// Load config from disk if present. Returns true when a new snapshot was applied.
fn try_reload_config(path: &std::path::Path, last_modified: &mut SystemTime) -> bool {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let modified = match metadata.modified() {
        Ok(m) => m,
        Err(_) => return false,
    };
    if modified <= *last_modified {
        return false;
    }
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let mut new_config = match serde_json::from_str::<GatewayConfig>(&data) {
        Ok(c) => c,
        Err(_) => return false,
    };
    apply_secret_overrides(&mut new_config);
    crate::router::update_router(&new_config);
    GLOBAL_CONFIG.store(Arc::new(new_config));
    *last_modified = modified;
    true
}

/// True once a non-default config snapshot has been loaded (routes present).
pub fn is_config_ready() -> bool {
    let cfg = GLOBAL_CONFIG.load();
    cfg.version != "v0" && !cfg.routes.is_empty()
}

pub fn start_config_sync() {
    thread::spawn(|| {
        let path = config_path();
        let mut last_modified = SystemTime::UNIX_EPOCH;

        // Eager load on worker start — do not wait for the next mtime tick.
        try_reload_config(&path, &mut last_modified);

        loop {
            try_reload_config(&path, &mut last_modified);
            thread::sleep(Duration::from_secs(1));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jwt_keys_valid_object() {
        let keys = parse_jwt_keys(r#"{"k1":"secret-a","k2":"secret-b"}"#).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.get("k1").map(String::as_str), Some("secret-a"));
        assert_eq!(keys.get("k2").map(String::as_str), Some("secret-b"));
    }

    #[test]
    fn parse_jwt_keys_empty_or_blank_is_none() {
        assert!(parse_jwt_keys("").is_none());
        assert!(parse_jwt_keys("   ").is_none());
        assert!(parse_jwt_keys("{}").is_none());
    }

    #[test]
    fn parse_jwt_keys_invalid_json_is_none() {
        // Must not panic — a bad value disables rotation, never crashes a worker.
        assert!(parse_jwt_keys("not json").is_none());
        assert!(parse_jwt_keys(r#"{"k1":123}"#).is_none()); // value not a string
        assert!(parse_jwt_keys(r#"["a","b"]"#).is_none());  // array, not object
    }

    #[test]
    fn apply_secret_overrides_loads_jwt_keys_from_env() {
        // Regression: jwt_keys are stripped from the config wire, so without this
        // env injection kid-based rotation is dead (every kid token rejected).
        std::env::set_var("JWT_KEYS", r#"{"rot-1":"s1"}"#);
        let mut cfg = GatewayConfig::default();
        assert!(cfg.jwt_keys.is_empty());
        apply_secret_overrides(&mut cfg);
        assert_eq!(cfg.jwt_keys.get("rot-1").map(String::as_str), Some("s1"));
        std::env::remove_var("JWT_KEYS");
    }

    #[test]
    fn is_config_ready_requires_version_and_routes() {
        let mut cfg = GatewayConfig::default();
        assert!(!is_config_ready_for(&cfg));
        cfg.version = "v1".into();
        assert!(!is_config_ready_for(&cfg)); // no routes yet
        cfg.routes.push(Route {
            path_prefix: "/".into(),
            service_name: "s".into(),
            strip_prefix: false,
            tier: String::new(),
            validation: None,
        });
        assert!(is_config_ready_for(&cfg));
    }

    #[test]
    fn cors_env_var_merges_into_config() {
        std::env::set_var("CORS_ALLOWED_ORIGINS", "https://a.com, https://b.com");
        let mut cfg = GatewayConfig::default();
        assert!(cfg.cors.is_none());
        apply_secret_overrides(&mut cfg);
        let cors = cfg.cors.unwrap();
        assert_eq!(cors.allowed_origins.len(), 2);
        assert!(cors.allowed_origins.contains(&"https://a.com".to_string()));
        assert!(cors.allowed_origins.contains(&"https://b.com".to_string()));
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    fn cors_env_var_appends_to_existing() {
        std::env::set_var("CORS_ALLOWED_ORIGINS", "https://new.com");
        let mut cfg = GatewayConfig::default();
        cfg.cors = Some(CorsConfig {
            allowed_origins: vec!["https://existing.com".to_string()],
            ..Default::default()
        });
        apply_secret_overrides(&mut cfg);
        let cors = cfg.cors.unwrap();
        assert_eq!(cors.allowed_origins.len(), 2);
        assert!(cors.allowed_origins.contains(&"https://existing.com".to_string()));
        assert!(cors.allowed_origins.contains(&"https://new.com".to_string()));
        std::env::remove_var("CORS_ALLOWED_ORIGINS");
    }

    #[test]
    fn upstream_env_var_overrides_service_address() {
        std::env::set_var("UPSTREAM_UAM_AUTH", "https://uam-backend.onrender.com:443");
        let mut cfg = GatewayConfig::default();
        let mut regional = HashMap::new();
        regional.insert("US".to_string(), vec![Upstream {
            name: "uam-backend".to_string(),
            address: "uam-backend:8080".to_string(),
            weight: 10,
            version: String::new(),
        }]);
        cfg.services.insert("uam-auth".to_string(), ServiceConfig {
            name: "uam-auth".to_string(),
            rate_limit_max: 2000,
            regional_upstreams: regional,
            require_auth: false,
            canary: None,
            quota: None,
        });
        apply_secret_overrides(&mut cfg);
        let addr = &cfg.services["uam-auth"].regional_upstreams["US"][0].address;
        assert_eq!(addr, "https://uam-backend.onrender.com:443");
        std::env::remove_var("UPSTREAM_UAM_AUTH");
    }
}

/// Pure readiness check on a given config — testable counterpart of
/// [`is_config_ready`] (which reads the global).
#[cfg(test)]
fn is_config_ready_for(cfg: &GatewayConfig) -> bool {
    cfg.version != "v0" && !cfg.routes.is_empty()
}
