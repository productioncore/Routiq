use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};

pub static POLLS: AtomicU64 = AtomicU64::new(0);
pub static UPDATES: AtomicU64 = AtomicU64::new(0);
pub static ERRORS: AtomicU64 = AtomicU64::new(0);
// Sync-agent gauges/counters (snapshot → SSE → reconcile model).
pub static CURRENT_REVISION: AtomicU64 = AtomicU64::new(0);
pub static CP_REVISION: AtomicU64 = AtomicU64::new(0);
pub static SSE_CONNECTED: AtomicU64 = AtomicU64::new(0);
pub static RECONNECTS: AtomicU64 = AtomicU64::new(0);
pub static RECONCILES: AtomicU64 = AtomicU64::new(0);
pub static RECONCILE_DRIFTS: AtomicU64 = AtomicU64::new(0);
pub static VALIDATION_FAILURES: AtomicU64 = AtomicU64::new(0);
pub static LAST_SYNC_UNIX: AtomicU64 = AtomicU64::new(0);

pub fn inc_polls() {
    POLLS.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_updates() {
    UPDATES.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_errors() {
    ERRORS.fetch_add(1, Ordering::Relaxed);
}

pub fn set_current_revision(rev: u64) {
    CURRENT_REVISION.store(rev, Ordering::Relaxed);
}

pub fn set_cp_revision(rev: u64) {
    CP_REVISION.fetch_max(rev, Ordering::Relaxed);
}

pub fn set_sse_connected(connected: bool) {
    SSE_CONNECTED.store(u64::from(connected), Ordering::Relaxed);
}

pub fn inc_reconnects() {
    RECONNECTS.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_reconciles() {
    RECONCILES.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_reconcile_drifts() {
    RECONCILE_DRIFTS.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_validation_failures() {
    VALIDATION_FAILURES.fetch_add(1, Ordering::Relaxed);
}

pub fn set_last_sync_unix(ts: u64) {
    LAST_SYNC_UNIX.store(ts, Ordering::Relaxed);
}

fn metrics_body() -> String {
    format!(
        "# HELP config_sidecar_up Sidecar process is up\n\
         # TYPE config_sidecar_up gauge\n\
         config_sidecar_up 1\n\
         # HELP config_sidecar_polls_total Snapshot fetch attempts toward control plane\n\
         # TYPE config_sidecar_polls_total counter\n\
         config_sidecar_polls_total {}\n\
         # HELP config_sidecar_updates_total Successful config file writes\n\
         # TYPE config_sidecar_updates_total counter\n\
         config_sidecar_updates_total {}\n\
         # HELP config_sidecar_errors_total Fetch, stream or write failures\n\
         # TYPE config_sidecar_errors_total counter\n\
         config_sidecar_errors_total {}\n\
         # HELP config_sidecar_current_revision Currently active local config revision\n\
         # TYPE config_sidecar_current_revision gauge\n\
         config_sidecar_current_revision {}\n\
         # HELP config_sidecar_cp_revision Highest control-plane revision observed\n\
         # TYPE config_sidecar_cp_revision gauge\n\
         config_sidecar_cp_revision {}\n\
         # HELP config_sidecar_lag_revisions CP revision minus active revision\n\
         # TYPE config_sidecar_lag_revisions gauge\n\
         config_sidecar_lag_revisions {}\n\
         # HELP config_sidecar_sse_connected SSE stream currently connected (0/1)\n\
         # TYPE config_sidecar_sse_connected gauge\n\
         config_sidecar_sse_connected {}\n\
         # HELP config_sidecar_reconnects_total SSE reconnect attempts\n\
         # TYPE config_sidecar_reconnects_total counter\n\
         config_sidecar_reconnects_total {}\n\
         # HELP config_sidecar_reconciles_total Periodic reconciliation runs\n\
         # TYPE config_sidecar_reconciles_total counter\n\
         config_sidecar_reconciles_total {}\n\
         # HELP config_sidecar_reconcile_drifts_total Reconciliations that found drift\n\
         # TYPE config_sidecar_reconcile_drifts_total counter\n\
         config_sidecar_reconcile_drifts_total {}\n\
         # HELP config_sidecar_validation_failures_total Snapshots rejected by validation\n\
         # TYPE config_sidecar_validation_failures_total counter\n\
         config_sidecar_validation_failures_total {}\n\
         # HELP config_sidecar_last_sync_unix Unix time of last successful activation\n\
         # TYPE config_sidecar_last_sync_unix gauge\n\
         config_sidecar_last_sync_unix {}\n",
        POLLS.load(Ordering::Relaxed),
        UPDATES.load(Ordering::Relaxed),
        ERRORS.load(Ordering::Relaxed),
        CURRENT_REVISION.load(Ordering::Relaxed),
        CP_REVISION.load(Ordering::Relaxed),
        CP_REVISION
            .load(Ordering::Relaxed)
            .saturating_sub(CURRENT_REVISION.load(Ordering::Relaxed)),
        SSE_CONNECTED.load(Ordering::Relaxed),
        RECONNECTS.load(Ordering::Relaxed),
        RECONCILES.load(Ordering::Relaxed),
        RECONCILE_DRIFTS.load(Ordering::Relaxed),
        VALIDATION_FAILURES.load(Ordering::Relaxed),
        LAST_SYNC_UNIX.load(Ordering::Relaxed),
    )
}

fn handle_connection(mut stream: std::net::TcpStream) {
    let mut buf = [0u8; 512];
    let _ = stream.read(&mut buf);
    let body = metrics_body();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Minimal Prometheus scrape server for internal Docker/K8s networks.
/// Bind to `127.0.0.1` on Render (`METRICS_BIND=127.0.0.1`) so the platform
/// does not treat metrics as the public web port.
pub fn spawn_metrics_server(bind: &str, port: u16) {
    let bind = bind.to_string();
    std::thread::spawn(move || {
        let addr = format!("{bind}:{port}");
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("config-sidecar metrics bind failed on {addr}: {e}");
                return;
            }
        };
        eprintln!("config-sidecar metrics listening on {addr}");
        for stream in listener.incoming().flatten() {
            handle_connection(stream);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_body_contains_counters() {
        POLLS.store(3, Ordering::Relaxed);
        UPDATES.store(1, Ordering::Relaxed);
        ERRORS.store(2, Ordering::Relaxed);
        let body = metrics_body();
        assert!(body.contains("config_sidecar_polls_total 3"));
        assert!(body.contains("config_sidecar_updates_total 1"));
        assert!(body.contains("config_sidecar_errors_total 2"));
    }

    #[test]
    fn metrics_body_reports_revision_lag() {
        CURRENT_REVISION.store(105, Ordering::Relaxed);
        CP_REVISION.store(108, Ordering::Relaxed);
        SSE_CONNECTED.store(1, Ordering::Relaxed);
        let body = metrics_body();
        assert!(body.contains("config_sidecar_current_revision 105"));
        assert!(body.contains("config_sidecar_cp_revision 108"));
        assert!(body.contains("config_sidecar_lag_revisions 3"));
        assert!(body.contains("config_sidecar_sse_connected 1"));
        CURRENT_REVISION.store(0, Ordering::Relaxed);
        CP_REVISION.store(0, Ordering::Relaxed);
        SSE_CONNECTED.store(0, Ordering::Relaxed);
    }
}
