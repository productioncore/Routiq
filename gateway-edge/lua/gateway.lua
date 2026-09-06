-- ============================================================
-- gateway.lua — OpenResty ⇄ Rust FFI bridge for the hot path
--
-- This module is the *only* glue between NGINX and the Rust data plane
-- (librust_ext.so). It is intentionally thin: all decisions (WAF, auth,
-- routing, rate limiting, load balancing, backpressure) happen in Rust.
--
-- Lifecycle:
--   * Required once in init_by_lua  → runs ffi.cdef + ffi.load (process-wide).
--   * .init() called in init_worker → starts Rust background threads per worker.
--   * .access() runs in access_by_lua → the per-request hot path.
--   * .log()    runs in log_by_lua    → telemetry + backpressure slot release.
--   * .metrics() runs in content_by_lua of /metrics.
--
-- See: docs/decisions/0002-lua-ffi-data-plane-over-native-module.md
-- ============================================================

local ffi = require "ffi"

-- C ABI of librust_ext.so. Must stay in sync with gateway/rust-ext/src/lib.rs.
ffi.cdef [[
void  init_extension(void);
int   process_request(const char* auth_header, const char* path,
                      const char* user_agent,  const char* body, size_t body_len,
                      const char* client_ip,   const char* canary_hint,
                      const char* content_type,
                      char* region_out,   size_t region_out_len,
                      char* upstream_out, size_t upstream_out_len,
                      char* req_id_out,   size_t req_id_out_len,
                      char* user_id_out,  size_t user_id_out_len,
                      char* home_region_out, size_t home_region_out_len,
                      char* tier_out,     size_t tier_out_len);
void  report_telemetry(int status, size_t latency_us, const char* upstream);
int   get_cors_headers(const char* origin, char* buf, size_t len);
void  release_slot(void);
int   is_ready(void);
int   get_config_version(char* buf, size_t len);
char* get_metrics_string(void);
void  free_metrics_string(char* p);
]]

-- Loads librust_ext.so via the dynamic linker (must be on the loader path).
local lib = ffi.load("rust_ext")

local M = { lib = lib }

-- Per-worker scratch buffers. An NGINX worker handles a single request between
-- the FFI call and the ffi.string() copy with no yield in between, so reusing
-- these is safe and avoids a per-request allocation.
local REGION_LEN, UPSTREAM_LEN, REQID_LEN = 16, 256, 40
local USER_ID_LEN, HOME_REGION_LEN = 128, 16
local TIER_LEN = 16

-- Bytes of the request body handed to the WAF. Must match MAX_BODY_SCAN_LEN in
-- gateway/rust-ext/src/waf.rs — the Rust WAF only scans the first 8KB, so we
-- never need to read more than that from a spooled body file.
local WAF_BODY_SCAN_BYTES = 8192
local region_buf   = ffi.new("char[?]", REGION_LEN)
local upstream_buf = ffi.new("char[?]", UPSTREAM_LEN)
local reqid_buf    = ffi.new("char[?]", REQID_LEN)
local user_id_buf  = ffi.new("char[?]", USER_ID_LEN)
local home_region_buf = ffi.new("char[?]", HOME_REGION_LEN)
local tier_buf     = ffi.new("char[?]", TIER_LEN)
local CORS_LEN     = 512
local cors_buf     = ffi.new("char[?]", CORS_LEN)

-- ── Dynamic CORS (ADR-0068) ──────────────────────────────────────────────
-- Origins/methods/headers come from the hot-reloaded config via Rust.
-- Preflight OPTIONS is answered here (204) and never reaches a backend.
local function apply_cors()
    local origin = ngx.var.http_origin
    if not origin or origin == "" then return end

    local n = lib.get_cors_headers(origin, cors_buf, CORS_LEN)
    local packed = ffi.string(cors_buf, n)
    if packed == "" then
        -- Origin not allow-listed: emit nothing; browser blocks the response.
        if ngx.req.get_method() == "OPTIONS" then
            ngx.status = 403
            ngx.header["Content-Length"] = "0"
            return ngx.exit(403)
        end
        return
    end

    local parts = {}
    local pos = 1
    while true do
        local s, e = packed:find("\x1f", pos, true)
        if not s then parts[#parts + 1] = packed:sub(pos); break end
        parts[#parts + 1] = packed:sub(pos, s - 1)
        pos = e + 1
    end

    ngx.header["Access-Control-Allow-Origin"] = parts[1]
    if parts[5] == "true" then
        ngx.header["Access-Control-Allow-Credentials"] = "true"
    end
    ngx.header["Vary"] = "Origin"
    if ngx.req.get_method() == "OPTIONS" then
        ngx.header["Access-Control-Allow-Methods"] = parts[2]
        ngx.header["Access-Control-Allow-Headers"] = parts[3]
        ngx.header["Access-Control-Max-Age"] = parts[4]
        if parts[5] == "true" then
            ngx.header["Access-Control-Allow-Credentials"] = "true"
        end
        ngx.status = 204
        ngx.header["Content-Length"] = "0"
        return ngx.exit(204)
    end
end

local ERROR_BODIES = {
    [400] = '{"error":"Bad Request"}',
    [401] = '{"error":"Unauthorized"}',
    [403] = '{"error":"Forbidden"}',
    [404] = '{"error":"Not Found"}',
    [429] = '{"error":"Too Many Requests"}',
    [500] = '{"error":"Internal Server Error"}',
    [503] = '{"error":"Service Unavailable"}',
}

-- Start the Rust background workers (config watcher, telemetry, etc.).
-- Must run post-fork (init_worker), because threads do not survive fork().
function M.init()
    lib.init_extension()
end

-- Hot path. Returns nothing; either sets target vars and falls through to
-- proxy_pass, or short-circuits with an error status.
function M.access()
    local var  = ngx.var
    var.gateway_request_id = ""
    var.gateway_user_id = ""
    var.gateway_home_region = ""
    -- CORS preflight/headers first (ADR-0068) — preflights never hit backends.
    apply_cors()
    -- Strip client-supplied identity headers before auth (ADR-0040, ADR-0048).
    -- Upstream only receives values the gateway sets after JWT validation.
    ngx.req.clear_header("X-User-Id")
    ngx.req.clear_header("X-Home-Region")
    local auth = var.http_authorization or ""
    -- Full request URI (path + query) so the WAF can inspect query strings.
    -- Rust strips the query before routing.
    local path = var.request_uri or var.uri or "/"
    local ua   = var.http_user_agent or ""
    local ip   = var.remote_addr or ""

    -- Only buffer a body for methods that carry one — keeps GET/HEAD allocation-free.
    local body = ""
    local method = ngx.req.get_method()
    if method == "POST" or method == "PUT" or method == "PATCH" then
        ngx.req.read_body()
        body = ngx.req.get_body_data()
        if not body then
            -- Body exceeded client_body_buffer_size and was spooled to a temp file,
            -- so get_body_data() is nil. Without this, the WAF would inspect an
            -- EMPTY body — an attacker could pad a payload past the buffer size to
            -- bypass body inspection. Read just the WAF scan window (8KB) from disk.
            local body_file = ngx.req.get_body_file()
            if body_file then
                local f = io.open(body_file, "rb")
                if f then
                    body = f:read(WAF_BODY_SCAN_BYTES)
                    f:close()
                end
            end
            body = body or ""
        end
    end

    -- Pass the body length explicitly (#body counts embedded NUL bytes). The Rust
    -- side reconstructs the body from ptr+len instead of treating it as a C string,
    -- so a payload after a NUL byte cannot bypass WAF body inspection.
    -- Canary stickiness hint: X-Canary header or gateway_canary cookie (ADR-0063).
    local canary = var.http_x_canary or var.cookie_gateway_canary or ""
    local code = tonumber(lib.process_request(
        auth, path, ua, body, #body, ip, canary, var.content_type or "",
        region_buf,   REGION_LEN,
        upstream_buf, UPSTREAM_LEN,
        reqid_buf,    REQID_LEN,
        user_id_buf,  USER_ID_LEN,
        home_region_buf, HOME_REGION_LEN,
        tier_buf,     TIER_LEN))

    local req_id = ffi.string(reqid_buf)
    ngx.ctx.request_id = req_id
    ngx.var.gateway_request_id = req_id
    ngx.req.set_header("X-Request-ID", req_id)

    -- W3C Trace Context: pass through client traceparent when present (ADR-0032).
    local traceparent = var.http_traceparent
    if traceparent and traceparent ~= "" then
        ngx.req.set_header("traceparent", traceparent)
    end

    if code ~= 200 then
        ngx.status = code
        ngx.header["Content-Type"] = "application/json"
        ngx.header["X-Request-ID"] = req_id
        if code == 429 or code == 503 then
            ngx.header["Retry-After"] = "1"
        end
        local body = ERROR_BODIES[code] or '{"error":"Request rejected"}'
        -- For server errors (5xx), attach a stack trace for debugging
        if code >= 500 then
            local stack = debug.traceback()
            ngx.log(ngx.ERR, "Gateway error (", code, "): ", body, " stack: ", stack)
            local json = require "cjson"
            body = json.encode({ error = body:match('"error":"([^"]+)"'), stack = stack })
        end
        ngx.say(body)
        return ngx.exit(code)
    end

    -- Admitted: the Rust backpressure slot is held until M.log() releases it.
    ngx.ctx.admitted   = true
    var.target_region   = ffi.string(region_buf)
    var.target_upstream = ffi.string(upstream_buf)
    local tier = ffi.string(tier_buf)
    if tier ~= "fast" and tier ~= "slow" then tier = "normal" end
    var.target_tier     = tier
    local uid = ffi.string(user_id_buf)
    local home = ffi.string(home_region_buf)
    var.gateway_user_id = uid
    var.gateway_home_region = home
    if uid ~= "" then
        ngx.req.set_header("X-User-Id", uid)
    end
    if home ~= "" then
        ngx.req.set_header("X-Home-Region", home)
    end

    -- Jump to the timeout-policy location for this route (ADR-0062).
    -- Named locations carry per-tier proxy budgets; method/body preserved.
    return ngx.exec("@up_" .. tier)
end

-- Runs for every request to `location /` (success or early-rejected).
function M.log()
    local status     = tonumber(ngx.var.status) or 0
    local latency_us = math.floor((tonumber(ngx.var.request_time) or 0) * 1e6)
    local upstream   = ngx.var.target_upstream or ""

    -- Always record metrics + circuit-breaker / EMA signal.
    lib.report_telemetry(status, latency_us, upstream)

    -- Release the slot exactly once, and only for requests we admitted.
    -- Early-rejected requests already released inside process_request.
    if ngx.ctx.admitted then
        lib.release_slot()
    end
end

-- Prometheus exposition. Rust owns the metric formatting.
function M.metrics()
    ngx.header["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
    local ptr = lib.get_metrics_string()
    if ptr ~= nil then
        local text = ffi.string(ptr)
        lib.free_metrics_string(ptr)
        ngx.print(text)
    else
        ngx.print("gateway_up 1\n")
    end
end

local VERSION_BUF_LEN = 64
local version_buf = ffi.new("char[?]", VERSION_BUF_LEN)

-- Liveness: process is up (does not require config).
function M.health()
    ngx.header["Content-Type"] = "application/json"
    local n = lib.get_config_version(version_buf, VERSION_BUF_LEN)
    local ver = n > 0 and ffi.string(version_buf) or "v0"
    ngx.say('{"status":"healthy","service":"gateway","config_version":"' .. ver .. '"}')
end

-- Readiness: config snapshot loaded and routes available.
function M.ready()
    ngx.header["Content-Type"] = "application/json"
    if lib.is_ready() == 1 then
        ngx.say('{"status":"ready"}')
    else
        ngx.status = 503
        ngx.say('{"status":"not_ready","reason":"config not loaded"}')
    end
end

return M
