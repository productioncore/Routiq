# UAM Backend — Architecture & Feature Specification

## Overview
User Access Management (UAM) service — authentication, authorization, sessions, account lifecycle. Designed as the **auth boundary** for the API gateway mesh.

---

## Core Auth Features

### Authentication
| Feature | Implementation |
|---------|---------------|
| **Register / Login / Logout** | Email/password, JWT access + refresh tokens |
| **JWT** | HS256, `issuer`/`audience`, `tv` (tokenVersion) claim, 15m access / 7d refresh |
| **Passwords** | bcrypt (cost 12) + HMAC-SHA256 pepper |
| **Refresh Tokens** | SHA-256 hashed at rest, HttpOnly Secure SameSite=Strict cookies, rotation on use |
| **Email Verification** | 32-byte token, SHA-256 at rest, 24h TTL, anti-enumeration uniform responses |
| **Password Reset** | Form token flow (1h TTL), rate limited (5/12h), token rotation on reset |

### Session Management
| Feature | Implementation |
|---------|---------------|
| **Token Version (`tv`)** | Integer per user, incremented on logout/reset/migration/breach |
| **Access JTI Tracking** | Redis sorted sets (`activeAccessJtis`) for granular revocation |
| **Refresh Token Rotation** | Atomic MongoDB `$pull` + `$push` + `$inc tokenVersion` — no race window |
| **Distributed Invalidation** | `tokenVersion` published to Redis `gateway:user:tv:{userId}` — gateway checks on every request |
| **Full Session Kill** | `invalidateAllSessions()` — clears refresh tokens, increments `tv`, publishes to Redis |

---

## Advanced Distributed Systems Features

### 🔴 Bloom Filter Token Revocation (Design)
```
┌─────────────────────────────────────────────────────────────────┐
│                    BLOOM FILTER REVOCATION                      │
├─────────────────────────────────────────────────────────────────┤
│  Problem: Redis key-per-JTI doesn't scale to millions of users │
│  Solution: Counting Bloom Filter per user in Redis             │
│                                                                 │
│  Data Structure:                                                │
│    - Key: `revocation:bf:{userId}`                              │
│    - Type: RedisBloom (RedisBloom module) OR custom Lua        │
│    - Params: 1M bits, 7 hash functions, ~0.1% FPR              │
│    - Counting: supports deletion on token refresh              │
│                                                                 │
│  Flow:                                                          │
│    1. On access token issue → BF.ADD revocation:bf:{uid} {jti} │
│    2. On refresh/logout → BF.DECR revocation:bf:{uid} {jti}    │
│    3. Gateway check: BF.EXISTS revocation:bf:{uid} {jti}       │
│       - FALSE = definitely valid (fast path)                   │
│       - TRUE  = possibly revoked → fallback to Redis key check │
│                                                                 │
│  Trade-offs:                                                    │
│    - Memory: ~125 KB per 1M tokens (vs 16 MB for keys)         │
│    - False positive rate: 0.1% → extra Redis round-trip        │
│    - No false negatives (safety)                               │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation**: `src/services/bloom-revocation.service.ts` (to be created)
- Uses `redis-bloom` module or custom Lua script for atomic ADD/DECR/EXISTS
- Gateway (nginx-rust) loads filter locally for fast-path checks

---

### 🔴 Distributed Rate Limiting with Bloom Filters (Design)
```
┌─────────────────────────────────────────────────────────────────┐
│              DISTRIBUTED RATE LIMITING (BLOOM)                  │
├─────────────────────────────────────────────────────────────────┤
│  Problem: Per-key Redis counters don't scale; sliding window   │
│           needs sorted sets (heavy)                            │
│                                                                 │
│  Solution: Fixed-window + Bloom filter for burst detection     │
│                                                                 │
│  Architecture:                                                  │
│    Layer 1 (Fast): Local in-memory token bucket (per pod)      │
│    Layer 2 (Distributed): Redis fixed-window counters          │
│    Layer 3 (Burst Detection): Counting Bloom Filter per IP     │
│                                                                 │
│  Redis Keys:                                                    │
│    - `ratelimit:{window}:{key}` → INCR + TTL (fixed window)    │
│    - `ratelimit:bloom:{ip}` → BF.ADD on each request           │
│       - If BF.EXISTS → probable burst → escalate to strict    │
│                                                                 │
│  Sliding Window Alternative (if precision needed):             │
│    - Redis sorted set: `ratelimit:sw:{key}`                    │
│    - ZADD timestamp, ZREMRANGEBYSCORE < window_start           │
│    - ZCARD = request count                                     │
│    - Lua script for atomicity                                  │
│                                                                 │
│  Config (per endpoint):                                        │
│    - windowMs, maxRequests, burstThreshold, bloomFPR           │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation**: `src/middleware/distributed-rate-limiter.ts` (to be created)
- Combines `rate-limit-redis` + custom Bloom burst detection
- Falls back to in-memory when Redis unavailable (circuit breaker)

---

### 🔴 Host Config Hot Swap (Design)
```
┌─────────────────────────────────────────────────────────────────┐
│                    HOT CONFIG RELOAD                            │
├─────────────────────────────────────────────────────────────────┤
│  Problem: Config changes require pod restart                   │
│                                                                 │
│  Solution: SIGHUP + file watcher + in-memory config cache      │
│                                                                 │
│  Architecture:                                                  │
│    1. Config loaded from: env vars → file → Consul/etcd        │
│    2. In-memory `ConfigStore` with versioned snapshots         │
│    3. File watcher (`chokidar`) on `/config/*.json`            │
│    4. SIGHUP handler → reload → atomic swap                    │
│    5. Subscribers (rate limiter, auth, etc.) get new snapshot  │
│                                                                 │
│  Safety:                                                        │
│    - Validation before swap (Zod schema)                       │
│    - Rollback on validation failure                            │
│    - No restart for: rate limit thresholds, CSP, CORS origins  │
│    - Restart required for: DB/Redis connections, JWT secrets   │
│                                                                 │
│  Config Sources (priority):                                    │
│    1. Environment variables (highest)                          │
│    2. `/config/runtime.json` (hot-reloadable)                  │
│    3. `/config/defaults.json` (base)                           │
│    4. Consul/etcd (if configured)                              │
└─────────────────────────────────────────────────────────────────┘
```

**Implementation**: `src/config/hot-reload.ts` (to be created)
- `ConfigStore` class with `subscribe(callback)` for live updates
- `SIGHUP` handler triggers reload
- Feature flags for gradual rollout

---

## OAuth / Federation

| Provider | Features |
|----------|----------|
| **Google** | PKCE, state, email verified, avatar sync, blocks verified local takeover |
| **GitHub** | Verified primary email fetch, PKCE, same takeover protection |
| **Account Linking** | Manual link in settings (requires password confirmation) |
| **Conflict Resolution** | Blocks OAuth on verified local account; allows on unverified |

---

## Account Migration (Email Change)

| Feature | Implementation |
|---------|---------------|
| **Dual Verification** | Both old and new email must verify |
| **Placeholder Account** | Created for target email if unregistered (`provider: 'migration-placeholder'`) |
| **Merge Logic** | If target exists → delete target, preserve source data (bio, avatar, history) |
| **Cooldown** | 10 days between migrations |
| **History** | Immutable append-only log (to be: hash-chained for integrity) |
| **Race Protection** | `tokenVersion` re-check + atomic `findOneAndUpdate` with version predicate |

---

## Security Headers & Hardening

| Header | Value |
|--------|-------|
| **HSTS** | `max-age=31536000; includeSubDomains; preload` |
| **CSP** | `default-src 'none'; frame-ancestors 'none'` |
| **COOP** | `same-origin` |
| **COEP** | `require-corp` |
| **Permissions-Policy** | `geolocation=(), microphone=(), camera=()` |
| **CORS** | `origin: CLIENT_URL`, `credentials: true`, no `Authorization` exposed |

---

## Observability

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness — `{ status: "ok" }` |
| `GET /ready` | Readiness — PG + Redis connectivity |
| `GET /metrics` | Prometheus — auth rates, Redis circuit breaker, token versions, rate limit stats |

**Tracing**: OpenTelemetry → Grafana Cloud (W3C trace context)

---

## Deployment

| Aspect | Detail |
|--------|--------|
| **Runtime** | Node.js 20, Docker multi-stage (Alpine) |
| **Platform** | Render (Docker), auto-deploy on push |
| **Config** | Env-only (`.env` deleted at build, `ca.crt` baked in) |
| **Secrets** | Render encrypted env vars (never in repo) |
| **Health** | `/ready` gates traffic; `/health` for LB |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js 20, TypeScript 5.x |
| Framework | **Express 4.21.x** (5.x RC not production-ready) |
| Database | PostgreSQL (Aiven) — custom `pg` wrapper (Mongoose-like) |
| Cache/Queue | Redis (Upstash) — `ioredis` + `rate-limit-redis` |
| Email | Nodemailer (SMTP) |
| OAuth | Passport + `passport-google-oauth20`, `passport-github2` |
| Validation | Zod |
| Metrics | Prometheus client + OpenTelemetry |
| Crypto | Node `crypto` (WebCrypto compatible) |

---

## Project Structure

```
src/
├── config/                 # Configuration & hot-reload
│   ├── index.ts           # Env parsing, validation
│   ├── hot-reload.ts      # SIGHUP + file watcher (WIP)
│   ├── redis.ts           # Redis clients + circuit breaker
│   └── passport.ts        # OAuth strategies
├── controllers/           # HTTP handlers
│   ├── auth.controller.ts
│   ├── migration.controller.ts
│   └── profile.controller.ts
├── middleware/            # Express middleware
│   ├── auth.middleware.ts      # JWT verify + tokenVersion check
│   ├── limiter.middleware.ts   # express-rate-limit + FallbackStore
│   ├── advancedLimiter.ts      # Exponential backoff login
│   ├── distributed-rate-limiter.ts  # Bloom + sliding window (WIP)
│   └── csrf.middleware.ts      # Double-submit cookie
├── services/              # Business logic
│   ├── session.service.ts      # Token version, JTI, rotation
│   ├── token.service.ts        # JWT sign/verify
│   ├── bloom-revocation.service.ts  # Bloom filter revocation (WIP)
│   ├── revoke.service.ts       # Control-plane sync
│   ├── oauth-pkce.service.ts   # PKCE state management
│   └── email-link.service.ts   # Verification/reset tokens
├── utils/                 # Helpers
│   ├── boot.ts              # Structured startup banner
│   ├── cookie.util.ts       # Cookie serialization
│   ├── refresh-token.util.ts # SHA-256 hashing
│   └── migration-data-preserver.ts
├── db/                    # PostgreSQL wrapper
│   ├── User.ts            # User model (pg-backed)
│   ├── client.ts          # Pool + CA cert
│   └── schema.ts          # Drizzle schema
├── routes/                # Route definitions
│   ├── auth.routes.ts
│   ├── migration.routes.ts
│   └── profile.routes.ts
└── index.ts               # App entry, middleware chain, routes
```

---

## Missing / Planned (from audit)

| Priority | Feature | Status |
|----------|---------|--------|
| **P0** | Express 5 → 4.21 downgrade | ⬜ |
| **P0** | Bloom filter revocation | 🟡 Design |
| **P0** | Distributed rate limiting (Bloom + sliding window) | 🟡 Design |
| **P0** | Host config hot reload (SIGHUP + watcher) | 🟡 Design |
| **P1** | Migration history hash-chaining | 🟡 Design |
| **P1** | Argon2id migration path | 🟡 Design |
| **P2** | Config via Consul/etcd | 🟡 Design |
| **P2** | Admin API for token revocation | 🟡 Design |

---

## Gateway Contract (nginx-rust)

| Check | UAM Provides | Gateway Validates |
|-------|--------------|-------------------|
| **Access Token** | HS256 JWT with `tv` claim | Signature, expiry, `iss`/`aud`, `tv` vs Redis |
| **Token Version** | `gateway:user:tv:{userId}` = integer | Reject if `jwt.tv < redis.tv` |
| **Revocation** | `revocation:bf:{userId}` (Bloom) | BF.EXISTS → fallback to Redis key |
| **Rate Limit** | `ratelimit:*` keys | Enforced at edge |

---

*Generated from codebase audit — update on architectural changes.*