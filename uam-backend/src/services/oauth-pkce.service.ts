/**
 * OAuth PKCE + state binding for SPA exchange codes (BFF-style).
 */
import crypto from 'crypto';
import { cacheDel, cacheGet, cacheSet, isRedisAvailable } from '../config/redis';
import { config } from '../config';

const STATE_TTL_SECS = 600;
const STATE_BYTES = 32;

interface StateRecord {
    codeChallenge: string;
    /** Per-client OAuth callback base, e.g. https://productioncore.dev/oauth-callback */
    redirectUri?: string;
}

/**
 * Validate a client-supplied OAuth redirectUri against the CLIENT_URL
 * allowlist. Only exact `{allowedOrigin}/oauth-callback` targets are
 * accepted (path is pinned to prevent open-redirect abuse).
 * Returns the normalized redirect base or null when rejected.
 */
export function resolveClientRedirectUri(redirectUri: unknown): string | null {
    if (typeof redirectUri !== 'string' || !redirectUri) return null;
    let parsed: URL;
    try {
        parsed = new URL(redirectUri);
    } catch {
        return null;
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
    if (parsed.pathname.replace(/\/$/, '') !== '/oauth-callback') return null;
    const allowed = config.clientUrls.some((base) => {
        try {
            return new URL(base).origin === parsed.origin;
        } catch {
            return false;
        }
    });
    if (!allowed) return null;
    return `${parsed.origin}/oauth-callback`;
}

const memoryStates = new Map<string, { record: StateRecord; exp: number }>();

function pruneMemory(): void {
    const now = Date.now();
    for (const [k, v] of memoryStates) {
        if (v.exp <= now) memoryStates.delete(k);
    }
}

function verifyPkceChallenge(codeVerifier: string, codeChallenge: string): boolean {
    const digest = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return digest === codeChallenge;
}

/** Store PKCE challenge (+ optional per-client redirect) and return opaque state for OAuth redirect. */
export async function createOAuthState(codeChallenge: string, redirectUri?: string): Promise<string> {
    if (!codeChallenge || codeChallenge.length < 43 || codeChallenge.length > 128) {
        throw new Error('Invalid code challenge');
    }

    const state = crypto.randomBytes(STATE_BYTES).toString('hex');
    const record: StateRecord = { codeChallenge, ...(redirectUri ? { redirectUri } : {})};

    if (isRedisAvailable()) {
        await cacheSet(`uam:oauth-state:${state}`, JSON.stringify(record), STATE_TTL_SECS);
        return state;
    }

    if (config.nodeEnv === 'production') {
        throw new Error('Redis required for OAuth state in production');
    }

    pruneMemory();
    memoryStates.set(state, { record, exp: Date.now() + STATE_TTL_SECS * 1000 });
    return state;
}

/** Read the per-client redirect bound to a state WITHOUT consuming it (used at OAuth callback time). */
export async function peekOAuthStateRedirectUri(state: string): Promise<string | null> {
    if (!state) return null;
    try {
        if (isRedisAvailable()) {
            const raw = await cacheGet(`uam:oauth-state:${state}`);
            if (!raw) return null;
            const record = JSON.parse(raw) as StateRecord;
            return record.redirectUri ?? null;
        }
        const entry = memoryStates.get(state);
        if (!entry || entry.exp < Date.now()) return null;
        return entry.record.redirectUri ?? null;
    } catch {
        return null;
    }
}

/** Validate PKCE verifier against stored state (one-time). */
export async function consumeOAuthState(
    state: string,
    codeVerifier: string,
): Promise<boolean> {
    if (!state || !codeVerifier) return false;

    let record: StateRecord | null = null;

    if (isRedisAvailable()) {
        const raw = await cacheGet(`uam:oauth-state:${state}`);
        if (!raw) return false;
        await cacheDel(`uam:oauth-state:${state}`);
        try {
            record = JSON.parse(raw) as StateRecord;
        } catch {
            return false;
        }
    } else {
        const entry = memoryStates.get(state);
        memoryStates.delete(state);
        if (!entry || entry.exp < Date.now()) return false;
        record = entry.record;
    }

    if (!record) return false;
    return verifyPkceChallenge(codeVerifier, record.codeChallenge);
}
