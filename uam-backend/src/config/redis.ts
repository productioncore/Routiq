import Redis, { RedisOptions } from 'ioredis';
import { config } from './index';
import { boot } from '../utils/boot';
import {
    redisCircuitBreaker,
    withCircuitBreaker,
    RedisCallOutcome,
} from './redisCircuitBreaker';

type RedisRole = 'cache' | 'ratelimit';

let redisCache: Redis | null = null;
let redisRateLimit: Redis | null = null;
let cacheReady = false;
let rateLimitReady = false;

function buildRedisOptions(role: RedisRole): RedisOptions {
    const { redis } = config;
    return {
        host: redis.host,
        port: redis.port,
        username: redis.username || undefined,
        password: redis.password || undefined,
        tls: redis.tls ? { rejectUnauthorized: true, servername: redis.host } : undefined,
        db: redis.db,
        connectionName: `uam-${role}`,
        lazyConnect: true,
        enableReadyCheck: true,
        enableOfflineQueue: true,
        maxRetriesPerRequest: redis.maxRetriesPerRequest,
        connectTimeout: redis.connectTimeoutMs,
        commandTimeout: redis.commandTimeoutMs,
        keepAlive: redis.keepAliveMs,
        // NEVER give up reconnecting: managed Redis (Upstash) drops idle TLS
        // connections; a bounded retryStrategy let the pools die permanently
        // ("Connection is closed") while Redis itself was perfectly healthy.
        retryStrategy: (times) => Math.min(times * 200, 5_000),
        reconnectOnError: (err) => {
            const message = err.message;
            return (
                message.includes('READONLY')
                || message.includes('ECONNRESET')
                || message.includes('Connection is closed')
                || message.includes('Stream isnt writeable')
            );
        },
    };
}

function wireClientEvents(client: Redis, role: RedisRole, onReady: (ready: boolean) => void): void {
    client.on('ready', () => {
        onReady(true);
    });

    client.on('connect', () => {
        // silent — boot summary covers this
    });

    client.on('error', (err) => {
        onReady(false);
    });

    client.on('close', () => {
        onReady(false);
    });

    client.on('reconnecting', () => {
        onReady(false);
    });
}

function buildUrlClient(url: string, role: RedisRole): Redis {
    const isTls = url.startsWith('rediss://');
    return new Redis(url, {
        connectionName: `uam-${role}`,
        tls: isTls ? { rejectUnauthorized: true } : undefined,
        lazyConnect: true,
        enableReadyCheck: true,
        enableOfflineQueue: true,
        maxRetriesPerRequest: config.redis.maxRetriesPerRequest,
        connectTimeout: config.redis.connectTimeoutMs,
        commandTimeout: config.redis.commandTimeoutMs,
        keepAlive: config.redis.keepAliveMs,
        retryStrategy: (times) => Math.min(times * 200, 5_000),
    });
}

function createClients(): void {
    if (!config.redis.enabled) {
        return;
    }

    const redisUrl = process.env.REDIS_URL;

    if (redisUrl) {
        redisCache = buildUrlClient(redisUrl, 'cache');
        wireClientEvents(redisCache, 'cache', (ready) => { cacheReady = ready; });

        redisRateLimit = buildUrlClient(redisUrl, 'ratelimit');
        wireClientEvents(redisRateLimit, 'ratelimit', (ready) => { rateLimitReady = ready; });
    } else {
        redisCache = new Redis(buildRedisOptions('cache'));
        wireClientEvents(redisCache, 'cache', (ready) => { cacheReady = ready; });

        redisRateLimit = new Redis(buildRedisOptions('ratelimit'));
        wireClientEvents(redisRateLimit, 'ratelimit', (ready) => { rateLimitReady = ready; });
    }
}

createClients();

async function ensureRedisConnected(client: Redis): Promise<void> {
    if (client.status === 'ready') return;
    if (client.status === 'wait') {
        await client.connect();
        return;
    }
    await new Promise<void>((resolve, reject) => {
        const finish = (err?: Error) => {
            client.off('ready', onReady);
            client.off('error', onError);
            if (err) reject(err);
            else resolve();
        };
        const onReady = () => finish();
        const onError = (e: Error) => finish(e);
        client.once('ready', onReady);
        client.once('error', onError);
    });
}

export const connectRedis = async (): Promise<void> => {
    if (!config.redis.enabled || !redisCache || !redisRateLimit) return;

    const viaUrl = Boolean(process.env.REDIS_URL);

    try {
        await Promise.all([
            ensureRedisConnected(redisCache),
            ensureRedisConnected(redisRateLimit),
        ]);
        await Promise.all([redisCache.ping(), redisRateLimit.ping()]);
        cacheReady = true;
        rateLimitReady = true;
        boot.redis('cache', true, viaUrl);
        boot.redis('ratelimit', true, viaUrl);
    } catch (err) {
        cacheReady = false;
        rateLimitReady = false;
    }
};

export const closeRedis = async (): Promise<void> => {
    const closes: Promise<'OK' | void>[] = [];
    if (redisCache) {
        closes.push(redisCache.quit().catch(() => redisCache?.disconnect()));
    }
    if (redisRateLimit) {
        closes.push(redisRateLimit.quit().catch(() => redisRateLimit?.disconnect()));
    }
    await Promise.all(closes);
    cacheReady = false;
    rateLimitReady = false;
};

export const pingRedisCache = async (): Promise<boolean> => {
    if (!redisCache) return false;
    // No cacheReady gate: a client stuck connecting at cold-start must not
    // poison readiness forever — the live ping (auto-(re)connects) decides.
    const res = await withCircuitBreaker(redisCircuitBreaker, () => redisCache!.ping());
    return res.ok && res.value === 'PONG';
};

export const pingRedisRateLimit = async (): Promise<boolean> => {
    if (!redisRateLimit) return false;
    const res = await withCircuitBreaker(redisCircuitBreaker, () => redisRateLimit!.ping());
    return res.ok && res.value === 'PONG';
};

export const isRedisAvailable = (): boolean => {
    return config.redis.enabled && cacheReady && redisCache !== null;
};

export const isRedisRateLimitAvailable = (): boolean => {
    return config.redis.enabled && rateLimitReady && redisRateLimit !== null;
};

/**
 * Run a cache-pool Redis command under circuit-breaker protection. On
 * `CIRCUIT_OPEN` / `CONCURRENCY_REJECTED` the breaker rejects immediately
 * without contacting Redis; the caller applies its own degradation policy.
 */
export const runCacheCommand = <T>(
    fn: () => Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false; outcome: RedisCallOutcome }> => {
    return withCircuitBreaker(redisCircuitBreaker, fn);
};

/**
 * Run a rate-limit-pool Redis command under circuit-breaker protection
 * (used by express-rate-limit's RedisStore sendCommand).
 */
export const runRateLimitCommand = <T>(
    fn: () => Promise<T>,
): Promise<{ ok: true; value: T } | { ok: false; outcome: RedisCallOutcome }> => {
    return withCircuitBreaker(redisCircuitBreaker, fn);
};

export const cacheSet = async (key: string, value: string, ttlSeconds?: number): Promise<void> => {
    if (!isRedisAvailable() || !redisCache) return;
    const res = await runCacheCommand(() => {
        if (ttlSeconds) {
            return redisCache!.setex(key, ttlSeconds, value);
        }
        return redisCache!.set(key, value);
    });
    if (!res.ok) {
        // Redis is an optional acceleration layer for some paths — fail-open.
    }
};

export const cacheGet = async (key: string): Promise<string | null> => {
    if (!isRedisAvailable() || !redisCache) return null;
    const res = await runCacheCommand(() => redisCache!.get(key));
    return res.ok ? res.value : null;
};

export const cacheDel = async (key: string): Promise<void> => {
    if (!isRedisAvailable() || !redisCache) return;
    const res = await runCacheCommand(() => redisCache!.del(key));
    if (!res.ok) {
        // best-effort
    }
};

/** Cache/session/oauth — backward-compatible export. */
export { redisCache as redis, redisRateLimit };
