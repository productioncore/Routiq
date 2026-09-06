import dotenv from 'dotenv';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { envBool, envInt } from './env.util';

// Load .env file only if running locally (not in production container)
const isLocalEnv = process.env.NODE_ENV !== 'production';
if (isLocalEnv) {
    dotenv.config();
}
const devEnv = resolve(process.cwd(), '.env.dev');
if (existsSync(devEnv) && isLocalEnv) {
    dotenv.config({ path: devEnv, override: true });
}

export const config = {
    port: parseInt(process.env.PORT || '8080', 10),
    nodeEnv: process.env.NODE_ENV || 'production',

    postgres: {
        url: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/uam',
        ssl:
            process.env.PG_SSL === '1'
            || process.env.PG_SSL === 'true',
        pool: {
            min: envInt('PG_POOL_MIN', 2),
            max: envInt('PG_POOL_MAX', 10),
            idleTimeoutMs: envInt('PG_IDLE_TIMEOUT_MS', 30_000),
            connectTimeoutMs: envInt('PG_CONNECT_TIMEOUT_MS', 10_000),
        },
        appName: process.env.PG_APP_NAME || 'uam-backend',
    },

    redis: (() => {
        const redisUrl = process.env.REDIS_URL;
        if (redisUrl) {
            try {
                const url = new URL(redisUrl);
                return {
                    enabled: true,
                    host: url.hostname,
                    port: parseInt(url.port || '6379', 10),
                    username: url.username || undefined,
                    password: url.password || '',
                    tls: url.protocol === 'rediss:',
                    db: envInt('REDIS_DB', 0),
                    connectTimeoutMs: envInt('REDIS_CONNECT_TIMEOUT_MS', 10_000),
                    commandTimeoutMs: envInt('REDIS_COMMAND_TIMEOUT_MS', 5_000),
                    keepAliveMs: envInt('REDIS_KEEPALIVE_MS', 30_000),
                    maxRetriesPerRequest: envInt('REDIS_MAX_RETRIES_PER_REQUEST', 3),
                    maxReconnectAttempts: envInt('REDIS_MAX_RECONNECT_ATTEMPTS', 20),
                };
            } catch {
                console.warn('⚠️ Invalid REDIS_URL, falling back to individual env vars');
            }
        }
        return {
            enabled: process.env.REDIS_ENABLED !== 'false',
            host: process.env.REDIS_HOST || 'localhost',
            port: parseInt(process.env.REDIS_PORT || '6379', 10),
            username: process.env.REDIS_USERNAME || undefined,
            password: process.env.REDIS_PASSWORD || '',
            tls: process.env.REDIS_TLS === 'true',
            db: envInt('REDIS_DB', 0),
            connectTimeoutMs: envInt('REDIS_CONNECT_TIMEOUT_MS', 10_000),
            commandTimeoutMs: envInt('REDIS_COMMAND_TIMEOUT_MS', 5_000),
            keepAliveMs: envInt('REDIS_KEEPALIVE_MS', 30_000),
            maxRetriesPerRequest: envInt('REDIS_MAX_RETRIES_PER_REQUEST', 3),
            maxReconnectAttempts: envInt('REDIS_MAX_RECONNECT_ATTEMPTS', 20),
        };
    })(),

    jwt: {
        accessSecret: process.env.JWT_ACCESS_SECRET || 'default-access-secret',
        refreshSecret: process.env.JWT_REFRESH_SECRET || 'default-refresh-secret',
        accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
        refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
        issuer: process.env.JWT_ISSUER || 'api-gateway-auth-server',
        audience: process.env.JWT_AUDIENCE || 'api-gateway-clients',
    },

    security: {
        passwordPepper: process.env.PASSWORD_PEPPER || '',
        defaultHomeRegion: process.env.DEFAULT_HOME_REGION || 'US',
        autoVerifyEmail:
            process.env.AUTO_VERIFY_EMAIL === '1'
            || process.env.AUTO_VERIFY_EMAIL === 'true',
    },

    google: {
        clientId: process.env.GOOGLE_CLIENT_ID || '',
        clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
        callbackUrl: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:5000/api/auth/google/callback',
    },

    github: {
        clientId: process.env.GITHUB_CLIENT_ID || '',
        clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
        callbackUrl: process.env.GITHUB_CALLBACK_URL || 'http://localhost:5000/api/auth/github/callback',
    },

    smtp: {
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT || '587', 10),
        user: process.env.SMTP_USER || '',
        pass: process.env.SMTP_PASS || '',
    },

    clientUrl: process.env.CLIENT_URL || 'http://localhost:5173',

    cookies: {
        secure:
            process.env.COOKIE_SECURE === '1'
            || process.env.COOKIE_SECURE === 'true',
        sameSite: (process.env.COOKIE_SAME_SITE || 'strict') as 'strict' | 'lax' | 'none',
        path: process.env.COOKIE_PATH || '/api/auth',
    },

    auth: {
        omitRefreshInBody:
            process.env.AUTH_OMIT_REFRESH_IN_BODY === '1'
            || process.env.AUTH_OMIT_REFRESH_IN_BODY === 'true',
    },

    oauth: {
        googleEnabled: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
        githubEnabled: Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET),
    },

    /** Auth rate limits must use Redis when scaling beyond one pod (Helm replicas > 1). */
    rateLimit: {
        requireDistributed:
            process.env.UAM_REQUIRE_DISTRIBUTED_RATE_LIMIT === '1'
            || process.env.UAM_REQUIRE_DISTRIBUTED_RATE_LIMIT === 'true'
            || (
                (process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'staging')
                && process.env.UAM_RELAX_AUTH_LIMITS !== '1'
                && process.env.UAM_RELAX_AUTH_LIMITS !== 'true'
            ),
    },

    /** Control plane - publishes gateway access-token revocations (ADR-0039). */
    controlPlane: {
        url: process.env.CONTROL_PLANE_URL || 'http://control-plane:8081',
        adminApiKey: process.env.ADMIN_API_KEY || 'CHANGE_ME_ADMIN_API_KEY',
    },

    /** Bearer token required for GET /metrics in production (empty = dev-only open scrape). */
    metricsToken: process.env.METRICS_TOKEN || '',
};