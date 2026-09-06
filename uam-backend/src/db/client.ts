import { Pool } from 'pg';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { drizzle } from 'drizzle-orm/node-postgres';
import { users, userIdentityIndexes } from './schema';
import { config } from '../config';

const sslConfig = config.postgres.ssl
    ? {
        rejectUnauthorized: true,
        ca: readFileSync(resolve(process.cwd(), 'ca.crt'), 'utf8'),
    }
    : undefined;

export const pool = new Pool({
    connectionString: config.postgres.url,
    max: config.postgres.pool.max,
    idleTimeoutMillis: config.postgres.pool.idleTimeoutMs,
    connectionTimeoutMillis: config.postgres.pool.connectTimeoutMs,
    ssl: sslConfig,
    application_name: config.postgres.appName,
});

pool.on('error', (err) => {
    console.error('PostgreSQL pool error:', err.message);
});

export const db = drizzle(pool, { schema: { users, userIdentityIndexes } });