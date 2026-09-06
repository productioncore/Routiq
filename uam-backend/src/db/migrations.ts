import { pool } from './client';

/**
 * Hand-rolled migration runner.
 *
 * Keeps the schema in sync without drizzle-kit or external tooling:
 * - Each migration is a named step that runs inside its own transaction.
 * - `schema_migrations` records which steps already ran, so boot is idempotent.
 * - If a migration fails, boot fails and the server refuses to start.
 *
 * NOTE: the DDL below must stay in lockstep with `./schema.ts` — add/remove
 * columns in both places together.
 */

export interface Migration {
    name: string;
    up: string;
    down?: string;
}

export const migrations: Migration[] = [
    {
        name: '001_init',
        up: `
            CREATE TABLE IF NOT EXISTS users (
                id                          TEXT PRIMARY KEY,
                email                       TEXT NOT NULL,
                previous_email              TEXT,
                password                    TEXT,
                display_name                TEXT NOT NULL,
                avatar                      TEXT,
                bio                         TEXT,
                is_email_verified           BOOLEAN NOT NULL DEFAULT FALSE,
                login_count                 INTEGER NOT NULL DEFAULT 0,
                last_login                  TIMESTAMPTZ,
                email_verification_token    TEXT,
                email_verification_expires  TIMESTAMPTZ,
                password_reset_token        TEXT,
                password_reset_expires      TIMESTAMPTZ,
                provider                    TEXT NOT NULL DEFAULT 'local',
                provider_id                 TEXT,
                refresh_tokens              JSONB NOT NULL DEFAULT '[]',
                active_access_jtis          JSONB NOT NULL DEFAULT '[]',
                token_version               INTEGER NOT NULL DEFAULT 0,
                migration_expiry            TIMESTAMPTZ,
                migration_token             TEXT,
                migration_token_expires     TIMESTAMPTZ,
                new_email_pending           TEXT,
                last_migration_date         TIMESTAMPTZ,
                current_email_verified      BOOLEAN,
                new_email_verified          BOOLEAN,
                current_email_token         TEXT,
                new_email_token             TEXT,
                last_migration_email_sent   TIMESTAMPTZ,
                migration_history           JSONB NOT NULL DEFAULT '[]',
                created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CONSTRAINT users_email_key UNIQUE (email),
                CONSTRAINT users_provider_provider_id_key UNIQUE (provider, provider_id),
                CONSTRAINT users_provider_check CHECK (provider IN ('local', 'google', 'github')),
                CONSTRAINT users_refresh_tokens_check CHECK (jsonb_typeof(refresh_tokens) = 'array'),
                CONSTRAINT users_active_access_jtis_check CHECK (jsonb_typeof(active_access_jtis) = 'array'),
                CONSTRAINT users_migration_history_check CHECK (jsonb_typeof(migration_history) = 'array')
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
            CREATE INDEX IF NOT EXISTS idx_users_previous_email ON users (previous_email);
            CREATE INDEX IF NOT EXISTS idx_users_provider_provider_id ON users (provider, provider_id);
            CREATE INDEX IF NOT EXISTS idx_users_created_at ON users (created_at);

            CREATE TABLE IF NOT EXISTS user_identity_indexes (
                key         TEXT PRIMARY KEY,
                kind        TEXT NOT NULL,
                user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                provider    TEXT,
                verified    BOOLEAN,
                expires_at  TIMESTAMPTZ,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_uii_user_id_kind ON user_identity_indexes (user_id, kind);
            CREATE INDEX IF NOT EXISTS idx_uii_expires_at ON user_identity_indexes (expires_at);
        `,
        down: `
            DROP TABLE IF EXISTS user_identity_indexes;
            DROP TABLE IF EXISTS users;
        `,
    },
];

export async function runMigrations(): Promise<number> {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(
            `CREATE TABLE IF NOT EXISTS schema_migrations (
                 id         BIGSERIAL PRIMARY KEY,
                 name       TEXT NOT NULL UNIQUE,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
             )`,
        );
        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }

    let applied = 0;
    for (const migration of migrations) {
        const { rows } = await pool.query(
            `SELECT 1 FROM schema_migrations WHERE name = $1`,
            [migration.name],
        );
        if (rows.length > 0) {
            continue;
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query(migration.up);
            await client.query(`INSERT INTO schema_migrations (name) VALUES ($1)`, [migration.name]);
            await client.query('COMMIT');
            applied++;
        } catch (err) {
            await client.query('ROLLBACK');
            throw new Error(`Migration ${migration.name} failed: ${(err as Error).message}`);
        } finally {
            client.release();
        }
    }
    return applied;
}

/**
 * TTL sweeper — periodically removes expired user_identity_indexes rows.
 * Mirrors MongoDB's TTL index without requiring a background service.
 */
export function startTtlSweeper(intervalMs = 60_000): NodeJS.Timeout {
    const timer = setInterval(async () => {
        try {
            const { rowCount } = await pool.query(
                `DELETE FROM user_identity_indexes
                 WHERE expires_at IS NOT NULL AND expires_at < NOW()`,
            );
            if (rowCount && rowCount > 0) {
                console.log(`TTL sweeper removed ${rowCount} expired identity index(es)`);
            }
        } catch (err) {
            console.error('TTL sweeper error:', (err as Error).message);
        }
    }, intervalMs);
    timer.unref();
    return timer;
}
