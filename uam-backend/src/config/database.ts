import { pool } from '../db/client';
import { runMigrations, startTtlSweeper } from '../db/migrations';
import { backfillIdentityIndexes } from '../services/identity-index.service';
import { config } from './index';
import { boot } from '../utils/boot';

let ttlSweeper: NodeJS.Timeout | null = null;

export const connectDatabase = async (): Promise<void> => {
    try {
        await pool.query('SELECT 1');
        boot.postgres(true, config.postgres.pool.max);

        const migrationCount = await runMigrations();
        boot.migrations(migrationCount);

        try {
            const { scanned, synced } = await backfillIdentityIndexes();
            boot.backfill(scanned, synced);
        } catch (err) {
            // silent — best-effort
        }

        ttlSweeper = startTtlSweeper();
    } catch (error) {
        boot.postgres(false, 0);
        process.exit(1);
    }
};

export const disconnectDatabase = async (): Promise<void> => {
    if (ttlSweeper) {
        clearInterval(ttlSweeper);
        ttlSweeper = null;
    }
    await pool.end();
    console.log('PostgreSQL pool closed');
};

/** Readiness probe — verifies the pool can serve a command. */
export const pingDatabase = async (): Promise<boolean> => {
    try {
        await pool.query('SELECT 1');
        return true;
    } catch {
        return false;
    }
};