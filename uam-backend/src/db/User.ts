import crypto from 'crypto';
import { pool } from './client';
import { hashPassword, verifyPassword } from '../utils/password.util';
import {
    columnName,
    fieldName,
    ALL_FIELDS,
    SENSITIVE_FIELDS,
    JSONB_FIELDS,
} from './columns';
import { buildWhere, Filter } from './filter';

/**
 * Translate a Postgres unique-violation (SQLSTATE 23505) into the Mongo-style
 * `{ code: 11000 }` duplicate-key error shape that existing controllers
 * (auth.controller.ts, migration.controller.ts) branch on.
 */
function translateDuplicateKey(err: unknown): unknown {
    const e = err as {
        code?: string | number;
        constraint?: string;
        detail?: string;
    };
    if (e && String(e.code) === '23505') {
        const match = /Key \((\w+)\)=\(([^)]*)\) already exists\./.exec(e.detail ?? '');
        const field = match?.[1] ?? 'key';
        const value = match?.[2] ?? null;
        const translated = new Error('E11000 duplicate key error');
        (translated as { code?: number }).code = 11000;
        (translated as { keyPattern?: Record<string, unknown> }).keyPattern = { [field]: 1 };
        (translated as { keyValue?: Record<string, unknown> }).keyValue = { [field]: value };
        return translated;
    }
    return err;
}


/**
 * PostgreSQL-backed replacement for the old Mongoose `User` model.
 *
 * The public surface mirrors the Mongoose API the codebase relied on, so the
 * ~200 existing call sites keep working unchanged:
 *
 *   User.find(filter).select('...')        -> Promise<User[]>
 *   User.findOne(filter).lean()            -> Promise<plain | null>
 *   User.findById(id).select('+password')  -> Promise<User | null>
 *   User.create(data)                      -> Promise<User>
 *   new User(data); await user.save()      -> INSERT
 *   User.findByIdAndUpdate(id, update)     -> Promise<User | null>  ($push/$pull/$set/$unset)
 *   User.findOneAndUpdate(filter, update)  -> Promise<User | null>
 *   User.findByIdAndDelete(id)             -> Promise<User | null>
 *   User.deleteMany(filter)                -> Promise<{ deletedCount }>
 *
 * Dirty tracking: instances wrap their data in a Proxy. Field reads/writes are
 * recorded against `_values`/`_modified`, so `save()` issues a minimal UPDATE
 * of only what changed. JSONB array fields (refreshTokens, activeAccessJtis,
 * migrationHistory) are always written back when loaded, so in-place mutations
 * like `user.migrationHistory.push(...)` persist correctly.
 */

// ---------------------------------------------------------------------------
// Row <-> field mapping
// ---------------------------------------------------------------------------

function rowToValues(row: Record<string, unknown>): Record<string, unknown> {
    const values: Record<string, unknown> = {};
    for (const [col, val] of Object.entries(row)) {
        if (Object.prototype.hasOwnProperty.call(COLUMN_TO_FIELD_REV, col)) {
            values[COLUMN_TO_FIELD_REV[col]] = val;
        }
    }
    return values;
}

const COLUMN_TO_FIELD_REV: Record<string, string> = Object.fromEntries(
    Object.entries(
        Object.fromEntries(
            ALL_FIELDS.map((f) => [f, columnName(f)]),
        ),
    ).map(([f, c]) => [c, f]),
);

// ---------------------------------------------------------------------------
// Update document support
// ---------------------------------------------------------------------------

type UpdateOperand = unknown;

interface PushSpec {
    $each?: unknown[];
    $slice?: number;
}

interface UpdateDoc {
    $push?: Record<string, PushSpec | UpdateOperand>;
    $pull?: Record<string, UpdateOperand>;
    $set?: Record<string, UpdateOperand>;
    $unset?: Record<string, string>;
    $inc?: Record<string, number>;
}

// ---------------------------------------------------------------------------
// Query class
// ---------------------------------------------------------------------------

export class UserQuery<T> implements PromiseLike<T> {
    private filter: Filter;
    private projection?: string;
    private _lean = false;
    private single: boolean;
    private orderBy?: { field: string; dir: 'asc' | 'desc' };
    private limitCount?: number;

    constructor(filter: Filter, opts?: { single?: boolean }) {
        this.filter = filter;
        this.single = opts?.single ?? false;
    }

    select(spec: string): this {
        this.projection = spec;
        return this;
    }

    lean(): this {
        this._lean = true;
        return this;
    }

    sort(spec: string): this {
        const m = spec.trim().match(/^(\S+)(?:\s+(asc|desc))?$/);
        if (m) {
            this.orderBy = { field: m[1], dir: (m[2] as 'asc' | 'desc') ?? 'asc' };
        }
        return this;
    }

    limit(n: number): this {
        this.limitCount = n;
        return this;
    }

    then<TResult1 = T, TResult2 = never>(
        onfulfilled?: ((value: T) => TResult1 | PromiseLike<TResult1>) | null,
        onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
    ): Promise<TResult1 | TResult2> {
        return this.execute().then(onfulfilled, onrejected);
    }

    private resolveFields(): string[] {
        if (!this.projection) {
            return ALL_FIELDS.filter((f) => !SENSITIVE_FIELDS.has(f));
        }
        const tokens = this.projection.trim().split(/\s+/).filter(Boolean);
        const additive = tokens.filter((t) => t.startsWith('+'));
        const inclusion = tokens.filter((t) => !t.startsWith('+'));

        if (inclusion.length > 0) {
            return Array.from(new Set(['id', ...inclusion]));
        }

        const fields = new Set(ALL_FIELDS.filter((f) => !SENSITIVE_FIELDS.has(f)));
        for (const t of additive) {
            fields.add(t.slice(1));
        }
        return Array.from(fields);
    }

    private async execute(): Promise<T> {
        const { sql, params } = this.buildSelect();
        const { rows } = await pool.query(sql, params);

        if (this.single) {
            const row = rows[0];
            if (!row) return null as T;
            return (this._lean
                ? rowToValues(row)
                : new User(rowToValues(row), { isNew: false })) as T;
        }

        const results = rows.map((r) =>
            this._lean
                ? rowToValues(r)
                : new User(rowToValues(r), { isNew: false }),
        );
        return results as T;
    }

    private buildSelect(): { sql: string; params: unknown[] } {
        const fields = this.resolveFields();
        const cols = fields.map((f) => `"${columnName(f)}"`).join(', ');
        const params: unknown[] = [];
        const { sql: where, params: whereParams } = buildWhere(this.filter, params);
        let sql = `SELECT ${cols} FROM users`;
        if (where) sql += ` WHERE ${where}`;
        if (this.orderBy) sql += ` ORDER BY ${columnName(this.orderBy.field)} ${this.orderBy.dir}`;
        if (this.limitCount !== undefined) sql += ` LIMIT ${this.limitCount}`;
        else if (this.single) sql += ` LIMIT 1`;
        return { sql, params };
    }

    /**
     * Keyset paginated cursor over `id` (Mongo-style `.cursor()`). Used by the
     * identity-index backfill; yields hydrated User documents.
     */
    async *cursor(): AsyncGenerator<User, void, unknown> {
        let lastId: string | null = null;
        const baseParams: unknown[] = [];
        const baseWhere = buildWhere(this.filter, baseParams).sql;

        for (;;) {
            const params = [...baseParams];
            let where = baseWhere;
            if (lastId !== null) {
                params.push(lastId);
                const extra = `id > $${params.length}`;
                where = where ? `(${where}) AND ${extra}` : extra;
            }
            const sql = `SELECT * FROM users${where ? ` WHERE ${where}` : ''} ORDER BY id ASC LIMIT 500`;
            const { rows } = await pool.query(sql, params);
            if (rows.length === 0) return;
            for (const r of rows) {
                yield new User(rowToValues(r), { isNew: false });
            }
            lastId = rows[rows.length - 1].id as string;
        }
    }
}

// ---------------------------------------------------------------------------
// Update query (findByIdAndUpdate / findOneAndUpdate)
// ---------------------------------------------------------------------------

class UserUpdateQuery implements PromiseLike<User | null> {
    constructor(
        private readonly filter: Filter,
        private readonly update: UpdateDoc,
    ) {}

    then<TResult1 = User | null, TResult2 = never>(
        onfulfilled?: ((value: User | null) => TResult1 | PromiseLike<TResult1>) | null,
        onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
    ): Promise<TResult1 | TResult2> {
        return applyUpdate(this.filter, this.update).then(onfulfilled, onrejected);
    }
}

/**
 * Atomic read-modify-write UPDATE in a transaction, supporting the array
 * operators the session layer relies on ($push/$each/$slice, $pull) plus
 * $set/$unset. Postgres has no native "append then slice jsonb array", so we
 * lock the row and rewrite the affected fields.
 */
async function applyUpdate(filter: Filter, update: UpdateDoc): Promise<User | null> {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const params: unknown[] = [];
        const { sql: where, params: whereParams } = buildWhere(filter, params);
        const selectSql = `SELECT * FROM users WHERE ${where} FOR UPDATE`;
        const { rows } = await client.query(selectSql, whereParams);
        if (rows.length === 0) {
            await client.query('ROLLBACK');
            return null;
        }
        const row = rows[0];
        const values = rowToValues(row);

        const changed = new Set<string>();

        for (const [field, spec] of Object.entries(update.$push ?? {})) {
            const current = Array.isArray(values[field]) ? [...(values[field] as unknown[])] : [];
            const push = (spec as PushSpec)?.$each;
            if (push && Array.isArray(push)) {
                current.push(...push);
            } else if (spec !== undefined) {
                current.push(spec);
            }
            const slice = (spec as PushSpec)?.$slice;
            values[field] = typeof slice === 'number'
                ? (slice < 0 ? current.slice(slice) : current.slice(0, slice))
                : current;
            changed.add(field);
        }

        for (const [field, value] of Object.entries(update.$pull ?? {})) {
            const current = Array.isArray(values[field]) ? [...(values[field] as unknown[])] : [];
            values[field] = current.filter((x) => x !== value);
            changed.add(field);
        }

        for (const [field, value] of Object.entries(update.$set ?? {})) {
            values[field] = value;
            changed.add(field);
        }

        for (const field of Object.keys(update.$unset ?? {})) {
            values[field] = undefined;
            changed.add(field);
        }

        for (const [field, value] of Object.entries(update.$inc ?? {})) {
            const current = typeof values[field] === 'number' ? values[field] : 0;
            values[field] = current + value;
            changed.add(field);
        }

        const setParams: unknown[] = [];
        const sets: string[] = [];
        for (const field of changed) {
            if (field === 'id') continue;
            const col = columnName(field);
            const raw = values[field];
            if (JSONB_FIELDS.has(field)) {
                setParams.push(raw === undefined || raw === null ? '[]' : JSON.stringify(raw));
                sets.push(`"${col}" = $${setParams.length}`);
            } else {
                setParams.push(raw ?? null);
                sets.push(`"${col}" = $${setParams.length}`);
            }
        }
        sets.push('updated_at = NOW()');

        const idParamIdx = setParams.length + 1;
        setParams.push(row.id);
        const { rows: updated } = await client.query(
            `UPDATE users SET ${sets.join(', ')} WHERE id = $${idParamIdx} RETURNING *`,
            setParams,
        );
        await client.query('COMMIT');
        return updated[0] ? new User(rowToValues(updated[0]), { isNew: false }) : null;
    } catch (err) {
        await client.query('ROLLBACK');
        throw translateDuplicateKey(err);
    } finally {
        client.release();
    }
}

// ---------------------------------------------------------------------------
// Proxy-based dirty tracking
// ---------------------------------------------------------------------------

const userHandler: ProxyHandler<User> = {
    get(target, prop, receiver) {
        if (prop === '_values' || prop === '_modified' || prop === '_isNew') {
            return (target as unknown as Record<string, unknown>)[prop];
        }
        if (prop === '_id') {
            return target._values['id'];
        }
        if (typeof prop === 'string' && Object.prototype.hasOwnProperty.call(target._values, prop)) {
            return target._values[prop];
        }
        return Reflect.get(target, prop, receiver);
    },
    set(target, prop, value) {
        if (typeof prop !== 'string') {
            Reflect.set(target, prop, value);
            return true;
        }
        if (prop.startsWith('_')) {
            (target as unknown as Record<string, unknown>)[prop] = value;
            return true;
        }
        target._values[prop] = value;
        target._modified.add(prop);
        return true;
    },
    has(target, prop) {
        return prop === '_id'
            || typeof prop === 'string' && Object.prototype.hasOwnProperty.call(target._values, prop)
            || Reflect.has(target, prop);
    },
};

// ---------------------------------------------------------------------------
// User model
// ---------------------------------------------------------------------------

export interface MigrationHistoryEntry {
    fromEmail: string;
    toEmail: string;
    status: 'success' | 'failed' | 'pending' | 'reverted';
    initiatedAt: Date;
    completedAt?: Date;
    revertedAt?: Date;
    currentEmailVerified?: boolean;
    newEmailVerified?: boolean;
    pendingFrom?: 'current' | 'new' | 'both';
}

export interface IUser {
    _id: string;
    email: string;
    previousEmail?: string;
    password?: string;
    displayName: string;
    avatar?: string;
    bio?: string;
    isEmailVerified: boolean;
    loginCount?: number;
    lastLogin?: Date;
    emailVerificationToken?: string;
    emailVerificationExpires?: Date;
    passwordResetToken?: string;
    passwordResetExpires?: Date;
    provider: 'local' | 'google' | 'github';
    providerId?: string;
    refreshTokens: string[];
    activeAccessJtis?: string[];
    tokenVersion?: number;
    migrationExpiry?: Date;
    migrationToken?: string;
    migrationTokenExpires?: Date;
    newEmailPending?: string;
    lastMigrationDate?: Date;
    currentEmailVerified?: boolean;
    newEmailVerified?: boolean;
    currentEmailToken?: string;
    newEmailToken?: string;
    lastMigrationEmailSent?: Date;
    migrationHistory?: MigrationHistoryEntry[];
    createdAt: Date;
    updatedAt: Date;
    save(options?: { validateBeforeSave?: boolean }): Promise<this>;
    comparePassword(candidatePassword: string): Promise<boolean>;
    markModified(field: string): void;
}

export class User implements IUser {
    _values: Record<string, unknown> = {};
    _modified = new Set<string>();
    _isNew = true;

    // Fields are backed by the Proxy over `_values`. Declared here so callers
    // (and TypeScript) see the IUser shape; unloaded select:false fields read
    // as `undefined` at runtime. `_id` is provided by the getter below.
    declare email: string;
    declare previousEmail?: string;
    declare password?: string;
    declare displayName: string;
    declare avatar?: string;
    declare bio?: string;
    declare isEmailVerified: boolean;
    declare loginCount?: number;
    declare lastLogin?: Date;
    declare emailVerificationToken?: string;
    declare emailVerificationExpires?: Date;
    declare passwordResetToken?: string;
    declare passwordResetExpires?: Date;
    declare provider: 'local' | 'google' | 'github';
    declare providerId?: string;
    declare refreshTokens: string[];
    declare activeAccessJtis?: string[];
    declare tokenVersion?: number;
    declare migrationExpiry?: Date;
    declare migrationToken?: string;
    declare migrationTokenExpires?: Date;
    declare newEmailPending?: string;
    declare lastMigrationDate?: Date;
    declare currentEmailVerified?: boolean;
    declare newEmailVerified?: boolean;
    declare currentEmailToken?: string;
    declare newEmailToken?: string;
    declare lastMigrationEmailSent?: Date;
    declare migrationHistory?: MigrationHistoryEntry[];
    declare createdAt: Date;
    declare updatedAt: Date;

    constructor(data?: Record<string, unknown>, opts?: { isNew?: boolean }) {
        if (data) {
            for (const [k, v] of Object.entries(data)) {
                if (v !== undefined) this._values[k] = v;
            }
        }
        this._isNew = opts?.isNew ?? true;
        return new Proxy(this, userHandler);
    }

    get _id(): string {
        return this._values['id'] as string;
    }

    /** Mongoose-compatible dirty marker — our Proxy already tracks writes, kept for callers. */
    markModified(field: string): void {
        this._modified.add(field);
    }

    async save(options?: { validateBeforeSave?: boolean }): Promise<this> {
        if (this._isNew) {
            await this._insert();
        } else {
            await this._update();
        }
        return this;
    }

    async comparePassword(candidatePassword: string): Promise<boolean> {
        const stored = this._values['password'];
        if (!stored) return false;

        const { match, needsRehash } = await verifyPassword(candidatePassword, stored as string);

        if (match && needsRehash) {
            try {
                this._values['password'] = candidatePassword;
                this._modified.add('password');
                await this.save();
            } catch {
                // Best-effort hash migration — never block a valid login.
            }
        }

        return match;
    }

    private async _insert(): Promise<void> {
        const values: Record<string, unknown> = { ...this._values };
        if (!values['id']) {
            values['id'] = crypto.randomUUID();
        }

        const cols: string[] = [];
        const params: unknown[] = [];
        for (const [field, value] of Object.entries(values)) {
            if (field === 'createdAt' || field === 'updatedAt') continue;
            const col = columnName(field);
            cols.push(`"${col}"`);
            if (JSONB_FIELDS.has(field)) {
                params.push(value === undefined || value === null ? '[]' : JSON.stringify(value));
            } else if (field === 'password' && typeof value === 'string' && value.length > 0) {
                params.push(await hashPassword(value));
            } else {
                params.push(value ?? null);
            }
        }

        const sql = `INSERT INTO users (${cols.join(', ')})
                     VALUES (${cols.map((_, i) => `$${i + 1}`).join(', ')})
                     RETURNING *`;

        try {
            const { rows } = await pool.query(sql, params);
            const saved = rows[0];
            this._values = rowToValues(saved);
            this._modified.clear();
            this._isNew = false;
        } catch (err) {
            throw translateDuplicateKey(err);
        }
    }

    private async _update(): Promise<void> {
        const writeFields = new Set<string>(this._modified);
        for (const f of JSONB_FIELDS) {
            if (Object.prototype.hasOwnProperty.call(this._values, f)) {
                writeFields.add(f);
            }
        }
        writeFields.delete('id');
        writeFields.delete('createdAt');
        writeFields.delete('updatedAt');

        const sets: string[] = [];
        const params: unknown[] = [];
        for (const field of writeFields) {
            const raw = this._values[field];
            const col = columnName(field);
            if (JSONB_FIELDS.has(field)) {
                params.push(raw === undefined || raw === null ? '[]' : JSON.stringify(raw));
                sets.push(`"${col}" = $${params.length}`);
            } else if (field === 'password' && typeof raw === 'string' && raw.length > 0) {
                params.push(await hashPassword(raw));
                sets.push(`"${col}" = $${params.length}`);
            } else {
                params.push(raw ?? null);
                sets.push(`"${col}" = $${params.length}`);
            }
        }
        sets.push('updated_at = NOW()');

        const idIdx = params.length + 1;
        params.push(this._values['id']);
        const sql = `UPDATE users SET ${sets.join(', ')} WHERE id = $${idIdx} RETURNING *`;
        try {
            const { rows } = await pool.query(sql, params);
            const saved = rows[0];
            if (saved) {
                this._values = rowToValues(saved);
            }
            this._modified.clear();
        } catch (err) {
            throw translateDuplicateKey(err);
        }
    }

    // -- Static API ---------------------------------------------------------

    static find(filter: Filter = {}): UserQuery<User[]> {
        return new UserQuery<User[]>(filter);
    }

    static findOne(filter: Filter): UserQuery<User | null> {
        return new UserQuery<User | null>(filter, { single: true });
    }

    static findById(id: string | number): UserQuery<User | null> {
        return new UserQuery<User | null>({ id: String(id) }, { single: true });
    }

    static async create(data: Record<string, unknown>): Promise<User> {
        const user = new User(data);
        await user.save();
        return user;
    }

    static findByIdAndUpdate(id: string | number, update: UpdateDoc): UserUpdateQuery {
        return new UserUpdateQuery({ id: String(id) }, update);
    }

    static findOneAndUpdate(filter: Filter, update: UpdateDoc): UserUpdateQuery {
        return new UserUpdateQuery(filter, update);
    }

    static async findByIdAndDelete(id: string | number): Promise<User | null> {
        const { rows } = await pool.query(
            `DELETE FROM users WHERE id = $1 RETURNING *`,
            [String(id)],
        );
        return rows[0] ? new User(rowToValues(rows[0]), { isNew: false }) : null;
    }

    static async deleteMany(filter: Filter): Promise<{ deletedCount: number }> {
        const params: unknown[] = [];
        const { sql, params: whereParams } = buildWhere(filter, params);
        const { rowCount } = await pool.query(`DELETE FROM users WHERE ${sql}`, whereParams);
        return { deletedCount: rowCount ?? 0 };
    }

    static async deleteOne(filter: Filter): Promise<{ deletedCount: number }> {
        const params: unknown[] = [];
        const { sql, params: whereParams } = buildWhere(filter, params);
        const { rowCount } = await pool.query(`DELETE FROM users WHERE ${sql}`, whereParams);
        return { deletedCount: rowCount ?? 0 };
    }
}

export { columnName, fieldName };