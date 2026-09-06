import crypto from 'crypto';

/** SHA-256 hash of refresh JWT for at-rest storage (never store raw tokens in MongoDB). */
export function hashRefreshToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
}

/** Match presented token against stored hashes. */
export function findStoredRefreshToken(stored: string[] | undefined, presented: string): string | null {
    if (!stored?.length) return null;
    const hashed = hashRefreshToken(presented);
    if (stored.includes(hashed)) return hashed;
    return null;
}
