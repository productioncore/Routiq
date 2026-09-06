import crypto from 'crypto';
import bcrypt from 'bcryptjs';

/**
 * Password hashing — bcrypt (per-hash salt) + optional server-side pepper.
 *
 * Layers:
 *   - Salt:   random per password, embedded by bcrypt in the `$2b$<cost>$…` hash.
 *   - Pepper: PASSWORD_PEPPER env secret, mixed via HMAC-SHA256 before bcrypt.
 *             Lives in env/vault only — never stored with the user.
 *
 * Backward compatibility (critical for real deployments):
 *   Existing rows may hold legacy `bcrypt(plaintext)` hashes created before the
 *   pepper existed. `verifyPassword` accepts those, and reports `needsRehash`
 *   so the caller can transparently migrate the hash to the current scheme on
 *   the next successful login. Changing a hashing scheme without this would lock
 *   out every existing user.
 */

const BCRYPT_COST = (() => {
    const n = parseInt(process.env.BCRYPT_COST || '12', 10);
    return Number.isFinite(n) && n >= 10 && n <= 15 ? n : 12;
})();

const DEV_PEPPERS = new Set([
    '',
    'change_me_use_a_long_random_password_pepper_at_least_32_chars',
    'CHANGE_ME_PASSWORD_PEPPER',
]);

export const getPepper = (): string => process.env.PASSWORD_PEPPER || '';

export const hasPepper = (): boolean => getPepper().length > 0;

/** Material fed to bcrypt: peppered when a pepper is configured, else plaintext. */
const material = (password: string): string => {
    const pepper = getPepper();
    if (!pepper) return password;
    return crypto.createHmac('sha256', pepper).update(password, 'utf8').digest('hex');
};

export const hashPassword = async (password: string): Promise<string> => {
    const salt = await bcrypt.genSalt(BCRYPT_COST);
    return bcrypt.hash(material(password), salt);
};

export interface VerifyResult {
    /** Whether the candidate password matched the stored hash. */
    match: boolean;
    /** True when the match came from a legacy (un-peppered) hash that should be re-hashed. */
    needsRehash: boolean;
}

export const verifyPassword = async (
    candidate: string,
    storedHash: string | undefined | null,
): Promise<VerifyResult> => {
    if (!storedHash) return { match: false, needsRehash: false };

    // 1. Current scheme (peppered if a pepper is configured, else plaintext).
    if (await bcrypt.compare(material(candidate), storedHash)) {
        return { match: true, needsRehash: false };
    }

    // 2. Legacy fallback: a pepper is configured now, but this hash predates it
    //    and was stored as bcrypt(plaintext). Accept and flag for migration.
    if (hasPepper() && (await bcrypt.compare(candidate, storedHash))) {
        return { match: true, needsRehash: true };
    }

    return { match: false, needsRehash: false };
};

/** Log a one-time warning when the pepper is missing or a known dev default. */
export const warnIfInsecurePepper = (): void => {
    if (DEV_PEPPERS.has(getPepper())) {
        // eslint-disable-next-line no-console
        console.warn(
            '[auth] PASSWORD_PEPPER is empty or a known dev default — set a long random pepper before production.',
        );
    }
};
