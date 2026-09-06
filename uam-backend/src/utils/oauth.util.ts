import { IUser } from '../models/User';

/**
 * Determine if OAuth can safely take over an existing account.
 * Returns null if safe, error message if blocked.
 * 
 * Safe to take over: unverified local account (no password/email verification).
 * Unsafe: verified local account with password — would enable account takeover.
 */
export function oauthProviderConflict(
    user: IUser,
    incoming: 'google' | 'github',
): string | null {
    // Different OAuth provider — always reject
    if (user.provider !== 'local' && user.provider !== incoming) {
        return `This email is registered with ${user.provider}. Use that provider to sign in.`;
    }

    // Local account with password and verified email — block takeover
    if (user.provider === 'local' && user.isEmailVerified && user.password) {
        return 'This email uses password login. Sign in with your password, then link OAuth in settings.';
    }

    return null;
}

/**
 * Check if OAuth can safely take over a local account (for passport strategy).
 * Returns true if safe, false if should block.
 */
export function canOAuthTakeOverLocalAccount(user: IUser): boolean {
    // No password set or email not verified — safe to take over
    return !user.password || !user.isEmailVerified;
}
