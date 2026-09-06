/**
 * Startup checks for known dev/default secrets (ADR-0041 / ADR-0058).
 */
import { config } from '../config';
import { getPepper } from './password.util';

const DEV_JWT_ACCESS = new Set([
    '',
    'default-access-secret',
    'super_secret_key_for_hmac_sha256',
    'CHANGE_ME_JWT_ACCESS_SECRET',
    'CHANGE_ME_JWT_ACCESS_SECRET',
]);

const DEV_JWT_REFRESH = new Set([
    '',
    'default-refresh-secret',
    'CHANGE_ME_JWT_REFRESH_SECRET',
]);

const DEV_ADMIN_KEYS = new Set([
    'CHANGE_ME_ADMIN_API_KEY',
    'change_me_use_a_long_random_admin_key',
]);

const DEV_PEPPERS = new Set([
    '',
    'change_me_use_a_long_random_password_pepper_at_least_32_chars',
    'CHANGE_ME_PASSWORD_PEPPER',
]);

function isProduction(): boolean {
    return config.nodeEnv === 'production';
}

function refuseInsecureSecretsEnabled(): boolean {
    return (
        process.env.UAM_REFUSE_INSECURE_SECRETS === '1'
        || process.env.UAM_REFUSE_INSECURE_SECRETS === 'true'
    );
}

function insecureSecretReasons(): string[] {
    const reasons: string[] = [];
    const access = process.env.JWT_ACCESS_SECRET || '';
    const refresh = process.env.JWT_REFRESH_SECRET || '';
    const admin = process.env.ADMIN_API_KEY || '';
    const pepper = getPepper();

    if (DEV_JWT_ACCESS.has(access)) {
        reasons.push('JWT_ACCESS_SECRET is empty or a known dev default');
    }
    if (DEV_JWT_REFRESH.has(refresh)) {
        reasons.push('JWT_REFRESH_SECRET is empty or a known dev default');
    }
    if (DEV_ADMIN_KEYS.has(admin)) {
        reasons.push('ADMIN_API_KEY is a known dev default');
    }
    if (DEV_PEPPERS.has(pepper)) {
        reasons.push('PASSWORD_PEPPER is empty or a known dev default');
    }
    return reasons;
}

function isDevStack(): boolean {
    return (
        process.env.UAM_DEV_STACK === '1'
        || process.env.UAM_DEV_STACK === 'true'
    );
}

function criticalProductionMisconfig(): string[] {
    const reasons: string[] = [];
    if (isProduction() && config.security.autoVerifyEmail) {
        reasons.push('AUTO_VERIFY_EMAIL must not be enabled in production');
    }
    return reasons;
}

/** Warn (or exit) on insecure startup secrets and production-only misconfigurations. */
export function warnIfInsecureSecrets(): void {
    const critical = criticalProductionMisconfig();
    if (critical.length > 0) {
        for (const reason of critical) {
            // eslint-disable-next-line no-console
            console.error(`[uam] ${reason}`);
        }
        process.exit(1);
    }

    const reasons = insecureSecretReasons();
    if (reasons.length === 0) {
        return;
    }

    for (const reason of reasons) {
        // eslint-disable-next-line no-console
        console.warn(`[uam] ${reason} — rotate before production (ADR-0058)`);
    }

    if (refuseInsecureSecretsEnabled()) {
        // eslint-disable-next-line no-console
        console.error('[uam] UAM_REFUSE_INSECURE_SECRETS=1 — refusing to start');
        process.exit(1);
    }
}
