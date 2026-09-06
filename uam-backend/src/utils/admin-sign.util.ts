/**
 * HMAC signing for control-plane admin mutations (ADR-0023).
 * Production: timestamp + nonce bound into the signed material to block replays.
 */
import crypto from 'crypto';
import { config } from '../config';

export interface AdminSignHeaders extends Record<string, string> {
    'Content-Type': string;
    'X-Admin-Timestamp': string;
    'X-Admin-Nonce': string;
    'X-Admin-Signature': string;
}

function signingMaterial(timestamp: string, nonce: string, body: string): Buffer {
    return Buffer.concat([
        Buffer.from(`${timestamp}\n${nonce}\n`, 'utf8'),
        Buffer.from(body, 'utf8'),
    ]);
}

/**
 * Headers for POST /revoke (and other admin mutations).
 * Dev default ADMIN_API_KEY skips verification on the control plane.
 */
export function adminSignHeaders(body: string): AdminSignHeaders {
    const headers: AdminSignHeaders = {
        'Content-Type': 'application/json',
        'X-Admin-Timestamp': String(Math.floor(Date.now() / 1000)),
        'X-Admin-Nonce': crypto.randomBytes(16).toString('hex'),
        'X-Admin-Signature': 'sha256=',
    };

    const key = config.controlPlane.adminApiKey;
    if (!key || key === 'CHANGE_ME_ADMIN_API_KEY') {
        return headers;
    }

    const material = signingMaterial(headers['X-Admin-Timestamp'], headers['X-Admin-Nonce'], body);
    const digest = crypto.createHmac('sha256', key).update(material).digest('hex');
    headers['X-Admin-Signature'] = `sha256=${digest}`;
    return headers;
}
