import { z } from 'zod';

// Email validation with comprehensive checks
const emailSchema = z
    .string()
    .min(1, 'Email is required')
    .email('Invalid email format')
    .max(255, 'Email is too long')
    .refine((email) => {
        // Additional validation for common disposable email domains
        const disposableDomains = ['tempmail.com', 'throwaway.com', '10minutemail.com', 'guerrillamail.com'];
        const domain = email.split('@')[1]?.toLowerCase();
        return !disposableDomains.includes(domain);
    }, 'Disposable email addresses are not allowed')
    .refine((email) => {
        // Check for valid TLD
        const tldRegex = /\.[a-zA-Z]{2,}$/;
        return tldRegex.test(email);
    }, 'Invalid email domain');

// Password validation with strength requirements
const passwordSchema = z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .max(128, 'Password is too long')
    .refine((password) => /[A-Z]/.test(password), 'Password must contain at least one uppercase letter')
    .refine((password) => /[a-z]/.test(password), 'Password must contain at least one lowercase letter')
    .refine((password) => /[0-9]/.test(password), 'Password must contain at least one number')
    .refine((password) => /[^A-Za-z0-9]/.test(password), 'Password must contain at least one special character');

// Display name validation
const displayNameSchema = z
    .string()
    .min(2, 'Display name must be at least 2 characters')
    .max(50, 'Display name is too long')
    .regex(/^[a-zA-Z0-9\s\-_]+$/, 'Display name can only contain letters, numbers, spaces, hyphens, and underscores');

// Registration schema
export const registerSchema = z.object({
    email: emailSchema,
    password: passwordSchema,
    displayName: displayNameSchema,
});

// Login schema
export const loginSchema = z.object({
    email: emailSchema,
    password: z.string().min(1, 'Password is required'),
});

// Email check schema (for quick availability check)
export const emailCheckSchema = z.object({
    email: emailSchema,
});

// Password reset request schema
export const passwordResetRequestSchema = z.object({
    email: emailSchema,
});

// Password reset schema — formToken from POST /redeem-email-link (raw token never in URL)
export const passwordResetSchema = z.object({
    formToken: z.string().min(64, 'Invalid form token').max(128),
    password: passwordSchema,
});

// Email verification — formToken from POST /redeem-email-link
export const emailVerifySchema = z.object({
    formToken: z.string().min(64, 'Invalid form token').max(128),
    password: passwordSchema,
});

export const redeemEmailLinkSchema = z.object({
    code: z.string().min(64, 'Invalid link code').max(128),
});

export const oauthPrepareSchema = z.object({
    codeChallenge: z.string().min(43).max(128),
    /** Optional per-client callback, e.g. https://productioncore.dev/oauth-callback (allowlisted). */
    redirectUri: z.string().url().max(200).optional(),
});

export const oauthExchangeSchema = z.object({
    code: z.string().min(64, 'Invalid OAuth code').max(128),
    state: z.string().min(64, 'Invalid OAuth state').max(128),
    codeVerifier: z.string().min(43).max(128),
});

export const resendVerificationSchema = z.object({
    email: emailSchema,
});

// Refresh token schema — body optional when HttpOnly cookie is used (ADR-0055)
export const refreshTokenSchema = z.object({
    refreshToken: z.string().optional(),
    /** Prior access token to revoke on rotation (recommended — limits refresh theft window). */
    accessToken: z.string().optional(),
});

export const verificationPollSchema = z.object({
    pollToken: z.string().min(64, 'Invalid poll token').max(128),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type EmailCheckInput = z.infer<typeof emailCheckSchema>;
export type PasswordResetRequestInput = z.infer<typeof passwordResetRequestSchema>;
export type PasswordResetInput = z.infer<typeof passwordResetSchema>;
export type EmailVerifyInput = z.infer<typeof emailVerifySchema>;
export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>;
