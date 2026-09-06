import { Request, Response } from 'express';

import crypto from 'crypto';
import { User, IUser } from '../models/User';
import { generateTokenPair, verifyRefreshToken, verifyAccessToken } from '../services/token.service';
import { revokeAccessToken } from '../services/revoke.service';
import { createOAuthExchangeCode, consumeOAuthExchangeCode } from '../services/oauth-exchange.service';
import { createOAuthState, consumeOAuthState } from '../services/oauth-pkce.service';
import {
    redeemEmailLinkCode,
    consumeFormToken,
} from '../services/email-link.service';
import {
    createVerificationPollToken,
    resolveVerificationPollToken,
} from '../services/verification-poll.service';
import {
    persistSessionTokens,
    publishTokenVersion,
    revokeAllTrackedAccessJtis,
    rotateSessionTokens,
    invalidateAllSessions,
    removeRefreshToken,
} from '../services/session.service';
import { findStoredRefreshToken } from '../utils/refresh-token.util';
import { sendVerificationEmail, sendPasswordResetEmail } from '../services/email.service';
import { config } from '../config';
import { rateLimitConfig } from '../config/rateLimit.config';
import {
    RegisterInput,
    LoginInput,
    EmailCheckInput,
    EmailVerifyInput,
} from '../validators/auth.validators';
import { setAuthCookies, clearAuthCookies, getRefreshFromRequest, publicTokenFields } from '../utils/cookie.util';
import {
    findPendingMigrationHolder,
    findUserIdByPrimaryEmail,
    resolveEmailIdentity,
    syncIdentityIndexesFromUser,
    releaseUserIdentityIndexes,
} from '../services/identity-index.service';

function issueSessionCookies(res: Response, refreshToken: string): void {
    setAuthCookies(res, refreshToken);
}

// Check email — uniform response prevents verified-email enumeration (ADR-0062).
export const checkEmailAvailability = async (req: Request, res: Response): Promise<void> => {
    try {
        res.json({ available: true, message: 'Continue if this is your email address' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

/** @deprecated Email query leaks verification state — always returns false (ADR-0062). */
export const getVerificationStatus = async (_req: Request, res: Response): Promise<void> => {
    res.json({ success: true, verified: false });
};

/** Poll verification status with opaque token issued at register (ADR-0062). */
export const postVerificationStatus = async (req: Request, res: Response): Promise<void> => {
    try {
        const { pollToken } = req.body as { pollToken?: string };
        if (!pollToken) {
            res.status(400).json({ success: false, message: 'pollToken is required' });
            return;
        }

        const userId = await resolveVerificationPollToken(pollToken);
        if (!userId) {
            res.json({ success: true, verified: false });
            return;
        }

        const user = await User.findById(userId).select('isEmailVerified').lean();
        res.json({
            success: true,
            verified: user?.isEmailVerified === true,
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Register new user
// Register new user
export const register = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password, displayName } = req.body as RegisterInput;
        const lowerEmail = email.toLowerCase();

        // CRITICAL: Check if this email has a pending migration from another account
        const pendingHolderId = await findPendingMigrationHolder(lowerEmail);
        if (pendingHolderId) {
            res.status(400).json({ 
                success: false, 
                message: 'This email is pending migration from another account. Please complete the migration process first.',
                code: 'PENDING_MIGRATION',
                requiresMigration: true
            });
            return;
        }

        // Inverted index lookup — O(1) primary email existence
        const existingUserId = await findUserIdByPrimaryEmail(lowerEmail);
        let user: any = existingUserId ? await User.findById(existingUserId) : null;

        if (user) {
            if (user.isEmailVerified) {
                res.status(400).json({ success: false, message: 'Email already registered' });
                return;
            }

            user.password = password;
            user.displayName = displayName;
            user.provider = 'local';
        } else {
            // Create new user instance
            user = new User({
                email: lowerEmail,
                password,
                displayName,
                provider: 'local',
            });
        }

        // Generate verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(verificationToken).digest('hex');

        // Set/Update verification fields
        user.emailVerificationToken = hashedToken;
        user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        user.isEmailVerified = false;

        if (config.security.autoVerifyEmail) {
            user.isEmailVerified = true;
            user.emailVerificationToken = undefined;
            user.emailVerificationExpires = undefined;
        }

        await user.save();
        await syncIdentityIndexesFromUser(user);

        // Send verification email (skipped when auto-verify is on)
        if (!config.security.autoVerifyEmail) {
            try {
                await sendVerificationEmail(lowerEmail, verificationToken);
            } catch (emailError) {
                console.error('Failed to send verification email:', emailError);
            }
        }

        if (config.security.autoVerifyEmail) {
            const tokens = generateTokenPair(user);
            await persistSessionTokens(user._id, tokens.accessToken, tokens.refreshToken, user.tokenVersion ?? 0);
            issueSessionCookies(res, tokens.refreshToken);

            res.status(201).json({
                success: true,
                message: 'Registration successful',
                ...publicTokenFields(tokens.accessToken, tokens.refreshToken),
                user: {
                    id: user._id,
                    email: user.email,
                    displayName: user.displayName,
                    avatar: user.avatar,
                    bio: user.bio,
                    isEmailVerified: user.isEmailVerified,
                },
            });
            return;
        }

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please check your email to verify your account.',
            verificationPollToken: await createVerificationPollToken(user._id),
            user: {
                id: user._id,
                email: user.email,
                displayName: user.displayName,
                avatar: user.avatar,
                bio: user.bio,
                isEmailVerified: user.isEmailVerified,
            },
        });
    } catch (error: unknown) {
        const mongoErr = error as { code?: number };
        if (mongoErr?.code === 11000) {
            res.status(400).json({ success: false, message: 'Email already registered' });
            return;
        }
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Registration failed' });
    }
};

// Login user
export const login = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password } = req.body as LoginInput;
        const lowerEmail = email.toLowerCase();

        // 1. Check Rate Limit Block (Handled by middleware, but check if we need to track this specific user context)

        const resolved = await resolveEmailIdentity(lowerEmail);
        const user = resolved
            ? await User.findById(resolved.userId).select('+password +refreshTokens +loginCount +lastLogin +bio +avatar +displayName +provider +providerId +previousEmail +migrationExpiry +newEmailPending +currentEmailVerified +newEmailVerified')
            : null;

        // Handle login with new email during migration (before finalization)
        if (user && user.newEmailPending === lowerEmail) {
            // If both emails are verified, migration should be finalized
            // But if user is logging in with new email, allow it and finalize if needed
            if (user.currentEmailVerified && user.newEmailVerified) {
                // Migration is complete but not finalized yet - finalize it now
                // This allows new email to login directly
                // IMPORTANT: Preserve ALL user data including bio
                const oldEmail = user.email;
                const pendingEmail = user.newEmailPending;
                if (!pendingEmail) {
                    res.status(500).json({ success: false, message: 'Migration state invalid' });
                    return;
                }
                user.previousEmail = oldEmail;
                user.email = pendingEmail;
                user.migrationExpiry = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000);
                user.lastMigrationDate = new Date();
                user.isEmailVerified = true;
                // Cleanup migration fields only
                user.newEmailPending = undefined;
                user.currentEmailVerified = undefined;
                user.newEmailVerified = undefined;
                user.currentEmailToken = undefined;
                user.newEmailToken = undefined;
                // bio, displayName, avatar, and all other fields are preserved automatically
                await user.save();
                await syncIdentityIndexesFromUser(user);
            } else {
                res.status(403).json({
                    success: false,
                    message: 'Please verify both email addresses before logging in with the new email.'
                });
                return;
            }
        }

        // Check migration expiry if logged in with old email
        if (user && user.previousEmail === lowerEmail) {
            if (user.migrationExpiry && user.migrationExpiry < new Date()) {
                res.status(403).json({
                    success: false,
                    message: 'This email is no longer valid for this account. Please use your new email address.'
                });
                return;
            }
        }

        if (!user) {
            res.status(401).json({ success: false, message: 'Invalid email or password' });
            return;
        }

        if (user.provider !== 'local') {
            res.status(401).json({
                success: false,
                message: 'Invalid email or password',
                code: 'AUTH_FAILED',
            });
            return;
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            res.status(401).json({ success: false, message: 'Invalid email or password' });
            return;
        }

        // 2. Check if Email Verified — same response as wrong password (ADR-0063)
        if (!user.isEmailVerified) {
            res.status(401).json({
                success: false,
                message: 'Invalid email or password',
                code: 'AUTH_FAILED',
            });
            return;
        }

        // 3. Check Daily Login Limit
        const today = new Date().setHours(0, 0, 0, 0);
        const lastLoginDate = user.lastLogin ? new Date(user.lastLogin).setHours(0, 0, 0, 0) : 0;

        if (lastLoginDate === today) {
            if ((user.loginCount || 0) >= rateLimitConfig.login.maxDailyLogins) {
                res.status(429).json({
                    success: false,
                    message: 'Daily login limit exceeded. Please try again tomorrow.'
                });
                return;
            }
            user.loginCount = (user.loginCount || 0) + 1;
        } else {
            // Reset for new day
            user.loginCount = 1;
        }

        // Update login stats
        user.lastLogin = new Date();

        // Generate tokens
        const { accessToken, refreshToken } = generateTokenPair(user);
        await persistSessionTokens(user._id, accessToken, refreshToken, user.tokenVersion ?? 0);
        issueSessionCookies(res, refreshToken);

        // CRITICAL: Reload user to ensure ALL fields are fresh (especially after migration)
        // This ensures bio, avatar, displayName, and all other data from previous account is loaded
        const freshUser = await User.findById(user._id).select('+bio +avatar +displayName +provider +providerId +previousEmail +migrationExpiry +createdAt');
        
        if (!freshUser) {
            res.status(500).json({ success: false, message: 'Failed to load user data' });
            return;
        }
        
        // Return ALL user data - this includes all data from previous account after migration
        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: freshUser._id,
                email: freshUser.email, // New email after migration
                displayName: freshUser.displayName, // Preserved from previous account
                avatar: freshUser.avatar, // Preserved from previous account (or Gravatar)
                bio: freshUser.bio, // CRITICAL: Bio from previous account is preserved
                isEmailVerified: freshUser.isEmailVerified,
                provider: freshUser.provider, // Preserved from previous account
                previousEmail: freshUser.previousEmail, // Old email (if migrated)
                createdAt: freshUser.createdAt, // Original account creation date
            },
            ...publicTokenFields(accessToken, refreshToken),
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Login failed' });
    }
};

// Resend verification email — uniform response prevents email enumeration (ADR-0060).
export const resendVerification = async (req: Request, res: Response): Promise<void> => {
    const genericSuccess = {
        success: true,
        message: 'If the account exists and is unverified, a verification email has been sent',
    };

    try {
        const { email } = req.body as EmailCheckInput;
        const lowerEmail = email.toLowerCase();
        const userId = await findUserIdByPrimaryEmail(lowerEmail);
        const user = userId ? await User.findById(userId) : null;

        if (!user || user.isEmailVerified || user.provider !== 'local') {
            res.json(genericSuccess);
            return;
        }

        const verificationToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(verificationToken).digest('hex');

        user.emailVerificationToken = hashedToken;
        user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
        await user.save();

        try {
            await sendVerificationEmail(lowerEmail, verificationToken);
        } catch (emailError) {
            console.error('Failed to send verification email:', emailError);
            // Do not reveal whether the address exists or mail failed
            res.json(genericSuccess);
            return;
        }

        res.json(genericSuccess);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Verify email — formToken from POST /redeem-email-link (raw token never in URL).
export const verifyEmail = async (req: Request, res: Response): Promise<void> => {
    try {
        const { formToken, password } = req.body as EmailVerifyInput;
        const redeemed = await consumeFormToken(formToken, 'verify-email');
        if (!redeemed) {
            res.status(400).json({ success: false, message: 'Invalid or expired verification session' });
            return;
        }

        const hashedToken = crypto.createHash('sha256').update(redeemed.secret).digest('hex');

        const user = await User.findOne({
            emailVerificationToken: hashedToken,
            emailVerificationExpires: { $gt: new Date() },
            provider: 'local',
        }).select('+refreshTokens +password');

        if (!user) {
            res.status(400).json({ success: false, message: 'Invalid or expired verification token' });
            return;
        }

        user.password = password;
        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;
        await user.save();
        await syncIdentityIndexesFromUser(user);

        const { accessToken, refreshToken } = generateTokenPair(user);
        await persistSessionTokens(user._id, accessToken, refreshToken, user.tokenVersion ?? 0);
        issueSessionCookies(res, refreshToken);

        res.json({
            success: true,
            message: 'Email verified successfully',
            user: {
                id: user._id,
                email: user.email,
                displayName: user.displayName,
                avatar: user.avatar,
                bio: user.bio,
                isEmailVerified: user.isEmailVerified,
            },
            ...publicTokenFields(accessToken, refreshToken),
        });
    } catch (error) {
        console.error('Verify email error:', error);
        res.status(500).json({ success: false, message: 'Email verification failed' });
    }
};

// Request password reset
export const requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email } = req.body;
        const lowerEmail = email.toLowerCase();
        const userId = await findUserIdByPrimaryEmail(lowerEmail);
        const user = userId ? await User.findById(userId) : null;

        // Always return success to prevent email enumeration
        if (!user || user.provider !== 'local') {
            res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
            return;
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

        user.passwordResetToken = hashedToken;
        user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        await user.save();

        try {
            await sendPasswordResetEmail(lowerEmail, resetToken);
        } catch (emailError) {
            console.error('Failed to send password reset email:', emailError);
        }

        res.json({ success: true, message: 'If the email exists, a reset link has been sent' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Password reset request failed' });
    }
};

// Reset password
export const resetPassword = async (req: Request, res: Response): Promise<void> => {
    try {
        const { formToken, password } = req.body;
        const redeemed = await consumeFormToken(formToken, 'reset-password');
        if (!redeemed) {
            res.status(400).json({ success: false, message: 'Invalid or expired reset session' });
            return;
        }

        const hashedToken = crypto.createHash('sha256').update(redeemed.secret).digest('hex');

        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: new Date() },
        }).select('+refreshTokens +activeAccessJtis');

        if (!user) {
            res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
            return;
        }

        const newVersion = (user.tokenVersion ?? 0) + 1;
        const published = await publishTokenVersion(user._id, newVersion);
        if (!published) {
            res.status(503).json({
                success: false,
                message: 'Password reset could not invalidate active sessions. Please try again.',
            });
            return;
        }

        await revokeAllTrackedAccessJtis(user.activeAccessJtis);

        user.password = password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        user.refreshTokens = [];
        user.activeAccessJtis = [];
        user.tokenVersion = newVersion;
        await user.save();

        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Password reset failed' });
    }
};

// Refresh access token
export const refreshAccessToken = async (req: Request, res: Response): Promise<void> => {
    try {
        const refreshToken = getRefreshFromRequest(req);
        const { accessToken: priorAccessToken } = req.body;

        if (!refreshToken) {
            res.status(401).json({ success: false, message: 'Refresh token is required' });
            return;
        }

        const payload = verifyRefreshToken(refreshToken);
        if (!payload) {
            res.status(401).json({ success: false, message: 'Invalid refresh token' });
            return;
        }

        const user = await User.findById(payload.userId).select('+refreshTokens');
        if (!user) {
            res.status(401).json({ success: false, message: 'User not found' });
            return;
        }

        // Check if refresh token exists in user's tokens
        const storedKey = findStoredRefreshToken(user.refreshTokens, refreshToken);
        if (!storedKey) {
            await invalidateAllSessions(user._id);
            res.status(401).json({
                success: false,
                message: 'Session invalidated — please sign in again',
            });
            return;
        }

        const tokens = generateTokenPair(user);

        // Revoke the previous access token if the client supplies it (rotation hygiene).
        if (typeof priorAccessToken === 'string' && priorAccessToken && verifyAccessToken(priorAccessToken)) {
            await revokeAccessToken(priorAccessToken);
        }

        const rotated = await rotateSessionTokens(
            user._id,
            refreshToken,
            tokens.accessToken,
            tokens.refreshToken,
            user.tokenVersion ?? 0,
        );
        if (!rotated) {
            await invalidateAllSessions(user._id);
            res.status(401).json({
                success: false,
                message: 'Session invalidated — please sign in again',
            });
            return;
        }

        issueSessionCookies(res, tokens.refreshToken);

        res.json({
            success: true,
            ...publicTokenFields(tokens.accessToken, tokens.refreshToken),
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Token refresh failed' });
    }
};

// Logout — invalidate refresh token server-side AND revoke access JWT in gateway Redis.
export const logout = async (req: Request, res: Response): Promise<void> => {
    try {
        const refreshToken = getRefreshFromRequest(req);
        const { accessToken: bodyAccessToken } = req.body;

        if (refreshToken) {
            const payload = verifyRefreshToken(refreshToken);
            if (payload) {
                await removeRefreshToken(payload.userId, refreshToken);
            }
        }

        // Body-only access token — never read Authorization (gateway JWT LRU cache, ADR-0038).
        const accessToken =
            typeof bodyAccessToken === 'string' && bodyAccessToken
                ? bodyAccessToken
                : undefined;

        if (accessToken && verifyAccessToken(accessToken)) {
            await revokeAccessToken(accessToken);
        }

        clearAuthCookies(res);
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Logout failed' });
    }
};

// Get current user
export const getCurrentUser = async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user as IUser | undefined;

        if (!user) {
            res.status(401).json({ success: false, message: 'Not authenticated' });
            return;
        }

        // CRITICAL: Reload user from database to ensure ALL fields are fresh
        // This is especially important after migration to get all preserved data
        const freshUser = await User.findById(user._id).select('+bio +avatar +displayName +provider +providerId +previousEmail +migrationExpiry +createdAt');
        
        if (!freshUser) {
            res.status(404).json({ success: false, message: 'User not found' });
            return;
        }

        // Return ALL user data including data from previous account after migration
        res.json({
            success: true,
            user: {
                id: freshUser._id,
                email: freshUser.email, // Current email (new email after migration)
                displayName: freshUser.displayName, // Preserved from previous account
                avatar: freshUser.avatar, // Preserved from previous account
                bio: freshUser.bio, // CRITICAL: Bio from previous account is preserved
                isEmailVerified: freshUser.isEmailVerified,
                provider: freshUser.provider, // Preserved from previous account
                previousEmail: freshUser.previousEmail, // Old email (if migrated)
                createdAt: freshUser.createdAt, // Original account creation date
            },
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Failed to get user' });
    }
};

// Redeem opaque email link code (POST-only — never pass raw tokens in URLs).
export const redeemEmailLink = async (req: Request, res: Response): Promise<void> => {
    try {
        const { code } = req.body as { code?: string };
        if (!code) {
            res.status(400).json({ success: false, message: 'Link code is required' });
            return;
        }

        const redeemed = await redeemEmailLinkCode(code);
        if (!redeemed) {
            res.status(400).json({ success: false, message: 'Invalid or expired link' });
            return;
        }

        res.json({
            success: true,
            kind: redeemed.kind,
            formToken: redeemed.formToken,
            meta: redeemed.meta,
        });
    } catch {
        res.status(500).json({ success: false, message: 'Failed to redeem link' });
    }
};

// Prepare OAuth PKCE state before redirecting to provider.
export const getOAuthProviders = (_req: Request, res: Response): void => {
    res.json({
        success: true,
        google: config.oauth.googleEnabled,
        github: config.oauth.githubEnabled,
    });
};

export const prepareOAuth = async (req: Request, res: Response): Promise<void> => {
    try {
        const { codeChallenge } = req.body as { codeChallenge?: string };
        if (!codeChallenge) {
            res.status(400).json({ success: false, message: 'codeChallenge is required' });
            return;
        }

        const state = await createOAuthState(codeChallenge);
        res.json({ success: true, state });
    } catch {
        res.status(500).json({ success: false, message: 'Failed to prepare OAuth' });
    }
};

// Handle OAuth callback success — redirect with one-time code + state, not tokens in URL.
export const handleOAuthSuccess = async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user as IUser | undefined;
        const state = typeof req.query.state === 'string' ? req.query.state : '';

        if (!user || !state) {
            res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
            return;
        }

        const { accessToken, refreshToken } = generateTokenPair(user);
        await persistSessionTokens(user._id, accessToken, refreshToken, user.tokenVersion ?? 0);

        const code = await createOAuthExchangeCode(accessToken, refreshToken, state);
        const redirectUrl = `${process.env.CLIENT_URL || 'http://localhost:5173'}/oauth-callback?code=${code}&state=${encodeURIComponent(state)}`;
        res.redirect(redirectUrl);
    } catch (error) {
        res.redirect(`${process.env.CLIENT_URL || 'http://localhost:5173'}/login?error=oauth_failed`);
    }
};

// Exchange one-time OAuth code for tokens (POST — PKCE + state bound).
export const exchangeOAuthCode = async (req: Request, res: Response): Promise<void> => {
    try {
        const { code, state, codeVerifier } = req.body as {
            code?: string;
            state?: string;
            codeVerifier?: string;
        };
        if (!code || !state || !codeVerifier) {
            res.status(400).json({ success: false, message: 'OAuth code, state, and codeVerifier are required' });
            return;
        }

        const pkceValid = await consumeOAuthState(state, codeVerifier);
        if (!pkceValid) {
            res.status(400).json({ success: false, message: 'Invalid OAuth state or PKCE verifier' });
            return;
        }

        const tokens = await consumeOAuthExchangeCode(code, state);
        if (!tokens) {
            res.status(400).json({ success: false, message: 'Invalid or expired OAuth code' });
            return;
        }

        issueSessionCookies(res, tokens.refreshToken);

        res.json({
            success: true,
            ...publicTokenFields(tokens.accessToken, tokens.refreshToken),
        });
    } catch {
        res.status(500).json({ success: false, message: 'OAuth exchange failed' });
    }
};
