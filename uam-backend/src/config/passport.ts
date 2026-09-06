import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import { User, IUser } from '../models/User';
import { config } from '../config';
import { oauthProviderConflict, canOAuthTakeOverLocalAccount } from '../utils/oauth.util';
import {
    findUserIdByOAuth,
    findUserIdByPrimaryEmail,
    resolveEmailIdentity,
    syncIdentityIndexesFromUser,
} from '../services/identity-index.service';
import { normalizeEmail } from '../utils/email-normalize.util';

interface GitHubEmailEntry {
    email: string;
    primary: boolean;
    verified: boolean;
    visibility: string | null;
}

async function fetchGitHubVerifiedPrimaryEmail(accessToken: string): Promise<string | null> {
    const response = await fetch('https://api.github.com/user/emails', {
        headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'uam-backend',
        },
    });

    if (!response.ok) {
        return null;
    }

    const emails = (await response.json()) as GitHubEmailEntry[];
    const primaryVerified = emails.find((entry) => entry.primary && entry.verified);
    if (primaryVerified?.email) {
        return primaryVerified.email.toLowerCase();
    }

    const anyVerified = emails.find((entry) => entry.verified);
    return anyVerified?.email?.toLowerCase() ?? null;
}

async function findUserForOAuth(
    email: string,
    provider: 'google' | 'github',
    providerId: string,
): Promise<IUser | null> {
    const byOAuthId = await findUserIdByOAuth(provider, providerId);
    if (byOAuthId) {
        const user = await User.findById(byOAuthId);
        if (user) return user;
    }

    const normalized = normalizeEmail(email);
    const resolved = await resolveEmailIdentity(normalized);
    if (!resolved) return null;

    let user = await User.findById(resolved.userId);
    if (!user) return null;

    if (user.previousEmail === normalized && user.email !== normalized) {
        if (user.migrationExpiry && user.migrationExpiry > new Date()) {
            return user;
        }
        const primaryUserId = await findUserIdByPrimaryEmail(normalized);
        if (primaryUserId) {
            const byNewEmail = await User.findById(primaryUserId);
            if (byNewEmail) user = byNewEmail;
        }
}

    // Check if this is a local account that OAuth is trying to take over
    if (user.provider === 'local') {
        const canTakeOver = canOAuthTakeOverLocalAccount(user);
        if (!canTakeOver) {
            // Account is verified with password — block OAuth takeover
            return null; // Will trigger conflict error in strategy
        }
        // Unverified local account — safe to take over, update provider
        user.provider = provider;
        user.providerId = providerId;
        user.isEmailVerified = true;
        await user.save();
        await syncIdentityIndexesFromUser(user);
        return user;
    }

    return user;
}

// Google OAuth Strategy
if (config.google.clientId && config.google.clientSecret) {
    passport.use(
        new GoogleStrategy(
            {
                clientID: config.google.clientId,
                clientSecret: config.google.clientSecret,
                callbackURL: config.google.callbackUrl,
                scope: ['profile', 'email'],
            },
            async (accessToken, refreshToken, profile, done) => {
                try {
                    const email = profile.emails?.[0]?.value?.toLowerCase();

                    if (!email) {
                        return done(new Error('No email found in Google profile'), undefined);
                    }

                    let user = await findUserForOAuth(email, 'google', profile.id);

                    if (user) {
                        const conflict = oauthProviderConflict(user, 'google');
                        if (conflict) {
                            return done(new Error(conflict), undefined);
                        }

                        let modified = false;
                        const profilePic = profile.photos?.[0]?.value;
                        if (profilePic && (!user.avatar || user.provider === 'google')) {
                            if (user.avatar !== profilePic) {
                                user.avatar = profilePic;
                                modified = true;
                            }
                        }

                        if (user.provider === 'google' && profile.displayName) {
                            if (user.displayName !== profile.displayName) {
                                user.displayName = profile.displayName;
                                modified = true;
                            }
                        }

                        if (modified) {
                            await user.save();
                            await syncIdentityIndexesFromUser(user);
                        }
                    } else {
                        user = await User.create({
                            email,
                            displayName: profile.displayName || email.split('@')[0],
                            avatar: profile.photos?.[0]?.value,
                            provider: 'google',
                            providerId: profile.id,
                            isEmailVerified: true,
                        });
                        await syncIdentityIndexesFromUser(user);
                    }

                    return done(null, user);
                } catch (error) {
                    return done(error as Error, undefined);
                }
            }
        )
    );
}

// GitHub OAuth Strategy
if (config.github.clientId && config.github.clientSecret) {
    passport.use(
        new GitHubStrategy(
            {
                clientID: config.github.clientId,
                clientSecret: config.github.clientSecret,
                callbackURL: config.github.callbackUrl,
                scope: ['user:email'],
            },
            async (
                accessToken: string,
                refreshToken: string,
                profile: any,
                done: (error: Error | null, user?: any) => void
            ) => {
                try {
                    const email = await fetchGitHubVerifiedPrimaryEmail(accessToken);

                    if (!email) {
                        return done(new Error('No verified email found in GitHub profile'));
                    }

                    let user = await findUserForOAuth(email, 'github', profile.id);

                    if (user) {
                        const conflict = oauthProviderConflict(user, 'github');
                        if (conflict) {
                            return done(new Error(conflict));
                        }

                        let modified = false;
                        const profilePic = profile.photos?.[0]?.value;
                        if (profilePic && (!user.avatar || user.provider === 'github')) {
                            if (user.avatar !== profilePic) {
                                user.avatar = profilePic;
                                modified = true;
                            }
                        }

                        const githubName = profile.displayName || profile.username;
                        if (user.provider === 'github' && githubName) {
                            if (user.displayName !== githubName) {
                                user.displayName = githubName;
                                modified = true;
                            }
                        }

                        if (modified) {
                            await user.save();
                            await syncIdentityIndexesFromUser(user);
                        }
                    } else {
                        user = await User.create({
                            email,
                            displayName: profile.displayName || profile.username || email.split('@')[0],
                            avatar: profile.photos?.[0]?.value,
                            provider: 'github',
                            providerId: profile.id,
                            isEmailVerified: true,
                        });
                        await syncIdentityIndexesFromUser(user);
                    }

                    return done(null, user);
                } catch (error) {
                    return done(error as Error);
                }
            }
        )
    );
}

export default passport;
