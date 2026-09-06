import { Request, Response } from 'express';
import crypto from 'crypto';
import { User, IUser } from '../models/User';
import { sendEmail } from '../services/email.service';
import { createEmailLinkCode, consumeFormToken } from '../services/email-link.service';
import { generateTokenPair } from '../services/token.service';
import { persistSessionTokens } from '../services/session.service';
import { setAuthCookies, publicTokenFields } from '../utils/cookie.util';
import { config } from '../config';
import { getAvatarUrl } from '../utils/gravatar';
import { 
    extractUserData, 
    applyUserData, 
    logPreservedData, 
    verifyPreservedData,
    PreservedUserData 
} from '../utils/migration-data-preserver';
import {
    findUserIdByPrimaryEmail,
    releaseUserIdentityIndexes,
    syncIdentityIndexesFromUser,
} from '../services/identity-index.service';

async function buildMigrationVerifyUrl(
    kind: 'migrate-current' | 'migrate-new',
    secretToken: string,
    meta?: Record<string, string>,
): Promise<string> {
    const code = await createEmailLinkCode(kind, secretToken, meta);
    return `${config.clientUrl}/migrate/verify?code=${code}`;
}

// Helper function to finalize migration
const finalizeMigrationInternal = async (user: IUser, res: Response): Promise<void> => {
    try {
        if (!user.newEmailPending) {
            res.status(400).json({ success: false, message: 'No pending migration' });
            return;
        }

        // SECURITY: Re-verify tokenVersion from DB to prevent race conditions
        const currentUser = await User.findById(user._id).select('+bio +avatar +displayName +loginCount +lastLogin +provider +providerId +createdAt +tokenVersion');
        if (!currentUser) {
            res.status(404).json({ success: false, message: 'User not found' });
            return;
        }
        // Verify tokenVersion matches (prevents stale request race)
        if (currentUser.tokenVersion !== user.tokenVersion) {
            res.status(409).json({ success: false, message: 'Concurrent modification detected — please retry' });
            return;
        }

        const newEmail = currentUser.newEmailPending?.toLowerCase();
        if (!newEmail) {
            res.status(400).json({ success: false, message: 'No pending migration' });
            return;
        }
        
        const existingUserId = await findUserIdByPrimaryEmail(newEmail);
        const existingUserWithNewEmail = existingUserId ? await User.findById(existingUserId) : null;
        
        if (existingUserWithNewEmail) {
            // If it's a different user (not the same _id), we need to merge accounts
            if (existingUserWithNewEmail._id.toString() !== currentUser._id.toString()) {
                console.log(`⚠️  User with new email ${newEmail} already exists. Merging accounts...`);
                
                // FLEXIBLE: Extract all user data using the extensible system
                const preservedData = await extractUserData(currentUser);
                logPreservedData(preservedData, 'Account Merge');
                
                // CRITICAL: DELETE the existing user FIRST before updating email to avoid duplicate key error
                const existingUserId = existingUserWithNewEmail._id;
                await releaseUserIdentityIndexes(existingUserId);
                await User.findByIdAndDelete(existingUserId);
                console.log(`✅ Deleted existing user ${existingUserId} with email ${newEmail} before updating original user`);
                
                // Now update the original user with new email (no duplicate key error)
                // Use atomic update with version check to prevent race conditions
                const updateResult = await User.findOneAndUpdate(
                    { _id: currentUser._id, tokenVersion: currentUser.tokenVersion },
                    {
                        $set: {
                            previousEmail: currentUser.email,
                            email: newEmail,
                            migrationExpiry: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
                            lastMigrationDate: new Date(),
                            isEmailVerified: true,
                            newEmailPending: undefined,
                            migrationToken: undefined,
                            migrationTokenExpires: undefined,
                            currentEmailVerified: undefined,
                            newEmailVerified: undefined,
                            currentEmailToken: undefined,
                            newEmailToken: undefined,
                        },
                        $inc: { tokenVersion: 1 },
                    }
                );
                
                if (!updateResult) {
                    // Version mismatch — concurrent modification
                    res.status(409).json({ success: false, message: 'Concurrent modification detected — please retry' });
                    return;
                }
                
                // Apply preserved data to the updated user
                applyUserData(updateResult, preservedData, newEmail);
                updateResult.markModified('bio');
                updateResult.markModified('displayName');
                updateResult.markModified('avatar');
                
                // Update migration history - mark pending as success
                if (!updateResult.migrationHistory) {
                    updateResult.migrationHistory = [];
                }
                const pendingMigration = updateResult.migrationHistory.find(
                    (m: any) => m.status === 'pending' && m.toEmail === newEmail
                );
                if (pendingMigration) {
                    pendingMigration.status = 'success';
                    pendingMigration.completedAt = new Date();
                    pendingMigration.currentEmailVerified = true;
                    pendingMigration.newEmailVerified = true;
                    pendingMigration.pendingFrom = undefined; // Both verified
                } else {
                    updateResult.migrationHistory.push({
                        fromEmail: updateResult.previousEmail || updateResult.email,
                        toEmail: newEmail,
                        status: 'success',
                        initiatedAt: new Date(),
                        completedAt: new Date(),
                        revertedAt: undefined as any,
                        currentEmailVerified: true,
                        newEmailVerified: true,
                        pendingFrom: undefined
                    });
                }
                
                // CRITICAL: Save with explicit options to ensure bio is saved
                await updateResult.save({ validateBeforeSave: true });
                await syncIdentityIndexesFromUser(updateResult);
                
                // CRITICAL: Verify bio was saved immediately after save
                const verifyBio = await User.findById(updateResult._id).select('+bio');
                if (verifyBio) {
                    console.log(`🔍 Bio verification after save: "${verifyBio.bio || 'EMPTY'}" (Expected: "${preservedData.bio || 'EMPTY'}")`);
                    if (verifyBio.bio !== preservedData.bio) {
                        console.error(`❌ CRITICAL: Bio was NOT saved correctly! Re-saving...`);
                        verifyBio.bio = preservedData.bio || '';
                        verifyBio.markModified('bio');
                        await verifyBio.save();
                        console.log(`✅ Bio re-saved. New value: "${verifyBio.bio || 'EMPTY'}"`);
                    } else {
                        console.log(`✅ Bio verified and saved correctly: "${verifyBio.bio || 'EMPTY'}"`);
                    }
                }
                
                console.log(`✅ Migration completed. User ${updateResult._id} now has email ${newEmail}`);
                console.log(`✅ Bio in migrated account: "${updateResult.bio || 'EMPTY'}"`);
                
                // Issue new tokens with incremented tokenVersion
                const tokens = generateTokenPair(updateResult);
                await persistSessionTokens(updateResult._id, tokens.accessToken, tokens.refreshToken, updateResult.tokenVersion);
                setAuthCookies(res, tokens.refreshToken);
                
                res.status(200).json({
                    success: true,
                    message: 'Migration completed successfully',
                    user: {
                        id: updateResult._id,
                        email: updateResult.email,
                        displayName: updateResult.displayName,
                        avatar: updateResult.avatar,
                        bio: updateResult.bio,
                        isEmailVerified: updateResult.isEmailVerified,
                    },
                    ...publicTokenFields(tokens.accessToken, tokens.refreshToken),
                });
                return;
            } else {
                // Same user, just update email
                const updateResult = await User.findOneAndUpdate(
                    { _id: currentUser._id, tokenVersion: currentUser.tokenVersion },
                    {
                        $set: {
                            previousEmail: currentUser.email,
                            email: newEmail,
                            migrationExpiry: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000),
                            lastMigrationDate: new Date(),
                            isEmailVerified: true,
                            newEmailPending: undefined,
                            migrationToken: undefined,
                            migrationTokenExpires: undefined,
                            currentEmailVerified: undefined,
                            newEmailVerified: undefined,
                            currentEmailToken: undefined,
                            newEmailToken: undefined,
                        },
                        $inc: { tokenVersion: 1 },
                    }
                );
                
                if (!updateResult) {
                    res.status(409).json({ success: false, message: 'Concurrent modification detected — please retry' });
                    return;
                }
                
                // Update migration history
                if (!updateResult.migrationHistory) {
                    updateResult.migrationHistory = [];
                }
                const pendingMigration = updateResult.migrationHistory.find(
                    (m: any) => m.status === 'pending' && m.toEmail === newEmail
                );
                if (pendingMigration) {
                    pendingMigration.status = 'success';
                    pendingMigration.completedAt = new Date();
                    pendingMigration.currentEmailVerified = true;
                    pendingMigration.newEmailVerified = true;
                    pendingMigration.pendingFrom = undefined; // Both verified
                } else {
                    updateResult.migrationHistory.push({
                        fromEmail: updateResult.email,
                        toEmail: newEmail,
                        status: 'success',
                        initiatedAt: new Date(),
                        completedAt: new Date(),
                        revertedAt: undefined as any,
                        currentEmailVerified: true,
                        newEmailVerified: true,
                        pendingFrom: undefined
                    });
                }
                
                await updateResult.save({ validateBeforeSave: true });
                await syncIdentityIndexesFromUser(updateResult);
                
                // Issue new tokens
                const tokens = generateTokenPair(updateResult);
                await persistSessionTokens(updateResult._id, tokens.accessToken, tokens.refreshToken, updateResult.tokenVersion);
                setAuthCookies(res, tokens.refreshToken);
                
                res.status(200).json({
                    success: true,
                    message: 'Migration completed successfully',
                    user: {
                        id: updateResult._id,
                        email: updateResult.email,
                        displayName: updateResult.displayName,
                        avatar: updateResult.avatar,
                        bio: updateResult.bio,
                        isEmailVerified: updateResult.isEmailVerified,
                    },
                    ...publicTokenFields(tokens.accessToken, tokens.refreshToken),
                });
                return;
            }
        } else {
            // No existing user, proceed with normal migration
            // CRITICAL: Reload user to ensure we have ALL fields including bio
            // Use select to explicitly include bio and all other fields
            const userDoc = await User.findById(user._id).select('+bio +avatar +displayName +loginCount +lastLogin +provider +providerId +createdAt');
            if (!userDoc) {
                res.status(404).json({ success: false, message: 'User not found' });
                return;
            }

            // FLEXIBLE: Extract all user data using the extensible system
            const preservedData = await extractUserData(userDoc);
            logPreservedData(preservedData, 'Normal Migration');

            const oldEmail = userDoc.email;
            userDoc.previousEmail = oldEmail;
            userDoc.email = newEmail;
            userDoc.migrationExpiry = new Date(Date.now() + 5 * 24 * 60 * 60 * 1000);
            userDoc.lastMigrationDate = new Date();
            userDoc.isEmailVerified = true;
            
            // FLEXIBLE: Apply preserved data (bio, displayName, avatar, etc.)
            // This can be extended to include posts, reels, etc. in the future
            applyUserData(userDoc, preservedData, newEmail);
            
            // CRITICAL: Explicitly mark bio as modified and ensure it's saved
            userDoc.markModified('bio');
            userDoc.markModified('displayName');
            userDoc.markModified('avatar');

            // Update migration history - mark pending as success
            if (!userDoc.migrationHistory) {
                userDoc.migrationHistory = [];
            }
            // Find and update the pending migration entry
            const pendingMigration = userDoc.migrationHistory.find(
                (m: any) => m.status === 'pending' && m.toEmail === newEmail
            );
            if (pendingMigration) {
                pendingMigration.status = 'success';
                pendingMigration.completedAt = new Date();
                pendingMigration.currentEmailVerified = true;
                pendingMigration.newEmailVerified = true;
                pendingMigration.pendingFrom = undefined; // Both verified
                console.log(`✅ Migration history updated: ${oldEmail} -> ${newEmail} marked as success`);
            } else {
                // If no pending entry found, create one (shouldn't happen, but safety)
                userDoc.migrationHistory.push({
                    fromEmail: oldEmail,
                    toEmail: newEmail,
                    status: 'success',
                    initiatedAt: new Date(),
                    completedAt: new Date(),
                    revertedAt: undefined as any,
                    currentEmailVerified: true,
                    newEmailVerified: true,
                    pendingFrom: undefined
                });
                console.log(`⚠️  No pending migration found, created new history entry`);
            }

            // Cleanup migration tokens only - preserve bio and all other fields
            userDoc.migrationToken = undefined;
            userDoc.migrationTokenExpires = undefined;
            userDoc.newEmailPending = undefined;
            userDoc.currentEmailVerified = undefined;
            userDoc.newEmailVerified = undefined;
            userDoc.currentEmailToken = undefined;
            userDoc.newEmailToken = undefined;
            
            // CRITICAL: Save with explicit options to ensure bio is saved
            await userDoc.save({ validateBeforeSave: true });
            await syncIdentityIndexesFromUser(userDoc);
            
            // CRITICAL: Verify bio was saved immediately after save
            const verifyBio = await User.findById(userDoc._id).select('+bio');
            if (verifyBio) {
                console.log(`🔍 Bio verification after save: "${verifyBio.bio || 'EMPTY'}" (Expected: "${preservedData.bio || 'EMPTY'}")`);
                if (verifyBio.bio !== preservedData.bio) {
                    console.error(`❌ CRITICAL: Bio was NOT saved correctly! Re-saving...`);
                    verifyBio.bio = preservedData.bio || '';
                    verifyBio.markModified('bio');
                    await verifyBio.save();
                    console.log(`✅ Bio re-saved. New value: "${verifyBio.bio || 'EMPTY'}"`);
                } else {
                    console.log(`✅ Bio verified and saved correctly: "${verifyBio.bio || 'EMPTY'}"`);
                }
            }
            
            console.log(`✅ Migration completed. User ${userDoc._id} migrated from ${oldEmail} to ${newEmail}`);
            console.log(`✅ Bio in migrated account: "${userDoc.bio || 'EMPTY'}"`);
            
            // FLEXIBLE: Verify that all data was preserved correctly
            const verifyUser = await User.findById(userDoc._id).select('+bio +avatar +displayName');
            if (verifyUser) {
                await verifyPreservedData(verifyUser, preservedData);
            }
            
            // Update user reference for token generation
            user = userDoc;
        }

        // Generate new tokens AFTER saving (needs updated email for token generation)
        const { accessToken, refreshToken } = generateTokenPair(user);
        await persistSessionTokens(user._id, accessToken, refreshToken, user.tokenVersion ?? 0);
        setAuthCookies(res, refreshToken);

        // CRITICAL: Get final user data to return - ensure ALL fields including bio are loaded
        const finalUser = await User.findById(user._id).select('+bio +avatar +displayName +provider +providerId +previousEmail +migrationExpiry +createdAt');
        
        if (!finalUser) {
            res.status(500).json({ success: false, message: 'Failed to retrieve migrated user data' });
            return;
        }
        
        if (config.nodeEnv !== 'production' && !finalUser.bio) {
            console.warn('Migration finalize: bio missing after migration');
        }
        
        res.json({
            success: true,
            message: 'Account migrated successfully! You can login with both emails for 5 days.',
            user: {
                id: finalUser._id,
                email: finalUser.email,
                displayName: finalUser.displayName,
                avatar: finalUser.avatar || getAvatarUrl(finalUser.email),
                bio: finalUser.bio || '',
                isEmailVerified: finalUser.isEmailVerified,
                previousEmail: finalUser.previousEmail,
                provider: finalUser.provider
            },
            ...publicTokenFields(accessToken, refreshToken),
        });
    } catch (error: any) {
        console.error('Finalize Migration Internal Error:', error);
        
        // CRITICAL: Handle duplicate key error specifically
        if (error.code === 11000 && error.keyPattern?.email) {
            console.error(`❌ Duplicate key error for email: ${error.keyValue?.email}`);
            console.error(`   This should not happen - existing user should have been deleted first`);
            
            // Try to recover: delete the existing user and retry
            try {
                const duplicateEmail = error.keyValue?.email;
                if (duplicateEmail) {
                    const duplicateUserId = await findUserIdByPrimaryEmail(duplicateEmail);
                    const duplicateUser = duplicateUserId ? await User.findById(duplicateUserId) : null;
                    if (duplicateUser && duplicateUser._id.toString() !== user._id.toString()) {
                        console.log(`🔄 Attempting recovery: Deleting duplicate user ${duplicateUser._id}`);
                        await releaseUserIdentityIndexes(duplicateUser._id);
                        await User.findByIdAndDelete(duplicateUser._id);
                        console.log(`✅ Duplicate user deleted. Migration should complete on next attempt.`);
                    }
                }
            } catch (recoveryError) {
                console.error('❌ Recovery attempt failed:', recoveryError);
            }
            
            res.status(500).json({ 
                success: false, 
                message: 'Migration failed due to duplicate email. Please try again or contact support.',
                code: 'DUPLICATE_EMAIL_ERROR',
                retryable: true
            });
        } else {
            res.status(500).json({ success: false, message: 'Migration failed' });
        }
    }
};

// 1. Initiate Migration - Now sends both emails at once
export const initiateMigration = async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user as IUser;
        const { password, newEmail, confirmOverride } = req.body;

        if (!newEmail) {
            res.status(400).json({ success: false, message: 'New email is required' });
            return;
        }

        // SECURITY: Prevent one-to-many migrations
        // Check if user already has a pending migration
        if (user.newEmailPending) {
            res.status(400).json({
                success: false,
                message: 'You already have a pending migration. Please complete or cancel it first.',
                code: 'PENDING_MIGRATION_EXISTS'
            });
            return;
        }

        // SECURITY: Prevent migrating if already in grace period
        if (user.previousEmail && user.migrationExpiry && user.migrationExpiry > new Date()) {
            res.status(400).json({
                success: false,
                message: 'You are currently in a migration grace period. Please wait until the grace period ends before migrating again.',
                code: 'MIGRATION_IN_PROGRESS',
                previousEmail: user.previousEmail,
                migrationExpiry: user.migrationExpiry
            });
            return;
        }

        // 10-day cooldown between migrations (ADR-0063)
        const MIGRATION_COOLDOWN_MS = 10 * 24 * 60 * 60 * 1000;
        if (user.lastMigrationDate) {
            const elapsed = Date.now() - user.lastMigrationDate.getTime();
            if (elapsed < MIGRATION_COOLDOWN_MS) {
                const daysRemaining = Math.ceil((MIGRATION_COOLDOWN_MS - elapsed) / (24 * 60 * 60 * 1000));
                res.status(429).json({
                    success: false,
                    message: `Migration cooldown active. Try again in ${daysRemaining} day(s).`,
                    code: 'MIGRATION_COOLDOWN',
                });
                return;
            }
        }

        // CRITICAL: Check account existence FIRST, before password verification
        // This shows warning BEFORE starting migration process
        const existingUserId = await findUserIdByPrimaryEmail(newEmail.toLowerCase());
        const existing = existingUserId ? await User.findById(existingUserId) : null;
        const accountExists = !!existing;
        
        if (existing) {
            if (existing._id.toString() === user._id.toString()) {
                res.status(400).json({ 
                    success: false, 
                    message: 'This is already your current email address' 
                });
                return;
            }
            
            if (!confirmOverride || confirmOverride !== 'true') {
                res.status(409).json({ 
                    success: false, 
                    message: 'An account with this email already exists',
                    code: 'EMAIL_EXISTS',
                    requiresConfirmation: true,
                    warning: `⚠️ WARNING: An account with email "${newEmail}" already exists.\n\n` +
                            `If you proceed:\n` +
                            `• The existing account will be PERMANENTLY DELETED\n` +
                            `• All data from the existing account will be LOST\n` +
                            `• Your current account data will be migrated to this email\n\n` +
                            `This action cannot be undone. Please confirm to proceed.`,
                });
                return;
            }
        }

        // Verify password if local provider (AFTER account existence check)
        if (user.provider === 'local') {
            if (!password) {
                res.status(400).json({ success: false, message: 'Password is required' });
                return;
            }
            const userWithPassword = await User.findById(user._id).select('+password');
            if (!userWithPassword || !(await userWithPassword.comparePassword(password))) {
                res.status(401).json({ success: false, message: 'Invalid password' });
                return;
            }
        }

        // Generate tokens for both emails
        const currentEmailToken = crypto.randomBytes(32).toString('hex');
        const newEmailToken = crypto.randomBytes(32).toString('hex');
        const currentEmailHashed = crypto.createHash('sha256').update(currentEmailToken).digest('hex');
        const newEmailHashed = crypto.createHash('sha256').update(newEmailToken).digest('hex');

        // Save to User
        const userDoc = await User.findById(user._id);
        if (!userDoc) {
            res.status(404).json({ success: false, message: 'User not found' });
            return;
        }

        // Set migration state
        userDoc.newEmailPending = newEmail.toLowerCase();
        userDoc.currentEmailToken = currentEmailHashed;
        userDoc.newEmailToken = newEmailHashed;
        userDoc.currentEmailVerified = false;
        userDoc.newEmailVerified = false;
        userDoc.migrationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        userDoc.lastMigrationEmailSent = new Date(); // Track when emails were sent

        // CRITICAL: Add migration history entry when migration is initiated
        if (!userDoc.migrationHistory) {
            userDoc.migrationHistory = [];
        }
        userDoc.migrationHistory.push({
            fromEmail: userDoc.email,
            toEmail: newEmail.toLowerCase(),
            status: 'pending',
            initiatedAt: new Date(),
            completedAt: undefined as any,
            revertedAt: undefined as any,
            currentEmailVerified: false,
            newEmailVerified: false,
            pendingFrom: 'both' // Both emails need verification initially
        });
        
        await userDoc.save();
        await syncIdentityIndexesFromUser(userDoc);
        console.log(`✅ Migration initiated. History entry added. Total entries: ${userDoc.migrationHistory.length}`);

        // Opaque link codes — raw tokens never in email URLs
        const currentVerifyUrl = await buildMigrationVerifyUrl('migrate-current', currentEmailToken);
        const newEmailMeta: Record<string, string> = accountExists
            ? { redirect: 'login' }
            : { redirect: 'signup' };
        const newEmailRedirectUrl = await buildMigrationVerifyUrl('migrate-new', newEmailToken, newEmailMeta);
        const currentEmailHtml = `
            <h3>Verify Your Current Email for Account Migration</h3>
            <p>You requested to migrate your account to a new email address: <strong>${newEmail}</strong></p>
            <p>To proceed, please verify your current email address by clicking the link below:</p>
            <a href="${currentVerifyUrl}" style="display: inline-block; padding: 12px 24px; background: #7c3aed; color: white; text-decoration: none; border-radius: 8px; margin: 16px 0;">Verify Current Email</a>
            <p>If you did not request this migration, please ignore this email or contact support immediately.</p>
        `;

        // Send email to NEW email with appropriate redirect
        const newEmailHtml = `
            <h3>Verify Your New Email for Account Migration</h3>
            <p>You are migrating your account to this email address: <strong>${newEmail}</strong></p>
            ${accountExists ? 
                '<p><strong>⚠️ Warning:</strong> An account with this email already exists. After verification, the existing account will be merged with your current account.</p>' :
                '<p><strong>ℹ️ Note:</strong> No account exists with this email. A placeholder account will be created during verification, and your current account data will be migrated to this email.</p>'
            }
            <p>To complete the migration, please verify this email address by clicking the link below:</p>
            <a href="${newEmailRedirectUrl}" style="display: inline-block; padding: 12px 24px; background: #7c3aed; color: white; text-decoration: none; border-radius: 8px; margin: 16px 0;">Verify New Email</a>
            <p>If you did not request this migration, please ignore this email.</p>
        `;

        // Send both emails simultaneously with better error handling
        console.log(`📧 Attempting to send migration emails to: ${userDoc.email} and ${newEmail.toLowerCase()}`);
        const emailResults = await Promise.allSettled([
            sendEmail({
                to: userDoc.email,
                subject: 'Verify Current Email - Account Migration',
                html: currentEmailHtml
            }),
            sendEmail({
                to: newEmail.toLowerCase(),
                subject: 'Verify New Email - Account Migration',
                html: newEmailHtml
            })
        ]);

        // Log results with detailed information
        let successCount = 0;
        emailResults.forEach((result, index) => {
            const emailType = index === 0 ? 'current' : 'new';
            const emailAddr = index === 0 ? userDoc.email : newEmail.toLowerCase();
            if (result.status === 'fulfilled') {
                console.log(`✅ Migration email sent successfully to ${emailType} email: ${emailAddr}`);
                successCount++;
            } else {
                console.error(`❌ Failed to send email to ${emailType} email (${emailAddr}):`, result.reason);
                console.error(`Error details:`, JSON.stringify(result.reason, null, 2));
            }
        });

        // If both failed, return error
        if (successCount === 0) {
            console.error(`❌ All migration emails failed to send`);
            res.status(500).json({ 
                success: false, 
                message: 'Failed to send verification emails. Please check your email configuration and try again later.' 
            });
            return;
        }

        // If at least one succeeded, continue (partial success is acceptable)
        if (successCount < 2) {
            console.warn(`⚠️  Only ${successCount} out of 2 emails were sent successfully`);
        }

        res.json({ 
            success: true, 
            message: 'Verification links sent to both email addresses',
            currentEmail: userDoc.email,
            newEmail: newEmail.toLowerCase(),
        });
    } catch (error) {
        console.error('Migration Init Error:', error);
        res.status(500).json({ success: false, message: 'Failed to initiate migration' });
    }
};

// 2. Verify Current Email
export const verifyCurrentEmail = async (req: Request, res: Response): Promise<void> => {
    try {
        const { formToken } = req.body;

        if (!formToken) {
            res.status(400).json({ success: false, message: 'formToken is required' });
            return;
        }

        const redeemed = await consumeFormToken(formToken, 'migrate-current');
        if (!redeemed) {
            res.status(400).json({ success: false, message: 'Invalid or expired verification session' });
            return;
        }

        const hashedToken = crypto.createHash('sha256').update(redeemed.secret).digest('hex');
        console.log(`🔐 Verifying current email with token (hashed): ${hashedToken.substring(0, 16)}...`);

        const user = await User.findOne({
            currentEmailToken: hashedToken,
            migrationTokenExpires: { $gt: new Date() }
        });

        if (!user) {
            console.error('❌ Verify Current Email: Invalid or expired token');
            res.status(400).json({ success: false, message: 'Invalid or expired token' });
            return;
        }
        
        console.log(`✅ Found user for current email verification: ${user.email}`);

        // Mark current email as verified
        user.currentEmailVerified = true;
        await user.save();
        
        // CRITICAL: Update migration history with verification status
        // Reload user to get latest migration history
        const userWithHistory = await User.findById(user._id);
        if (userWithHistory && userWithHistory.migrationHistory && userWithHistory.migrationHistory.length > 0) {
            // Find the latest pending migration
            const latestMigration = userWithHistory.migrationHistory[userWithHistory.migrationHistory.length - 1];
            if (latestMigration.status === 'pending' && latestMigration.toEmail === user.newEmailPending?.toLowerCase()) {
                latestMigration.currentEmailVerified = true;
                // Update pendingFrom based on verification status
                if (user.newEmailVerified) {
                    latestMigration.pendingFrom = undefined; // Both verified - will be marked success in finalize
                } else {
                    latestMigration.pendingFrom = 'new'; // Only new email pending
                }
                await userWithHistory.save();
                console.log(`✅ Updated migration history: current email verified, pendingFrom=${latestMigration.pendingFrom}`);
            }
        }
        
        // CRITICAL: Reload user to ensure we have the latest state, including bio
        const updatedUser = await User.findById(user._id).select('+bio +avatar +displayName');
        if (!updatedUser) {
            res.status(404).json({ success: false, message: 'User not found after verification' });
            return;
        }

        console.log(`✅ Current email verified for user ${updatedUser.email}. Status: current=${updatedUser.currentEmailVerified}, new=${updatedUser.newEmailVerified}`);

        // Check if both are verified, then finalize
        // Use explicit boolean checks to ensure proper comparison
        const bothVerified = updatedUser.currentEmailVerified === true && 
                            updatedUser.newEmailVerified === true && 
                            updatedUser.newEmailPending;
        
        console.log(`🔍 Finalization check: current=${updatedUser.currentEmailVerified}, new=${updatedUser.newEmailVerified}, pending=${!!updatedUser.newEmailPending}, bothVerified=${bothVerified}`);
        
        if (bothVerified) {
            console.log(`✅ Both emails verified - triggering finalization`);
            return finalizeMigrationInternal(updatedUser, res);
        }

        res.json({ 
            success: true, 
            message: updatedUser.newEmailVerified ? 
                'Current email verified! Both emails are now verified. Migration will finalize automatically.' : 
                'Current email verified successfully! Please verify your new email to complete migration.',
            currentEmailVerified: true,
            newEmailVerified: updatedUser.newEmailVerified === true, // Explicit boolean
            bothVerified: false,
            waitingFor: updatedUser.newEmailVerified ? 'none' : 'new'
        });
    } catch (error) {
        console.error('Verify Current Email Error:', error);
        res.status(500).json({ success: false, message: 'Verification failed' });
    }
};

// 3. Verify New Email
export const verifyNewEmail = async (req: Request, res: Response): Promise<void> => {
    try {
        const { formToken } = req.body;

        if (!formToken) {
            res.status(400).json({ success: false, message: 'formToken is required' });
            return;
        }

        const redeemed = await consumeFormToken(formToken, 'migrate-new');
        if (!redeemed) {
            res.status(400).json({ success: false, message: 'Invalid or expired verification session' });
            return;
        }

        const hashedToken = crypto.createHash('sha256').update(redeemed.secret).digest('hex');
        console.log(`🔐 Verifying new email with token (hashed): ${hashedToken.substring(0, 16)}...`);

        const user = await User.findOne({
            newEmailToken: hashedToken,
            migrationTokenExpires: { $gt: new Date() },
            newEmailPending: { $exists: true, $ne: null }
        });

        if (!user) {
            console.error('❌ Verify New Email: Invalid or expired token');
            res.status(400).json({ success: false, message: 'Invalid or expired token' });
            return;
        }
        
        console.log(`✅ Found user for new email verification: ${user.email}, newEmailPending: ${user.newEmailPending}`);

        // Check if new email account already exists
        const newEmail = user.newEmailPending!.toLowerCase();
        const existingNewEmailUserId = await findUserIdByPrimaryEmail(newEmail);
        let existingNewEmailUser = existingNewEmailUserId ? await User.findById(existingNewEmailUserId) : null;
        const accountExists = !!existingNewEmailUser;
        
        // If account doesn't exist, create a placeholder account for the new email
        // This account will be merged/deleted during finalization
        if (!accountExists) {
            console.log(`📧 Account doesn't exist for ${newEmail} - creating placeholder account`);
            
            // Create a minimal placeholder account
            // This will be deleted during finalization when the original account takes over
            const placeholderAccount = new User({
                email: newEmail,
                displayName: `User ${newEmail.split('@')[0]}`, // Temporary display name
                provider: 'local',
                isEmailVerified: false, // Will be set to true during finalization
                // No password - this is just a placeholder
            });
            
            await placeholderAccount.save();
            await syncIdentityIndexesFromUser(placeholderAccount);
            console.log(`✅ Placeholder account created for ${newEmail}`);
            
            existingNewEmailUser = placeholderAccount;
        }

        // Mark new email as verified
        user.newEmailVerified = true;
        await user.save();
        
        // CRITICAL: Update migration history with verification status
        // Reload user to get latest migration history
        const userWithHistory = await User.findById(user._id);
        if (userWithHistory && userWithHistory.migrationHistory && userWithHistory.migrationHistory.length > 0) {
            // Find the latest pending migration
            const latestMigration = userWithHistory.migrationHistory[userWithHistory.migrationHistory.length - 1];
            if (latestMigration.status === 'pending' && latestMigration.toEmail === user.newEmailPending?.toLowerCase()) {
                latestMigration.newEmailVerified = true;
                // Update pendingFrom based on verification status
                if (user.currentEmailVerified) {
                    latestMigration.pendingFrom = undefined; // Both verified - will be marked success in finalize
                } else {
                    latestMigration.pendingFrom = 'current'; // Only current email pending
                }
                await userWithHistory.save();
                console.log(`✅ Updated migration history: new email verified, pendingFrom=${latestMigration.pendingFrom}`);
            }
        }
        
        // CRITICAL: Reload user to ensure we have the latest state, including bio
        const updatedUser = await User.findById(user._id).select('+bio +avatar +displayName');
        if (!updatedUser) {
            res.status(404).json({ success: false, message: 'User not found after verification' });
            return;
        }

        console.log(`✅ New email verified for user ${updatedUser.email}. Status: current=${updatedUser.currentEmailVerified}, new=${updatedUser.newEmailVerified}`);

        // Check if both are verified, then finalize
        // Use explicit boolean checks to ensure proper comparison
        const bothVerified = updatedUser.currentEmailVerified === true && 
                            updatedUser.newEmailVerified === true && 
                            updatedUser.newEmailPending;
        
        console.log(`🔍 Finalization check: current=${updatedUser.currentEmailVerified}, new=${updatedUser.newEmailVerified}, pending=${!!updatedUser.newEmailPending}, bothVerified=${bothVerified}`);
        
        if (bothVerified) {
            console.log(`✅ Both emails verified - triggering finalization`);
            return finalizeMigrationInternal(updatedUser, res);
        }

        // Use the accountExists variable we already calculated above (line 614)
        res.json({ 
            success: true, 
            message: 'New email verified successfully! Status updated in real-time.',
            currentEmailVerified: updatedUser.currentEmailVerified === true, // Explicit boolean
            newEmailVerified: true,
            bothVerified: false,
            redirectTo: 'login',
            waitingFor: updatedUser.currentEmailVerified ? 'new' : 'current'
        });
    } catch (error) {
        console.error('Verify New Email Error:', error);
        res.status(500).json({ success: false, message: 'Verification failed' });
    }
};

// 4. Resend Migration Emails
export const resendMigrationEmails = async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user as IUser;
        const userDoc = await User.findById(user._id);

        if (!userDoc) {
            res.status(404).json({ success: false, message: 'User not found' });
            return;
        }

        // Check if there's a pending migration
        if (!userDoc.newEmailPending || !userDoc.migrationTokenExpires || userDoc.migrationTokenExpires < new Date()) {
            res.status(400).json({ success: false, message: 'No pending migration found' });
            return;
        }

        // Check 30-second cooldown
        if (userDoc.lastMigrationEmailSent) {
            const secondsSinceLastEmail = (Date.now() - new Date(userDoc.lastMigrationEmailSent).getTime()) / 1000;
            if (secondsSinceLastEmail < 30) {
                const remainingSeconds = Math.ceil(30 - secondsSinceLastEmail);
                res.status(429).json({
                    success: false,
                    message: `Please wait ${remainingSeconds} more second(s) before resending.`,
                    cooldownRemaining: remainingSeconds
                });
                return;
            }
        }

        // Invalidate old tokens by generating new ones
        const currentEmailToken = crypto.randomBytes(32).toString('hex');
        const newEmailToken = crypto.randomBytes(32).toString('hex');
        const currentEmailHashed = crypto.createHash('sha256').update(currentEmailToken).digest('hex');
        const newEmailHashed = crypto.createHash('sha256').update(newEmailToken).digest('hex');

        // Update tokens (this invalidates old ones)
        userDoc.currentEmailToken = currentEmailHashed;
        userDoc.newEmailToken = newEmailHashed;
        userDoc.migrationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // Reset expiry
        userDoc.lastMigrationEmailSent = new Date();
        await userDoc.save();
        await syncIdentityIndexesFromUser(userDoc);

        const newEmailExists = !!(await findUserIdByPrimaryEmail(userDoc.newEmailPending!.toLowerCase()));

        const currentVerifyUrl = await buildMigrationVerifyUrl('migrate-current', currentEmailToken);
        const newEmailMeta: Record<string, string> = newEmailExists
            ? { redirect: 'login' }
            : { redirect: 'signup' };
        const newVerifyUrl = await buildMigrationVerifyUrl('migrate-new', newEmailToken, newEmailMeta);

        const currentEmailHtml = `
            <h3>Verify Your Current Email for Account Migration</h3>
            <p>You requested to migrate your account to a new email address: <strong>${userDoc.newEmailPending}</strong></p>
            <p>To proceed, please verify your current email address by clicking the link below:</p>
            <a href="${currentVerifyUrl}" style="display: inline-block; padding: 12px 24px; background: #7c3aed; color: white; text-decoration: none; border-radius: 8px; margin: 16px 0;">Verify Current Email</a>
            <p><strong>Note:</strong> This is a new verification link. Previous links are no longer valid.</p>
            <p>If you did not request this migration, please ignore this email or contact support immediately.</p>
        `;

        const newEmailHtml = `
            <h3>Verify Your New Email for Account Migration</h3>
            <p>You are migrating your account to this email address: <strong>${userDoc.newEmailPending}</strong></p>
            ${newEmailExists ? 
                '<p><strong>⚠️ Warning:</strong> An account with this email already exists. After verification, you will be redirected to the login page.</p>' :
                '<p>To complete the migration, please verify this email address by clicking the link below. After verification, you will be redirected to the signup page.</p>'
            }
            <a href="${newVerifyUrl}" style="display: inline-block; padding: 12px 24px; background: #7c3aed; color: white; text-decoration: none; border-radius: 8px; margin: 16px 0;">Verify New Email</a>
            <p><strong>Note:</strong> This is a new verification link. Previous links are no longer valid.</p>
            <p>If you did not request this migration, please ignore this email.</p>
        `;

        // Send both emails simultaneously with better error handling
        const emailResults = await Promise.allSettled([
            sendEmail({
                to: userDoc.email,
                subject: 'Verify Current Email - Account Migration (Resent)',
                html: currentEmailHtml
            }),
            sendEmail({
                to: userDoc.newEmailPending,
                subject: 'Verify New Email - Account Migration (Resent)',
                html: newEmailHtml
            })
        ]);

        // Log results
        emailResults.forEach((result, index) => {
            const emailType = index === 0 ? 'current' : 'new';
            const emailAddr = index === 0 ? userDoc.email : userDoc.newEmailPending;
            if (result.status === 'fulfilled') {
                console.log(`✅ Resent migration email to ${emailType} email: ${emailAddr}`);
            } else {
                console.error(`❌ Failed to resend email to ${emailType} email (${emailAddr}):`, result.reason);
            }
        });

        // If both failed, return error
        if (emailResults[0].status === 'rejected' && emailResults[1].status === 'rejected') {
            res.status(500).json({ 
                success: false, 
                message: 'Failed to resend verification emails. Please try again later.' 
            });
            return;
        }

        res.json({ 
            success: true, 
            message: 'Verification emails resent to both email addresses',
            currentEmail: userDoc.email,
            newEmail: userDoc.newEmailPending,
            accountExists: newEmailExists // Tell frontend if account exists for redirect
        });
    } catch (error) {
        console.error('Resend Migration Emails Error:', error);
        res.status(500).json({ success: false, message: 'Failed to resend emails' });
    }
};

// 5. Get Migration Status - CRITICAL: Always reload from DB to get latest verification status
export const getMigrationStatus = async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user as IUser;
        
        // CRITICAL: Always reload user from database to get latest verification status
        // Don't use cached JWT user data - it may be stale after verification
        const userDoc = await User.findById(user._id).select('+currentEmailVerified +newEmailVerified +currentEmailToken +newEmailToken');

        if (!userDoc) {
            res.status(404).json({ success: false, message: 'User not found' });
            return;
        }

        const hasPendingMigration = !!userDoc.newEmailPending && 
                                   userDoc.migrationTokenExpires && 
                                   userDoc.migrationTokenExpires > new Date();

        // Calculate cooldown remaining
        let cooldownRemaining = 0;
        if (userDoc.lastMigrationEmailSent) {
            const secondsSinceLastEmail = (Date.now() - new Date(userDoc.lastMigrationEmailSent).getTime()) / 1000;
            if (secondsSinceLastEmail < 30) {
                cooldownRemaining = Math.ceil(30 - secondsSinceLastEmail);
            }
        }

        // CRITICAL: Return explicit boolean values (not undefined/null)
        const currentEmailVerified = userDoc.currentEmailVerified === true;
        const newEmailVerified = userDoc.newEmailVerified === true;

        console.log(`📊 Migration Status for ${userDoc.email}: current=${currentEmailVerified}, new=${newEmailVerified}, pending=${hasPendingMigration}`);

        // CRITICAL: If both emails are verified but migration is still pending, trigger finalization
        if (hasPendingMigration && currentEmailVerified && newEmailVerified && userDoc.newEmailPending) {
            console.log(`⚠️  Both emails verified but migration not finalized - triggering finalization now`);
            // Note: We can't call finalizeMigrationInternal here because we don't have access to res
            // Instead, we'll return a flag that tells the frontend to call the finalize endpoint
            res.json({
                success: true,
                hasPendingMigration: true,
                currentEmail: userDoc.email,
                newEmail: userDoc.newEmailPending || null,
                currentEmailVerified: currentEmailVerified,
                newEmailVerified: newEmailVerified,
                migrationExpiry: userDoc.migrationTokenExpires || null,
                cooldownRemaining,
                needsFinalization: true, // Flag to trigger finalization on frontend
                message: 'Both emails verified! Finalizing migration...'
            });
            return;
        }

        res.json({
            success: true,
            hasPendingMigration,
            currentEmail: userDoc.email,
            newEmail: userDoc.newEmailPending || null,
            currentEmailVerified: currentEmailVerified, // Explicit boolean
            newEmailVerified: newEmailVerified, // Explicit boolean
            migrationExpiry: userDoc.migrationTokenExpires || null,
            cooldownRemaining,
            needsFinalization: false
        });
    } catch (error) {
        console.error('Get Migration Status Error:', error);
        res.status(500).json({ success: false, message: 'Failed to get migration status' });
    }
};

// 6. Manual Finalize Migration - For cases where auto-finalization didn't trigger
export const finalizeMigration = async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user as IUser;
        
        // Reload user to get latest state
        const userDoc = await User.findById(user._id).select('+currentEmailVerified +newEmailVerified +newEmailPending');
        
        if (!userDoc) {
            res.status(404).json({ success: false, message: 'User not found' });
            return;
        }
        
        // Check if migration can be finalized
        if (!userDoc.newEmailPending) {
            res.status(400).json({ 
                success: false, 
                message: 'No pending migration found' 
            });
            return;
        }
        
        // Check if both emails are verified
        if (userDoc.currentEmailVerified !== true || userDoc.newEmailVerified !== true) {
            res.status(400).json({ 
                success: false, 
                message: 'Both emails must be verified before finalizing migration',
                currentEmailVerified: userDoc.currentEmailVerified === true,
                newEmailVerified: userDoc.newEmailVerified === true
            });
            return;
        }
        
        console.log(`🔄 Manual finalization triggered for user ${userDoc.email}`);
        
        // Call finalization
        return finalizeMigrationInternal(userDoc, res);
    } catch (error) {
        console.error('Manual Finalize Migration Error:', error);
        res.status(500).json({ success: false, message: 'Failed to finalize migration' });
    }
};

// 7. Get Migration History
export const getMigrationHistory = async (req: Request, res: Response): Promise<void> => {
    try {
        const user = (req as any).user as IUser;
        // CRITICAL: Reload user to get latest migration history
        const userDoc = await User.findById(user._id).select('+migrationHistory');

        if (!userDoc) {
            res.status(404).json({ success: false, message: 'User not found' });
            return;
        }

        // Get migration history - ensure it's properly formatted with verification details
        const history = (userDoc.migrationHistory || []).map((migration: any) => {
            // Determine pending status based on verification flags
            let displayStatus = migration.status || 'pending';
            let pendingFrom = migration.pendingFrom;
            
            // CRITICAL: If both emails are verified, status MUST be success (not pending or failed)
            const currentVerified = migration.currentEmailVerified === true;
            const newVerified = migration.newEmailVerified === true;
            
            if (currentVerified && newVerified) {
                // Both verified - migration MUST be successful
                displayStatus = 'success';
                pendingFrom = undefined;
            } else if (displayStatus === 'pending') {
                // Still pending - determine which email is pending
                if (!currentVerified && !newVerified) {
                    pendingFrom = 'both';
                } else if (!currentVerified) {
                    pendingFrom = 'current';
                } else if (!newVerified) {
                    pendingFrom = 'new';
                } else {
                    // Both verified but status still pending - update to success
                    displayStatus = 'success';
                    pendingFrom = undefined;
                }
            }
            
            // CRITICAL: If migration has completedAt, it should be success (not failed)
            if (migration.completedAt && displayStatus !== 'success') {
                console.log(`⚠️  Migration has completedAt but status is ${displayStatus} - correcting to success`);
                displayStatus = 'success';
                pendingFrom = undefined;
            }
            
            return {
                fromEmail: migration.fromEmail || '',
                toEmail: migration.toEmail || '',
                status: displayStatus,
                initiatedAt: migration.initiatedAt ? (typeof migration.initiatedAt === 'string' ? migration.initiatedAt : migration.initiatedAt.toISOString()) : new Date().toISOString(),
                completedAt: migration.completedAt ? (typeof migration.completedAt === 'string' ? migration.completedAt : migration.completedAt.toISOString()) : undefined,
                revertedAt: migration.revertedAt ? (typeof migration.revertedAt === 'string' ? migration.revertedAt : migration.revertedAt.toISOString()) : undefined,
                currentEmailVerified: currentVerified,
                newEmailVerified: newVerified,
                pendingFrom: pendingFrom
            };
        });

        // Only log if there are entries (to reduce log spam)
        if (history.length > 0) {
            console.log(`📋 Migration history for user ${userDoc._id} (${userDoc.email}): ${history.length} entries`);
            history.forEach((h, idx) => {
                console.log(`   [${idx + 1}] ${h.fromEmail} -> ${h.toEmail}: ${h.status} (current: ${h.currentEmailVerified}, new: ${h.newEmailVerified})`);
            });
        }

        res.json({
            success: true,
            history: history.reverse() // Most recent first
        });
    } catch (error) {
        console.error('Get Migration History Error:', error);
        res.status(500).json({ success: false, message: 'Failed to get migration history' });
    }
};
