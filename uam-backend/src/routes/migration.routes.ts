import { Router } from 'express';
import { authenticate, requireVerifiedEmail } from '../middleware/auth.middleware';
import { validate } from '../middleware/validate.middleware';
import {
    migrationInitSchema,
    migrationVerifySchema,
} from '../validators/migration.validators';
import {
    initiateMigration,
    verifyCurrentEmail,
    verifyNewEmail,
    resendMigrationEmails,
    getMigrationStatus,
    getMigrationHistory,
    finalizeMigration
} from '../controllers/migration.controller';

const router = Router();

const protectedMigration = [authenticate, requireVerifiedEmail];

router.post('/init', ...protectedMigration, validate(migrationInitSchema), initiateMigration);
router.post('/verify-current', validate(migrationVerifySchema), verifyCurrentEmail);
router.post('/verify-new', validate(migrationVerifySchema), verifyNewEmail);
router.post('/resend', ...protectedMigration, resendMigrationEmails);
router.get('/status', ...protectedMigration, getMigrationStatus);
router.get('/history', ...protectedMigration, getMigrationHistory);
router.post('/finalize', ...protectedMigration, finalizeMigration);

export default router;
