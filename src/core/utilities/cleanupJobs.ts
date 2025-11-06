// src/core/utilities/cleanupJobs.ts
import { pool } from './database';

/**
 * Cleanup expired email verification tokens
 * Removes tokens that have expired to keep database clean
 */
export const cleanupExpiredEmailTokens = async (): Promise<number> => {
    try {
        const result = await pool.query(
            `DELETE FROM Email_Verification
             WHERE Token_Expires < CURRENT_TIMESTAMP
             AND Verified = FALSE
             RETURNING Verification_ID`
        );

        const deletedCount = result.rowCount || 0;
        if (deletedCount > 0) {
            console.log(`🧹 Cleaned up ${deletedCount} expired email verification token(s)`);
        }

        return deletedCount;
    } catch (error) {
        console.error('Error cleaning up expired email tokens:', error);
        return 0;
    }
};

/**
 * Cleanup expired phone verification codes
 * Removes codes that have expired to keep database clean
 */
export const cleanupExpiredPhoneCodes = async (): Promise<number> => {
    try {
        const result = await pool.query(
            `DELETE FROM Phone_Verification
             WHERE Code_Expires < CURRENT_TIMESTAMP
             AND Verified = FALSE
             RETURNING Verification_ID`
        );

        const deletedCount = result.rowCount || 0;
        if (deletedCount > 0) {
            console.log(`🧹 Cleaned up ${deletedCount} expired phone verification code(s)`);
        }

        return deletedCount;
    } catch (error) {
        console.error('Error cleaning up expired phone codes:', error);
        return 0;
    }
};

/**
 * Cleanup old verified records (optional - keeps database lean)
 * Removes verified records older than specified days
 */
export const cleanupOldVerifiedRecords = async (daysOld: number = 30): Promise<number> => {
    try {
        // Clean old verified email records
        const emailResult = await pool.query(
            `DELETE FROM Email_Verification
             WHERE Verified = TRUE
             AND Created_At < CURRENT_TIMESTAMP - INTERVAL '${daysOld} days'
             RETURNING Verification_ID`
        );

        // Clean old verified phone records
        const phoneResult = await pool.query(
            `DELETE FROM Phone_Verification
             WHERE Verified = TRUE
             AND Created_At < CURRENT_TIMESTAMP - INTERVAL '${daysOld} days'
             RETURNING Verification_ID`
        );

        const totalDeleted = (emailResult.rowCount || 0) + (phoneResult.rowCount || 0);
        if (totalDeleted > 0) {
            console.log(`🧹 Cleaned up ${totalDeleted} old verified record(s) (${daysOld}+ days old)`);
        }

        return totalDeleted;
    } catch (error) {
        console.error('Error cleaning up old verified records:', error);
        return 0;
    }
};

/**
 * Run all cleanup jobs
 * Call this periodically (e.g., every hour)
 */
export const runAllCleanupJobs = async (): Promise<{
    expiredEmails: number;
    expiredPhones: number;
    oldRecords: number;
}> => {
    console.log('🧹 Starting verification cleanup jobs...');

    const expiredEmails = await cleanupExpiredEmailTokens();
    const expiredPhones = await cleanupExpiredPhoneCodes();
    const oldRecords = await cleanupOldVerifiedRecords(30);

    const total = expiredEmails + expiredPhones + oldRecords;
    if (total > 0) {
        console.log(`✅ Cleanup complete: ${total} total records removed`);
    } else {
        console.log('✅ Cleanup complete: No records to remove');
    }

    return {
        expiredEmails,
        expiredPhones,
        oldRecords,
    };
};

/**
 * Schedule cleanup jobs to run periodically
 * @param intervalMinutes - How often to run cleanup (default: 60 minutes)
 */
export const scheduleCleanupJobs = (intervalMinutes: number = 60): NodeJS.Timeout => {
    console.log(`📅 Scheduling cleanup jobs to run every ${intervalMinutes} minutes`);

    // Run immediately on startup
    runAllCleanupJobs();

    // Then run periodically
    const intervalMs = intervalMinutes * 60 * 1000;
    return setInterval(() => {
        runAllCleanupJobs();
    }, intervalMs);
};
