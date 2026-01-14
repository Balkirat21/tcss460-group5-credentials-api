import { NextFunction, Response } from 'express';
import { IJwtRequest } from '@models';
import { pool } from '../utilities/database';

export const checkParamsIdToJwtId = (
    request: IJwtRequest,
    response: Response,
    next: NextFunction
) => {
    if (request.params.id !== request.claims.id.toString()) {
        response.status(400).send({
            message: 'Credentials do not match for this user.',
        });
    }
    next();
};

/**
 * Middleware to require email verification
 * Checks if the user's email has been verified in the Email_Verification table
 * Returns 403 if email is not verified
 */
export const requireEmailVerified = async (
    request: IJwtRequest,
    response: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const userId = request.claims.id;

        // Check if user has a verified email record
        const verificationResult = await pool.query(
            `SELECT Verified
             FROM Email_Verification
             WHERE Person_ID = $1
             AND Verified = TRUE
             ORDER BY Verified_At DESC
             LIMIT 1`,
            [userId]
        );

        if (verificationResult.rowCount === 0) {
            response.status(403).json({
                success: false,
                message: 'Email verification required. Please verify your email address to access this resource.',
                error: 'EMAIL_NOT_VERIFIED'
            });
            return;
        }

        // Email is verified, continue to next middleware
        next();
    } catch (error) {
        console.error('Error checking email verification:', error);
        response.status(500).json({
            success: false,
            message: 'Error verifying email status',
            error: 'VERIFICATION_CHECK_FAILED'
        });
    }
};

/**
 * Middleware to require phone verification
 * Checks if the user's phone has been verified in the Phone_Verification table
 * Returns 403 if phone is not verified
 */
export const requirePhoneVerified = async (
    request: IJwtRequest,
    response: Response,
    next: NextFunction
): Promise<void> => {
    try {
        const userId = request.claims.id;

        // Check if user has a verified phone record
        const verificationResult = await pool.query(
            `SELECT Verified
             FROM Phone_Verification
             WHERE Person_ID = $1
             AND Verified = TRUE
             ORDER BY Verified_At DESC
             LIMIT 1`,
            [userId]
        );

        if (verificationResult.rowCount === 0) {
            response.status(403).json({
                success: false,
                message: 'Phone verification required. Please verify your phone number to access this resource.',
                error: 'PHONE_NOT_VERIFIED'
            });
            return;
        }

        // Phone is verified, continue to next middleware
        next();
    } catch (error) {
        console.error('Error checking phone verification:', error);
        response.status(500).json({
            success: false,
            message: 'Error verifying phone status',
            error: 'VERIFICATION_CHECK_FAILED'
        });
    }
};
