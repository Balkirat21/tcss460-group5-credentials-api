import express, { Router } from 'express';
import { AuthController, VerificationController } from '@controllers';
import { checkToken, validatePhoneSend, validatePhoneVerify } from '@middleware';
import {
    validatePasswordChange,
    handleValidationErrors
  } from '@core/middleware/validation';


const closedRoutes: Router = express.Router();

// All closed routes require authentication
closedRoutes.use(checkToken);

// JWT test route has been moved to open routes for easier testing

// ===== AUTHENTICATED AUTH ROUTES =====

/**
 * Change password (requires authentication and old password)
 * POST /auth/user/password/change
 * TODO: Add validation middleware (validatePasswordChange)
 */
closedRoutes.post(
    '/auth/user/password/change',
    validatePasswordChange,
    handleValidationErrors,
    AuthController.changePassword
  );

/**
 * Send SMS verification code
 * POST /auth/verify/phone/send
 */
closedRoutes.post('/auth/verify/phone/send', validatePhoneSend, VerificationController.sendSMSVerification);

/**
 * Verify SMS code
 * POST /auth/verify/phone/verify
 */
closedRoutes.post('/auth/verify/phone/verify', validatePhoneVerify, VerificationController.verifySMSCode);

/**
 * Send email verification
 * POST /auth/verify/email/send
 */
closedRoutes.post('/auth/verify/email/send', VerificationController.sendEmailVerification);

export { closedRoutes };
