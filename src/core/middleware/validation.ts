// src/core/middleware/validation.ts
import { body, param, query, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { SMS_GATEWAYS } from '@models';
import { normalizePhoneNumber, isValidUSPhoneNumber } from '../utilities/phoneUtils';

/**
 * Middleware to handle validation errors
 * Add this after validation rules to check for errors
 */
export const handleValidationErrors = (request: Request, response: Response, next: NextFunction) => {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
        return response.status(400).json({
            success: false,
            message: 'Validation failed',
            errors: errors.array().map(err => ({
                field: err.type === 'field' ? err.path : undefined,
                message: err.msg
            }))
        });
    }
    next();
};

// ============================================
// AUTH VALIDATION
// ============================================

/**
 * Login validation
 * - Email: required, valid email format, normalized
 * - Password: required
 */
export const validateLogin = [
    body('email')
        .trim()
        .notEmpty().withMessage('Email is required')
        .isEmail().withMessage('Must be a valid email')
        .normalizeEmail(),
    body('password')
        .notEmpty().withMessage('Password is required'),
    handleValidationErrors
];

/**
 * Public registration validation (no role field allowed)
 * - firstname: required, 1-100 characters
 * - lastname: required, 1-100 characters
 * - email: required, valid email format, normalized
 * - username: required, 3-50 characters, alphanumeric with underscore/hyphen
 * - password: required, 8-128 characters (simple validation - user friendly)
 * - phone: required, valid US phone number with normalization
 * NOTE: No role validation - public registration always creates basic users
 */
export const validateRegister = [
    body('firstname')
        .trim()
        .notEmpty().withMessage('First name is required')
        .isLength({ min: 1, max: 100 }).withMessage('First name must be 1-100 characters'),
    body('lastname')
        .trim()
        .notEmpty().withMessage('Last name is required')
        .isLength({ min: 1, max: 100 }).withMessage('Last name must be 1-100 characters'),
    body('email')
        .trim()
        .notEmpty().withMessage('Email is required')
        .isEmail().withMessage('Must be a valid email')
        .normalizeEmail(),
    body('username')
        .trim()
        .notEmpty().withMessage('Username is required')
        .isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters')
        .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Username can only contain letters, numbers, underscore, and hyphen'),
    body('password')
        .notEmpty().withMessage('Password is required')
        .isLength({ min: 8, max: 128 }).withMessage('Password must be 8-128 characters'),
    body('phone')
        .trim()
        .notEmpty().withMessage('Phone is required')
        .customSanitizer((value) => {
            // Normalize phone number to 10-digit format
            return normalizePhoneNumber(value);
        })
        .custom((value) => {
            // Validate normalized phone number
            if (!isValidUSPhoneNumber(value)) {
                throw new Error('Phone must be a valid 10-digit US phone number');
            }
            return true;
        }),
    handleValidationErrors
];

// ============================================
// PASSWORD VALIDATION
// ============================================

/**
 * Password reset request validation
 * - Email: required, valid email format, normalized
 */
export const validatePasswordResetRequest = [
    body('email')
        .trim()
        .notEmpty().withMessage('Email is required')
        .isEmail().withMessage('Must be a valid email')
        .normalizeEmail(),
    handleValidationErrors
];

/**
 * Password reset validation (with token)
 * - token: required, trimmed
 * - password: required, 8-128 characters (simple validation - user friendly)
 */
export const validatePasswordReset = [
    body('token')
        .trim()
        .notEmpty().withMessage('Reset token is required'),
    body('password')
        .notEmpty().withMessage('Password is required')
        .isLength({ min: 8, max: 128 }).withMessage('Password must be 8-128 characters'),
    handleValidationErrors
];

/**
 * Password change validation (for authenticated users)
 * - oldPassword: required
 * - newPassword: required, 8-128 characters, different from old password
 */
export const validatePasswordChange = [
    body('oldPassword')
        .notEmpty().withMessage('Current password is required'),
    body('newPassword')
        .notEmpty().withMessage('New password is required')
        .isLength({ min: 8, max: 128 }).withMessage('New password must be 8-128 characters')
        .custom((value, { req }) => {
            if (value === req.body.oldPassword) {
                throw new Error('New password must be different from current password');
            }
            return true;
        }),
    handleValidationErrors
];

// ============================================
// VERIFICATION VALIDATION
// ============================================

/**
 * Phone verification send validation
 * - phone: required, normalized to 10-digit US format, validated
 * - carrier: optional, must be valid SMS gateway from SMS_GATEWAYS
 */
export const validatePhoneSend = [
    body('phone')
        .trim()
        .notEmpty().withMessage('Phone is required')
        .customSanitizer((value) => {
            // Normalize phone number to 10-digit format
            return normalizePhoneNumber(value);
        })
        .custom((value) => {
            // Validate normalized phone number
            if (!isValidUSPhoneNumber(value)) {
                throw new Error('Phone must be a valid 10-digit US phone number');
            }
            return true;
        }),
    body('carrier')
        .optional()
        .trim()
        .isIn(Object.keys(SMS_GATEWAYS)).withMessage('Invalid carrier'),
    handleValidationErrors
];

/**
 * Phone verification code validation
 * - phone: required, normalized to 10-digit US format, validated
 * - code: required, trimmed, 4-8 digits
 */
export const validatePhoneVerify = [
    body('phone')
        .trim()
        .notEmpty().withMessage('Phone is required')
        .customSanitizer((value) => {
            // Normalize phone number to 10-digit format
            return normalizePhoneNumber(value);
        })
        .custom((value) => {
            // Validate normalized phone number
            if (!isValidUSPhoneNumber(value)) {
                throw new Error('Phone must be a valid 10-digit US phone number');
            }
            return true;
        }),
    body('code')
        .trim()
        .notEmpty().withMessage('Verification code is required')
        .matches(/^\d{4,8}$/).withMessage('Code must be 4-8 digits'),
    handleValidationErrors
];

/**
 * Email verification token validation (query param)
 * - token: required parameter, trimmed, minimum length
 */
export const validateEmailToken = [
    query('token')
        .trim()
        .notEmpty().withMessage('Token is required')
        .isLength({ min: 10 }).withMessage('Token appears invalid'),
    handleValidationErrors
];

// ============================================
// ADMIN VALIDATION
// ============================================

/**
 * Admin user creation validation
 * - All registration fields plus role
 * - role: required, integer between 1 and 5
 */
export const validateAdminCreateUser = [
    body('firstname')
        .trim()
        .notEmpty().withMessage('First name is required')
        .isLength({ min: 1, max: 100 }).withMessage('First name must be 1-100 characters'),
    body('lastname')
        .trim()
        .notEmpty().withMessage('Last name is required')
        .isLength({ min: 1, max: 100 }).withMessage('Last name must be 1-100 characters'),
    body('email')
        .trim()
        .notEmpty().withMessage('Email is required')
        .isEmail().withMessage('Must be a valid email')
        .normalizeEmail(),
    body('username')
        .trim()
        .notEmpty().withMessage('Username is required')
        .isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters')
        .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Username can only contain letters, numbers, underscore, and hyphen'),
    body('password')
        .notEmpty().withMessage('Password is required')
        .isLength({ min: 8, max: 128 }).withMessage('Password must be 8-128 characters'),
    body('phone')
        .trim()
        .notEmpty().withMessage('Phone is required')
        .customSanitizer((value) => {
            // Normalize phone number to 10-digit format
            return normalizePhoneNumber(value);
        })
        .custom((value) => {
            // Validate normalized phone number
            if (!isValidUSPhoneNumber(value)) {
                throw new Error('Phone must be a valid 10-digit US phone number');
            }
            return true;
        }),
    body('role')
        .notEmpty().withMessage('Role is required')
        .isInt({ min: 1, max: 5 }).withMessage('Role must be an integer between 1 and 5')
        .toInt(),
    handleValidationErrors
];

/**
 * Admin user update validation
 * - All fields optional
 * - Email must be valid if provided
 * - Username must meet requirements if provided
 * - Phone must meet requirements if provided
 */
export const validateAdminUpdateUser = [
    body('firstname')
        .optional()
        .trim()
        .isLength({ min: 1, max: 100 }).withMessage('First name must be 1-100 characters'),
    body('lastname')
        .optional()
        .trim()
        .isLength({ min: 1, max: 100 }).withMessage('Last name must be 1-100 characters'),
    body('email')
        .optional()
        .trim()
        .isEmail().withMessage('Must be a valid email')
        .normalizeEmail(),
    body('username')
        .optional()
        .trim()
        .isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters')
        .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Username can only contain letters, numbers, underscore, and hyphen'),
    body('phone')
        .optional()
        .trim()
        .customSanitizer((value) => {
            // Normalize phone number to 10-digit format if provided
            return value ? normalizePhoneNumber(value) : value;
        })
        .custom((value) => {
            // Only validate if a phone number is provided
            if (value && !isValidUSPhoneNumber(value)) {
                throw new Error('Phone must be a valid 10-digit US phone number');
            }
            return true;
        }),
    handleValidationErrors
];

/**
 * Admin password reset validation
 * - newPassword: required, 8-128 characters (simple validation - user friendly)
 */
export const validateAdminPasswordReset = [
    body('newPassword')
        .notEmpty().withMessage('New password is required')
        .isLength({ min: 8, max: 128 }).withMessage('New password must be 8-128 characters'),
    handleValidationErrors
];

/**
 * Admin role change validation
 * - role: required, integer between 1 and 5
 */
export const validateAdminRoleChange = [
    body('role')
        .notEmpty().withMessage('Role is required')
        .isInt({ min: 1, max: 5 }).withMessage('Role must be an integer between 1 and 5')
        .toInt(),
    handleValidationErrors
];

/**
 * Admin search validation
 * - q: required search query parameter, minimum 1 character
 */
export const validateAdminSearch = [
    query('q')
        .trim()
        .notEmpty().withMessage('Search query is required')
        .isLength({ min: 1, max: 100 }).withMessage('Search query must be 1-100 characters'),
    handleValidationErrors
];

// ============================================
// USER/PARAMS VALIDATION
// ============================================

/**
 * Validate user ID in params
 * - id: required, must be UUID or integer
 */
export const validateUserIdParam = [
    param('id')
        .trim()
        .notEmpty().withMessage('ID is required')
        .custom((value) => {
            const isUUIDv4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
            const isIntegerId = /^\d+$/.test(value);
            if (!isUUIDv4 && !isIntegerId) {
                throw new Error('ID must be UUID or integer');
            }
            return true;
        }),
    handleValidationErrors
];

// ============================================
// PAGINATION/QUERY VALIDATION
// ============================================

/**
 * Sanitize and validate pagination parameters
 * - page: optional, positive integer (default: 1)
 * - limit: optional, integer between 1 and 100 (default: 10)
 * - sortBy: optional, allowed values only
 * - sortOrder: optional, 'asc' or 'desc' (default: 'desc')
 */
const SORT_WHITELIST = ['created_at','email','username','id'];

export const validatePagination = [
    query('page')
        .optional()
        .isInt({ min: 1 }).withMessage('Page must be a positive integer')
        .toInt(),
    query('limit')
        .optional()
        .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
        .toInt(),
    query('sortBy')
        .optional()
        .trim()
        .isIn(['created_at', 'email', 'username', 'role', 'firstname', 'lastname'])
        .withMessage('Invalid sort field'),
    query('sortOrder')
        .optional()
        .trim()
        .toLowerCase()
        .isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc'),
    query('role')
        .optional()
        .isInt({ min: 1, max: 5 }).withMessage('Role must be between 1 and 5')
        .toInt(),
    query('status')
        .optional()
        .trim()
        .isIn(['pending', 'active', 'suspended', 'locked'])
        .withMessage('Invalid status'),
    handleValidationErrors
];

// ============================================
// OPTIONAL VALIDATORS (from main)
// ============================================

/**
 * Custom password strength validator (optional, more strict)
 * Add to password fields if you want stronger validation
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character (@$!%*?&)
 * NOTE: Not currently used - available if needed
 */
export const passwordStrength = [
  body('password', 'Password is required').exists().bail().isString(),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[a-z]/).withMessage('Password must include a lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must include an uppercase letter')
    .matches(/\d/).withMessage('Password must include a number')
    .matches(/[^A-Za-z0-9]/).withMessage('Password must include a special character'),
  handleValidationErrors
];
