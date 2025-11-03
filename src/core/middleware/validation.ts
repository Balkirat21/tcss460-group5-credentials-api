// src/core/middleware/validation.ts
import { body, param, query, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { SMS_GATEWAYS } from '@models';

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
 * TODO: Implement validation for login
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
 * TODO: Implement validation for registration
 * - firstname: required, 1-100 characters
 * - lastname: required, 1-100 characters
 * - email: required, valid email format, normalized
 * - username: required, 3-50 characters, alphanumeric with underscore/hyphen
 * - password: required, 8-128 characters
 * - phone: required, at least 10 digits
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
        .matches(/^\d{10,}$/).withMessage('Phone must contain at least 10 digits'),
    handleValidationErrors
];

// ============================================
// PASSWORD VALIDATION
// ============================================

/**
 * Password reset request validation
 * TODO: Implement validation for password reset request
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
 * TODO: Implement validation for password reset
 * - token: required, trimmed
 * - password: required, 8-128 characters
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
 * TODO: Implement validation for password change
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
 * - carrier: optional, must be valid SMS gateway from SMS_GATEWAYS
 */
export const validatePhoneSend = [
  body('phone', 'phone is required').exists().bail().isString().trim(),
  body('phone').isMobilePhone('any').withMessage('phone must be valid'),
  handleValidationErrors
];

/**
 * Phone verification code validation
 * - code: required, trimmed, exactly 6 digits
 */
export const validatePhoneVerify = [
  body('phone', 'phone is required').exists().bail().isString().trim(),
  body('phone').isMobilePhone('any').withMessage('phone must be valid'),
  body('code', 'code is required').exists().bail().isString().trim(),
  body('code').matches(/^\d{4,8}$/).withMessage('code must be 4-8 digits'),
  handleValidationErrors
];

/**
 * Email verification token validation (query param)
 * - token: required parameter, trimmed
 */
export const validateEmailToken = [
  query('token', 'token is required').exists().bail().isString().trim(),
  query('token').isLength({ min: 10 }).withMessage('token appears invalid'),
  handleValidationErrors
];

// ============================================
// USER/PARAMS VALIDATION
// ============================================

/**
 * Validate user ID in params matches JWT claims
 * Use this for routes where users can only access their own resources
 * - id: required, integer
 */
export const validateUserIdParam = [
  param('id', 'id is required').exists().bail().isString().trim(),
  param('id').custom((value) => {
    const isUUIDv4 =
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
    const isIntegerId = /^\d+$/.test(value);
    if (!isUUIDv4 && !isIntegerId) throw new Error('id must be UUID or integer');
    return true;
  }),
  handleValidationErrors
];

// ============================================
// CUSTOM VALIDATORS (OPTIONAL)
// ============================================

/**
 * Custom password strength validator (optional, more strict)
 * Add to password fields if you want stronger validation
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character (@$!%*?&)
 */
// ----------------- Person 2 Validators ------------------

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

/**
 * Sanitize and validate pagination parameters
 * - page: optional, positive integer
 * - limit: optional, integer between 1 and 100
 */
const SORT_WHITELIST = ['created_at','email','username','id'];

export const validatePagination = [
  query('page').optional().isInt({ min:1 }).toInt(),
  query('limit').optional().isInt({ min:1, max:100 }).toInt(),
  query('order').optional().isIn(['asc','desc']),
  query('sort').optional().custom((value)=>{
    if(!SORT_WHITELIST.includes(value)) throw new Error('invalid sort field');
    return true;
  }),
  handleValidationErrors
];
