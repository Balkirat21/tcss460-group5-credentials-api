// src/core/middleware/adminAuth.ts
import { Response, NextFunction } from 'express';
import { IJwtRequest, UserRole } from '@models';
import { getPool } from '@db';

/**
 * Middleware to require a specific role or higher
 *
 * Role hierarchy: USER (1) < MODERATOR (2) < ADMIN (3) < SUPER_ADMIN (4) < OWNER (5)
 *
 * @param minRole - Minimum role required (users with this role or higher can access)
 * @returns Express middleware function
 *
 * @example
 * // Only admins (3), super admins (4), and owners (5) can access
 * router.post('/admin/users', requireRole(UserRole.ADMIN), createUser);
 *
 * @example
 * // Only super admins (4) and owners (5) can access
 * router.delete('/admin/users/:id', requireRole(UserRole.SUPER_ADMIN), deleteUser);
 */
export const requireRole = (minRole: UserRole) => {
    return (request: IJwtRequest, response: Response, next: NextFunction) => {
        // Check if user is authenticated
        if (!request.claims) {
            return response.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        // Check if user has sufficient role
        if (request.claims.role < minRole) {
            return response.status(403).json({
                success: false,
                message: 'Insufficient permissions',
                required: `Role ${minRole} or higher`,
                current: `Role ${request.claims.role}`
            });
        }

        // User has sufficient role, proceed
        next();
    };
};

/**
 * Middleware to require admin access (role 3 or higher)
 *
 * This is a convenience wrapper around requireRole(UserRole.ADMIN)
 * Ensures the user is at least an Admin (3), Super Admin (4), or Owner (5)
 *
 * @example
 * router.get('/admin/users', requireAdmin, getAllUsers);
 * router.post('/admin/users', requireAdmin, createUser);
 */
export const requireAdmin = requireRole(UserRole.ADMIN);

/**
 * Middleware to check role hierarchy for user management operations
 *
 * Ensures that:
 * 1. The requesting user has a HIGHER role than the target user
 * 2. Users cannot modify accounts with equal or higher roles
 *
 * Use this middleware for operations like:
 * - Updating another user's information
 * - Deleting another user
 * - Changing another user's role
 * - Resetting another user's password
 *
 * This middleware should be placed AFTER requireAdmin and AFTER the
 * middleware that fetches the target user's information.
 *
 * The target user's role should be stored in request.targetUserRole
 * by a prior middleware.
 *
 * @example
 * router.delete('/admin/users/:id',
 *   requireAdmin,
 *   fetchTargetUser,  // Sets request.targetUserRole
 *   checkRoleHierarchy,
 *   deleteUser
 * );
 *
 * @example
 * // An Admin (role 3) trying to delete a Super Admin (role 4):
 * // ❌ DENIED - Admin cannot modify Super Admin
 *
 * // A Super Admin (role 4) trying to delete an Admin (role 3):
 * // ✅ ALLOWED - Super Admin can modify Admin
 *
 * // An Admin (role 3) trying to delete another Admin (role 3):
 * // ❌ DENIED - Cannot modify users with equal role
 */
export const checkRoleHierarchy = (
    request: IJwtRequest,
    response: Response,
    next: NextFunction
) => {
    // Check if user is authenticated
    if (!request.claims) {
        return response.status(401).json({
            success: false,
            message: 'Authentication required'
        });
    }

    // Check if target user role has been set by previous middleware
    if (request.targetUserRole === undefined) {
        return response.status(500).json({
            success: false,
            message: 'Server error: Target user role not set',
            hint: 'checkRoleHierarchy requires prior middleware to set request.targetUserRole'
        });
    }

    const requestingUserRole = request.claims.role;
    const targetUserRole = request.targetUserRole;

    // Check if requesting user has a HIGHER role than target user
    if (requestingUserRole <= targetUserRole) {
        return response.status(403).json({
            success: false,
            message: 'Insufficient permissions to modify this user',
            reason: 'You can only modify users with a lower role than yours',
            yourRole: requestingUserRole,
            targetRole: targetUserRole
        });
    }

    // Hierarchy check passed, proceed
    next();
};

/**
 * Helper middleware to fetch target user's role from database
 * Sets request.targetUserRole for use by checkRoleHierarchy
 *
 * This middleware extracts the user ID from request params and
 * queries the database to get their role.
 *
 * @param paramName - The name of the route parameter containing user ID (default: 'id')
 * @returns Express middleware function
 *
 * @example
 * router.delete('/admin/users/:id',
 *   requireAdmin,
 *   fetchTargetUserRole('id'),  // Sets request.targetUserRole
 *   checkRoleHierarchy,
 *   deleteUser
 * );
 *
 * @example
 * router.put('/admin/users/:userId/role',
 *   requireAdmin,
 *   fetchTargetUserRole('userId'),  // Parameter name is 'userId'
 *   checkRoleHierarchy,
 *   changeUserRole
 * );
 */
export const fetchTargetUserRole = (paramName: string = 'id') => {
    return async (request: IJwtRequest, response: Response, next: NextFunction) => {
        try {
            const targetUserId = parseInt(request.params[paramName]);

            // Validate user ID
            if (isNaN(targetUserId)) {
                return response.status(400).json({
                    success: false,
                    message: 'Invalid user ID'
                });
            }

            // Query database for target user's role
            const pool = getPool();
            const result = await pool.query(
                'SELECT Account_Role FROM Account WHERE Account_ID = $1',
                [targetUserId]
            );

            // Check if user exists
            if (result.rows.length === 0) {
                return response.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            // Set target user's role on request object
            request.targetUserRole = result.rows[0].account_role as UserRole;

            next();
        } catch (error) {
            console.error('Error fetching target user role:', error);
            return response.status(500).json({
                success: false,
                message: 'Server error while checking user permissions'
            });
        }
    };
};
