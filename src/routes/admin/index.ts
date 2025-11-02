// src/routes/admin/index.ts
import express, { Router, Request, Response } from 'express';
import { checkToken, requireAdmin, requireRole, fetchTargetUserRole, checkRoleHierarchy } from '@middleware';
import { UserRole } from '@models';
import { AdminController } from '@controllers';

const adminRoutes: Router = express.Router();

// All admin routes require authentication
adminRoutes.use(checkToken);

/**
 * ===== ADMIN USER MANAGEMENT ENDPOINTS =====
 *
 * All admin endpoints require at least Admin role (3) or higher.
 * Some operations also enforce role hierarchy (cannot modify equal/higher roles).
 */

/**
 * Create new user with specified role
 * POST /admin/users
 *
 * Required role: Admin (3) or higher
 *
 * Request body:
 * {
 *   "firstname": "string",
 *   "lastname": "string",
 *   "username": "string",
 *   "email": "string",
 *   "phone": "string",
 *   "password": "string",
 *   "role": number (1-5)
 * }
 *
 * Admins can only create users with roles less than their own.
 *
 * TODO: Add validation middleware (validateCreateUser) when Person 1/2 completes validation
 * TODO: Connect to AdminController.createUser when Person 4 completes controller
 */
adminRoutes.post('/users',
    requireAdmin,
    // TODO: validateCreateUser, // Uncomment when Person 1/2 completes this
    AdminController.createUser
);

/**
 * Get all users with pagination and filtering
 * GET /admin/users
 *
 * Required role: Admin (3) or higher
 *
 * Query parameters:
 * - page: number (default: 1)
 * - limit: number (default: 10, max: 100)
 * - role: number (optional filter by role)
 * - status: string (optional filter by status: pending, active, suspended, locked)
 * - sortBy: string (default: created_at)
 * - sortOrder: string (asc or desc, default: desc)
 *
 * Response includes:
 * - users: array of user objects
 * - pagination: { page, limit, total, totalPages }
 *
 * TODO: Add validation middleware (validatePagination) when Person 2 completes validation
 * TODO: Connect to AdminController.getAllUsers when Person 4 completes controller
 */
adminRoutes.get('/users',
    requireAdmin,
    // TODO: validatePagination, // Uncomment when Person 2 completes this
    AdminController.getAllUsers
);

/**
 * Search users by email, username, name, or phone
 * GET /admin/users/search
 *
 * Required role: Admin (3) or higher
 *
 * Query parameters:
 * - q: string (required - search query)
 * - page: number (default: 1)
 * - limit: number (default: 10)
 *
 * Searches across:
 * - Email (partial match)
 * - Username (partial match)
 * - First name (partial match)
 * - Last name (partial match)
 * - Phone (partial match)
 *
 * TODO: Add validation middleware (validateSearch) when Person 1/2 completes validation
 * TODO: Connect to AdminController.searchUsers when Person 4 completes controller
 */
adminRoutes.get('/users/search',
    requireAdmin,
    // TODO: validateSearch, // Uncomment when Person 1/2 completes this
    (req: Request, res: Response) => {
        // TODO: Replace with AdminController.searchUsers when Person 4 completes controller
        res.status(501).json({
            success: false,
            message: 'Admin search users endpoint - Controller pending implementation by Person 4',
            endpoint: 'GET /admin/users/search'
        });
    }
);

/**
 * Get user by ID
 * GET /admin/users/:id
 *
 * Required role: Admin (3) or higher
 *
 * Returns detailed user information including:
 * - Account details
 * - Verification status
 * - Account status
 * - Role information
 * - Created/updated timestamps
 *
 * TODO: Add validation middleware (validateUserIdParam) when Person 2 completes validation
 * TODO: Connect to AdminController.getUserById when Person 4 completes controller
 */
adminRoutes.get('/users/:id',
    requireAdmin,
    // TODO: validateUserIdParam, // Uncomment when Person 2 completes this
    AdminController.getUserById
);

/**
 * Update user information
 * PUT /admin/users/:id
 *
 * Required role: Admin (3) or higher
 * Enforces role hierarchy: Cannot update users with equal or higher role
 *
 * Request body (all fields optional):
 * {
 *   "firstname": "string",
 *   "lastname": "string",
 *   "username": "string",
 *   "email": "string",
 *   "phone": "string"
 * }
 *
 * Note: Use separate endpoints to change role or password
 *
 * TODO: Add validation middleware (validateUpdateUser) when Person 1/2 completes validation
 * TODO: Connect to AdminController.updateUser when Person 4 completes controller
 */
adminRoutes.put('/users/:id',
    requireAdmin,
    fetchTargetUserRole('id'),  // Fetches target user's role
    checkRoleHierarchy,         // Ensures requesting user has higher role
    // TODO: validateUpdateUser, // Uncomment when Person 1/2 completes this
    (req: Request, res: Response) => {
        // TODO: Replace with AdminController.updateUser when Person 4 completes controller
        res.status(501).json({
            success: false,
            message: 'Admin update user endpoint - Controller pending implementation by Person 4',
            endpoint: 'PUT /admin/users/:id',
            requestedId: req.params.id
        });
    }
);

/**
 * Delete user (soft delete)
 * DELETE /admin/users/:id
 *
 * Required role: Admin (3) or higher
 * Enforces role hierarchy: Cannot delete users with equal or higher role
 *
 * Performs a soft delete by:
 * - Setting account_status to 'locked'
 * - Optionally anonymizing data (depending on implementation)
 *
 * Note: Physical deletion may require Owner role (5)
 *
 * TODO: Add validation middleware (validateUserIdParam) when Person 2 completes validation
 * TODO: Connect to AdminController.deleteUser when Person 4 completes controller
 */
adminRoutes.delete('/users/:id',
    requireAdmin,
    fetchTargetUserRole('id'),  // Fetches target user's role
    checkRoleHierarchy,         // Ensures requesting user has higher role
    // TODO: validateUserIdParam, // Uncomment when Person 2 completes this
    (req: Request, res: Response) => {
        // TODO: Replace with AdminController.deleteUser when Person 4 completes controller
        res.status(501).json({
            success: false,
            message: 'Admin delete user endpoint - Controller pending implementation by Person 4',
            endpoint: 'DELETE /admin/users/:id',
            requestedId: req.params.id
        });
    }
);

/**
 * Reset user password (admin override)
 * PUT /admin/users/:id/password
 *
 * Required role: Admin (3) or higher
 * Enforces role hierarchy: Cannot reset passwords for users with equal or higher role
 *
 * Request body:
 * {
 *   "newPassword": "string"
 * }
 *
 * Allows admin to set a new password without requiring the old one.
 * User should be notified via email about the password change.
 *
 * TODO: Add validation middleware (validateAdminPasswordReset) when Person 1/2 completes validation
 * TODO: Connect to AdminController.resetUserPassword when Person 4 completes controller
 */
adminRoutes.put('/users/:id/password',
    requireAdmin,
    fetchTargetUserRole('id'),  // Fetches target user's role
    checkRoleHierarchy,         // Ensures requesting user has higher role
    // TODO: validateAdminPasswordReset, // Uncomment when Person 1/2 completes this
    (req: Request, res: Response) => {
        // TODO: Replace with AdminController.resetUserPassword when Person 4 completes controller
        res.status(501).json({
            success: false,
            message: 'Admin reset password endpoint - Controller pending implementation by Person 4',
            endpoint: 'PUT /admin/users/:id/password',
            requestedId: req.params.id
        });
    }
);

/**
 * Change user role
 * PUT /admin/users/:id/role
 *
 * Required role: Admin (3) or higher
 * Enforces role hierarchy:
 * - Cannot modify users with equal or higher role
 * - Cannot assign roles equal to or higher than your own
 *
 * Request body:
 * {
 *   "role": number (1-5)
 * }
 *
 * Role hierarchy:
 * 1 = USER
 * 2 = MODERATOR
 * 3 = ADMIN
 * 4 = SUPER_ADMIN
 * 5 = OWNER
 *
 * Example: An Admin (3) can:
 * ✅ Change User (1) → Moderator (2)
 * ✅ Change Moderator (2) → User (1)
 * ❌ Change User (1) → Admin (3) or higher
 * ❌ Change Admin (3) to any role
 *
 * TODO: Add validation middleware (validateChangeRole) when Person 1/2 completes validation
 * TODO: Connect to AdminController.changeUserRole when Person 4 completes controller
 */
adminRoutes.put('/users/:id/role',
    requireAdmin,
    fetchTargetUserRole('id'),  // Fetches target user's role
    checkRoleHierarchy,         // Ensures requesting user has higher role
    // TODO: validateChangeRole, // Uncomment when Person 1/2 completes this
    (req: Request, res: Response) => {
        // TODO: Replace with AdminController.changeUserRole when Person 4 completes controller
        res.status(501).json({
            success: false,
            message: 'Admin change role endpoint - Controller pending implementation by Person 4',
            endpoint: 'PUT /admin/users/:id/role',
            requestedId: req.params.id
        });
    }
);

/**
 * Get admin dashboard statistics
 * GET /admin/users/stats/dashboard
 *
 * Required role: Admin (3) or higher
 *
 * Returns statistics including:
 * - Total users count
 * - Users by role (breakdown)
 * - Users by status (pending, active, suspended, locked)
 * - Email verification rate
 * - Phone verification rate
 * - New users (last 24 hours, last 7 days, last 30 days)
 * - Recent activity metrics
 *
 * TODO: Connect to AdminController.getDashboardStats when Person 4 completes controller
 */
adminRoutes.get('/users/stats/dashboard',
    requireAdmin,
    AdminController.getDashboardStats
);

export { adminRoutes };
