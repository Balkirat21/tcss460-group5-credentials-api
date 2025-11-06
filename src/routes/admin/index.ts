// src/routes/admin/index.ts
import express, { Router, Request, Response } from 'express';
import {
    checkToken,
    requireAdmin,
    requireRole,
    fetchTargetUserRole,
    checkRoleHierarchy,
    validateAdminCreateUser,
    validateAdminUpdateUser,
    validateAdminPasswordReset,
    validateAdminRoleChange,
    validateAdminSearch,
    validateUserIdParam,
    validatePagination
} from '@middleware';
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
 */
adminRoutes.post('/users',
    requireAdmin,
    validateAdminCreateUser,
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
 */
adminRoutes.get('/users',
    requireAdmin,
    validatePagination,
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
 */
adminRoutes.get('/users/search',
    requireAdmin,
    validateAdminSearch,
    AdminController.searchUsers
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
 */
adminRoutes.get('/users/:id',
    requireAdmin,
    validateUserIdParam,
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
 */
adminRoutes.put('/users/:id',
    requireAdmin,
    fetchTargetUserRole('id'),  // Fetches target user's role
    checkRoleHierarchy,         // Ensures requesting user has higher role
    validateUserIdParam,
    validateAdminUpdateUser,
    AdminController.updateUser
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
 */
adminRoutes.delete('/users/:id',
    requireAdmin,
    fetchTargetUserRole('id'),  // Fetches target user's role
    checkRoleHierarchy,         // Ensures requesting user has higher role
    validateUserIdParam,
    AdminController.deleteUser
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
 */
adminRoutes.put('/users/:id/password',
    requireAdmin,
    fetchTargetUserRole('id'),  // Fetches target user's role
    checkRoleHierarchy,         // Ensures requesting user has higher role
    validateUserIdParam,
    validateAdminPasswordReset,
    AdminController.resetUserPassword
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
 */
adminRoutes.put('/users/:id/role',
    requireAdmin,
    fetchTargetUserRole('id'),  // Fetches target user's role
    checkRoleHierarchy,         // Ensures requesting user has higher role
    validateUserIdParam,
    validateAdminRoleChange,
    AdminController.changeUserRole
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
