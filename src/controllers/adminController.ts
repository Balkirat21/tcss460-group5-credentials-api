// src/controllers/adminController.ts
import { Response } from 'express';
import { pool, sendSuccess, sendError, ErrorCodes } from '@utilities';
import { IJwtRequest, UserRole, RoleName } from '@models';

/**
 * Admin Controller
 * Handles administrative user management operations
 *
 * Note: All methods assume authentication and authorization middleware
 * have already validated that the requesting user is an admin.
 */
export class AdminController {
    /**
     * Get user by ID
     * GET /admin/users/:id
     *
     * Returns detailed information about a specific user including:
     * - Basic account information
     * - Role and status
     * - Verification status
     * - Account timestamps
     *
     * @param request - Express request with user ID in params
     * @param response - Express response
     */
    static async getUserById(request: IJwtRequest, response: Response): Promise<void> {
        try {
            const userId = parseInt(request.params.id);

            // Validate user ID
            if (isNaN(userId)) {
                return sendError(response, 400, 'Invalid user ID', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Query user from database
            const result = await pool.query(
                `SELECT
                    Account_ID as id,
                    FirstName as firstname,
                    LastName as lastname,
                    Username as username,
                    Email as email,
                    Phone as phone,
                    Account_Role as role,
                    Email_Verified as email_verified,
                    Phone_Verified as phone_verified,
                    Account_Status as account_status,
                    Created_At as created_at,
                    Updated_At as updated_at
                FROM Account
                WHERE Account_ID = $1`,
                [userId]
            );

            // Check if user exists
            if (result.rows.length === 0) {
                return sendError(response, 404, 'User not found', ErrorCodes.USER_NOT_FOUND);
            }

            const user = result.rows[0];

            // Format response with role name
            const userResponse = {
                id: user.id,
                firstname: user.firstname,
                lastname: user.lastname,
                username: user.username,
                email: user.email,
                phone: user.phone,
                role: user.role,
                roleName: RoleName[user.role as UserRole],
                emailVerified: user.email_verified,
                phoneVerified: user.phone_verified,
                accountStatus: user.account_status,
                createdAt: user.created_at,
                updatedAt: user.updated_at
            };

            sendSuccess(response, userResponse, 'User retrieved successfully', 200);
        } catch (error) {
            console.error('Error in getUserById:', error);
            sendError(response, 500, 'Failed to retrieve user', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }

    /**
     * Get all users with pagination and filtering
     * GET /admin/users
     *
     * Supports:
     * - Pagination (page, limit)
     * - Filtering by role and status
     * - Sorting (sortBy, sortOrder)
     *
     * @param request - Express request with query parameters
     * @param response - Express response
     */
    static async getAllUsers(request: IJwtRequest, response: Response): Promise<void> {
        try {
            // Parse and validate query parameters
            const page = parseInt(request.query.page as string) || 1;
            const limit = Math.min(parseInt(request.query.limit as string) || 10, 100); // Max 100
            const role = request.query.role ? parseInt(request.query.role as string) : null;
            const status = request.query.status as string;
            const sortBy = (request.query.sortBy as string) || 'created_at';
            const sortOrder = (request.query.sortOrder as string) === 'asc' ? 'ASC' : 'DESC';

            // Validate pagination
            if (page < 1 || limit < 1) {
                return sendError(response, 400, 'Invalid pagination parameters', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Validate role filter
            if (role !== null && (role < 1 || role > 5)) {
                return sendError(response, 400, 'Invalid role filter', ErrorCodes.VALD_INVALID_ROLE);
            }

            // Validate status filter
            const validStatuses = ['pending', 'active', 'suspended', 'locked'];
            if (status && !validStatuses.includes(status)) {
                return sendError(response, 400, 'Invalid status filter', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Validate sortBy field (prevent SQL injection)
            const allowedSortFields = ['created_at', 'updated_at', 'email', 'username', 'account_role'];
            if (!allowedSortFields.includes(sortBy)) {
                return sendError(response, 400, 'Invalid sort field', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Build WHERE clause
            const whereClauses: string[] = [];
            const queryParams: any[] = [];
            let paramIndex = 1;

            if (role !== null) {
                whereClauses.push(`Account_Role = $${paramIndex++}`);
                queryParams.push(role);
            }

            if (status) {
                whereClauses.push(`Account_Status = $${paramIndex++}`);
                queryParams.push(status);
            } else {
                // By default, exclude locked (deleted) users unless status filter is specified
                whereClauses.push(`Account_Status != 'locked'`);
            }

            const whereClause = whereClauses.length > 0
                ? 'WHERE ' + whereClauses.join(' AND ')
                : '';

            // Get total count for pagination
            const countResult = await pool.query(
                `SELECT COUNT(*) as total FROM Account ${whereClause}`,
                queryParams
            );
            const totalUsers = parseInt(countResult.rows[0].total);
            const totalPages = Math.ceil(totalUsers / limit);

            // Calculate offset
            const offset = (page - 1) * limit;

            // Query users with pagination
            const usersResult = await pool.query(
                `SELECT
                    Account_ID as id,
                    FirstName as firstname,
                    LastName as lastname,
                    Username as username,
                    Email as email,
                    Phone as phone,
                    Account_Role as role,
                    Email_Verified as email_verified,
                    Phone_Verified as phone_verified,
                    Account_Status as account_status,
                    Created_At as created_at,
                    Updated_At as updated_at
                FROM Account
                ${whereClause}
                ORDER BY ${sortBy} ${sortOrder}
                LIMIT $${paramIndex++} OFFSET $${paramIndex++}`,
                [...queryParams, limit, offset]
            );

            // Format users with role names
            const users = usersResult.rows.map(user => ({
                id: user.id,
                firstname: user.firstname,
                lastname: user.lastname,
                username: user.username,
                email: user.email,
                phone: user.phone,
                role: user.role,
                roleName: RoleName[user.role as UserRole],
                emailVerified: user.email_verified,
                phoneVerified: user.phone_verified,
                accountStatus: user.account_status,
                createdAt: user.created_at,
                updatedAt: user.updated_at
            }));

            // Build response
            const responseData = {
                users,
                pagination: {
                    page,
                    limit,
                    total: totalUsers,
                    totalPages
                }
            };

            sendSuccess(response, responseData, 'Users retrieved successfully', 200);
        } catch (error) {
            console.error('Error in getAllUsers:', error);
            sendError(response, 500, 'Failed to retrieve users', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }

    /**
     * Get dashboard statistics
     * GET /admin/users/stats/dashboard
     *
     * Returns system-wide statistics including:
     * - Total user count
     * - Users by role breakdown
     * - Users by status breakdown
     * - Email and phone verification rates
     * - Recent user registrations (24h, 7d, 30d)
     *
     * @param request - Express request
     * @param response - Express response
     */
    static async getDashboardStats(request: IJwtRequest, response: Response): Promise<void> {
        try {
            // Get total users
            const totalResult = await pool.query(
                'SELECT COUNT(*) as total FROM Account'
            );
            const totalUsers = parseInt(totalResult.rows[0].total);

            // Get users by role
            const roleResult = await pool.query(
                `SELECT
                    Account_Role as role,
                    COUNT(*) as count
                FROM Account
                GROUP BY Account_Role
                ORDER BY Account_Role`
            );

            const usersByRole = roleResult.rows.reduce((acc, row) => {
                const roleName = RoleName[row.role as UserRole];
                acc[roleName] = parseInt(row.count);
                return acc;
            }, {} as Record<string, number>);

            // Get users by status
            const statusResult = await pool.query(
                `SELECT
                    Account_Status as status,
                    COUNT(*) as count
                FROM Account
                GROUP BY Account_Status
                ORDER BY Account_Status`
            );

            const usersByStatus = statusResult.rows.reduce((acc, row) => {
                acc[row.status] = parseInt(row.count);
                return acc;
            }, {} as Record<string, number>);

            // Get verification statistics
            const verificationResult = await pool.query(
                `SELECT
                    COUNT(CASE WHEN Email_Verified = TRUE THEN 1 END) as email_verified,
                    COUNT(CASE WHEN Phone_Verified = TRUE THEN 1 END) as phone_verified,
                    COUNT(*) as total
                FROM Account`
            );

            const verificationStats = verificationResult.rows[0];
            const emailVerificationRate = totalUsers > 0
                ? (parseInt(verificationStats.email_verified) / totalUsers) * 100
                : 0;
            const phoneVerificationRate = totalUsers > 0
                ? (parseInt(verificationStats.phone_verified) / totalUsers) * 100
                : 0;

            // Get recent registrations
            const recentResult = await pool.query(
                `SELECT
                    COUNT(CASE WHEN Created_At >= NOW() - INTERVAL '24 hours' THEN 1 END) as last_24h,
                    COUNT(CASE WHEN Created_At >= NOW() - INTERVAL '7 days' THEN 1 END) as last_7d,
                    COUNT(CASE WHEN Created_At >= NOW() - INTERVAL '30 days' THEN 1 END) as last_30d
                FROM Account`
            );

            const recentStats = recentResult.rows[0];

            // Build response
            const stats = {
                totalUsers,
                usersByRole,
                usersByStatus,
                verificationRates: {
                    email: Math.round(emailVerificationRate * 100) / 100,
                    phone: Math.round(phoneVerificationRate * 100) / 100
                },
                recentRegistrations: {
                    last24Hours: parseInt(recentStats.last_24h),
                    last7Days: parseInt(recentStats.last_7d),
                    last30Days: parseInt(recentStats.last_30d)
                }
            };

            sendSuccess(response, stats, 'Dashboard statistics retrieved successfully', 200);
        } catch (error) {
            console.error('Error in getDashboardStats:', error);
            sendError(response, 500, 'Failed to retrieve statistics', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }

    /**
     * Create new user with specified role
     * POST /admin/users
     *
     * Admins can only create users with roles lower than their own.
     *
     * @param request - Express request with user data in body
     * @param response - Express response
     */
    static async createUser(request: IJwtRequest, response: Response): Promise<void> {
        try {
            const { firstname, lastname, email, password, username, phone, role } = request.body;
            const adminRole = request.claims.role;

            // Validate that admin can create user with requested role
            if (role >= adminRole) {
                return sendError(
                    response,
                    403,
                    'Cannot create user with role equal to or higher than your own',
                    ErrorCodes.AUTH_UNAUTHORIZED
                );
            }

            // Validate role is within valid range
            if (role < 1 || role > 5) {
                return sendError(response, 400, 'Invalid role', ErrorCodes.VALD_INVALID_ROLE);
            }

            // Check if user already exists
            const existingUser = await pool.query(
                'SELECT Account_ID FROM Account WHERE Email = $1 OR Username = $2 OR Phone = $3',
                [email, username, phone]
            );

            if (existingUser.rows.length > 0) {
                return sendError(
                    response,
                    400,
                    'User with this email, username, or phone already exists',
                    ErrorCodes.AUTH_EMAIL_EXISTS
                );
            }

            // Begin transaction
            const client = await pool.connect();
            try {
                await client.query('BEGIN');

                // Create account
                const accountResult = await client.query(
                    `INSERT INTO Account
                     (FirstName, LastName, Username, Email, Phone, Account_Role, Email_Verified, Phone_Verified, Account_Status)
                     VALUES ($1, $2, $3, $4, $5, $6, FALSE, FALSE, 'pending')
                     RETURNING Account_ID`,
                    [firstname, lastname, username, email, phone, role]
                );

                const accountId = accountResult.rows[0].account_id;

                // Generate salt and hash for password
                const crypto = require('crypto');
                const salt = crypto.randomBytes(32).toString('hex');
                const hash = crypto.createHash('sha256');
                hash.update(password + salt);
                const saltedHash = hash.digest('hex');

                // Store credentials
                await client.query(
                    'INSERT INTO Account_Credential (Account_ID, Salted_Hash, Salt) VALUES ($1, $2, $3)',
                    [accountId, saltedHash, salt]
                );

                await client.query('COMMIT');

                const userResponse = {
                    id: accountId,
                    firstname,
                    lastname,
                    username,
                    email,
                    phone,
                    role,
                    roleName: RoleName[role as UserRole],
                    emailVerified: false,
                    phoneVerified: false,
                    accountStatus: 'pending'
                };

                sendSuccess(response, userResponse, 'User created successfully', 201);
            } catch (error) {
                await client.query('ROLLBACK');
                throw error;
            } finally {
                client.release();
            }
        } catch (error) {
            console.error('Error in createUser:', error);
            sendError(response, 500, 'Failed to create user', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }

    /**
     * Search users by email, username, name, or phone
     * GET /admin/users/search
     *
     * Searches across multiple fields with pagination:
     * - Email (partial match)
     * - Username (partial match)
     * - First name (partial match)
     * - Last name (partial match)
     * - Phone (partial match)
     *
     * @param request - Express request with query parameters (q, page, limit)
     * @param response - Express response
     */
    static async searchUsers(request: IJwtRequest, response: Response): Promise<void> {
        try {
            const searchQuery = request.query.q as string;
            const page = parseInt(request.query.page as string) || 1;
            const limit = Math.min(parseInt(request.query.limit as string) || 10, 100);

            // Validate search query
            if (!searchQuery || searchQuery.trim().length === 0) {
                return sendError(response, 400, 'Search query is required', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Validate pagination
            if (page < 1 || limit < 1) {
                return sendError(response, 400, 'Invalid pagination parameters', ErrorCodes.VALD_INVALID_INPUT);
            }

            const searchPattern = `%${searchQuery.trim()}%`;

            // Get total count for pagination
            const countResult = await pool.query(
                `SELECT COUNT(*) as total
                FROM Account
                WHERE Email ILIKE $1
                   OR Username ILIKE $1
                   OR FirstName ILIKE $1
                   OR LastName ILIKE $1
                   OR Phone ILIKE $1`,
                [searchPattern]
            );
            const totalUsers = parseInt(countResult.rows[0].total);
            const totalPages = Math.ceil(totalUsers / limit);

            // Calculate offset
            const offset = (page - 1) * limit;

            // Search users with pagination
            const usersResult = await pool.query(
                `SELECT
                    Account_ID as id,
                    FirstName as firstname,
                    LastName as lastname,
                    Username as username,
                    Email as email,
                    Phone as phone,
                    Account_Role as role,
                    Email_Verified as email_verified,
                    Phone_Verified as phone_verified,
                    Account_Status as account_status,
                    Created_At as created_at,
                    Updated_At as updated_at
                FROM Account
                WHERE Email ILIKE $1
                   OR Username ILIKE $1
                   OR FirstName ILIKE $1
                   OR LastName ILIKE $1
                   OR Phone ILIKE $1
                ORDER BY Created_At DESC
                LIMIT $2 OFFSET $3`,
                [searchPattern, limit, offset]
            );

            // Format users with role names
            const users = usersResult.rows.map(user => ({
                id: user.id,
                firstname: user.firstname,
                lastname: user.lastname,
                username: user.username,
                email: user.email,
                phone: user.phone,
                role: user.role,
                roleName: RoleName[user.role as UserRole],
                emailVerified: user.email_verified,
                phoneVerified: user.phone_verified,
                accountStatus: user.account_status,
                createdAt: user.created_at,
                updatedAt: user.updated_at
            }));

            // Build response
            const responseData = {
                users,
                pagination: {
                    page,
                    limit,
                    total: totalUsers,
                    totalPages
                },
                searchQuery
            };

            sendSuccess(response, responseData, 'Users search completed successfully', 200);
        } catch (error) {
            console.error('Error in searchUsers:', error);
            sendError(response, 500, 'Failed to search users', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }

    /**
     * Update user information
     * PUT /admin/users/:id
     *
     * Allows updating basic user information:
     * - First name, last name, username, email, phone
     *
     * Note: Role hierarchy is enforced via middleware
     * Note: Use separate endpoints for password and role changes
     *
     * @param request - Express request with user ID in params and update data in body
     * @param response - Express response
     */
    static async updateUser(request: IJwtRequest, response: Response): Promise<void> {
        try {
            const userId = parseInt(request.params.id);
            const { firstname, lastname, username, email, phone } = request.body;

            // Validate user ID
            if (isNaN(userId)) {
                return sendError(response, 400, 'Invalid user ID', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Check if at least one field is being updated
            if (!firstname && !lastname && !username && !email && !phone) {
                return sendError(response, 400, 'At least one field must be provided for update', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Check if user exists
            const userCheck = await pool.query(
                'SELECT Account_ID FROM Account WHERE Account_ID = $1',
                [userId]
            );

            if (userCheck.rows.length === 0) {
                return sendError(response, 404, 'User not found', ErrorCodes.USER_NOT_FOUND);
            }

            // Check for duplicate email, username, or phone (if being updated)
            if (email || username || phone) {
                const duplicateCheck = await pool.query(
                    `SELECT Account_ID, Email, Username, Phone
                    FROM Account
                    WHERE (Email = $1 OR Username = $2 OR Phone = $3)
                      AND Account_ID != $4`,
                    [email || '', username || '', phone || '', userId]
                );

                if (duplicateCheck.rows.length > 0) {
                    const duplicate = duplicateCheck.rows[0];
                    if (email && duplicate.email === email) {
                        return sendError(response, 400, 'Email already in use', ErrorCodes.AUTH_EMAIL_EXISTS);
                    }
                    if (username && duplicate.username === username) {
                        return sendError(response, 400, 'Username already in use', ErrorCodes.AUTH_USERNAME_EXISTS);
                    }
                    if (phone && duplicate.phone === phone) {
                        return sendError(response, 400, 'Phone already in use', ErrorCodes.AUTH_PHONE_EXISTS);
                    }
                }
            }

            // Build UPDATE query dynamically based on provided fields
            const updateFields: string[] = [];
            const updateValues: any[] = [];
            let paramIndex = 1;

            if (firstname) {
                updateFields.push(`FirstName = $${paramIndex++}`);
                updateValues.push(firstname);
            }
            if (lastname) {
                updateFields.push(`LastName = $${paramIndex++}`);
                updateValues.push(lastname);
            }
            if (username) {
                updateFields.push(`Username = $${paramIndex++}`);
                updateValues.push(username);
            }
            if (email) {
                updateFields.push(`Email = $${paramIndex++}`);
                updateValues.push(email);
                // Reset email verification if email is changed
                updateFields.push(`Email_Verified = FALSE`);
            }
            if (phone) {
                updateFields.push(`Phone = $${paramIndex++}`);
                updateValues.push(phone);
                // Reset phone verification if phone is changed
                updateFields.push(`Phone_Verified = FALSE`);
            }

            // Add updated_at timestamp
            updateFields.push(`Updated_At = NOW()`);

            // Add user ID as final parameter
            updateValues.push(userId);

            // Execute update
            const updateResult = await pool.query(
                `UPDATE Account
                SET ${updateFields.join(', ')}
                WHERE Account_ID = $${paramIndex}
                RETURNING
                    Account_ID as id,
                    FirstName as firstname,
                    LastName as lastname,
                    Username as username,
                    Email as email,
                    Phone as phone,
                    Account_Role as role,
                    Email_Verified as email_verified,
                    Phone_Verified as phone_verified,
                    Account_Status as account_status,
                    Created_At as created_at,
                    Updated_At as updated_at`,
                updateValues
            );

            const updatedUser = updateResult.rows[0];

            // Format response
            const userResponse = {
                id: updatedUser.id,
                firstname: updatedUser.firstname,
                lastname: updatedUser.lastname,
                username: updatedUser.username,
                email: updatedUser.email,
                phone: updatedUser.phone,
                role: updatedUser.role,
                roleName: RoleName[updatedUser.role as UserRole],
                emailVerified: updatedUser.email_verified,
                phoneVerified: updatedUser.phone_verified,
                accountStatus: updatedUser.account_status,
                createdAt: updatedUser.created_at,
                updatedAt: updatedUser.updated_at
            };

            sendSuccess(response, userResponse, 'User updated successfully', 200);
        } catch (error) {
            console.error('Error in updateUser:', error);
            sendError(response, 500, 'Failed to update user', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }

    /**
     * Delete user (soft delete)
     * DELETE /admin/users/:id
     *
     * Performs a soft delete by setting account_status to 'locked'
     * Role hierarchy is enforced via middleware
     *
     * @param request - Express request with user ID in params
     * @param response - Express response
     */
    static async deleteUser(request: IJwtRequest, response: Response): Promise<void> {
        try {
            const userId = parseInt(request.params.id);

            // Validate user ID
            if (isNaN(userId)) {
                return sendError(response, 400, 'Invalid user ID', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Prevent admin from deleting themselves
            if (userId === request.claims.id) {
                return sendError(response, 400, 'Cannot delete your own account', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Check if user exists
            const userCheck = await pool.query(
                'SELECT Account_ID, Account_Status FROM Account WHERE Account_ID = $1',
                [userId]
            );

            if (userCheck.rows.length === 0) {
                return sendError(response, 404, 'User not found', ErrorCodes.USER_NOT_FOUND);
            }

            // Check if already deleted
            if (userCheck.rows[0].account_status === 'locked') {
                return sendError(response, 400, 'User is already deleted', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Perform soft delete
            await pool.query(
                `UPDATE Account
                SET Account_Status = 'locked', Updated_At = NOW()
                WHERE Account_ID = $1`,
                [userId]
            );

            sendSuccess(
                response,
                { id: userId, status: 'locked' },
                'User deleted successfully',
                200
            );
        } catch (error) {
            console.error('Error in deleteUser:', error);
            sendError(response, 500, 'Failed to delete user', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }

    /**
     * Reset user password (admin override)
     * PUT /admin/users/:id/password
     *
     * Allows admin to set a new password without requiring the old one
     * Role hierarchy is enforced via middleware
     *
     * @param request - Express request with user ID in params and newPassword in body
     * @param response - Express response
     */
    static async resetUserPassword(request: IJwtRequest, response: Response): Promise<void> {
        try {
            const userId = parseInt(request.params.id);
            const { newPassword } = request.body;

            // Validate user ID
            if (isNaN(userId)) {
                return sendError(response, 400, 'Invalid user ID', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Validate new password
            if (!newPassword || newPassword.trim().length === 0) {
                return sendError(response, 400, 'New password is required', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Basic password strength check
            if (newPassword.length < 8) {
                return sendError(response, 400, 'Password must be at least 8 characters long', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Check if user exists
            const userCheck = await pool.query(
                'SELECT Account_ID FROM Account WHERE Account_ID = $1',
                [userId]
            );

            if (userCheck.rows.length === 0) {
                return sendError(response, 404, 'User not found', ErrorCodes.USER_NOT_FOUND);
            }

            // Generate new salt and hash
            const crypto = require('crypto');
            const salt = crypto.randomBytes(32).toString('hex');
            const hash = crypto.createHash('sha256');
            hash.update(newPassword + salt);
            const saltedHash = hash.digest('hex');

            // Update password in database
            await pool.query(
                `UPDATE Account_Credential
                SET Salted_Hash = $1, Salt = $2
                WHERE Account_ID = $3`,
                [saltedHash, salt, userId]
            );

            // Update the Account table's Updated_At timestamp
            await pool.query(
                'UPDATE Account SET Updated_At = NOW() WHERE Account_ID = $1',
                [userId]
            );

            sendSuccess(
                response,
                { id: userId, message: 'Password has been reset' },
                'Password reset successfully',
                200
            );
        } catch (error) {
            console.error('Error in resetUserPassword:', error);
            sendError(response, 500, 'Failed to reset password', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }

    /**
     * Change user role
     * PUT /admin/users/:id/role
     *
     * Enforces role hierarchy:
     * - Cannot modify users with equal or higher role (enforced by middleware)
     * - Cannot assign roles equal to or higher than your own
     *
     * @param request - Express request with user ID in params and role in body
     * @param response - Express response
     */
    static async changeUserRole(request: IJwtRequest, response: Response): Promise<void> {
        try {
            const userId = parseInt(request.params.id);
            const { role } = request.body;
            const adminRole = request.claims.role;

            // Validate user ID
            if (isNaN(userId)) {
                return sendError(response, 400, 'Invalid user ID', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Validate role is provided
            if (role === undefined || role === null) {
                return sendError(response, 400, 'Role is required', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Validate role is within valid range
            if (role < 1 || role > 5) {
                return sendError(response, 400, 'Invalid role value', ErrorCodes.VALD_INVALID_ROLE);
            }

            // Validate admin cannot assign role equal to or higher than their own
            if (role >= adminRole) {
                return sendError(
                    response,
                    403,
                    'Cannot assign role equal to or higher than your own',
                    ErrorCodes.AUTH_UNAUTHORIZED
                );
            }

            // Check if user exists
            const userCheck = await pool.query(
                'SELECT Account_ID, Account_Role FROM Account WHERE Account_ID = $1',
                [userId]
            );

            if (userCheck.rows.length === 0) {
                return sendError(response, 404, 'User not found', ErrorCodes.USER_NOT_FOUND);
            }

            const currentRole = userCheck.rows[0].account_role;

            // Check if role is actually changing
            if (currentRole === role) {
                return sendError(response, 400, 'User already has this role', ErrorCodes.VALD_INVALID_INPUT);
            }

            // Update user role
            const updateResult = await pool.query(
                `UPDATE Account
                SET Account_Role = $1, Updated_At = NOW()
                WHERE Account_ID = $2
                RETURNING
                    Account_ID as id,
                    FirstName as firstname,
                    LastName as lastname,
                    Username as username,
                    Email as email,
                    Account_Role as role`,
                [role, userId]
            );

            const updatedUser = updateResult.rows[0];

            sendSuccess(
                response,
                {
                    id: updatedUser.id,
                    username: updatedUser.username,
                    email: updatedUser.email,
                    previousRole: currentRole,
                    previousRoleName: RoleName[currentRole as UserRole],
                    newRole: updatedUser.role,
                    newRoleName: RoleName[updatedUser.role as UserRole]
                },
                'User role updated successfully',
                200
            );
        } catch (error) {
            console.error('Error in changeUserRole:', error);
            sendError(response, 500, 'Failed to change user role', ErrorCodes.SRVR_GENERIC_ERROR);
        }
    }
}
