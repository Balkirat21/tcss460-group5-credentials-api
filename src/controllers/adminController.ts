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

    static async searchUsers(request: IJwtRequest, response: Response): Promise<void> {
        sendError(response, 501, 'Not implemented - Person 4 to complete', ErrorCodes.SRVR_GENERIC_ERROR);
    }

    static async updateUser(request: IJwtRequest, response: Response): Promise<void> {
        sendError(response, 501, 'Not implemented - Person 4 to complete', ErrorCodes.SRVR_GENERIC_ERROR);
    }

    static async deleteUser(request: IJwtRequest, response: Response): Promise<void> {
        sendError(response, 501, 'Not implemented - Person 4 to complete', ErrorCodes.SRVR_GENERIC_ERROR);
    }

    static async resetUserPassword(request: IJwtRequest, response: Response): Promise<void> {
        sendError(response, 501, 'Not implemented - Person 4 to complete', ErrorCodes.SRVR_GENERIC_ERROR);
    }

    static async changeUserRole(request: IJwtRequest, response: Response): Promise<void> {
        sendError(response, 501, 'Not implemented - Person 4 to complete', ErrorCodes.SRVR_GENERIC_ERROR);
    }
}
