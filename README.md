# TCSS 460 – Group 5 Credentials Web API (Identity & Access Management)

This repository contains the Group 5 Credentials Web API project for the TCSS 460 Client/Server Programming course. This is a comprehensive **Identity and Access Management (IAM) API** built with Node.js, Express, TypeScript, and PostgreSQL, providing secure user authentication, authorization, and role-based access control.

🌐 **Hosted Credentials API URL (Render)**: https://tcss460-group5-credentials-api.onrender.com

📚 **API Documentation**: https://tcss460-group5-credentials-api.onrender.com/api-docs

---

## 🚀 Sprint Contribution

### Group Members

### **Balkirat Singh**  
Set up the **PostgreSQL database** for the Credentials API, created schemas and relations, and implemented **admin endpoints**.  
Also assisted with integration between authentication and show routes. Supported deployment to Render and database debugging.

### **Kobe Benavente**  
Implemented and tested **admin-related routes**, working closely on role-based access and endpoint validation.  
Contributed to middleware refinement and assisted in refactoring shared logic across routes.

### **MD Khan (Shanto)**  
Developed the **email verification and confirmation** flow for the Credentials API.  
Handled email service configuration, testing verification logic, and ensuring secure token expiration handling.

### **Pham Nguyen**  
Led work on **authentication and login/register logic** in the Credentials API.  
Configured JWT authentication, integrated middleware into routes, and assisted with user testing using Postman.


---

## 💬 Sprint Meetings

### Primary Communication Methods

- **Discord**: Used for group coordination, sprint planning, and real-time collaboration
- **GitHub**: Used for version control, pull requests, code reviews, and tracking sprint progress

### Meeting Details

**When/Where**: Weekly Discord voice meetings and continuous asynchronous collaboration via Discord text channels and GitHub throughout the sprint period.

**What Was Discussed**:
- Implementing complete authentication system with JWT tokens
- Building role-based access control (RBAC) with hierarchical permissions
- Creating comprehensive validation middleware using express-validator
- Implementing email and SMS verification systems
- Developing admin API for user management with proper authorization
- Setting up PostgreSQL database with Docker
- Creating extensive API documentation (Swagger + educational guides)
- Establishing test infrastructure with Jest and Supertest
- Deploying to Render with environment configuration
- Coordinating TypeScript implementation and path aliases

---

## 🧠 Sprint Comments

- Successfully implemented a **production-ready authentication and authorization API** with industry-standard security practices
- Complete **JWT-based authentication** system with secure token generation and validation
- **Role-Based Access Control (RBAC)** with 5-tier hierarchy (User, Moderator, Admin, SuperAdmin, Owner)
- **Multi-factor verification** supporting both email (48-hour expiry) and SMS (15-minute expiry) verification
- **Comprehensive validation** using express-validator for all input data with security-focused sanitization
- **Admin API** with full CRUD operations, pagination, filtering, sorting, and search capabilities
- **Role hierarchy enforcement** - admins can only manage users with lower roles than their own
- **SHA256 password hashing** with unique salts per user for secure credential storage
- **Parameterized SQL queries** throughout codebase for SQL injection prevention
- **TypeScript implementation** with path aliases for clean, maintainable code structure
- **Extensive documentation** including Swagger/OpenAPI specs and 29 educational markdown guides
- **Test infrastructure** established with Jest, Supertest, and 80% coverage requirements
- **Docker development environment** for consistent PostgreSQL database setup
- **Soft delete pattern** implemented - accounts are locked/suspended rather than permanently deleted
- **Rate limiting** on verification endpoints to prevent abuse (email: 5 min, SMS: 1 min)
- **Account status management** - pending, active, suspended, and locked states
- **Email enumeration prevention** - consistent responses for security
- **Password reset** functionality with secure token generation and 1-hour expiry
- All endpoints return **consistent error messages** with appropriate HTTP status codes (400, 401, 403, 404, 500)

---

## 🗂️ Current Repository Structure

```
tcss460-group5-credentials-api/
  .claude/                  # Claude Code custom commands
  .idea/                    # IDE configuration files
  ai.prof/                  # AI assistant instructions
  data/
    init.sql                # PostgreSQL database schema
    heroku.sql              # Heroku deployment schema
  dist/                     # Compiled JavaScript output
  docs/
    swagger.yaml            # OpenAPI/Swagger specification
    Complete_API_Testing.postman_collection.json
    Admin_Role_Management_Testing.postman_collection.json
  docs-2.0/                 # Educational documentation (29 guides)
    API_Documentation.md
    Authentication_Guide.md
    RBAC_Guide.md
    Password_Security_Guide.md
    JWT_Implementation_Guide.md
    Validation_Strategies.md
    Web_Security_Guide.md
    ... (and 22 more guides)
  node_modules/
  src/
    controllers/
      authController.ts     # Authentication logic
      adminController.ts    # Admin user management
      verificationController.ts  # Email/SMS verification
      index.ts
    routes/
      open/                 # Public routes (no auth required)
        index.ts
      closed/               # Protected routes (JWT required)
        index.ts
      admin/                # Admin routes (role 3+ required)
        index.ts
    core/
      middleware/
        jwt.ts              # JWT token validation
        validation.ts       # Express-validator chains
        adminAuth.ts        # Role-based authorization
        index.ts
      utilities/
        credentialingUtils.ts  # Password hashing
        database.ts         # PostgreSQL connection pool
        emailService.ts     # Email sending (Nodemailer)
        envConfig.ts        # Environment configuration
        responseUtils.ts    # Standardized responses
        validationUtils.ts  # Validation helpers
        __tests__/          # Unit tests
        index.ts
      models/
        auth.model.ts       # TypeScript interfaces
        request.model.ts
        response.model.ts
        index.ts
    test/
      setup.ts              # Jest test configuration
    app.ts                  # Express app configuration
    index.ts                # Server entry point
  .env.example              # Environment variables template
  .gitignore
  docker-compose.yml        # PostgreSQL Docker setup
  jest.config.js            # Jest testing configuration
  package.json
  package-lock.json
  Procfile                  # Heroku deployment config
  README.md
  tsconfig.json             # TypeScript configuration
```

---

## 🧩 Sprint Summary

This project represents a comprehensive **Identity and Access Management (IAM) API** for TCSS 460. The API provides enterprise-grade authentication, authorization, and user management capabilities with a focus on security best practices and educational value.

### Key Achievements:

#### ✅ Authentication System:

- **POST /auth/register** – User registration with password hashing and automatic JWT issuance
- **POST /auth/login** – Secure login with account status verification
- **POST /auth/password/reset-request** – Password reset via email with secure tokens
- **POST /auth/password/reset** – Complete password reset flow
- **POST /auth/user/password/change** – User-initiated password changes (requires current password)

#### ✅ Verification System:

- **Email Verification**:
  - POST /auth/verify/email/send – Send verification email
  - GET /auth/verify/email/confirm?token=xxx – Verify email via link
  - 64-character secure tokens with 48-hour expiry
  - Rate limited to 1 per 5 minutes

- **SMS Verification**:
  - POST /auth/verify/phone/send – Send 6-digit SMS code
  - POST /auth/verify/phone/verify – Verify SMS code
  - 15-minute expiry with max 3 attempts
  - Rate limited to 1 per minute
  - Email-to-SMS gateway support

- **GET /auth/verify/carriers** – List supported mobile carriers for SMS

#### ✅ Admin API (Role 3+ Required):

- **POST /admin/users** – Create users with specified roles (respects role hierarchy)
- **GET /admin/users** – List all users with pagination, filtering by role/status, sorting
- **GET /admin/users/search?q=query** – Search users by email, username, name, or phone
- **GET /admin/users/:id** – Retrieve detailed user information
- **PUT /admin/users/:id** – Update user details (role hierarchy enforced)
- **DELETE /admin/users/:id** – Soft delete user (sets status to 'locked')
- **PUT /admin/users/:id/password** – Admin password reset (no current password required)
- **PUT /admin/users/:id/role** – Change user role (can only assign roles lower than admin's role)
- **GET /admin/users/stats/dashboard** – Dashboard statistics

#### ✅ Role-Based Access Control (RBAC):

**Role Hierarchy**:
1. **User** (1) – Basic access
2. **Moderator** (2) – User management capabilities
3. **Admin** (3) – Full user CRUD, can manage roles ≤ 3
4. **SuperAdmin** (4) – System administration, can manage roles ≤ 4
5. **Owner** (5) – Complete system control

**Enforcement Rules**:
- Admins can only create/modify/delete users with roles lower than their own
- Role hierarchy validation on all admin operations
- Admins cannot delete themselves
- Automatic permission checks based on JWT token role

#### ✅ Security Features:

- **Password Security**: SHA256 hashing with unique 32-byte salts per user
- **SQL Injection Prevention**: Parameterized queries throughout entire codebase
- **JWT Security**: Signed tokens with configurable 14-day expiry
- **Input Validation**: Comprehensive express-validator chains on all endpoints
- **Timing-Safe Comparison**: Prevents timing attacks on password verification
- **Account Protection**: Status checks (pending/active/suspended/locked)
- **Email Enumeration Prevention**: Consistent responses for security
- **Rate Limiting**: Verification endpoints protected from abuse
- **Token Expiry**: Time-limited verification tokens and reset links

#### ✅ Database Design:

**Four Core Tables**:
1. **Account** – User information, verification status, role, and account status
2. **Account_Credential** – Salted password hashes
3. **Email_Verification** – Email verification tokens with 48-hour expiry
4. **Phone_Verification** – SMS codes with 15-minute expiry and attempt tracking

**Optimizations**:
- Performance indexes on email, phone, username, status
- Foreign key constraints for data integrity
- Timestamp tracking (created_at, updated_at)
- Unique constraints on email, phone, username

#### ✅ Comprehensive Documentation:

- **Swagger/OpenAPI**: Complete API specification hosted at /api-docs
- **Educational Guides**: 29 markdown documents covering authentication, security, testing, validation, RBAC, and more
- **Postman Collections**: Complete test collections for all endpoints including admin features
- **Code Documentation**: Inline comments and TypeScript interfaces throughout

#### ✅ TypeScript Implementation:

- **Path Aliases**: Clean imports (@utilities, @middleware, @controllers, @models)
- **Type Safety**: Strong typing with interfaces for requests, responses, and models
- **Compile-Time Checks**: Catch errors before runtime
- **IDE Support**: Enhanced autocomplete and refactoring

#### ✅ Testing Infrastructure:

- **Jest + Supertest**: Complete test framework setup
- **Unit Tests**: Utility function tests (credentialing, validation, email, env config)
- **Coverage Requirements**: 80% minimum for branches, functions, lines, statements
- **Test Commands**: test, test:watch, test:coverage scripts configured

#### ✅ Development Environment:

- **Docker Compose**: PostgreSQL database with automatic initialization
- **Hot Reload**: Nodemon with ts-node for development
- **Linting**: ESLint with TypeScript support
- **Formatting**: Prettier for consistent code style
- **Environment Variables**: Comprehensive .env.example template

#### ✅ Deployment:

- **Platform**: Render (with Heroku configuration available)
- **Production URL**: https://tcss460-group5-credentials-api.onrender.com
- **Environment**: Production-ready with proper secret management
- **Database**: External PostgreSQL database configuration

---

## 🔐 Security Best Practices Implemented

This API demonstrates industry-standard security practices suitable for production environments:

1. **Never store plain-text passwords** – All passwords hashed with SHA256 and unique salts
2. **Parameterized SQL queries** – Complete protection against SQL injection
3. **JWT token authentication** – Stateless authentication with signed tokens
4. **Role-based authorization** – Granular access control with hierarchy enforcement
5. **Input validation and sanitization** – Express-validator on all user inputs
6. **Rate limiting** – Protection against brute force and abuse
7. **Secure token generation** – Cryptographically random tokens for verification
8. **Time-limited credentials** – Expiry on tokens, codes, and reset links
9. **Account status management** – Ability to suspend/lock compromised accounts
10. **Timing-safe comparisons** – Protection against timing attacks
11. **CORS configuration** – Controlled cross-origin resource sharing
12. **Environment-based secrets** – No hardcoded credentials in code

---

## 📊 API Statistics

- **Total Endpoints**: 22+
- **Public Routes**: 7 (authentication, verification, documentation)
- **Protected Routes**: 4 (user password change, verification)
- **Admin Routes**: 9 (full user management CRUD)
- **Database Tables**: 4
- **Role Levels**: 5 (hierarchical)
- **Account Statuses**: 4 (pending, active, suspended, locked)

---

## 🎓 Educational Value

This project serves as a comprehensive learning resource for:

- **Backend Development**: Express.js API design patterns
- **TypeScript**: Type-safe development practices
- **Authentication**: JWT implementation and session management
- **Authorization**: Role-based access control (RBAC)
- **Security**: Industry-standard security practices (OWASP)
- **Database Design**: PostgreSQL schema design and optimization
- **Validation**: Input validation and sanitization strategies
- **Testing**: Unit testing with Jest and Supertest
- **DevOps**: Docker containerization and cloud deployment
- **Documentation**: API documentation and educational materials


---

### API Access

- **Local API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/api-docs
- **Educational Docs**: http://localhost:8000/doc
- **Health Check**: http://localhost:8000/jwt_test

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Watch mode for development
npm run test:watch

# Generate coverage report
npm run test:coverage
```

**Postman Collections**:
- Import `docs/Complete_API_Testing.postman_collection.json` for comprehensive API testing
- Import `docs/Admin_Role_Management_Testing.postman_collection.json` for admin feature testing

---

## 📝 Notes

- **Production Deployment**: Currently hosted on Render at https://tcss460-group5-credentials-api.onrender.com
- **Database**: PostgreSQL with Docker for local development, external database for production
- **TypeScript**: Full TypeScript implementation with strict type checking
- **Path Aliases**: Clean import statements using @ prefixes for better code organization
- **Email Service**: Uses Nodemailer with Gmail (configurable for other providers)
- **SMS Service**: Email-to-SMS gateway (Twilio support available but optional

