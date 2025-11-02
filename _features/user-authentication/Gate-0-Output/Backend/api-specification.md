---
layout: default
title: Api Specification
nav_exclude: true
---


# Backend API Specification - User Registration & Authentication

## 1. API Overview

### RESTful Design Principles
- Resource-based URLs following REST conventions
- Standard HTTP methods (POST, GET, PUT, DELETE)
- JSON content type for all requests and responses
- Stateless authentication using JWT tokens

### Authentication & Authorization
- JWT-based authentication with refresh token mechanism
- Access token expiry: 15 minutes
- Refresh token expiry: 7 days
- Role-based access control (RBAC) for protected endpoints

### Rate Limiting
- Registration: 5 requests per hour per IP
- Login: 10 requests per 15 minutes per IP
- Password reset: 3 requests per hour per email
- Token refresh: 20 requests per hour per user

### API Versioning
- URI versioning: `/api/v1/`
- Version included in all endpoint paths
- Deprecation notices in response headers

## 2. Endpoint Specifications

### 2.1 User Registration

**Endpoint**: `POST /api/v1/auth/register`

**Authentication**: None (public endpoint)

**Rate Limit**: 5 requests/hour per IP

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "acceptedTerms": true,
  "acceptedPrivacyPolicy": true
}
```

**Request Schema Validation**:
| Field | Type | Required | Validation Rules |
|-------|------|----------|------------------|
| email | string | Yes | Valid email format, unique, max 255 chars |
| password | string | Yes | Min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char |
| firstName | string | Yes | Min 1 char, max 100 chars, alphabetic only |
| lastName | string | Yes | Min 1 char, max 100 chars, alphabetic only |
| acceptedTerms | boolean | Yes | Must be true |
| acceptedPrivacyPolicy | boolean | Yes | Must be true |

**Response (201 Created)**:
```json
{
  "success": true,
  "data": {
    "userId": "uuid-v4-string",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "createdAt": "2025-11-01T10:30:00Z",
    "emailVerificationRequired": true
  },
  "message": "Registration successful. Please check your email for verification."
}
```

**Error Responses**:
- `400 Bad Request`: Invalid input data
- `409 Conflict`: Email already registered
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

### 2.2 User Login

**Endpoint**: `POST /api/v1/auth/login`

**Authentication**: None (public endpoint)

**Rate Limit**: 10 requests/15 minutes per IP

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "user": {
      "userId": "uuid-v4-string",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "roles": ["user"],
      "emailVerified": true
    }
  }
}
```

**Error Responses**:
- `400 Bad Request`: Missing credentials
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Email not verified or account suspended
- `429 Too Many Requests`: Rate limit exceeded

### 2.3 Token Refresh

**Endpoint**: `POST /api/v1/auth/refresh`

**Authentication**: Refresh token required

**Request Body**:
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer",
    "expiresIn": 900
  }
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired refresh token
- `429 Too Many Requests`: Rate limit exceeded

### 2.4 Logout

**Endpoint**: `POST /api/v1/auth/logout`

**Authentication**: Bearer token required

**Request Headers**:
```
Authorization: Bearer <access_token>
```

**Response (200 OK)**:
```json
{
  "success": true,
  "message": "Logout successful"
}
```

### 2.5 Email Verification

**Endpoint**: `POST /api/v1/auth/verify-email`

**Authentication**: None (uses verification token)

**Request Body**:
```json
{
  "token": "email-verification-token-uuid"
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "message": "Email verified successfully"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid token format
- `404 Not Found`: Token not found or expired
- `409 Conflict`: Email already verified

### 2.6 Resend Verification Email

**Endpoint**: `POST /api/v1/auth/resend-verification`

**Authentication**: None

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "message": "Verification email sent"
}
```

### 2.7 Password Reset Request

**Endpoint**: `POST /api/v1/auth/forgot-password`

**Rate Limit**: 3 requests/hour per email

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "message": "Password reset instructions sent to email"
}
```

### 2.8 Password Reset Confirmation

**Endpoint**: `POST /api/v1/auth/reset-password`

**Request Body**:
```json
{
  "token": "password-reset-token-uuid",
  "newPassword": "NewSecurePass123!"
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "message": "Password reset successful"
}
```

### 2.9 Get Current User Profile

**Endpoint**: `GET /api/v1/users/me`

**Authentication**: Bearer token required

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "userId": "uuid-v4-string",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "emailVerified": true,
    "roles": ["user"],
    "createdAt": "2025-11-01T10:30:00Z",
    "updatedAt": "2025-11-01T10:30:00Z"
  }
}
```

### 2.10 Update User Profile

**Endpoint**: `PUT /api/v1/users/me`

**Authentication**: Bearer token required

**Request Body**:
```json
{
  "firstName": "John",
  "lastName": "Smith"
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "userId": "uuid-v4-string",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Smith",
    "updatedAt": "2025-11-01T11:00:00Z"
  }
}
```

### 2.11 Change Password

**Endpoint**: `POST /api/v1/users/me/change-password`

**Authentication**: Bearer token required

**Request Body**:
```json
{
  "currentPassword": "SecurePass123!",
  "newPassword": "NewSecurePass456!"
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid password format
- `401 Unauthorized`: Current password incorrect
- `422 Unprocessable Entity`: New password same as old password

## 3. Data Models

### 3.1 User Entity

```typescript
interface User {
  userId: string;           // UUID v4
  email: string;            // Unique, indexed
  passwordHash: string;     // bcrypt hashed
  firstName: string;
  lastName: string;
  emailVerified: boolean;
  emailVerificationToken?: string;
  emailVerificationExpiry?: Date;
  passwordResetToken?: string;
  passwordResetExpiry?: Date;
  roles: string[];          // e.g., ["user", "admin"]
  accountStatus: 'active' | 'suspended' | 'deleted';
  failedLoginAttempts: number;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date;         // Soft delete
}
```

### 3.2 Refresh Token Entity

```typescript
interface RefreshToken {
  tokenId: string;          // UUID v4
  userId: string;           // Foreign key to User
  token: string;            // Hashed token, indexed
  expiresAt: Date;
  createdAt: Date;
  revokedAt?: Date;
  replacedByToken?: string; // Token rotation tracking
}
```

### 3.3 Login Audit Log

```typescript
interface LoginAuditLog {
  logId: string;
  userId: string;
  email: string;
  ipAddress: string;
  userAgent: string;
  loginStatus: 'success' | 'failed';
  failureReason?: string;
  timestamp: Date;
}
```

### 3.4 Request DTOs

**RegisterUserDTO**:
```typescript
interface RegisterUserDTO {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  acceptedTerms: boolean;
  acceptedPrivacyPolicy: boolean;
}
```

**LoginDTO**:
```typescript
interface LoginDTO {
  email: string;
  password: string;
}
```

**UpdateProfileDTO**:
```typescript
interface UpdateProfileDTO {
  firstName?: string;
  lastName?: string;
}
```

**ChangePasswordDTO**:
```typescript
interface ChangePasswordDTO {
  currentPassword: string;
  newPassword: string;
}
```

### 3.5 Response Models

**UserResponseDTO**:
```typescript
interface UserResponseDTO {
  userId: string;
  email: string;
  firstName: string;
  lastName: string;
  emailVerified: boolean;
  roles: string[];
  createdAt: string;        // ISO 8601
  updatedAt: string;
}
```

**AuthResponseDTO**:
```typescript
interface AuthResponseDTO {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;        // seconds
  user: UserResponseDTO;
}
```

## 4. Business Logic Requirements

### 4.1 User Registration
1. Validate all input fields against schema
2. Check email uniqueness in database
3. Hash password using bcrypt (cost factor: 12)
4. Generate UUID for userId
5. Generate email verification token (UUID v4)
6. Set verification token expiry (24 hours)
7. Insert user record with emailVerified=false
8. Send verification email asynchronously
9. Return success response (do not expose verification token)

### 4.2 User Login
1. Validate input format
2. Retrieve user by email
3. Check account status (must be 'active')
4. Check email verification status
5. Compare password with stored hash using bcrypt
6. If password invalid:
   - Increment failedLoginAttempts
   - If attempts >= 5, suspend account for 15 minutes
   - Return 401 error
7. If password valid:
   - Reset failedLoginAttempts to 0
   - Generate JWT access token (15 min expiry)
   - Generate refresh token (7 day expiry)
   - Store refresh token in database (hashed)
   - Update lastLoginAt timestamp
   - Log successful login
   - Return tokens and user data
8. Log all login attempts (success and failure)

### 4.3 Token Refresh
1. Validate refresh token format
2. Hash received token and lookup in database
3. Check token expiry
4. Check if token is revoked
5. Retrieve associated user
6. Generate new access token
7. Generate new refresh token (token rotation)
8. Revoke old refresh token
9. Store new refresh token
10. Return new tokens

### 4.4 Email Verification
1. Validate token format
2. Lookup token in database
3. Check token expiry (24 hours)
4. Check if email already verified
5. Update user: emailVerified=true
6. Clear verification token fields
7. Log verification event
8. Return success response

### 4.5 Password Reset Flow
1. **Request Phase**:
   - Validate email format
   - Check if user exists (don't expose this info)
   - Generate password reset token (UUID v4)
   - Set token expiry (1 hour)
   - Store token in database
   - Send password reset email
   - Return generic success message

2. **Confirmation Phase**:
   - Validate token and new password
   - Check token expiry
   - Hash new password
   - Update user password
   - Clear reset token fields
   - Revoke all existing refresh tokens
   - Log password change
   - Return success response

### 4.6 Password Validation Rules
- Minimum 8 characters
- Maximum 128 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character (!@#$%^&*)
- Not in common password list (check against top 10k)
- Not same as previous password

### 4.7 Transaction Management
All database operations involving multiple tables must be wrapped in transactions:
- User registration (user + verification token)
- Login (user update + refresh token insert + audit log)
- Token refresh (old token revoke + new token insert)
- Password reset (user update + token clear + token revocation)

## 5. Security Requirements

### 5.1 Authentication Mechanisms

**JWT Token Structure**:
```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user-uuid",
    "email": "user@example.com",
    "roles": ["user"],
    "iat": 1730459400,
    "exp": 1730460300
  }
}
```

**JWT Signing**:
- Algorithm: HMAC SHA-256 (HS256)
- Secret key: 256-bit minimum, stored in environment variable
- Token expiry: Access 15 min, Refresh 7 days
- Include user ID, email, and roles in payload
- Validate signature on every protected request

### 5.2 Password Security
- **Hashing**: bcrypt with cost factor 12
- **Storage**: Never store plaintext passwords
- **Transmission**: HTTPS only
- **Validation**: Enforce strong password policy
- **Reset Tokens**: Cryptographically secure random tokens, single-use, 1-hour expiry

### 5.3 Input Validation & Sanitization
- Validate all inputs against strict schemas
- Sanitize email inputs (lowercase, trim)
- Reject requests with invalid content types
- Implement request size limits (max 1MB)
- Use parameterized queries for all database operations

### 5.4 SQL Injection Prevention
- **Never** concatenate user input into SQL queries
- Use ORM with parameterized queries or prepared statements
- Validate and sanitize all inputs
- Apply least privilege principle to database users
- Use separate read/write database credentials where possible

Example (Go):
```go
// SECURE - Parameterized query
db.Query("SELECT * FROM users WHERE email = ?", email)

// INSECURE - DO NOT USE
db.Query("SELECT * FROM users WHERE email = '" + email + "'")
```

### 5.5 Authorization Rules

**Role-Based Access Control (RBAC)**:

| Endpoint | Public | User Role | Admin Role |
|----------|--------|-----------|------------|
| POST /auth/register | ✓ | - | - |
| POST /auth/login | ✓ | - | - |
| POST /auth/verify-email | ✓ | - | - |
| POST /auth/forgot-password | ✓ | - | - |
| POST /auth/reset-password | ✓ | - | - |
| POST /auth/refresh | - | ✓ | ✓ |
| POST /auth/logout | - | ✓ | ✓ |
| GET /users/me | - | ✓ (own) | ✓ |
| PUT /users/me | - | ✓ (own) | ✓ |
| POST /users/me/change-password | - | ✓ (own) | ✓ |

### 5.6 CORS Configuration
```json
{
  "allowedOrigins": ["https://finance.suma.com"],
  "allowedMethods": ["GET", "POST", "PUT", "DELETE"],
  "allowedHeaders": ["Content-Type", "Authorization"],
  "exposedHeaders": ["X-Request-ID"],
  "allowCredentials": true,
  "maxAge": 3600
}
```

### 5.7 Security Headers
All responses must include:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

### 5.8 Audit Logging
Log all security-relevant events:
- All login attempts (success and failure)
- Password changes and resets
- Email verification
- Account status changes
- Token generation and revocation
- Failed authorization attempts

Log format:
```json
{
  "timestamp": "2025-11-01T10:30:00Z",
  "event": "login_success",
  "userId": "uuid",
  "email": "user@example.com",
  "ipAddress": "192.168.1.1",
  "userAgent": "Mozilla/5.0..."
}
```

## 6. Performance Requirements

### 6.1 Response Time Targets
| Endpoint | Target (p95) | Maximum (p99) |
|----------|--------------|---------------|
| POST /auth/register | 200ms | 500ms |
| POST /auth/login | 150ms | 300ms |
| POST /auth/refresh | 50ms | 100ms |
| GET /users/me | 50ms | 100ms |
| PUT /users/me | 100ms | 200ms |

### 6.2 Concurrent Request Handling
- Support minimum 100 concurrent login requests
- Support minimum 500 concurrent authenticated requests
- Use connection pooling (min: 10, max: 50 connections)
- Implement circuit breakers for external services

### 6.3 Database Query Optimization

**Required Indexes**:
```sql
-- Users table
CREATE UNIQUE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token);
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token);
CREATE INDEX idx_users_status ON users(account_status);

-- Refresh tokens table
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```

**Query Optimization**:
- Use `SELECT` with specific columns instead of `SELECT *`
- Implement query result caching for user profile (1 minute TTL)
- Use database connection pooling
- Implement prepared statements for repeated queries

### 6.4 Caching Strategy

**Redis Cache Keys**:
```
user:profile:{userId}     # TTL: 60 seconds
rate_limit:login:{ip}     # TTL: 900 seconds (15 min)
rate_limit:register:{ip}  # TTL: 3600 seconds (1 hour)
rate_limit:reset:{email}  # TTL: 3600 seconds (1 hour)
account_lock:{userId}     # TTL: 900 seconds (15 min)
```

**Caching Rules**:
- Cache user profile after successful login
- Invalidate cache on profile update
- Use Redis for rate limiting counters
- Cache negative lookups (non-existent users) for 5 minutes

## 7. Dependencies

### 7.1 External APIs
- **Email Service**: SendGrid / AWS SES / Postmark
  - Send verification emails
  - Send password reset emails
  - Send account notification emails
  
### 7.2 Database Requirements
- **PostgreSQL 14+**
  - Users table
  - Refresh tokens table
  - Audit logs table
  - Transactions support (ACID compliance)

**Schema**:
```sql
CREATE TABLE users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  email_verified BOOLEAN DEFAULT FALSE,
  email_verification_token UUID,
  email_verification_expiry TIMESTAMP,
  password_reset_token UUID,
  password_reset_expiry TIMESTAMP,
  roles TEXT[] DEFAULT ARRAY['user'],
  account_status VARCHAR(20) DEFAULT 'active',
  failed_login_attempts INTEGER DEFAULT 0,
  last_login_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  deleted_at TIMESTAMP
);

CREATE TABLE refresh_tokens (
  token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  token VARCHAR(255) UNIQUE NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  revoked_at TIMESTAMP,
  replaced_by_token VARCHAR(255)
);

CREATE TABLE login_audit_logs (
  log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
  email VARCHAR(255) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  user_agent TEXT,
  login_status VARCHAR(20) NOT NULL,
  failure_reason TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 7.3 Third-Party Services
- **Redis** (caching and rate limiting)
- **Email Service Provider** (SendGrid/SES)
- **Logging Service** (Structured logging to stdout/file)

### 7.4 Message Queues / Async Processing
- **Email Queue**: Process email sending asynchronously
  - Queue: `email_verification_queue`
  - Queue: `password_reset_queue`
  - Message format: `{type, recipient, templateData, priority}`

## 8. Testing Requirements

### 8.1 Unit Test Scenarios

**Registration Tests**:
- ✓ Successful registration with valid data
- ✓ Reject duplicate email registration
- ✓ Reject weak passwords
- ✓ Reject invalid email formats
- ✓ Require terms acceptance
- ✓ Generate verification token
- ✓ Hash password correctly

**Login Tests**:
- ✓ Successful login with valid credentials
- ✓ Reject invalid email
- ✓ Reject invalid password
- ✓ Lock account after 5 failed attempts
- ✓ Reject unverified email
- ✓ Reject suspended accounts
- ✓ Generate valid JWT tokens
- ✓ Log login attempts

**Token Management Tests**:
- ✓ Refresh token successfully
- ✓ Reject expired refresh token
- ✓ Reject revoked refresh token
- ✓ Implement token rotation
- ✓ Logout revokes tokens

**Email Verification Tests**:
- ✓ Verify email with valid token
- ✓ Reject expired token
- ✓ Reject invalid token
- ✓ Handle already verified emails

**Password Reset Tests**:
- ✓ Generate reset token
- ✓ Reset password with valid token
- ✓ Reject expired reset token
- ✓ Revoke tokens after successful reset
- ✓ Don't expose user existence

### 8.2 Integration Test Requirements
- Database transaction rollback on errors
- Email service integration (mock in tests)
- Redis caching functionality
- Rate limiting enforcement
- End-to-end registration flow
- End-to-end login flow
- End-to-end password reset flow

### 8.3 API Contract Testing
- OpenAPI/Swagger specification compliance
- Request schema validation
- Response schema validation
- Error response format consistency
- HTTP status code correctness

### 8.4 Security Testing
- SQL injection attempt blocking
- XSS attempt blocking
- CSRF protection
- Rate limit enforcement
- JWT signature validation
- Password hash strength validation

### 8.5 Performance Testing
- Load test: 100 concurrent logins
- Stress test: 500 concurrent requests
- Response time validation against targets
- Database connection pool behavior
- Cache hit rate measurement

---

## Implementation Notes

This specification provides implementation-ready details for backend developers. Key implementation considerations:

1. **Security First**: All security requirements are mandatory and non-negotiable
2. **Performance Targets**: Monitor and alert on p95/p99 response times
3. **Error Handling**: Always return consistent error response format
4. **Logging**: Comprehensive audit logging for security events
5. **Testing**: Achieve minimum 80% code coverage with unit and integration tests
6. **Documentation**: Generate OpenAPI specification from this document

**Next Steps**: Proceed to Gate 1 for detailed implementation planning and technical design decisions.
