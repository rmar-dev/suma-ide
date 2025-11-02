```markdown
# Component Architecture: User Registration & Authentication

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Identity & Access Management (IAM)
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Executive Summary

This document defines the component architecture for the User Registration & Authentication system within the SUMA Finance platform. The system implements a secure, GDPR-compliant authentication solution with JWT-based session management, email verification, two-factor authentication, and comprehensive audit logging.

**Key Architecture Principles:**
- Security-first design following OWASP Top 10 2021
- GDPR compliance by design
- High availability (99.95% uptime target)
- Sub-200ms authentication response times
- Horizontal scalability to support 1000+ req/s

---

## 2. System Context

### 2.1 Stakeholders
- **End Users**: Individuals registering and authenticating to access financial services
- **Mobile App Users**: iOS/Android users requiring biometric authentication
- **System Administrators**: Managing security policies and monitoring suspicious activities
- **Compliance Officers**: Ensuring GDPR, PCI-DSS, SOC2, ISO 27001 adherence
- **Security Team**: Monitoring security events and responding to incidents
- **Development Team**: Maintaining and extending authentication capabilities

### 2.2 External Systems & Dependencies
- **SendGrid**: Transactional email delivery (verification, password reset, OTP)
- **Twilio**: SMS-based 2FA (alternative to email OTP)
- **Redis Cluster (ElastiCache)**: Session storage, OTP caching, rate limiting
- **PostgreSQL**: User credentials, audit logs, consent records
- **Datadog**: Security monitoring, alerting, performance metrics
- **Sentry**: Error tracking and exception monitoring
- **HaveIBeenPwned API**: Password breach detection
- **CloudFront CDN**: Static asset delivery
- **AWS WAF**: Web application firewall protection

### 2.3 Compliance Requirements
- **GDPR**: Privacy by design, explicit consent, data subject rights (access, erasure, portability)
- **PCI-DSS v4.0**: Strong cryptography, secure authentication mechanisms
- **SOC 2 Type II**: Change management, incident response, access control reviews
- **ISO 27001**: Information security management
- **OWASP Top 10 2021**: Comprehensive security controls

---

## 3. Component Breakdown

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Web App     │  │  iOS App     │  │ Android App  │          │
│  │  (React)     │  │ (React Native)│ │(React Native)│          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      API Gateway Layer                           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  AWS ALB + AWS WAF (Rate Limiting, DDoS Protection)       │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Authentication Service (Go)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   Auth      │  │  Session    │  │   2FA       │            │
│  │ Controller  │  │  Manager    │  │  Manager    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   Token     │  │   GDPR      │  │   Audit     │            │
│  │  Service    │  │  Service    │  │   Logger    │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
┌─────────────────────────┐  ┌─────────────────────────┐
│   Redis Cluster         │  │   PostgreSQL Cluster    │
│   (Session, OTP, Rate   │  │   (Users, Audit Logs,   │
│    Limiting)            │  │    Consent Records)     │
└─────────────────────────┘  └─────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    External Services                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ SendGrid │  │  Twilio  │  │ Datadog  │  │  Sentry  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Core Components

### 4.1 Authentication Controller

**Responsibility**: HTTP request handling for all authentication endpoints

**Endpoints**:
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/verify-email` - Email verification
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Token refresh
- `POST /api/v1/auth/password-reset/request` - Request password reset
- `POST /api/v1/auth/password-reset/confirm` - Confirm password reset
- `POST /api/v1/auth/2fa/enable` - Enable 2FA
- `POST /api/v1/auth/2fa/verify` - Verify 2FA code
- `POST /api/v1/auth/2fa/disable` - Disable 2FA
- `GET /api/v1/auth/session` - Get current session info
- `DELETE /api/v1/auth/session/:id` - Revoke session

**Security Controls**:
- Input validation (email format, password complexity, length limits)
- Rate limiting (5 login attempts/min/IP, 10/user/hour)
- CAPTCHA after 3 failed login attempts
- CSRF token validation
- Request/response logging with correlation IDs

**Dependencies**:
- AuthService (business logic)
- TokenService (JWT operations)
- SessionManager (session lifecycle)
- AuditLogger (security events)

**Performance Targets**:
- Response time: < 200ms (p95)
- Throughput: 1000 req/s
- Error rate: < 0.1%

---

### 4.2 User Repository

**Responsibility**: Data access layer for user credentials and profiles

**Database Schema** (PostgreSQL):
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,  -- Argon2id
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),  -- Encrypted
    account_locked BOOLEAN DEFAULT FALSE,
    locked_until TIMESTAMP,
    failed_login_attempts INT DEFAULT 0,
    last_login_at TIMESTAMP,
    last_login_ip INET,
    password_changed_at TIMESTAMP,
    password_history JSONB,  -- Last 5 hashed passwords
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP,  -- Soft delete for GDPR
    
    -- Indexes
    INDEX idx_users_email (email),
    INDEX idx_users_email_verified (email_verified),
    INDEX idx_users_account_locked (account_locked)
);

CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone_number VARCHAR(20),
    country_code VARCHAR(3),
    locale VARCHAR(10) DEFAULT 'en-US',
    timezone VARCHAR(50) DEFAULT 'UTC',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

**Operations**:
- `CreateUser(email, passwordHash, profile) -> User, error`
- `GetUserByEmail(email) -> User, error`
- `GetUserByID(id) -> User, error`
- `UpdateUser(id, updates) -> error`
- `UpdatePasswordHash(id, hash) -> error`
- `IncrementFailedAttempts(id) -> error`
- `ResetFailedAttempts(id) -> error`
- `LockAccount(id, duration) -> error`
- `UnlockAccount(id) -> error`
- `MarkEmailVerified(id) -> error`
- `SoftDeleteUser(id) -> error` (GDPR right to erasure)

**Security**:
- Prepared statements (SQL injection prevention)
- Password hashing with Argon2id (memory-hard algorithm)
- Encryption at rest (AES-256-GCM for 2FA secrets)
- Connection pooling with max 50 connections
- Query timeout: 5 seconds

---

### 4.3 Token Service

**Responsibility**: JWT token generation, validation, and lifecycle management

**Token Types**:
1. **Access Token** (JWT)
   - Expiration: 15 minutes
   - Claims: `user_id`, `email`, `roles`, `iat`, `exp`, `jti`
   - Algorithm: RS256 (RSA asymmetric signing)
   - Storage: Client-side (memory, not localStorage)

2. **Refresh Token** (Opaque)
   - Expiration: 7 days
   - Stored: Redis + PostgreSQL (for rotation detection)
   - Format: 64-byte random string (base64url encoded)
   - Rotation: New refresh token issued on each use

3. **Email Verification Token** (Signed)
   - Expiration: 24 hours
   - Algorithm: HMAC-SHA256
   - Format: `user_id|expiry|signature`

4. **Password Reset Token** (Signed)
   - Expiration: 1 hour
   - Algorithm: HMAC-SHA256
   - Single-use (invalidated after use)

**Operations**:
- `GenerateAccessToken(user) -> string, error`
- `GenerateRefreshToken(user) -> string, error`
- `ValidateAccessToken(token) -> Claims, error`
- `ValidateRefreshToken(token) -> UserID, error`
- `RotateRefreshToken(oldToken) -> newToken, error`
- `RevokeRefreshToken(token) -> error`
- `GenerateEmailVerificationToken(userID) -> string, error`
- `ValidateEmailVerificationToken(token) -> userID, error`
- `GeneratePasswordResetToken(userID) -> string, error`
- `ValidatePasswordResetToken(token) -> userID, error`

**Key Management**:
- RSA 4096-bit key pair for JWT signing
- Key rotation every 90 days
- AWS Secrets Manager for key storage
- Separate signing keys per environment

**Security Controls**:
- Refresh token reuse detection (invalidate entire token family)
- Token binding to device fingerprint
- Revocation list in Redis (with TTL matching token expiry)
- JTI claim for unique token identification

---

### 4.4 Session Manager

**Responsibility**: Session lifecycle management using Redis

**Session Structure** (Redis Hash):
```
Key: session:{user_id}:{session_id}
TTL: 8 hours (absolute timeout)
Fields:
  - user_id: UUID
  - session_id: UUID
  - refresh_token_hash: SHA256(refresh_token)
  - device_fingerprint: string
  - ip_address: string
  - user_agent: string
  - created_at: timestamp
  - last_activity: timestamp
  - mfa_verified: boolean
```

**Operations**:
- `CreateSession(userID, deviceInfo) -> Session, error`
- `GetSession(sessionID) -> Session, error`
- `UpdateLastActivity(sessionID) -> error`
- `ListUserSessions(userID) -> []Session, error`
- `RevokeSession(sessionID) -> error`
- `RevokeAllSessions(userID) -> error`
- `CleanupExpiredSessions() -> error` (background job)

**Session Policies**:
- Idle timeout: 15 minutes (sliding window)
- Absolute timeout: 8 hours
- Concurrent session limit: 5 per user
- Session pinning: Device fingerprint + IP validation

**Redis Configuration**:
- Cluster mode: 3 nodes (primary-replica)
- Persistence: RDB + AOF
- Eviction policy: allkeys-lru
- Max memory: 4GB per node

---

### 4.5 Two-Factor Authentication (2FA) Manager

**Responsibility**: Email-based OTP generation and validation

**OTP Structure** (Redis):
```
Key: otp:{user_id}:{purpose}  (purpose: login|password_reset|enable_2fa)
TTL: 5 minutes
Value: {
  "code": "123456",  (6-digit numeric)
  "attempts": 0,
  "created_at": "2025-10-29T12:00:00Z"
}
```

**Operations**:
- `GenerateOTP(userID, purpose) -> code, error`
- `ValidateOTP(userID, purpose, code) -> bool, error`
- `InvalidateOTP(userID, purpose) -> error`
- `GetRemainingAttempts(userID, purpose) -> int, error`

**Security Controls**:
- 6-digit numeric code (1 million combinations)
- 5-minute expiry
- Max 3 validation attempts per OTP
- Rate limiting: 1 OTP generation per minute per user
- Anti-enumeration: Same response for invalid user/code

**Backup Codes**:
- Generated during 2FA enablement
- 10 single-use codes (8 alphanumeric characters each)
- Stored hashed (bcrypt) in PostgreSQL
- Regeneration option available

**Email Delivery**:
- Template: "Your SUMA Finance verification code is {code}"
- Sender: noreply@sumafinance.com
- Priority: High
- Retry logic: 3 attempts with exponential backoff
- Fallback: SMS via Twilio (if configured)

---

### 4.6 GDPR Consent Service

**Responsibility**: Manage user consents and data subject rights

**Consent Schema** (PostgreSQL):
```sql
CREATE TABLE user_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    consent_type VARCHAR(50) NOT NULL,  -- terms_of_service, privacy_policy, marketing
    version VARCHAR(20) NOT NULL,
    granted BOOLEAN NOT NULL,
    granted_at TIMESTAMP,
    withdrawn_at TIMESTAMP,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    
    INDEX idx_consents_user (user_id),
    INDEX idx_consents_type (consent_type)
);

CREATE TABLE data_subject_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    request_type VARCHAR(50) NOT NULL,  -- access, erasure, portability, rectification
    status VARCHAR(20) NOT NULL,  -- pending, in_progress, completed, rejected
    submitted_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    data_export_url TEXT,  -- S3 pre-signed URL for data export
    notes TEXT,
    
    INDEX idx_dsr_user (user_id),
    INDEX idx_dsr_status (status)
);
```

**Operations**:
- `RecordConsent(userID, type, version, granted, metadata) -> error`
- `WithdrawConsent(userID, type) -> error`
- `GetUserConsents(userID) -> []Consent, error`
- `SubmitDataSubjectRequest(userID, requestType) -> Request, error`
- `ProcessAccessRequest(userID) -> dataExport, error`
- `ProcessErasureRequest(userID) -> error`
- `ProcessPortabilityRequest(userID) -> dataExport, error`

**Consent Requirements** (GDPR):
- Freely given, specific, informed, unambiguous
- Granular (separate consents for terms, privacy, marketing)
- Withdrawable at any time
- Audit trail with timestamps and IP addresses

**Data Subject Rights**:
1. **Right to Access** (Article 15): Export all user data in JSON format
2. **Right to Erasure** (Article 17): Soft delete + anonymization after 30 days
3. **Right to Portability** (Article 20): Machine-readable data export (JSON)
4. **Right to Rectification** (Article 16): Self-service profile updates

**Response Time**: 30 days (GDPR requirement)

---

### 4.7 Audit Logger

**Responsibility**: Comprehensive security event logging

**Log Schema** (PostgreSQL + Datadog):
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50) NOT NULL,
    event_category VARCHAR(20) NOT NULL,  -- authentication, authorization, data_access, configuration
    severity VARCHAR(10) NOT NULL,  -- info, warning, critical
    ip_address INET,
    user_agent TEXT,
    session_id UUID,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    action VARCHAR(50),
    result VARCHAR(20),  -- success, failure
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_event_type (event_type),
    INDEX idx_audit_created_at (created_at),
    INDEX idx_audit_severity (severity)
);
```

**Logged Events**:
- **Authentication**: login_attempt, login_success, login_failure, logout, session_created, session_revoked, password_changed, password_reset_requested, password_reset_completed
- **2FA**: 2fa_enabled, 2fa_disabled, 2fa_verified, 2fa_failed, backup_code_used
- **Email**: email_verification_sent, email_verified, verification_resent
- **Account**: account_created, account_locked, account_unlocked, account_deleted
- **GDPR**: consent_granted, consent_withdrawn, data_access_request, data_erasure_request, data_export_generated
- **Security**: suspicious_activity_detected, impossible_travel, password_breach_detected, rate_limit_exceeded

**Real-Time Alerting** (Datadog):
- Multiple failed login attempts (>3 in 5 min)
- Account lockout triggered
- Impossible travel detection (login from different countries within 1 hour)
- Password reset from new device
- Admin privilege escalation
- Bulk data export requests

**Retention Policy**:
- Hot storage (PostgreSQL): 90 days
- Cold storage (S3 Glacier): 7 years (compliance requirement)
- PII anonymization after user deletion

---

### 4.8 Password Service

**Responsibility**: Secure password hashing, validation, and breach detection

**Operations**:
- `HashPassword(plaintext) -> hash, error`
- `ValidatePassword(plaintext, hash) -> bool, error`
- `CheckPasswordStrength(password) -> score, errors`
- `CheckPasswordBreach(password) -> breached, error`
- `EnforcePasswordHistory(userID, newPassword) -> error`

**Hashing Algorithm**: Argon2id
```go
Argon2idParams {
    Memory:      64 * 1024,  // 64 MB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32
}
```

**Password Complexity Rules**:
- Minimum length: 12 characters
- Requires: uppercase, lowercase, number, special character
- Maximum length: 128 characters
- Disallowed: common passwords (top 10,000 list), user's email/name
- History enforcement: Cannot reuse last 5 passwords

**Breach Detection**:
- Integration: HaveIBeenPwned API (k-anonymity model)
- Check: On registration and password change
- Action: Warn user if password found in breach database
- Privacy: Send only first 5 chars of SHA-1 hash

---

### 4.9 Rate Limiter

**Responsibility**: Protect against brute-force and DDoS attacks

**Rate Limit Rules** (Redis Token Bucket):
```yaml
Authentication Endpoints:
  - POST /api/v1/auth/login:
      per_ip: 5 requests/minute
      per_user: 10 requests/hour
  - POST /api/v1/auth/register:
      per_ip: 3 requests/hour
  - POST /api/v1/auth/password-reset/request:
      per_ip: 5 requests/hour
      per_user: 3 requests/hour
  - POST /api/v1/auth/verify-email:
      per_user: 5 requests/hour
  - POST /api/v1/auth/2fa/verify:
      per_session: 3 requests/5 minutes

OTP Generation:
  - All OTP endpoints:
      per_user: 1 request/minute
```

**Implementation** (Redis):
```
Key: rate_limit:{endpoint}:{identifier}
TTL: Window duration
Value: Request count
Algorithm: Token bucket
```

**Response Headers**:
```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 3
X-RateLimit-Reset: 1730169600
Retry-After: 45 (if rate limited)
```

**HTTP Status**: 429 Too Many Requests

---

### 4.10 Email Service

**Responsibility**: Transactional email delivery via SendGrid

**Email Templates**:
1. **Welcome Email** (after registration)
2. **Email Verification** (with OTP or magic link)
3. **Password Reset** (with reset link)
4. **2FA OTP** (6-digit code)
5. **Login from New Device** (security notification)
6. **Password Changed** (security notification)
7. **Account Locked** (security notification)
8. **Data Export Ready** (GDPR data portability)

**Operations**:
- `SendWelcomeEmail(userID, email) -> error`
- `SendVerificationEmail(userID, email, token) -> error`
- `SendPasswordResetEmail(userID, email, token) -> error`
- `SendOTPEmail(userID, email, code) -> error`
- `SendSecurityNotification(userID, email, eventType) -> error`

**SendGrid Configuration**:
- API Key: Stored in AWS Secrets Manager
- Sender Domain: sumafinance.com (SPF, DKIM, DMARC configured)
- Template Engine: Dynamic templates with Handlebars
- Retry Logic: 3 attempts with exponential backoff (1s, 2s, 4s)
- Webhook: Delivery status tracking (delivered, bounced, opened, clicked)

**Failover**:
- Primary: SendGrid
- Secondary: AWS SES (if SendGrid fails)

**Monitoring**:
- Delivery rate: > 99%
- Bounce rate: < 2%
- Average delivery time: < 5 seconds

---

## 5. Data Flow Diagrams

### 5.1 User Registration Flow

```
┌──────┐                                                      ┌──────────────┐
│Client│                                                      │Auth Service  │
└──┬───┘                                                      └──────┬───────┘
   │                                                                  │
   │ 1. POST /api/v1/auth/register                                  │
   │    { email, password, consents }                               │
   ├──────────────────────────────────────────────────────────────>│
   │                                                                  │
   │                                                       2. Validate input
   │                                                       3. Check email exists
   │                                                       4. Hash password (Argon2id)
   │                                                       5. Create user record
   │                                                       6. Record GDPR consents
   │                                                       7. Generate verification token
   │                                                       8. Send verification email
   │                                                       9. Log audit event
   │                                                                  │
   │ 10. { user_id, message: "Verification email sent" }           │
   │<───────────────────────────────────────────────────────────────┤
   │                                                                  │
   │ 11. User checks email and clicks verification link            │
   │                                                                  │
   │ 12. GET /api/v1/auth/verify-email?token=xxx                   │
   ├──────────────────────────────────────────────────────────────>│
   │                                                                  │
   │                                                       13. Validate token
   │                                                       14. Mark email verified
   │                                                       15. Log audit event
   │                                                                  │
   │ 16. { success: true, redirect_to: "/login" }                  │
   │<───────────────────────────────────────────────────────────────┤
```

---

### 5.2 Login Flow with 2FA

```
┌──────┐                                                      ┌──────────────┐
│Client│                                                      │Auth Service  │
└──┬───┘                                                      └──────┬───────┘
   │                                                                  │
   │ 1. POST /api/v1/auth/login                                      │
   │    { email, password }                                          │
   ├──────────────────────────────────────────────────────────────>│
   │                                                                  │
   │                                                       2. Validate credentials
   │                                                       3. Check account locked
   │                                                       4. Verify password hash
   │                                                       5. Reset failed attempts
   │                                                       6. Check if 2FA enabled
   │                                                       7. Generate OTP
   │                                                       8. Send OTP email
   │                                                       9. Create temp session
   │                                                       10. Log audit event
   │                                                                  │
   │ 11. { requires_2fa: true, temp_token: "xxx" }                 │
   │<───────────────────────────────────────────────────────────────┤
   │                                                                  │
   │ 12. User receives OTP email (123456)                           │
   │                                                                  │
   │ 13. POST /api/v1/auth/2fa/verify                               │
   │     { temp_token, otp: "123456" }                              │
   ├──────────────────────────────────────────────────────────────>│
   │                                                                  │
   │                                                       14. Validate OTP
   │                                                       15. Generate access token (JWT)
   │                                                       16. Generate refresh token
   │                                                       17. Create session (Redis)
   │                                                       18. Log audit event
   │                                                                  │
   │ 19. { access_token, refresh_token, expires_in: 900 }          │
   │<───────────────────────────────────────────────────────────────┤
```

---

### 5.3 Token Refresh Flow

```
┌──────┐                                                      ┌──────────────┐
│Client│                                                      │Auth Service  │
└──┬───┘                                                      └──────┬───────┘
   │                                                                  │
   │ 1. POST /api/v1/auth/refresh                                    │
   │    { refresh_token }                                            │
   ├──────────────────────────────────────────────────────────────>│
   │                                                                  │
   │                                                       2. Validate refresh token
   │                                                       3. Check reuse detection
   │                                                       4. Get user from token
   │                                                       5. Verify session exists
   │                                                       6. Revoke old refresh token
   │                                                       7. Generate new access token
   │                                                       8. Generate new refresh token
   │                                                       9. Update session
   │                                                       10. Log audit event
   │                                                                  │
   │ 11. { access_token, refresh_token, expires_in: 900 }          │
   │<───────────────────────────────────────────────────────────────┤
```

---

### 5.4 Password Reset Flow

```
┌──────┐                                                      ┌──────────────┐
│Client│                                                      │Auth Service  │
└──┬───┘                                                      └──────┬───────┘
   │                                                                  │
   │ 1. POST /api/v1/auth/password-reset/request                    │
   │    { email }                                                    │
   ├──────────────────────────────────────────────────────────────>│
   │                                                                  │
   │                                                       2. Check rate limit
   │                                                       3. Find user by email
   │                                                       4. Generate reset token (1h expiry)
   │                                                       5. Store token hash (Redis)
   │                                                       6. Send reset email
   │                                                       7. Log audit event
   │                                                                  │
   │ 8. { message: "Reset email sent if account exists" }          │
   │    (Anti-enumeration: same response for existing/non-existing) │
   │<───────────────────────────────────────────────────────────────┤
   │                                                                  │
   │ 9. User clicks reset link in email                             │
   │                                                                  │
   │ 10. POST /api/v1/auth/password-reset/confirm                   │
   │     { token, new_password }                                    │
   ├──────────────────────────────────────────────────────────────>│
   │                                                                  │
   │                                                       11. Validate token
   │                                                       12. Check token not used
   │                                                       13. Validate password strength
   │                                                       14. Check password history
   │                                                       15. Check breach database
   │                                                       16. Hash new password
   │                                                       17. Update user password
   │                                                       18. Invalidate token
   │                                                       19. Revoke all sessions
   │                                                       20. Send security notification
   │                                                       21. Log audit event
   │                                                                  │
   │ 22. { success: true, message: "Password reset successful" }   │
   │<───────────────────────────────────────────────────────────────┤
```

---

## 6. Security Architecture

### 6.1 OWASP Top 10 2021 Mitigations

**A01: Broken Access Control**
- JWT-based RBAC with role claims
- Least privilege principle enforced
- Session timeout (15 min idle, 8h absolute)
- Middleware authorization checks on all protected endpoints

**A02: Cryptographic Failures**
- Argon2id password hashing (memory-hard)
- AES-256-GCM encryption at rest (PII, 2FA secrets)
- TLS 1.3 for all data in transit
- RSA-4096 for JWT signing
- Key rotation every 90 days

**A03: Injection**
- Prepared statements for all SQL queries
- Input validation using Pydantic/Go validators
- Email format validation (RFC 5322)
- Password complexity enforcement
- Output encoding to prevent XSS

**A04: Insecure Design**
- Threat modeling for authentication flows
- Security design reviews
- Defense in depth (WAF + rate limiting + application-level controls)

**A05: Security Misconfiguration**
- Security hardening (disable debug endpoints in production)
- Remove default credentials
- HttpOnly, Secure, SameSite=Strict cookies
- Security headers (CSP, HSTS, X-Frame-Options)
- Environment-specific configurations

**A06: Vulnerable and Outdated Components**
- Automated dependency scanning (Snyk, Dependabot)
- Quarterly vulnerability assessments
- Patch management SLA (critical: 7 days, high: 30 days)

**A07: Identification and Authentication Failures**
- Multi-factor authentication (email OTP)
- Account lockout (5 attempts, 15-min cooldown)
- Password complexity (12+ chars, mixed case, number, special)
- JWT short expiration (15 min access, 7-day refresh)
- Refresh token rotation with reuse detection
- Session fixation prevention

**A08: Software and Data Integrity Failures**
- HMAC-SHA256 signatures for email/password reset tokens
- Digital signatures for critical operations
- Integrity checks on user data

**A09: Security Logging and Monitoring Failures**
- Comprehensive audit logging (all auth events)
- Real-time alerting (failed logins, impossible travel)
- Datadog security monitoring
- Log retention (90 days hot, 7 years cold)

**A10: Server-Side Request Forgery (SSRF)**
- URL validation for email verification callbacks
- Whitelist allowed domains
- Network segmentation

---

### 6.2 Encryption Standards

**Data at Rest**:
- Algorithm: AES-256-GCM
- Key Management: AWS KMS with automatic rotation
- Encrypted Fields:
  - Password hashes (Argon2id)
  - 2FA secrets
  - Backup codes
  - Session tokens
  - Audit log PII

**Data in Transit**:
- Protocol: TLS 1.3
- Cipher Suites:
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
- Certificate: Let's Encrypt (auto-renewal)
- HSTS: max-age=31536000; includeSubDomains; preload

**Key Rotation Schedule**:
- JWT signing keys: 90 days
- Database encryption keys: 180 days
- API keys (SendGrid, Twilio): 90 days
- TLS certificates: Auto-renewal 30 days before expiry

---

### 6.3 Device Fingerprinting

**Fingerprint Components**:
- User-Agent string
- Accept-Language header
- Screen resolution
- Timezone offset
- Canvas fingerprint (web)
- WebGL fingerprint (web)
- Device model (mobile)
- OS version (mobile)

**Implementation**:
```javascript
// Client-side fingerprinting library
import FingerprintJS from '@fingerprintjs/fingerprintjs-pro';

const fpPromise = FingerprintJS.load();
const fp = await fpPromise;
const result = await fp.get();
const deviceFingerprint = result.visitorId;
```

**Use Cases**:
- Session binding (detect session hijacking)
- Login from new device alerts
- Device management (list trusted devices)
- Fraud detection

---

### 6.4 Secure Cookie Configuration

```go
http.SetCookie(w, &http.Cookie{
    Name:     "refresh_token",
    Value:    refreshToken,
    Path:     "/api/v1/auth",
    MaxAge:   604800,  // 7 days
    HttpOnly: true,    // Prevent XSS
    Secure:   true,    // HTTPS only
    SameSite: http.SameSiteStrictMode,  // CSRF protection
    Domain:   ".sumafinance.com",
})
```

---

## 7. Compliance Architecture

### 7.1 GDPR Compliance

**Privacy by Design**:
- Data minimization (collect only necessary fields)
- Purpose limitation (explicit consent per use case)
- Storage limitation (retention policies)
- Pseudonymization (user IDs instead of emails in logs)

**Lawful Basis**:
- Consent: Marketing communications
- Contract: Account creation and authentication
- Legal Obligation: Audit logs for financial regulations

**Data Subject Rights Implementation**:
```go
// Article 15: Right to Access
func (s *GDPRService) ExportUserData(userID string) (*DataExport, error) {
    return &DataExport{
        User:     s.userRepo.GetUser(userID),
        Profile:  s.profileRepo.GetProfile(userID),
        Consents: s.consentRepo.GetConsents(userID),
        Sessions: s.sessionMgr.ListSessions(userID),
        AuditLog: s.auditLogger.GetUserLogs(userID),
        Format:   "JSON",
    }
}

// Article 17: Right to Erasure
func (s *GDPRService) EraseUserData(userID string) error {
    // Soft delete + anonymization after 30 days
    if err := s.userRepo.SoftDelete(userID); err != nil {
        return err
    }
    
    // Schedule anonymization job
    return s.scheduler.Schedule(
        time.Now().Add(30*24*time.Hour),
        func() { s.anonymizeUser(userID) },
    )
}
```

**Breach Notification**:
- Detection: Datadog security alerts
- Assessment: Security team review within 24 hours
- Notification: Data Protection Officer (DPO) within 72 hours
- User Notification: If high risk to rights and freedoms

---

### 7.2 PCI-DSS Compliance

**Requirement 8: Identify and Authenticate Access**
- Unique user IDs (UUIDs)
- Strong password requirements (12+ chars, complexity)
- Multi-factor authentication (email OTP)
- Account lockout after 5 failed attempts
- Password history (last 5 passwords)
- 90-day password expiration (optional, user configurable)

**Requirement 10: Log and Monitor All Access**
- Audit trail for all authentication events
- Log user ID, timestamp, event type, success/failure
- Log review by security team (daily)
- Log retention: 7 years

---

### 7.3 SOC 2 Type II Compliance

**CC6.1: Logical Access Controls**
- Access control policies and procedures documented
- User access reviews quarterly
- Privileged access management
- Access revocation process

**CC7.2: System Monitoring**
- Continuous monitoring of security events
- Automated alerting for anomalies
- Incident response procedures
- Security metrics dashboard

---

## 8. Performance Architecture

### 8.1 Caching Strategy

**Redis Cache Layers**:

1. **Session Cache**
   - Key Pattern: `session:{user_id}:{session_id}`
   - TTL: 8 hours
   - Eviction: LRU

2. **OTP Cache**
   - Key Pattern: `otp:{user_id}:{purpose}`
   - TTL: 5 minutes
   - Eviction: TTL expiry

3. **Rate Limit Cache**
   - Key Pattern: `rate_limit:{endpoint}:{identifier}`
   - TTL: Rate limit window
   - Eviction: TTL expiry

4. **Token Revocation List**
   - Key Pattern: `revoked_token:{jti}`
   - TTL: Token expiry time
   - Eviction: TTL expiry

5. **User Profile Cache** (optional)
   - Key Pattern: `user_profile:{user_id}`
   - TTL: 15 minutes
   - Eviction: LRU
   - Invalidation: On profile update

**Cache-Aside Pattern**:
```go
func (s *SessionManager) GetSession(sessionID string) (*Session, error) {
    // Try cache first
    if session, err := s.redis.Get(ctx, "session:" + sessionID); err == nil {
        return session, nil
    }
    
    // Cache miss - fetch from database
    session, err := s.db.GetSession(sessionID)
    if err != nil {
        return nil, err
    }
    
    // Update cache
    s.redis.Set(ctx, "session:" + sessionID, session, 8*time.Hour)
    
    return session, nil
}
```

---

### 8.2 Database Optimization

**Connection Pooling**:
```go
PostgreSQLConfig {
    MaxOpenConns:    50,
    MaxIdleConns:    10,
    ConnMaxLifetime: 1 * time.Hour,
    ConnMaxIdleTime: 10 * time.Minute,
}
```

**Indexes**:
```sql
-- Critical indexes for authentication queries
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_email_verified ON users(email_verified);
CREATE INDEX idx_audit_logs_user_created ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
```

**Query Optimization**:
- Use `EXPLAIN ANALYZE` for all critical queries
- Limit result sets (pagination)
- Avoid N+1 queries (use JOINs or batch loading)
- Read replicas for audit log queries

---

### 8.3 Horizontal Scaling

**Stateless Design**:
- All session state in Redis (not in-memory)
- JWT tokens for authentication (no server-side state)
- Shared cache layer (Redis Cluster)

**Load Balancing**:
- AWS Application Load Balancer (ALB)
- Health checks: `GET /health` (200 OK if healthy)
- Sticky sessions: Not required (stateless)
- Connection draining: 30 seconds

**Auto-Scaling Policy**:
```yaml
Metrics:
  - CPU > 70% for 5 minutes → Scale up
  - CPU < 30% for 10 minutes → Scale down
  - Request latency (p95) > 500ms → Scale up

Min Instances: 2
Max Instances: 10
Target CPU: 60%
```

---

### 8.4 Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Login Response Time (p95) | < 200ms | Datadog APM |
| Registration Response Time (p95) | < 300ms | Datadog APM |
| Token Refresh Response Time (p95) | < 100ms | Datadog APM |
| Session Lookup Time (Redis) | < 10ms | Redis monitoring |
| Database Query Time (p95) | < 50ms | PostgreSQL slow query log |
| Email Delivery Time (p95) | < 5 seconds | SendGrid webhook |
| Throughput (Authentication Endpoints) | 1000 req/s | Load testing (k6) |
| Availability | 99.95% | Uptime monitoring (Pingdom) |
| Error Rate | < 0.1% | Datadog error tracking |

---

## 9. Mobile App Considerations

### 9.1 Biometric Authentication

**iOS (TouchID / FaceID)**:
```swift
import LocalAuthentication

func authenticateWithBiometrics(completion: @escaping (Bool) -> Void) {
    let context = LAContext()
    var error: NSError?
    
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Authenticate to access SUMA Finance"
        ) { success, error in
            completion(success)
        }
    }
}
```

**Android (BiometricPrompt)**:
```kotlin
import androidx.biometric.BiometricPrompt

val biometricPrompt = BiometricPrompt(this, executor,
    object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            // Success - proceed with login
        }
    })

val promptInfo = BiometricPrompt.PromptInfo.Builder()
    .setTitle("Biometric Login")
    .setSubtitle("Authenticate with your fingerprint or face")
    .setNegativeButtonText("Use password")
    .build()

biometricPrompt.authenticate(promptInfo)
```

**Security**:
- Biometric authentication only unlocks locally stored refresh token
- Refresh token stored in iOS Keychain / Android KeyStore
- Server-side validation still required (JWT)
- Fallback to password if biometric fails

---

### 9.2 Secure Token Storage

**iOS Keychain**:
```swift
import Security

func saveTokenToKeychain(token: String) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "refresh_token",
        kSecValueData as String: token.data(using: .utf8)!,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemAdd(query as CFDictionary, nil)
}
```

**Android KeyStore**:
```kotlin
import android.security.keystore.KeyGenParameterSpec

val keyStore = KeyStore.getInstance("AndroidKeyStore")
keyStore.load(null)

val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES,
    "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder(
        "refresh_token_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .build()
)
```

---

### 9.3 Certificate Pinning

**Purpose**: Prevent man-in-the-middle attacks

**Implementation (iOS)**:
```swift
import Alamofire

let evaluators = [
    "api.sumafinance.com": PinnedCertificatesTrustEvaluator()
]

let serverTrustManager = ServerTrustManager(evaluators: evaluators)
let session = Session(serverTrustManager: serverTrustManager)
```

**Implementation (Android)**:
```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.sumafinance.com</domain>
        <pin-set>
            <pin digest="SHA-256">base64-encoded-cert-hash</pin>
            <pin digest="SHA-256">backup-cert-hash</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

---

### 9.4 Root/Jailbreak Detection

**Purpose**: Detect compromised devices

**iOS Jailbreak Detection**:
```swift
func isJailbroken() -> Bool {
    let paths = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt"
    ]
    
    return paths.contains { FileManager.default.fileExists(atPath: $0) }
}
```

**Android Root Detection**:
```kotlin
fun isRooted(): Boolean {
    val paths = arrayOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su"
    )
    
    return paths.any { File(it).exists() }
}
```

**Action**: Warn user or disable sensitive features (not block entirely)

---

## 10. Testing Strategy

### 10.1 Unit Tests

**Coverage Target**: 80%+

**Test Cases (Example - Token Service)**:
```go
func TestGenerateAccessToken(t *testing.T) {
    t.Run("generates valid JWT with correct claims", func(t *testing.T) {
        user := &User{ID: "123", Email: "test@example.com", Roles: []string{"user"}}
        token, err := tokenService.GenerateAccessToken(user)
        
        assert.NoError(t, err)
        assert.NotEmpty(t, token)
        
        claims, err := tokenService.ValidateAccessToken(token)
        assert.NoError(t, err)
        assert.Equal(t, user.ID, claims.UserID)
        assert.Equal(t, user.Email, claims.Email)
    })
    
    t.Run("sets expiration to 15 minutes", func(t *testing.T) {
        token, _ := tokenService.GenerateAccessToken(user)
        claims, _ := tokenService.ValidateAccessToken(token)
        
        expectedExpiry := time.Now().Add(15 * time.Minute).Unix()
        assert.InDelta(t, expectedExpiry, claims.ExpiresAt, 5)
    })
}
```

---

### 10.2 Integration Tests

**Test Scenarios**:
1. End-to-end registration flow
2. Login with 2FA flow
3. Password reset flow
4. Token refresh flow
5. Session revocation
6. GDPR data export
7. Rate limiting enforcement
8. Account lockout after failed attempts

**Example**:
```go
func TestRegistrationFlow(t *testing.T) {
    // Setup
    db := setupTestDatabase()
    redis := setupTestRedis()
    emailSvc := &MockEmailService{}
    
    // Test
    resp := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(`{
        "email": "test@example.com",
        "password": "SecurePass123!",
        "consents": [{"type": "terms_of_service", "granted": true}]
    }`))
    
    w := httptest.NewRecorder()
    handler.ServeHTTP(w, resp)
    
    // Assertions
    assert.Equal(t, 201, w.Code)
    assert.Equal(t, 1, emailSvc.CallCount("SendVerificationEmail"))
    
    // Verify user created in database
    user, err := db.GetUserByEmail("test@example.com")
    assert.NoError(t, err)
    assert.False(t, user.EmailVerified)
}
```

---

### 10.3 Security Tests

**Automated Scans**:
- OWASP ZAP (weekly)
- Snyk dependency scanning (on every commit)
- Trivy container scanning (on every build)

**Penetration Testing**:
- Quarterly manual penetration testing
- Focus areas: authentication bypass, session hijacking, rate limit bypass

**Vulnerability Disclosure**:
- Bug bounty program (HackerOne)
- Scope: All authentication endpoints
- Rewards: $100-$5000 based on severity

---

### 10.4 Load Testing

**Tool**: k6

**Test Scenarios**:
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
    stages: [
        { duration: '2m', target: 100 },   // Ramp up to 100 users
        { duration: '5m', target: 1000 },  // Ramp up to 1000 users
        { duration: '5m', target: 1000 },  // Stay at 1000 users
        { duration: '2m', target: 0 },     // Ramp down
    ],
    thresholds: {
        http_req_duration: ['p(95)<200'],  // 95% of requests < 200ms
        http_req_failed: ['rate<0.01'],    // Error rate < 1%
    },
};

export default function () {
    let loginResp = http.post('https://api.sumafinance.com/api/v1/auth/login', JSON.stringify({
        email: 'loadtest@example.com',
        password: 'LoadTest123!',
    }), {
        headers: { 'Content-Type': 'application/json' },
    });
    
    check(loginResp, {
        'status is 200': (r) => r.status === 200,
        'has access_token': (r) => r.json('access_token') !== undefined,
    });
    
    sleep(1);
}
```

---

## 11. Monitoring & Observability

### 11.1 Metrics (Datadog)

**Golden Signals**:
- **Latency**: p50, p95, p99 response times per endpoint
- **Traffic**: Requests per second
- **Errors**: Error rate (4xx, 5xx)
- **Saturation**: CPU, memory, Redis connection pool usage

**Custom Metrics**:
- `auth.login.attempts` (counter)
- `auth.login.success` (counter)
- `auth.login.failures` (counter)
- `auth.2fa.enabled` (gauge)
- `auth.account.locked` (counter)
- `auth.token.refresh` (counter)
- `auth.session.active` (gauge)

**Dashboards**:
1. **Authentication Overview**: Login rate, success/failure ratio, active sessions
2. **Security Events**: Failed login attempts, account lockouts, suspicious activities
3. **Performance**: Response times, throughput, error rates
4. **Infrastructure**: CPU, memory, Redis metrics, database connections

---

### 11.2 Logging (Structured JSON)

**Log Format**:
```json
{
  "timestamp": "2025-10-29T12:00:00Z",
  "level": "info",
  "service": "auth-service",
  "trace_id": "abc123",
  "span_id": "def456",
  "event": "login_success",
  "user_id": "user-123",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "session_id": "session-456",
  "duration_ms": 145,
  "metadata": {
    "2fa_used": true,
    "device_fingerprint": "fp-789"
  }
}
```

**Log Aggregation**: Datadog Logs

**Log Retention**:
- Live Logs: 15 days (Datadog)
- Archive: 90 days (S3)
- Audit Logs: 7 years (S3 Glacier)

---

### 11.3 Distributed Tracing (Datadog APM)

**Instrumentation**:
```go
import "gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"

func LoginHandler(w http.ResponseWriter, r *http.Request) {
    span, ctx := tracer.StartSpanFromContext(r.Context(), "auth.login")
    defer span.Finish()
    
    // Add tags
    span.SetTag("user.email", email)
    span.SetTag("user.ip", ip)
    
    // Business logic
    user, err := authService.Authenticate(ctx, email, password)
    if err != nil {
        span.SetTag("error", true)
        span.SetTag("error.message", err.Error())
    }
}
```

**Trace Sampling**: 100% for authentication endpoints (critical path)

---

### 11.4 Alerting Rules

**Critical Alerts** (PagerDuty):
- Service down (health check failing)
- Error rate > 1% for 5 minutes
- p95 latency > 500ms for 5 minutes
- Redis connection failures
- Database connection failures

**Warning Alerts** (Slack):
- Failed login rate > 10% for 10 minutes
- Account lockout rate spike (>50 in 5 min)
- OTP delivery failures > 5% for 10 minutes
- Impossible travel detected
- Multiple failed 2FA attempts

**Security Alerts** (Slack + Email):
- Suspicious activity detected (same IP, multiple accounts)
- Password breach detected in registration
- Admin privilege escalation
- Bulk data export requests

---

## 12. Deployment Architecture

### 12.1 Infrastructure (AWS)

```
                    ┌─────────────────────┐
                    │   Route 53 (DNS)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  CloudFront (CDN)   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   AWS WAF           │
                    └──────────┬──────────┘
                               │
    ┌──────────────────────────▼──────────────────────────┐
    │  Application Load Balancer (ALB)                    │
    │  - Health checks                                    │
    │  - TLS termination                                  │
    └──────────┬────────────────────────┬─────────────────┘
               │                        │
    ┌──────────▼──────────┐  ┌─────────▼──────────┐
    │  ECS Task (AZ-1)    │  │  ECS Task (AZ-2)   │
    │  - Auth Service     │  │  - Auth Service    │
    │  - Docker Container │  │  - Docker Container│
    └──────────┬──────────┘  └─────────┬──────────┘
               │                        │
    ┌──────────▼────────────────────────▼─────────────┐
    │         ElastiCache Redis Cluster               │
    │         - Primary (AZ-1)                         │
    │         - Replica (AZ-2)                         │
    └──────────┬──────────────────────────────────────┘
               │
    ┌──────────▼────────────────────────────────────┐
    │         RDS PostgreSQL Multi-AZ               │
    │         - Primary (AZ-1)                      │
    │         - Standby (AZ-2)                      │
    └────────────────────────────────────────────────┘
```

---

### 12.2 Container Configuration (Docker)

**Dockerfile**:
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service ./cmd/server

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/auth-service .
EXPOSE 8080
CMD ["./auth-service"]
```

**ECS Task Definition**:
```json
{
  "family": "auth-service",
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [{
    "name": "auth-service",
    "image": "123456789.dkr.ecr.us-east-1.amazonaws.com/auth-service:latest",
    "portMappings": [{"containerPort": 8080}],
    "environment": [
      {"name": "ENVIRONMENT", "value": "production"},
      {"name": "LOG_LEVEL", "value": "info"}
    ],
    "secrets": [
      {"name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:..."},
      {"name": "JWT_PRIVATE_KEY", "valueFrom": "arn:aws:secretsmanager:..."}
    ],
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3
    }
  }]
}
```

---

### 12.3 CI/CD Pipeline (GitHub Actions)

```yaml
name: Deploy Auth Service

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run tests
        run: go test -v -race -coverprofile=coverage.out ./...
      - name: Check coverage
        run: |
          coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
          if (( $(echo "$coverage < 80" | bc -l) )); then
            echo "Coverage $coverage is below 80%"
            exit 1
          fi

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Snyk
        uses: snyk/actions/golang@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'CRITICAL,HIGH'

  deploy:
    needs: [test, security]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker image
        run: docker build -t auth-service .
      - name: Push to ECR
        run: |
          aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_REGISTRY
          docker tag auth-service:latest $ECR_REGISTRY/auth-service:$GITHUB_SHA
          docker push $ECR_REGISTRY/auth-service:$GITHUB_SHA
      - name: Deploy to ECS
        run: |
          aws ecs update-service --cluster production --service auth-service --force-new-deployment
```

---

### 12.4 Rollback Strategy

**Blue-Green Deployment**:
1. Deploy new version to "green" environment
2. Run smoke tests
3. Gradually shift traffic (10%, 25%, 50%, 100%)
4. Monitor error rates and latency
5. Automatic rollback if error rate > 1%

**Rollback Triggers**:
- Error rate increase > 200%
- p95 latency > 500ms
- Failed health checks
- Manual intervention

**Rollback Time**: < 5 minutes

---

## 13. Disaster Recovery

### 13.1 Backup Strategy

**Database Backups (RDS)**:
- Automated daily snapshots (retained 30 days)
- Manual snapshots before major releases
- Point-in-time recovery (PITR) enabled
- Cross-region replication to us-west-2

**Redis Backups (ElastiCache)**:
- RDB snapshots every 6 hours
- AOF persistence enabled
- Snapshot retention: 7 days

**Secrets Backup (AWS Secrets Manager)**:
- Automatic replication to us-west-2
- Version history (last 10 versions)

---

### 13.2 Recovery Procedures

**RTO (Recovery Time Objective)**: 1 hour
**RPO (Recovery Point Objective)**: 15 minutes

**Database Recovery**:
1. Identify failure (monitoring alerts)
2. Promote read replica to primary (RDS Multi-AZ failover: ~2 min)
3. Update DNS if needed
4. Verify data integrity
5. Post-incident review

**Redis Recovery**:
1. ElastiCache automatic failover to replica (~30 seconds)
2. If total failure, restore from latest snapshot (~15 min)
3. Sessions lost during downtime (users need to re-login)

**Service Recovery**:
1. ECS service auto-recovery (restarts unhealthy tasks)
2. If persistent failure, rollback to previous version
3. Scale up additional tasks for increased capacity

---

## 14. Cost Optimization

### 14.1 Infrastructure Costs (Estimated Monthly)

| Service | Configuration | Cost |
|---------|--------------|------|
| ECS Fargate | 4 tasks x 1 vCPU x 2GB | $120 |
| ElastiCache Redis | cache.r6g.large x 2 nodes | $260 |
| RDS PostgreSQL | db.r6g.large Multi-AZ | $580 |
| ALB | 1 ALB + data transfer | $40 |
| CloudFront | CDN + data transfer | $30 |
| AWS WAF | Rules + requests | $20 |
| Secrets Manager | 10 secrets | $4 |
| CloudWatch Logs | 50GB ingestion | $25 |
| Datadog | APM + Logs | $150 |
| SendGrid | 100K emails/month | $15 |
| **Total** | | **$1,244/month** |

---

### 14.2 Optimization Strategies

- Use AWS Reserved Instances for RDS (save 40%)
- Right-size ECS tasks based on actual usage
- Implement aggressive caching to reduce database queries
- Use S3 Intelligent-Tiering for audit logs
- Review and remove unused resources monthly

---

## 15. Future Enhancements

### Phase 1 (0-3 months)
- ✅ Email/password registration
- ✅ JWT authentication
- ✅ Email verification
- ✅ Password reset
- ✅ 2FA (email OTP)
- ✅ Session management
- ✅ GDPR compliance

### Phase 2 (3-6 months)
- Social login (Google, Apple OAuth 2.0)
- Biometric authentication (TouchID, FaceID)
- Device management (trusted devices)
- Password strength indicator
- Impossible travel detection

### Phase 3 (6-12 months)
- Passwordless login (magic links)
- WebAuthn/Passkey support
- Risk-based authentication
- Fraud detection (ML-based)
- SSO integration (SAML 2.0)

### Phase 4 (12+ months)
- Decentralized identity (DID)
- Zero-knowledge proofs
- Blockchain-based audit logs
- Quantum-resistant cryptography

---

## 16. Conclusion

This component architecture provides a comprehensive, secure, and scalable foundation for the SUMA Finance user registration and authentication system. The design adheres to industry best practices (OWASP Top 10), regulatory requirements (GDPR, PCI-DSS, SOC2), and achieves high performance targets (< 200ms response time, 99.95% availability, 1000 req/s throughput).

**Key Strengths**:
- Security-first design with defense in depth
- GDPR compliance by design
- Horizontal scalability to support growth
- Comprehensive monitoring and observability
- Clear disaster recovery procedures

**Next Steps**:
1. Review and approve this architecture with stakeholders
2. Begin Gate 1 (detailed technical design)
3. Set up development environment
4. Implement MVP (Phase 1 features)
5. Conduct security review and penetration testing

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Authors**: Architecture Team
**Reviewers**: Security Team, Compliance Team, Engineering Team