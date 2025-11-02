

# Backend API Specification - Authentication System

## 1. Backend Architecture Overview

### Architecture Pattern
- **Monolithic REST API** with modular service layer (microservices-ready architecture)
- Clean architecture with separation of concerns (handlers → services → repositories)
- Event-driven for audit logging and notifications

### Technology Stack
- **Language**: Go 1.21+
- **Framework**: Gin (HTTP router)
- **Database**: PostgreSQL 15+ with encryption at rest
- **Cache**: Redis 7+ (sessions, rate limiting, OTP storage)
- **Email**: SendGrid API
- **Authentication**: JWT (RS256)

### API Design
- RESTful API with JSON payloads
- API versioning: `/api/v1/`
- Standard HTTP status codes
- Consistent error response format

## 2. API Endpoints Specification

### Authentication Endpoints

```
POST /api/v1/auth/register
Request:
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "consent_terms": true,
  "consent_privacy": true,
  "consent_marketing": false
}
Response (201):
{
  "user_id": "uuid",
  "email": "user@example.com",
  "email_verified": false,
  "message": "Verification email sent"
}
Authentication: None
Rate Limit: 10 req/hour per IP
```

```
POST /api/v1/auth/verify-email
Request:
{
  "token": "signed_verification_token"
}
Response (200):
{
  "email_verified": true,
  "message": "Email verified successfully"
}
Authentication: None
Rate Limit: 10 req/hour per token
```

```
POST /api/v1/auth/resend-verification
Request:
{
  "email": "user@example.com"
}
Response (200):
{
  "message": "Verification email sent"
}
Authentication: None
Rate Limit: 3 req/hour per email
```

```
POST /api/v1/auth/login
Request:
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "device_id": "optional_device_fingerprint"
}
Response (200):
{
  "access_token": "jwt_token",
  "refresh_token": "refresh_token",
  "expires_in": 900,
  "mfa_required": false,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "email_verified": true
  }
}
Authentication: None
Rate Limit: 5 attempts/15min per IP
```

```
POST /api/v1/auth/login/mfa
Request:
{
  "session_token": "temporary_session_token",
  "otp_code": "123456"
}
Response (200):
{
  "access_token": "jwt_token",
  "refresh_token": "refresh_token",
  "expires_in": 900
}
Authentication: Temporary session token
Rate Limit: 3 attempts/5min per session
```

```
POST /api/v1/auth/refresh
Request:
{
  "refresh_token": "current_refresh_token"
}
Response (200):
{
  "access_token": "new_jwt_token",
  "refresh_token": "new_refresh_token",
  "expires_in": 900
}
Authentication: Valid refresh token
Rate Limit: 20 req/hour per user
```

```
POST /api/v1/auth/logout
Request:
{
  "refresh_token": "current_refresh_token"
}
Response (204): No content
Authentication: Bearer token
Rate Limit: 100 req/hour per user
```

```
POST /api/v1/auth/logout-all
Request: {}
Response (204): No content
Authentication: Bearer token
Rate Limit: 10 req/hour per user
```

```
POST /api/v1/auth/password-reset/request
Request:
{
  "email": "user@example.com"
}
Response (200):
{
  "message": "Password reset email sent"
}
Authentication: None
Rate Limit: 3 req/hour per email
```

```
POST /api/v1/auth/password-reset/verify
Request:
{
  "token": "reset_token",
  "new_password": "NewSecurePass123!"
}
Response (200):
{
  "message": "Password reset successfully"
}
Authentication: None
Rate Limit: 5 req/hour per token
```

### MFA Endpoints

```
POST /api/v1/auth/mfa/enable
Request:
{
  "method": "email" // or "totp"
}
Response (200):
{
  "mfa_enabled": true,
  "backup_codes": ["code1", "code2", ...],
  "totp_secret": "base32_secret" // if method=totp
}
Authentication: Bearer token
Rate Limit: 5 req/hour per user
```

```
POST /api/v1/auth/mfa/disable
Request:
{
  "password": "CurrentPassword123!"
}
Response (200):
{
  "mfa_enabled": false
}
Authentication: Bearer token
Rate Limit: 5 req/hour per user
```

```
POST /api/v1/auth/mfa/send-otp
Request: {}
Response (200):
{
  "message": "OTP sent to email",
  "expires_in": 300
}
Authentication: Temporary session token
Rate Limit: 3 req/5min per user
```

### User Management Endpoints

```
GET /api/v1/users/me
Request: {}
Response (200):
{
  "id": "uuid",
  "email": "user@example.com",
  "email_verified": true,
  "mfa_enabled": true,
  "created_at": "2025-01-15T10:00:00Z",
  "last_login_at": "2025-01-20T14:30:00Z"
}
Authentication: Bearer token
Rate Limit: 100 req/min per user
```

```
PATCH /api/v1/users/me/password
Request:
{
  "current_password": "OldPass123!",
  "new_password": "NewPass123!"
}
Response (200):
{
  "message": "Password updated successfully"
}
Authentication: Bearer token
Rate Limit: 5 req/hour per user
```

```
GET /api/v1/users/me/sessions
Request: {}
Response (200):
{
  "sessions": [
    {
      "id": "uuid",
      "device_id": "device_fingerprint",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "last_active": "2025-01-20T14:30:00Z",
      "is_current": true
    }
  ]
}
Authentication: Bearer token
Rate Limit: 20 req/min per user
```

```
DELETE /api/v1/users/me/sessions/:session_id
Request: {}
Response (204): No content
Authentication: Bearer token
Rate Limit: 10 req/min per user
```

```
GET /api/v1/users/me/audit-log
Request:
{
  "limit": 50,
  "offset": 0,
  "event_type": "login" // optional filter
}
Response (200):
{
  "events": [
    {
      "id": "uuid",
      "event_type": "login",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "success": true,
      "created_at": "2025-01-20T14:30:00Z"
    }
  ],
  "total": 150
}
Authentication: Bearer token
Rate Limit: 20 req/min per user
```

### GDPR Endpoints

```
GET /api/v1/users/me/consents
Request: {}
Response (200):
{
  "consents": [
    {
      "consent_type": "terms",
      "consented": true,
      "consented_at": "2025-01-15T10:00:00Z"
    },
    {
      "consent_type": "privacy",
      "consented": true,
      "consented_at": "2025-01-15T10:00:00Z"
    },
    {
      "consent_type": "marketing",
      "consented": false,
      "consented_at": null
    }
  ]
}
Authentication: Bearer token
Rate Limit: 20 req/min per user
```

```
PATCH /api/v1/users/me/consents
Request:
{
  "consent_type": "marketing",
  "consented": true
}
Response (200):
{
  "message": "Consent updated"
}
Authentication: Bearer token
Rate Limit: 10 req/hour per user
```

```
GET /api/v1/users/me/data-export
Request: {}
Response (200):
{
  "export_id": "uuid",
  "status": "processing",
  "message": "Export will be emailed within 24 hours"
}
Authentication: Bearer token
Rate Limit: 1 req/day per user
```

```
DELETE /api/v1/users/me
Request:
{
  "password": "CurrentPassword123!",
  "confirmation": "DELETE MY ACCOUNT"
}
Response (204): No content
Authentication: Bearer token
Rate Limit: 1 req/day per user
```

### Health & Monitoring

```
GET /api/v1/health
Request: {}
Response (200):
{
  "status": "healthy",
  "timestamp": "2025-01-20T14:30:00Z",
  "version": "1.0.0"
}
Authentication: None
Rate Limit: None
```

```
GET /api/v1/health/ready
Request: {}
Response (200):
{
  "database": "connected",
  "redis": "connected",
  "email_service": "operational"
}
Authentication: Internal (from load balancer)
Rate Limit: None
```

## 3. Authentication & Authorization

### JWT Structure

**Access Token (RS256, 15 min expiry):**
```json
{
  "sub": "user_uuid",
  "email": "user@example.com",
  "exp": 1642684200,
  "iat": 1642683300,
  "roles": ["user"],
  "mfa_verified": true,
  "jti": "token_uuid"
}
```

**Refresh Token (Opaque, 7 days expiry):**
- Stored as SHA256 hash in database
- Linked to device_id and IP address
- Rotated on each use with reuse detection

### Authorization Flow

1. User authenticates with email/password
2. If MFA enabled, issue temporary session token (5 min expiry)
3. User provides OTP code
4. Issue access token (JWT) and refresh token
5. Access token sent in `Authorization: Bearer <token>` header
6. When access token expires, use refresh token to get new pair
7. Refresh token rotation: old token invalidated, new token issued
8. Reuse detection: if old refresh token used again, revoke all user sessions

### RBAC Roles

| Role | Permissions |
|------|-------------|
| user | Read own data, update own profile, manage own sessions |
| admin | All user permissions + manage all users, view audit logs |
| system | Internal service-to-service calls |

### Permission Matrix

| Endpoint | user | admin | system |
|----------|------|-------|--------|
| POST /auth/register | ✓ | ✓ | ✓ |
| GET /users/me | ✓ | ✓ | - |
| GET /users/:id | - | ✓ | ✓ |
| DELETE /users/:id | - | ✓ | ✓ |
| GET /admin/audit-log | - | ✓ | ✓ |

## 4. Data Models

### User Model
```
Model: User
Fields:
- id: UUID (primary key, gen_random_uuid())
- email: VARCHAR(255) (unique, not null, indexed, AES-256-GCM encrypted)
- password_hash: VARCHAR(255) (Argon2id, not null)
- email_verified: BOOLEAN (default false)
- email_verified_at: TIMESTAMP (nullable)
- mfa_enabled: BOOLEAN (default false)
- mfa_secret: VARCHAR(255) (AES-256-GCM encrypted, nullable)
- account_locked_until: TIMESTAMP (nullable)
- failed_login_attempts: INTEGER (default 0)
- last_login_at: TIMESTAMP (nullable)
- created_at: TIMESTAMP (not null, default now())
- updated_at: TIMESTAMP (not null, default now())

Indexes:
- idx_users_email (unique btree on email)
- idx_users_created_at (btree on created_at)

Relationships:
- has_many: UserConsents (cascade delete)
- has_many: RefreshTokens (cascade delete)
- has_many: AuthEvents (set null on delete)
- has_one: PasswordResetToken
- has_one: EmailVerificationToken
```

### UserConsent Model
```
Model: UserConsent
Fields:
- id: UUID (primary key, gen_random_uuid())
- user_id: UUID (foreign key → users.id, not null, indexed)
- consent_type: VARCHAR(50) (enum: terms, privacy, marketing, not null)
- consented: BOOLEAN (not null)
- consented_at: TIMESTAMP (nullable)
- ip_address: INET (not null)
- user_agent: TEXT (not null)
- created_at: TIMESTAMP (not null, default now())

Indexes:
- idx_user_consents_user_id (btree on user_id)
- idx_user_consents_consent_type (btree on consent_type)

Relationships:
- belongs_to: User
```

### RefreshToken Model
```
Model: RefreshToken
Fields:
- id: UUID (primary key, gen_random_uuid())
- user_id: UUID (foreign key → users.id, not null, indexed)
- token_hash: VARCHAR(64) (SHA256, unique, not null, indexed)
- device_id: VARCHAR(255) (nullable)
- ip_address: INET (not null)
- user_agent: TEXT (not null)
- expires_at: TIMESTAMP (not null, indexed)
- revoked_at: TIMESTAMP (nullable)
- created_at: TIMESTAMP (not null, default now())

Indexes:
- idx_refresh_tokens_token_hash (unique btree on token_hash)
- idx_refresh_tokens_user_id (btree on user_id)
- idx_refresh_tokens_expires_at (btree on expires_at)

Relationships:
- belongs_to: User
```

### AuthEvent Model
```
Model: AuthEvent
Fields:
- id: UUID (primary key, gen_random_uuid())
- user_id: UUID (foreign key → users.id, nullable, indexed)
- event_type: VARCHAR(50) (enum: login, logout, login_failed, password_reset, mfa_enabled, mfa_disabled, password_changed, account_locked, session_revoked, not null)
- ip_address: INET (not null, indexed)
- user_agent: TEXT (not null)
- success: BOOLEAN (not null)
- metadata: JSONB (nullable)
- created_at: TIMESTAMP (not null, default now(), indexed)

Indexes:
- idx_auth_events_user_id (btree on user_id)
- idx_auth_events_event_type (btree on event_type)
- idx_auth_events_created_at (btree on created_at desc)
- idx_auth_events_ip_address (btree on ip_address)

Relationships:
- belongs_to: User (optional)
```

### PasswordResetToken Model
```
Model: PasswordResetToken
Fields:
- id: UUID (primary key, gen_random_uuid())
- user_id: UUID (foreign key → users.id, not null, indexed)
- token_hash: VARCHAR(64) (SHA256, unique, not null, indexed)
- expires_at: TIMESTAMP (not null, indexed)
- used_at: TIMESTAMP (nullable)
- created_at: TIMESTAMP (not null, default now())

Indexes:
- idx_password_reset_tokens_token_hash (unique btree on token_hash)
- idx_password_reset_tokens_user_id (btree on user_id)
- idx_password_reset_tokens_expires_at (btree on expires_at)

Relationships:
- belongs_to: User
```

### EmailVerificationToken Model
```
Model: EmailVerificationToken
Fields:
- id: UUID (primary key, gen_random_uuid())
- user_id: UUID (foreign key → users.id, not null, indexed)
- token_hash: VARCHAR(64) (SHA256, unique, not null, indexed)
- expires_at: TIMESTAMP (not null, indexed)
- verified_at: TIMESTAMP (nullable)
- created_at: TIMESTAMP (not null, default now())

Indexes:
- idx_email_verification_tokens_token_hash (unique btree on token_hash)
- idx_email_verification_tokens_user_id (btree on user_id)
- idx_email_verification_tokens_expires_at (btree on expires_at)

Relationships:
- belongs_to: User
```

## 5. Business Logic Layer

### Service Layer Architecture

```
services/
├── auth_service.go          // Registration, login, logout
├── mfa_service.go           // MFA enrollment, OTP generation/validation
├── password_service.go      // Password hashing, validation, reset
├── token_service.go         // JWT generation/validation, refresh token rotation
├── session_service.go       // Session management, device tracking
├── consent_service.go       // GDPR consent management
├── email_service.go         // Email sending (verification, OTP, notifications)
├── rate_limit_service.go    // Rate limiting logic
└── audit_service.go         // Security event logging
```

### Business Rules Implementation

**Account Lockout Policy:**
- Trigger: 5 consecutive failed login attempts
- Lockout duration: 30 minutes
- Counter reset: on successful login or after lockout expires
- Admin unlock: available via admin dashboard
- Notification: email sent to user on lockout

**Password Policy:**
- Minimum length: 12 characters
- Maximum length: 128 characters
- Complexity: must contain uppercase, lowercase, number, special character
- Password history: prevent reuse of last 5 passwords
- Compromised password check: integrate HaveIBeenPwned API
- Strength meter: real-time feedback during password entry

**Session Management:**
- Access token expiry: 15 minutes
- Refresh token expiry: 7 days
- Idle timeout: 15 minutes (refresh token must be used)
- Absolute timeout: 7 days (re-authentication required)
- Concurrent sessions: unlimited (user can revoke individually)
- Session fixation prevention: regenerate tokens on authentication

**Email Verification:**
- Token expiry: 24 hours
- Token format: HMAC-SHA256 signed, base64url encoded
- Resend limit: 3 times per hour per email
- Auto-cleanup: expired tokens deleted after 48 hours

**Password Reset:**
- Token expiry: 15 minutes
- Token format: HMAC-SHA256 signed, base64url encoded
- Request limit: 3 times per hour per email
- One-time use: token invalidated after successful reset
- Notification: email sent on successful password change

**MFA Policy:**
- OTP length: 6 digits
- OTP expiry: 5 minutes
- OTP retry limit: 3 attempts
- Backup codes: 10 single-use codes generated on MFA enrollment
- Backup code format: 8-character alphanumeric
- Fallback: email OTP if TOTP unavailable

**Business Event Triggers:**
- User registered → send verification email, log auth_event
- Email verified → update user record, log auth_event
- Login success → generate tokens, log auth_event, send notification if new device
- Login failure → increment failed attempts, log auth_event, lock account if threshold reached
- Password changed → revoke all sessions, send notification email, log auth_event
- MFA enabled → generate backup codes, log auth_event
- Session revoked → invalidate refresh token, log auth_event
- Account locked → send notification email, log auth_event
- Password reset requested → send reset email, log auth_event
- Password reset completed → send confirmation email, log auth_event

### Validation Logic

**Email Validation:**
- RFC 5322 compliant regex
- Maximum length: 255 characters
- DNS MX record check (optional, async)
- Disposable email blocking (optional)

**Password Validation:**
- Length: 12-128 characters
- Complexity: `^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{12,128}$`
- Not in common password list (10k most common passwords)
- Not matching user email or parts of email

**Token Validation:**
- JWT: signature verification (RS256), expiry check, issuer check
- Refresh token: hash comparison, expiry check, revocation check
- Password reset token: HMAC verification, expiry check, one-time use check
- Email verification token: HMAC verification, expiry check

### Error Handling Strategy

**Error Types:**
- Validation errors (400 Bad Request)
- Authentication errors (401 Unauthorized)
- Authorization errors (403 Forbidden)
- Not found errors (404 Not Found)
- Rate limit errors (429 Too Many Requests)
- Server errors (500 Internal Server Error)

**Error Response Format:**
```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "details": {},
    "trace_id": "uuid"
  }
}
```

**Error Codes:**
- `INVALID_CREDENTIALS` - login failure
- `EMAIL_NOT_VERIFIED` - unverified email
- `ACCOUNT_LOCKED` - account lockout
- `MFA_REQUIRED` - 2FA needed
- `INVALID_TOKEN` - token validation failure
- `TOKEN_EXPIRED` - token expiration
- `RATE_LIMIT_EXCEEDED` - rate limit hit
- `VALIDATION_ERROR` - input validation failure

## 6. Database Design

### Database Choice
PostgreSQL 15+ for:
- ACID compliance for financial data integrity
- Advanced indexing (btree, hash, gin for jsonb)
- Row-level security for multi-tenancy
- Native UUID support
- JSONB for flexible metadata storage
- Built-in encryption at rest (via pgcrypto)

### Schema Design

**Normalization:** 3NF (Third Normal Form)
- Separate tables for users, consents, tokens, events
- Foreign key constraints for referential integrity
- No redundant data storage

**Data Types:**
- UUIDs for primary keys (128-bit, collision-resistant)
- INET for IP addresses (efficient storage, indexing)
- TIMESTAMP WITH TIME ZONE for all timestamps
- JSONB for metadata (indexed with gin)
- VARCHAR with explicit lengths for constrained fields

**Encryption:**
- Application-level: AES-256-GCM for email, mfa_secret (encrypt before insert)
- Database-level: transparent data encryption (TDE) via PostgreSQL encryption
- Key management: AWS KMS or HashiCorp Vault

### Indexing Strategy

**Primary Indexes:**
- All primary keys (UUID): btree index
- All foreign keys: btree index

**Query-Specific Indexes:**
- `users.email`: unique btree (login lookup)
- `refresh_tokens.token_hash`: unique btree (refresh flow)
- `refresh_tokens.expires_at`: btree (cleanup job)
- `auth_events.created_at`: btree desc (audit log queries)
- `auth_events.user_id`: btree (user audit log)
- `auth_events.ip_address`: btree (IP-based analysis)

**Composite Indexes:**
- `auth_events (user_id, created_at desc)`: user audit log with time filtering
- `refresh_tokens (user_id, revoked_at)`: active sessions per user

**Partial Indexes:**
- `refresh_tokens WHERE revoked_at IS NULL`: active tokens only
- `password_reset_tokens WHERE used_at IS NULL`: unused tokens only

### Migration Approach

**Tool:** golang-migrate or Goose

**Versioning:** Sequential version numbers (001_initial_schema.up.sql)

**Process:**
1. Development: migrations tested locally
2. Staging: migrations applied with dry-run first
3. Production: migrations applied during maintenance window
4. Rollback: down migrations for every up migration

**Safety:**
- Idempotent migrations (IF NOT EXISTS, IF EXISTS)
- No data loss migrations (rename → copy → cleanup)
- Index creation: CONCURRENTLY to avoid table locks

### Backup and Recovery

**Backup Strategy:**
- Full backup: daily at 2 AM UTC (pg_dump)
- Incremental backup: WAL archiving (continuous)
- Retention: 30 days full backups, 90 days WAL archives

**Recovery Point Objective (RPO):** 5 minutes (WAL archiving interval)

**Recovery Time Objective (RTO):** 1 hour (restore from backup + WAL replay)

**Testing:** Monthly recovery drills on staging environment

## 7. Security Implementation

### OWASP Top 10 Protections

**A01 - Broken Access Control:**
- JWT-based authentication with role claims
- Middleware validates JWT on every protected endpoint
- RBAC enforced at service layer
- User can only access own resources (user_id validation)
- Admin endpoints require admin role

**A02 - Cryptographic Failures:**
- Password hashing: Argon2id (memory=64MB, iterations=3, parallelism=4)
- Sensitive data encryption: AES-256-GCM
- TLS 1.3 for all API traffic
- JWT signing: RS256 with 2048-bit RSA keys
- Secure random token generation: crypto/rand (32 bytes)

**A03 - Injection:**
- Parameterized queries for all database interactions (sqlx)
- Input validation with go-playground/validator
- Email validation with regex
- Password sanitization (remove control characters)
- No dynamic SQL construction

**A03 - XSS:**
- Content-Type: application/json (no HTML responses)
- Content-Security-Policy header: default-src 'none'
- X-Content-Type-Options: nosniff
- Output encoding in email templates

**A03 - CSRF:**
- SameSite=Strict cookie attribute for refresh tokens (if using cookies)
- Double-submit cookie pattern for state-changing operations
- Stateless JWT (no CSRF vulnerability)

**A04 - Insecure Design:**
- Threat model: credential theft, session hijacking, brute force
- Security design review: authentication flows peer-reviewed
- Principle of least privilege: default deny, explicit allow

**A05 - Security Misconfiguration:**
- No debug endpoints in production (build tags)
- Default credentials removed (no test accounts in production)
- Security headers:
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
- Secrets in AWS Secrets Manager or Vault (not environment variables)

**A06 - Vulnerable Components:**
- Dependency scanning: Snyk or Dependabot (weekly scans)
- Automated PR creation for security updates
- Security patch policy: critical patches within 7 days, high within 30 days
- Minimal dependencies (audit go.mod regularly)

**A07 - Authentication Failures:**
- Short JWT expiry: 15 minutes
- Refresh token rotation with reuse detection
- Account lockout: 5 failed attempts → 30 min lockout
- Password reset token: 15 min expiry, one-time use
- MFA support: email OTP (6 digits, 5 min expiry)
- No verbose error messages (don't reveal if email exists)

**A08 - Software and Data Integrity:**
- HMAC-SHA256 for all tokens (verification, password reset)
- Digital signatures for audit logs (append-only)
- Code signing for deployments
- Immutable audit trail (no updates to auth_events)

**A09 - Security Logging:**
- Log all authentication events: login, logout, failed attempts, password changes, MFA events
- Log format: JSON with timestamp, user_id, event_type, ip_address, user_agent, success
- No sensitive data in logs (no passwords, tokens)
- SIEM integration: forward logs to Datadog or Splunk
- Alerting:
  - Failed login rate > 10/min for single IP → potential brute force
  - Account lockouts > 5/hour → credential stuffing attack
  - MFA bypass attempts

**A10 - SSRF:**
- Email verification links: validate redirect URLs against whitelist
- No user-controlled URLs in server-side requests
- Disable HTTP redirects in email service client

### Input Validation and Sanitization

**Validation Library:** go-playground/validator

**Validation Rules:**
```go
type RegisterRequest struct {
    Email    string `json:"email" validate:"required,email,max=255"`
    Password string `json:"password" validate:"required,min=12,max=128,password_complexity"`
}
```

**Custom Validators:**
- `password_complexity`: regex validation + common password check
- `no_sql_keywords`: prevent SQL injection in free-text fields

### Rate Limiting

**Implementation:** Redis-based sliding window

**Limits:**
- Login: 5 attempts per 15 min per IP, 10 attempts per hour per email
- Registration: 10 attempts per hour per IP
- Password reset: 3 requests per hour per email
- Email verification resend: 3 requests per hour per email
- MFA OTP send: 3 requests per 5 min per user
- Token refresh: 20 requests per hour per user

**Response:** HTTP 429 with `Retry-After` header

## 8. Compliance Requirements

### GDPR Compliance

**Privacy by Design:**
- Data minimization: collect only required fields (email, password)
- Purpose limitation: explicit consent for terms, privacy, marketing
- Storage limitation: data retention policy (inactive accounts deleted after 3 years)

**Consent Management:**
- Granular consent: separate checkboxes for terms, privacy, marketing
- Consent audit trail: ip_address, user_agent, timestamp
- Consent withdrawal: user can revoke consent via UI
- Re-consent: prompt users if privacy policy updated

**Data Subject Rights:**
- Right to access: GET /users/me/data-export (JSON with all user data)
- Right to erasure: DELETE /users/me (hard delete after 30-day grace period)
- Right to portability: export in JSON format
- Right to rectification: PATCH /users/me

**Data Retention:**
- Active accounts: indefinite
- Inactive accounts (no login 3 years): deleted automatically
- Audit logs: 7 years retention (compliance requirement)
- Deleted account audit logs: anonymized (user_id set to NULL)

**Breach Notification:**
- Detection: automated alerts on suspicious login patterns
- Assessment: incident response team evaluates impact within 12 hours
- Notification: DPA notified within 72 hours if high risk
- User notification: email to affected users within 72 hours

**Privacy Policy:**
- Clear disclosure: what data collected, why, how long stored
- User rights: how to access, delete, export data
- Contact: DPO email address
- Updates: users notified via email on material changes

### SOC 2 Compliance

**CC6.1 - Logical Access:**
- RBAC with least privilege
- MFA for sensitive operations
- Session timeout enforcement
- Access reviews quarterly

**CC6.2 - System Operations:**
- Change management: all auth changes require approval + review
- Incident response plan: playbook for credential compromise
- Disaster recovery: RTO 1 hour, RPO 5 minutes

**CC6.3 - Monitoring:**
- Real-time alerts on failed logins, account lockouts
- Audit log review: weekly by security team
- Anomaly detection: ML-based detection of unusual login patterns

**CC7.2 - System Monitoring:**
- Security event logging: all authentication events logged
- Log retention: 7 years
- SIEM integration: Datadog or Splunk

### PCI-DSS (if payment processing)

**Requirement 8 - Identify Users:**
- Unique user ID (UUID)
- Strong password policy (12+ chars, complexity)
- MFA for all users

**Requirement 8.2.1:**
- Password hashing: Argon2id (stronger than bcrypt)
- No reversible encryption for passwords

**Requirement 10 - Track Access:**
- Audit trail: all authentication events logged
- Log immutability: append-only auth_events table

**Requirement 12.10:**
- Incident response plan for credential compromise
- Quarterly security reviews

### ISO 27001

**A.9.2 - User Access Management:**
- User registration and deregistration process
- Access review quarterly

**A.9.4 - Authentication:**
- MFA for sensitive operations
- Password policy enforcement
- Session management

**A.12.4 - Logging:**
- Security event logging
- Log protection (append-only)
- Log review process

## 9. Performance & Scalability

### Performance Targets

**Response Times:**
- p50: < 100ms (login, registration)
- p95: < 200ms
- p99: < 500ms
- Password hashing: < 500ms per hash (tuned Argon2id)

**Throughput:**
- 500 concurrent authentications/second
- 1000 registration requests/hour sustained
- 10,000 token refresh requests/minute

**Availability:**
- 99.95% uptime (22 minutes downtime per month)
- Multi-AZ deployment for high availability

### Caching Strategy

**Redis Usage:**

**Session Store:**
- Key: `session:{token_hash}`
- Value: JSON with user_id, device_id, expires_at
- TTL: 7 days (refresh token expiry)

**Rate Limiting:**
- Key: `ratelimit:login:{ip}`, `ratelimit:register:{ip}`
- Value: counter
- TTL: sliding window (15 min, 1 hour)

**OTP Storage:**
- Key: `otp:{user_id}`
- Value: hashed OTP + attempts count
- TTL: 5 minutes

**JWT Blacklist (optional):**
- Key: `revoked:{jti}`
- Value: 1
- TTL: 15 minutes (access token expiry)

**Cache Invalidation:**
- Logout: delete session key
- Password change: delete all session keys for user
- Account deletion: delete all session keys for user

### Load Balancing

**Strategy:** Round-robin across multiple API instances

**Health Checks:**
- Endpoint: GET /api/v1/health/ready
- Interval: 10 seconds
- Timeout: 2 seconds
- Unhealthy threshold: 3 consecutive failures

**Sticky Sessions:** Not required (stateless JWT)

### Horizontal Scaling

**API Layer:**
- Stateless design (no in-memory sessions)
- Auto-scaling: CPU > 70% → add instance
- Min instances: 2 (high availability)
- Max instances: 10

**Database Layer:**
- Read replicas: 2 replicas for read-heavy queries (audit logs)
- Connection pooling: max 100 connections per instance
- PgBouncer for connection pooling

**Redis Layer:**
- Redis Cluster: 3 master nodes, 3 replica nodes
- High availability: automatic failover

### Query Optimization

**N+1 Query Prevention:**
- Eager loading: fetch user consents with single query
- Batch queries: load multiple users in single query

**Indexing:**
- Covered indexes: include all columns in SELECT for index-only scans
- Partial indexes: index only active sessions, unused tokens

**Connection Pooling:**
- Pool size: 25 connections per API instance
- Idle timeout: 5 minutes
- Max lifetime: 30 minutes

### Data Growth Projections

**3 Months:**
- Users: 10,000
- Auth events: 500,000 (50 events per user)
- Database size: 500 MB

**1 Year:**
- Users: 100,000
- Auth events: 10,000,000 (100 events per user)
- Database size: 5 GB

**3 Years:**
- Users: 1,000,000
- Auth events: 200,000,000 (200 events per user)
- Database size: 100 GB

**Scaling Plan:**
- Partition auth_events table by created_at (monthly partitions)
- Archive old partitions to S3 (after 1 year)
- Compression: enable PostgreSQL table compression for archived partitions

### Disaster Recovery

**RPO (Recovery Point Objective):** 5 minutes
- WAL archiving to S3 every 5 minutes

**RTO (Recovery Time Objective):** 1 hour
- Restore from latest backup + replay WAL archives

**Backup Strategy:**
- Full backup: daily pg_dump to S3
- Incremental: WAL archiving continuous
- Retention: 30 days full backups, 90 days WAL

**Multi-Region:**
- Primary region: us-east-1
- DR region: us-west-2
- Database replication: async streaming replication
- Failover: manual (tested quarterly)

## 10. Monitoring & Logging

### Logging Framework

**Library:** zerolog (structured JSON logging)

**Log Format:**
```json
{
  "level": "info",
  "time": "2025-01-20T14:30:00Z",
  "service": "auth-api",
  "trace_id": "uuid",
  "user_id": "uuid",
  "event_type": "login",
  "ip_address": "192.168.1.1",
  "user_agent": "Mozilla/5.0...",
  "success": true,
  "duration_ms": 150,
  "message": "User logged in successfully"
}
```

**Log Levels:**
- DEBUG: detailed request/response (development only)
- INFO: successful operations (login, registration)
- WARN: rate limit exceeded, suspicious activity
- ERROR: failed operations, exceptions
- FATAL: service crashes

**Log Destinations:**
- Stdout: JSON logs (captured by Docker)
- Datadog: via log forwarder (production)
- Sentry: errors and exceptions

### Metrics to Track

**Application Metrics:**
- `auth.login.success` (counter)
- `auth.login.failure` (counter)
- `auth.registration.success` (counter)
- `auth.password_reset.requests` (counter)
- `auth.mfa.enabled` (counter)
- `auth.session.revoked` (counter)

**Performance Metrics:**
- `http.request.duration` (histogram, p50/p95/p99)
- `http.request.size` (histogram)
- `http.response.size` (histogram)
- `db.query.duration` (histogram)
- `password.hash.duration` (histogram)

**Infrastructure Metrics:**
- `cpu.usage` (gauge)
- `memory.usage` (gauge)
- `db.connections.active` (gauge)
- `redis.connections.active` (gauge)
- `http.requests.rate` (rate)

**Business Metrics:**
- `users.total` (gauge)
- `users.registered.daily` (counter)
- `users.mfa_enabled` (gauge)
- `sessions.active` (gauge)

### Health Check Endpoints

**Liveness Probe:** GET /api/v1/health
- Returns 200 if service is running
- No external dependencies checked

**Readiness Probe:** GET /api/v1/health/ready
- Returns 200 if service ready to accept traffic
- Checks:
  - Database connection: SELECT 1
  - Redis connection: PING
  - Email service: API health check

### Alerting Thresholds

**Critical Alerts (PagerDuty):**
- Error rate > 5% for 5 minutes → on-call engineer paged
- p95 response time > 1s for 5 minutes → on-call engineer paged
- Database connections > 90% for 2 minutes → on-call engineer paged
- Service down (health check fails 3 times) → on-call engineer paged

**High Priority Alerts (Slack):**
- Failed login rate > 10/min for single IP → potential brute force
- Account lockouts > 5/hour → credential stuffing attack
- Password reset requests > 20/hour → potential abuse
- CPU usage > 80% for 10 minutes → scale up needed

**Medium Priority Alerts (Email):**
- Error rate > 2% for 15 minutes
- p99 response time > 2s for 15 minutes
- Failed authentication attempts > 100/hour per IP
- MFA bypass attempts detected

**Low Priority Alerts (Dashboard):**
- Memory usage > 70%
- Disk usage > 80%
- Certificate expiring in 30 days

### SLA Monitoring

**Uptime Target:** 99.95%
- Allowed downtime: 22 minutes per month
- Monitoring: synthetic checks every 60 seconds (Pingdom, UptimeRobot)

**Performance SLA:**
- p95 response time < 200ms for 95% of time windows (5-min windows)
- Login success rate > 99.9%

**Alerting:**
- Downtime > 5 minutes → critical alert
- SLA breach imminent (95% of monthly budget used) → high priority alert

## 11. Testing Strategy

### Unit Testing

**Framework:** Go testing package + testify

**Coverage Target:** > 80%

**Test Cases:**

**Password Service:**
- Hash password with Argon2id
- Verify password hash
- Validate password complexity
- Check password against common password list
- Check password history (no reuse)

**JWT Service:**
- Generate access token
- Verify access token signature
- Check token expiration
- Validate token claims
- Handle malformed tokens

**Rate Limiter:**
- Increment counter on request
- Block request when limit exceeded
- Reset counter after time window
- Sliding window calculation

**Input Validation:**
- Email validation (valid, invalid, max length)
- Password validation (length, complexity)
- Request body validation (missing fields, invalid types)

### Integration Testing

**Framework:** Go testing + dockertest (test containers)

**Test Cases:**

**Registration Flow:**
1. POST /auth/register with valid data → 201
2. Check user created in database
3. Check verification email sent
4. POST /auth/verify-email with token → 200
5. Check user.email_verified = true

**Login Flow:**
1. POST /auth/login with valid credentials → 200
2. Check access token and refresh token returned
3. Check refresh token stored in database
4. Check auth_event logged

**Password Reset Flow:**
1. POST /auth/password-reset/request → 200
2. Check reset email sent
3. Check reset token stored in database
4. POST /auth/password-reset/verify with token → 200
5. Check password updated
6. Check all sessions revoked

**MFA Flow:**
1. POST /auth/mfa/enable → 200
2. Check mfa_enabled = true
3. Check backup codes returned
4. POST /auth/login → 200 with mfa_required=true
5. POST /auth/mfa/send-otp → 200
6. POST /auth/login/mfa with OTP → 200 with tokens

**Session Management:**
1. POST /auth/login → get tokens
2. POST /auth/refresh with refresh token → new tokens
3. Check old refresh token revoked
4. POST /auth/refresh with old token → 401 (reuse detection)
5. Check all user sessions revoked

### API Contract Testing

**Framework:** Pact or Dredd

**Test Cases:**
- Verify request/response schemas match OpenAPI spec
- Check required fields present
- Validate data types
- Test error response format

### Performance Testing

**Framework:** k6 or Gatling

**Test Scenarios:**

**Load Test:**
- 500 concurrent users
- 10-minute duration
- Mix: 60% login, 30% refresh, 10% registration
- Success criteria: p95 < 200ms, error rate < 1%

**Spike Test:**
- Ramp from 0 to 1000 users in 1 minute
- Hold for 5 minutes
- Ramp down to 0 in 1 minute
- Success criteria: no errors, auto-scaling works

**Soak Test:**
- 200 concurrent users
- 4-hour duration
- Success criteria: no memory leaks, no degradation

**Stress Test:**
- Ramp up until system breaks
- Identify breaking point
- Success criteria: graceful degradation, no data loss

### Security Testing

**SAST (Static Analysis):**
- Tool: gosec
- Run on every PR
- Check for: hardcoded secrets, SQL injection, unsafe crypto

**DAST (Dynamic Analysis):**
- Tool: OWASP ZAP
- Run weekly on staging
- Check for: XSS, SQLi, auth bypass

**Dependency Scanning:**
- Tool: Snyk or Dependabot
- Run weekly
- Auto-create PRs for security updates

**Penetration Testing:**
- Frequency: quarterly
- Scope: authentication flows, session management, MFA
- Report: delivered within 2 weeks

**Security Test Cases:**

**SQL Injection:**
- Test email field: `admin' OR '1'='1`
- Test password field: `' OR '1'='1' --`
- Verify parameterized queries prevent injection

**XSS:**
- Test registration with `<script>alert('XSS')</script>`
- Verify output encoding in email templates

**CSRF:**
- Attempt POST /auth/logout without CSRF token
- Verify 403 or token validation

**Brute Force:**
- Attempt 10 failed logins in 1 minute
- Verify rate limiting kicks in
- Verify account lockout after 5 attempts

**Session Hijacking:**
- Steal access token
- Use from different IP
- Verify works (stateless JWT)
- Implement device fingerprinting for additional security (optional)

**Token Manipulation:**
- Modify JWT claims (role: admin)
- Verify signature validation fails
- Modify JWT expiry
- Verify expiry validation fails

**Timing Attacks:**
- Measure login response time for valid vs invalid email
- Verify constant-time comparison

## 12. External Integrations

### Email Service (SendGrid)

**Purpose:** Transactional emails (verification, password reset, OTP, notifications)

**SLA Requirements:**
- Delivery time: < 30 seconds
- Delivery rate: > 99%
- Uptime: 99.95%

**Fallback Provider:** AWS SES (automatic failover if SendGrid fails)

**Email Templates:**

**Verification Email:**
- Subject: "Verify your email address"
- CTA: "Verify Email" button with token link
- Expiry: "Link expires in 24 hours"

**Password Reset Email:**
- Subject: "Reset your password"
- CTA: "Reset Password" button with token link
- Expiry: "Link expires in 15 minutes"
- Security note: "Didn't request this? Ignore this email"

**MFA OTP Email:**
- Subject: "Your verification code"
- Body: "Your code is: 123456"
- Expiry: "Expires in 5 minutes"

**Login Notification:**
- Subject: "New login detected"
- Body: Device, IP, location, timestamp
- CTA: "Wasn't you? Secure your account"

**Account Locked:**
- Subject: "Your account has been locked"
- Body: "Too many failed login attempts"
- CTA: "Unlock your account"

**Password Changed:**
- Subject: "Your password was changed"
- Body: "Password changed at [timestamp]"
- CTA: "Wasn't you? Contact support immediately"

**API Configuration:**
```go
sendgrid.API_KEY = os.Getenv("SENDGRID_API_KEY")
sendgrid.FROM_EMAIL = "noreply@example.com"
sendgrid.FROM_NAME = "Finance App"
```

**Error Handling:**
- Retry: 3 attempts with exponential backoff (1s, 2s, 4s)
- Fallback: switch to AWS SES after 3 failed attempts
- Logging: log all email events (sent, delivered, bounced, failed)

### Banking API (Tink/Plaid)

**Purpose:** Bank account aggregation, transaction sync

**Authentication Flow:**
1. User initiates bank connection
2. Redirect to Tink OAuth flow
3. User authorizes access
4. Receive authorization code
5. Exchange code for access token
6. Store access token (encrypted)

**Data Sync Frequency:**
- Transactions: daily at 3 AM
- Balances: every 6 hours
- Account info: weekly

**Error Handling:**
- Token expired: prompt user to re-authenticate
- API rate limit: exponential backoff (1s, 2s, 4s, 8s)
- Bank connection lost: notify user via email

**API Rate Limits:**
- Tink: 100 requests/min
- Plaid: 200 requests/min

**Webhook Handlers:**
- `transactions.added`: fetch new transactions
- `accounts.removed`: mark account as disconnected
- `item.error`: notify user of connection issue

### SMS Provider (Twilio)

**Purpose:** SMS-based 2FA (alternative to email OTP)

**Configuration:**
```go
twilio.ACCOUNT_SID = os.Getenv("TWILIO_ACCOUNT_SID")
twilio.AUTH_TOKEN = os.Getenv("TWILIO_AUTH_TOKEN")
twilio.FROM_NUMBER = "+1234567890"
```

**Message Template:**
- "Your verification code is: 123456. Expires in 5 minutes."

**Rate Limits:**
- 3 SMS per 5 minutes per user
- 100 SMS per hour per account

**Error Handling:**
- Retry: 2 attempts
- Fallback: switch to email OTP if SMS fails

### Analytics/Monitoring (Datadog)

**Purpose:** Application monitoring, log aggregation, alerting

**Metrics Sent:**
- Application metrics (login success/failure, registrations)
- Performance metrics (response time, throughput)
- Infrastructure metrics (CPU, memory, DB connections)

**Logs Forwarded:**
- All application logs (JSON format)
- Filter: exclude sensitive data (passwords, tokens)

**Dashboards:**
- Authentication Overview: login success rate, failed attempts, MFA usage
- Performance: p50/p95/p99 response times, throughput
- Infrastructure: CPU, memory, DB connections, Redis connections

**SLA Monitoring:**
- Synthetic checks: login flow every 60 seconds
- Alert on failure: critical alert if 3 consecutive failures

### HaveIBeenPwned API

**Purpose:** Check passwords against breach database

**API Endpoint:** GET https://api.pwnedpasswords.com/range/{hash_prefix}

**Implementation:**
- Hash password with SHA-1
- Send first 5 characters of hash
- Check if remaining hash in response
- If found, password is compromised

**Rate Limits:** No official limit (use respectfully)

**Error Handling:**
- Timeout: 2 seconds
- Fallback: allow registration if API unavailable (log for review)

### Sentry

**Purpose:** Error tracking and monitoring

**Configuration:**
```go
sentry.Init(sentry.ClientOptions{
    Dsn: os.Getenv("SENTRY_DSN"),
    Environment: "production",
})
```

**Events Captured:**
- All errors and exceptions
- User feedback (optional)
- Performance traces (sample rate 10%)

**PII Filtering:**
- Exclude passwords, tokens from error messages
- Use before_send hook to scrub sensitive data

## 13. Deployment & DevOps

### Containerization

**Dockerfile:**
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o auth-api ./cmd/api

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/auth-api /auth-api
EXPOSE 8080
CMD ["/auth-api"]
```

**Image Size:** < 20 MB (multi-stage build)

**Security:**
- Non-root user
- No shell (distroless alternative)
- Minimal dependencies

### Orchestration

**Platform:** AWS ECS (Fargate)

**Task Definition:**
- CPU: 512 (0.5 vCPU)
- Memory: 1024 MB
- Desired count: 2 (minimum)
- Max count: 10 (auto-scaling)

**Service Discovery:** AWS Cloud Map

**Load Balancer:** Application Load Balancer (ALB)
- HTTPS listener (port 443)
- Target group: port 8080
- Health check: /api/v1/health/ready

### CI/CD Pipeline

**Platform:** GitHub Actions

**Workflow:**

**On Pull Request:**
1. Lint code (golangci-lint)
2. Run unit tests
3. Run integration tests (docker-compose)
4. Security scan (gosec)
5. Build Docker image (no push)

**On Merge to Main:**
1. Run full test suite
2. Build Docker image
3. Tag image: `auth-api:latest`, `auth-api:commit-sha`
4. Push to ECR
5. Deploy to staging
6. Run smoke tests on staging
7. Manual approval required for production
8. Deploy to production
9. Run smoke tests on production

**Rollback:**
- Automated rollback if health checks fail 3 times
- Manual rollback via GitHub Actions workflow

### Environment Configuration

**Configuration Management:** AWS Systems Manager Parameter Store

**Secrets Management:** AWS Secrets Manager

**Environment Variables:**
```
ENVIRONMENT=production
LOG_LEVEL=INFO
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
JWT_PRIVATE_KEY_PATH=/secrets/jwt_private_key.pem
JWT_PUBLIC_KEY_PATH=/secrets/jwt_public_key.pem
SENDGRID_API_KEY=/secrets/sendgrid_api_key
TWILIO_AUTH_TOKEN=/secrets/twilio_auth_token
```

**Secret Rotation:**
- Database password: 90 days
- API keys: 180 days
- JWT signing keys: 1 year

### Deployment Strategies

**Blue/Green Deployment:**
- Deploy new version (green) alongside old (blue)
- Run health checks on green
- Switch traffic to green
- Keep blue running for 1 hour (rollback window)
- Terminate blue if no issues

**Canary Deployment:**
- Route 10% traffic to new version
- Monitor error rate, response time
- If metrics good, increase to 50%
- If metrics good, increase to 100%
- Rollback if error rate > 2%
