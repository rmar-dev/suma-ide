# MICROSERVICES DESIGN

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Services
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

The SUMA Finance authentication system follows a microservices architecture designed for high security, scalability, and compliance with financial industry standards (GDPR, PCI-DSS, SOC 2). The architecture consists of five core microservices: **Authentication Service** (credential management and JWT issuance), **User Service** (user profile and account management), **Session Service** (token lifecycle and session tracking), **Notification Service** (email/SMS delivery for verification and alerts), and **Audit Service** (comprehensive security event logging and compliance reporting).

This design emphasizes defense-in-depth security, with each service implementing OWASP Top 10 protections, encryption at rest and in transit, and role-based access control. The system uses JWT-based authentication with short-lived access tokens (15 minutes) and long-lived refresh tokens (7 days) with rotation. Two-factor authentication via email OTP adds an additional security layer. All services communicate asynchronously through RabbitMQ for event-driven workflows (email verification, password reset, security alerts) while synchronous REST APIs handle real-time authentication flows.

The architecture supports horizontal scaling with stateless services, Redis-backed caching for session data, and PostgreSQL for persistent storage. Each service can be independently deployed using Docker containers orchestrated by Kubernetes, with comprehensive monitoring via Prometheus/Grafana and distributed tracing via Jaeger. The design accommodates future enhancements including social login (OAuth 2.0), biometric authentication, and passwordless login while maintaining backward compatibility.

## Architecture Philosophy

### Design Principles
- **Single Responsibility**: Each service owns one business capability (authentication, user management, session lifecycle, notifications, audit)
- **Loose Coupling**: Services communicate through well-defined REST APIs and asynchronous events, allowing independent evolution
- **High Cohesion**: Related functionality grouped within service boundaries (e.g., all JWT operations in Auth Service)
- **Autonomous**: Services can be developed, deployed, and scaled independently with separate databases
- **Resilient**: Circuit breakers, retries, and fallback mechanisms prevent cascading failures

### Domain-Driven Design (DDD)
**Bounded Contexts**:
- **Identity & Access Context**: Authentication Service, Session Service (credential validation, token issuance, session lifecycle)
- **User Management Context**: User Service (user profiles, account status, GDPR consent)
- **Communication Context**: Notification Service (email/SMS delivery, template management)
- **Compliance & Audit Context**: Audit Service (security events, compliance reporting)

**Ubiquitous Language**:
- **User**: Individual with account in SUMA Finance system
- **Credential**: Email/password combination for authentication
- **Access Token**: Short-lived JWT (15 min) for API authorization
- **Refresh Token**: Long-lived token (7 days) for obtaining new access tokens
- **OTP**: One-Time Password (6-digit code, 5-min expiry) for two-factor authentication
- **Session**: Active authentication context tied to refresh token
- **Account Lockout**: Temporary suspension after failed login attempts
- **Verification Token**: Signed token for email verification (24-hour expiry)
- **Reset Token**: Signed token for password reset (1-hour expiry)
- **Security Event**: Authentication-related action requiring audit trail
- **Consent**: GDPR-compliant permission for data processing

## Microservices Catalog

### Service 1: Authentication Service

#### Service Overview
**Purpose**: Core authentication logic including credential validation, password management, JWT issuance, and two-factor authentication
**Domain**: Identity & Access Context
**Team Ownership**: Identity Team

#### Responsibilities
- User registration with email/password
- Login credential validation
- Password hashing (Argon2id) and verification
- JWT access token generation and signing (RS256)
- JWT refresh token generation with rotation
- Password reset flow with signed tokens
- Email verification token generation
- Two-factor authentication (email OTP)
- Account lockout enforcement
- Password complexity validation
- Password breach detection (HaveIBeenPwned integration)

#### Technology Stack
- **Language/Runtime**: Go 1.21
- **Framework**: Gin (HTTP router)
- **API Protocol**: REST (JSON)
- **Database**: PostgreSQL 15 (credentials, password history, lockout state)
- **Cache**: Redis 7.2 (OTP storage, rate limiting)
- **Message Broker**: RabbitMQ 3.12 (events for email notifications)
- **Cryptography**: Argon2id (password hashing), RS256 (JWT signing)

#### Domain Model
**Entities**:
```
User Credential Entity
├── user_id: UUID (Primary Key, Foreign Key to User Service)
├── email: String (Unique, Indexed)
├── password_hash: String (Argon2id)
├── password_salt: String
├── is_verified: Boolean
├── verification_token_hash: String (Nullable)
├── verification_token_expiry: Timestamp (Nullable)
├── reset_token_hash: String (Nullable)
├── reset_token_expiry: Timestamp (Nullable)
├── failed_login_attempts: Integer (Default: 0)
├── locked_until: Timestamp (Nullable)
├── last_password_change: Timestamp
├── created_at: Timestamp
└── updated_at: Timestamp

Password History Entity
├── id: UUID (Primary Key)
├── user_id: UUID (Foreign Key)
├── password_hash: String (Argon2id)
├── created_at: Timestamp
└── INDEX on (user_id, created_at DESC)

OTP Entity (Redis Cache)
├── key: "otp:{user_id}" 
├── otp_code: String (6 digits)
├── attempts: Integer (Max 3)
├── ttl: 300 seconds (5 minutes)

Rate Limit Tracker (Redis Cache)
├── key: "ratelimit:login:{ip}" or "ratelimit:login:{user_id}"
├── attempts: Integer
├── ttl: 3600 seconds (1 hour)
```

**Value Objects**:
- **PasswordPolicy**: Min 12 chars, uppercase, lowercase, number, special character
- **JWTClaims**: user_id, email, roles, issued_at, expires_at
- **VerificationToken**: Signed with HMAC-SHA256, 24-hour expiry
- **ResetToken**: Signed with HMAC-SHA256, 1-hour expiry

**Aggregates**:
- **Root**: User Credential
- **Entities**: Password History (up to 5 records)
- **Invariants**: 
  - Password must not match last 5 passwords
  - Account locked if failed_login_attempts >= 5
  - Verification token must be valid and not expired
  - Reset token must be valid and not expired

#### API Endpoints

##### Endpoint 1: Register User
```
POST /api/v1/auth/register
```

**Request**:
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd123",
  "gdpr_consent": true,
  "privacy_policy_accepted": true,
  "terms_of_service_accepted": true
}
```

**Response (201 Created)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "is_verified": false,
  "message": "Registration successful. Verification email sent.",
  "verification_required": true
}
```

**Error Responses**:
- `400 Bad Request`: Invalid email format, weak password, missing consent
- `409 Conflict`: Email already registered
- `429 Too Many Requests`: Rate limit exceeded (5 per minute per IP)
- `500 Internal Server Error`: Server error

**Business Rules**:
- Email must be valid format and unique
- Password must meet complexity requirements (12+ chars, mixed case, number, special)
- Password must not be in HaveIBeenPwned breach database
- GDPR consent must be explicitly provided
- Generate email verification token (24-hour expiry)
- Publish `user.registered` event for email notification
- Store password hash using Argon2id (memory-hard, time cost: 2, memory cost: 64MB, parallelism: 4)

##### Endpoint 2: Verify Email
```
GET /api/v1/auth/verify-email?token={verification_token}
```

**Response (200 OK)**:
```json
{
  "message": "Email verified successfully",
  "is_verified": true
}
```

**Error Responses**:
- `400 Bad Request`: Invalid or expired token
- `404 Not Found`: User not found
- `410 Gone`: Token already used
- `500 Internal Server Error`: Server error

**Business Rules**:
- Verify HMAC-SHA256 signature of token
- Check token expiry (24 hours from generation)
- Mark user as verified
- Invalidate verification token after use
- Publish `user.verified` event

##### Endpoint 3: Login
```
POST /api/v1/auth/login
```

**Request**:
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd123",
  "device_info": {
    "device_id": "device-fingerprint-hash",
    "device_name": "iPhone 14 Pro",
    "os": "iOS 17.1",
    "ip_address": "192.168.1.100",
    "user_agent": "SUMA Finance iOS/1.0.0"
  }
}
```

**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_550e8400-e29b-41d4-a716-446655440000",
  "token_type": "Bearer",
  "expires_in": 900,
  "requires_2fa": false,
  "user": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "is_verified": true
  }
}
```

**Response (200 OK - 2FA Required)**:
```json
{
  "requires_2fa": true,
  "session_id": "temp_session_550e8400",
  "message": "OTP sent to your email"
}
```

**Error Responses**:
- `400 Bad Request`: Missing email or password
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Account locked, email not verified
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

**Business Rules**:
- Validate email and password against stored hash
- Check account lockout status (locked_until)
- Increment failed_login_attempts on failure
- Lock account after 5 failed attempts (15-minute cooldown)
- Reset failed_login_attempts on successful login
- Generate JWT access token (15-min expiry) and refresh token (7-day expiry)
- If 2FA enabled: Generate OTP, store in Redis (5-min TTL), send via Notification Service
- Log security event (successful login, failed login, account lockout)
- Publish `user.logged_in` event

##### Endpoint 4: Verify OTP (2FA)
```
POST /api/v1/auth/verify-otp
```

**Request**:
```json
{
  "session_id": "temp_session_550e8400",
  "otp_code": "123456"
}
```

**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_550e8400-e29b-41d4-a716-446655440000",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Error Responses**:
- `400 Bad Request`: Invalid OTP format
- `401 Unauthorized`: Incorrect OTP
- `403 Forbidden`: OTP expired or max attempts exceeded
- `404 Not Found`: Session not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Retrieve OTP from Redis using session_id
- Compare submitted OTP with stored OTP
- Increment attempts counter (max 3 attempts)
- Delete OTP from Redis after successful verification
- Generate JWT tokens upon successful verification
- Log 2FA security event

##### Endpoint 5: Refresh Access Token
```
POST /api/v1/auth/refresh
```

**Request**:
```json
{
  "refresh_token": "rt_550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK)**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_660e8400-e29b-41d4-a716-446655440001",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired refresh token
- `403 Forbidden`: Refresh token reuse detected (security breach)
- `500 Internal Server Error`: Server error

**Business Rules**:
- Validate refresh token with Session Service
- Detect refresh token reuse (revoke all tokens if detected)
- Generate new access token (15-min expiry)
- Rotate refresh token (generate new one, invalidate old one)
- Update session in Session Service
- Log token refresh event

##### Endpoint 6: Request Password Reset
```
POST /api/v1/auth/password-reset/request
```

**Request**:
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK)**:
```json
{
  "message": "If the email exists, a password reset link has been sent."
}
```

**Error Responses**:
- `429 Too Many Requests`: Rate limit exceeded (3 per hour per email)
- `500 Internal Server Error`: Server error

**Business Rules**:
- Always return same response (prevent email enumeration)
- If email exists: Generate reset token (1-hour expiry), send via Notification Service
- Rate limit: 3 requests per hour per email
- Store reset token hash in database
- Publish `password_reset.requested` event
- Log security event

##### Endpoint 7: Reset Password
```
POST /api/v1/auth/password-reset/confirm
```

**Request**:
```json
{
  "token": "reset_token_hash",
  "new_password": "NewSecureP@ssw0rd456"
}
```

**Response (200 OK)**:
```json
{
  "message": "Password reset successfully"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid or expired token, weak password
- `409 Conflict`: Password matches one of last 5 passwords
- `500 Internal Server Error`: Server error

**Business Rules**:
- Verify HMAC-SHA256 signature of token
- Check token expiry (1 hour from generation)
- Validate new password complexity
- Check new password against last 5 passwords
- Hash password with Argon2id
- Invalidate reset token after use
- Invalidate all existing sessions for user
- Publish `password.changed` event
- Log security event

##### Endpoint 8: Validate JWT (Internal API)
```
POST /api/v1/auth/validate-token
```

**Request**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK)**:
```json
{
  "valid": true,
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "roles": ["user"],
  "expires_at": "2025-10-29T01:00:00Z"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid, expired, or malformed token
- `500 Internal Server Error`: Server error

**Business Rules**:
- Verify JWT signature using RS256 public key
- Check token expiry
- Extract claims (user_id, email, roles)
- Return validation result

#### Database Schema

**Tables**:
```sql
CREATE TABLE user_credentials (
    user_id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    password_salt VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token_hash VARCHAR(255),
    verification_token_expiry TIMESTAMP,
    reset_token_hash VARCHAR(255),
    reset_token_expiry TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_password_change TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

CREATE INDEX idx_user_credentials_email ON user_credentials(email);
CREATE INDEX idx_user_credentials_locked_until ON user_credentials(locked_until) WHERE locked_until IS NOT NULL;

CREATE TABLE password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES user_credentials(user_id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_password_history_user_created ON password_history(user_id, created_at DESC);

-- Trigger to maintain only last 5 passwords
CREATE OR REPLACE FUNCTION maintain_password_history()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM password_history
    WHERE user_id = NEW.user_id
    AND id NOT IN (
        SELECT id FROM password_history
        WHERE user_id = NEW.user_id
        ORDER BY created_at DESC
        LIMIT 5
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_maintain_password_history
AFTER INSERT ON password_history
FOR EACH ROW
EXECUTE FUNCTION maintain_password_history();
```

**Indexes**:
- `idx_user_credentials_email`: For login lookups (WHERE email = ?)
- `idx_user_credentials_locked_until`: For cleanup of expired lockouts
- `idx_password_history_user_created`: For retrieving last 5 passwords

**Partitioning Strategy**: None (table size expected to remain manageable)

#### Dependencies

**Upstream Dependencies** (Services this service calls):
- **Session Service**: Create/invalidate sessions after login/logout
  - **Endpoints Used**: `POST /api/v1/sessions`, `DELETE /api/v1/sessions/{session_id}`
  - **Failure Strategy**: Circuit breaker with 5-second timeout, fallback to local token generation without session tracking
  
- **User Service**: Retrieve user profile and GDPR consent status
  - **Endpoints Used**: `GET /api/v1/users/{user_id}`, `POST /api/v1/users/validate-consent`
  - **Failure Strategy**: Retry 3 times with exponential backoff, fail authentication if unavailable

- **HaveIBeenPwned API**: Check password breach status
  - **Endpoints Used**: `GET /range/{hash_prefix}` (k-anonymity model)
  - **Failure Strategy**: Timeout after 3 seconds, log warning but allow registration (security vs availability trade-off)

**Downstream Consumers** (Services that call this service):
- **API Gateway**: All authentication requests routed through this service
- **User Service**: Validate JWT tokens for protected endpoints
- **Session Service**: Refresh token validation

**External Dependencies**:
- **Redis**: OTP storage, rate limiting, token blacklist
  - **SLA**: 99.9% uptime
  - **Rate Limit**: No limit (internal)
  - **Fallback**: Degrade to in-memory cache (single instance only), alert DevOps
  
- **PostgreSQL**: Credential storage
  - **SLA**: 99.95% uptime
  - **Rate Limit**: Connection pool (max 100 connections)
  - **Fallback**: Retry with exponential backoff, return 503 if unavailable

- **RabbitMQ**: Event publishing for notifications
  - **SLA**: 99.9% uptime
  - **Rate Limit**: No limit (internal)
  - **Fallback**: Store events in local queue, retry delivery

#### Events Published

**Event**: `user.registered`
```json
{
  "event_id": "evt_550e8400-e29b-41d4-a716-446655440000",
  "event_type": "user.registered",
  "timestamp": "2025-10-29T00:00:00Z",
  "version": "1.0",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "verification_token": "signed_token_hash",
    "verification_url": "https://app.sumafinance.com/verify?token=..."
  },
  "metadata": {
    "trace_id": "trace_550e8400",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0"
  }
}
```

**Event**: `user.verified`
```json
{
  "event_id": "evt_660e8400-e29b-41d4-a716-446655440001",
  "event_type": "user.verified",
  "timestamp": "2025-10-29T01:00:00Z",
  "version": "1.0",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "verified_at": "2025-10-29T01:00:00Z"
  }
}
```

**Event**: `user.logged_in`
```json
{
  "event_id": "evt_770e8400-e29b-41d4-a716-446655440002",
  "event_type": "user.logged_in",
  "timestamp": "2025-10-29T02:00:00Z",
  "version": "1.0",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "device_id": "device-fingerprint-hash",
    "ip_address": "192.168.1.100",
    "session_id": "session_550e8400"
  }
}
```

**Event**: `password_reset.requested`
**Event**: `password.changed`
**Event**: `account.locked`
**Event**: `2fa.required`
**Event**: `2fa.verified`

#### Events Consumed
None (Authentication Service does not consume events)

#### Data Management

**Data Ownership**:
- This service is the single source of truth for: User credentials, password hashes, password history, verification tokens, reset tokens, lockout state

**Data Access Patterns**:
- Read-heavy: 40% (login lookups, token validation)
- Write-heavy: 60% (failed attempt tracking, token generation)
- Read/Write ratio: 1:1.5

**Caching Strategy**:
- **Cache Layer**: Redis
- **Cache Keys**: 
  - `credential:{email}` (credential lookup)
  - `lockout:{user_id}` (lockout state)
  - `otp:{user_id}` (OTP codes)
  - `ratelimit:login:{ip}` and `ratelimit:login:{user_id}` (rate limiting)
- **TTL**: 
  - Credentials: 5 minutes
  - Lockout state: 15 minutes
  - OTP: 5 minutes
  - Rate limits: 1 hour
- **Invalidation**: On password change, reset, or verification
- **Cache-Aside Pattern**: Read from cache, on miss read from DB and populate cache

**Data Retention**:
- **Active Credentials**: Kept indefinitely
- **Password History**: Last 5 passwords per user
- **Expired Tokens**: Purged after expiry + 24 hours
- **Failed Login Attempts**: Reset after successful login

#### Scalability Design

**Horizontal Scaling**:
- **Stateless**: No in-memory session state (tokens are self-contained JWTs)
- **Container-based**: Deployed as Docker containers in Kubernetes
- **Auto-scaling Triggers**:
  - CPU > 70% for 5 minutes
  - Request queue depth > 100
  - Average response time > 500ms

**Performance Targets**:
- **Response Time**: p50 < 100ms, p95 < 200ms, p99 < 500ms
- **Throughput**: 1000 requests/second per instance
- **Concurrent Connections**: 10,000 per instance

**Load Testing Results**: Expected to handle 5,000 concurrent logins with 3 instances

#### Resilience Patterns

**Circuit Breaker**:
```yaml
circuit_breaker:
  failure_threshold: 5
  success_threshold: 2
  timeout: 30s
  half_open_max_requests: 3
```

**Retry Policy**:
- **Strategy**: Exponential backoff
- **Initial Delay**: 100ms
- **Max Delay**: 5s
- **Max Attempts**: 3
- **Idempotency**: Login is idempotent (generates new token each time)

**Timeout Configuration**:
- **HTTP Requests**: 10s
- **Database Queries**: 5s
- **Redis Operations**: 1s
- **External API Calls** (HaveIBeenPwned): 3s

**Fallback Strategies**:
- HaveIBeenPwned unavailable: Log warning, allow registration
- Redis unavailable: Degrade to in-memory cache (single instance)
- Session Service unavailable: Generate tokens without session tracking
- RabbitMQ unavailable: Queue events locally, retry delivery

**Bulkhead Pattern**:
- Separate thread pools for database connections (50 threads) and external API calls (10 threads)

#### Security Implementation

**Authentication**:
- JWT tokens with RS256 signing (2048-bit RSA keys)
- Token validation at API Gateway
- Token expiry: 15 minutes (access), 7 days (refresh)
- Private key stored in AWS Secrets Manager with 90-day rotation

**Authorization**:
- Role-Based Access Control (RBAC)
- JWT includes `roles` claim (e.g., ["user"], ["admin"])
- Permissions checked on every request

**Data Protection**:
- Encryption at rest: PostgreSQL encrypted with AES-256-GCM
- Encryption in transit: TLS 1.3
- Password hashes never logged or exposed in APIs
- PII (email) encrypted in database
- Sensitive fields masked in logs (password redacted)

**Input Validation**:
- Email format validation (RFC 5322)
- Password complexity validation (min 12 chars, mixed case, number, special)
- SQL injection prevention via parameterized queries (sqlx library)
- XSS prevention via output encoding (not applicable for JSON APIs)

**Rate Limiting**:
- Per-IP: 5 login attempts per minute
- Per-User: 10 login attempts per hour
- Per-Email (password reset): 3 requests per hour
- Implemented using Redis sliding window

#### Monitoring & Observability

**Health Checks**:
- `/health/live`: Returns 200 if service is running
- `/health/ready`: Returns 200 if database and Redis are accessible
- `/health/startup`: Returns 200 after initial JWT key load

**Metrics (Prometheus format)**:
- `auth_requests_total{method, endpoint, status}`: Counter of authentication requests
- `auth_request_duration_seconds{endpoint}`: Histogram of request latency
- `auth_failed_login_attempts_total`: Counter of failed login attempts
- `auth_account_lockouts_total`: Counter of account lockouts
- `auth_password_reset_requests_total`: Counter of password reset requests
- `auth_2fa_otp_sent_total`: Counter of OTPs sent
- `auth_2fa_otp_verified_total`: Counter of OTPs verified
- `auth_jwt_tokens_issued_total{type}`: Counter of tokens issued (access, refresh)
- `database_connections_active`: Gauge of DB connections
- `redis_connections_active`: Gauge of Redis connections
- `cache_hit_ratio{cache_key_prefix}`: Gauge of cache effectiveness

**Logging**:
```json
{
  "timestamp": "2025-10-29T00:00:00Z",
  "level": "INFO",
  "service": "auth-service",
  "trace_id": "trace_550e8400",
  "span_id": "span_123",
  "message": "User logged in successfully",
  "context": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "action": "login",
    "ip_address": "192.168.1.100",
    "device_id": "device-fingerprint-hash"
  }
}
```

**Distributed Tracing**:
- OpenTelemetry instrumentation
- Trace context propagation via `X-Trace-Id` header
- Spans for all database queries, cache operations, external API calls

**Alerting Rules**:
- Failed login rate > 10% for 5 minutes
- Account lockout rate > 5% for 5 minutes
- p95 latency > 500ms for 5 minutes
- Password reset request rate > 100/minute (potential attack)
- Redis connection pool exhausted
- Database connection pool > 80% utilized

#### Testing Strategy

**Unit Tests**:
- Coverage target: >85%
- Test password hashing and verification
- Test JWT token generation and validation
- Test password complexity validation
- Test account lockout logic
- Mock database, Redis, external APIs

**Integration Tests**:
- Test full registration flow (DB insert, event publish)
- Test login flow (DB query, JWT generation, session creation)
- Test password reset flow (token generation, email event, DB update)
- Test 2FA flow (OTP generation, Redis storage, validation)

**Contract Tests**:
- Pact contracts with API Gateway
- Pact contracts with Session Service

**Performance Tests**:
- Load testing: 1000 req/s for 10 minutes
- Stress testing: Increase load until p95 > 1s
- Soak testing: 500 req/s for 24 hours

**Security Tests**:
- OWASP ZAP scan for common vulnerabilities
- SQL injection testing
- Brute-force attack simulation (rate limiting validation)
- JWT tampering tests

**Chaos Engineering**:
- Random pod termination during load test
- Redis failure injection
- Database connection pool exhaustion

#### Deployment Configuration

**Container Configuration**:
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service ./cmd/auth

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/auth-service .
EXPOSE 8080
USER nobody
CMD ["./auth-service"]
```

**Resource Limits**:
```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 1Gi
```

**Environment Variables**:
- `DATABASE_URL`: PostgreSQL connection string (from secrets)
- `REDIS_URL`: Redis connection string (from secrets)
- `JWT_PRIVATE_KEY`: RS256 private key (from AWS Secrets Manager)
- `JWT_PUBLIC_KEY`: RS256 public key
- `JWT_ACCESS_TOKEN_EXPIRY`: 15m
- `JWT_REFRESH_TOKEN_EXPIRY`: 168h (7 days)
- `LOG_LEVEL`: info
- `HIBP_API_KEY`: HaveIBeenPwned API key (from secrets)
- `RABBITMQ_URL`: RabbitMQ connection string (from secrets)

**Replicas**: Minimum 3 for HA

#### Disaster Recovery

**Backup Strategy**:
- Database: Continuous replication to read replica + daily snapshots retained for 30 days
- Redis: AOF persistence + daily RDB snapshots
- JWT private key: Backed up in AWS Secrets Manager with versioning

**Recovery Procedures**:
- **RTO**: 1 hour
- **RPO**: 5 minutes (database point-in-time recovery)
- **Multi-Region**: Active-passive failover (primary: us-east-1, passive: eu-west-1)

---

### Service 2: User Service

#### Service Overview
**Purpose**: Manage user profiles, account status, GDPR consent, and personal information
**Domain**: User Management Context
**Team Ownership**: User Management Team

#### Responsibilities
- User profile creation and updates
- GDPR consent tracking and management
- User account status management (active, suspended, deleted)
- User data export (GDPR compliance)
- User data deletion (GDPR right to erasure)
- Privacy policy and terms of service acceptance
- User metadata storage (name, phone, preferences)

#### Technology Stack
- **Language/Runtime**: Go 1.21
- **Framework**: Gin (HTTP router)
- **API Protocol**: REST (JSON)
- **Database**: PostgreSQL 15 (user profiles, consent records)
- **Cache**: Redis 7.2 (profile caching)
- **Message Broker**: RabbitMQ 3.12 (event consumption from Auth Service)

#### Domain Model
**Entities**:
```
User Profile Entity
├── user_id: UUID (Primary Key)
├── email: String (Unique, Indexed)
├── first_name: String (Encrypted at rest)
├── last_name: String (Encrypted at rest)
├── phone_number: String (Nullable, Encrypted at rest)
├── date_of_birth: Date (Nullable, Encrypted at rest)
├── account_status: Enum (active, suspended, deleted)
├── deletion_requested_at: Timestamp (Nullable)
├── deletion_scheduled_at: Timestamp (Nullable, GDPR 30-day grace period)
├── created_at: Timestamp
├── updated_at: Timestamp
└── last_login_at: Timestamp

GDPR Consent Entity
├── id: UUID (Primary Key)
├── user_id: UUID (Foreign Key)
├── consent_type: Enum (marketing, analytics, data_processing, third_party_sharing)
├── consent_given: Boolean
├── consent_version: String (e.g., "v1.0")
├── ip_address: String (for audit trail)
├── user_agent: String (for audit trail)
├── consented_at: Timestamp
├── withdrawn_at: Timestamp (Nullable)
└── INDEX on (user_id, consent_type)

Privacy Policy Acceptance Entity
├── id: UUID (Primary Key)
├── user_id: UUID (Foreign Key)
├── policy_version: String (e.g., "2025-01-01")
├── accepted_at: Timestamp
├── ip_address: String
└── INDEX on (user_id, policy_version)
```

**Value Objects**:
- **AccountStatus**: active, suspended, deleted (soft delete)
- **ConsentType**: marketing, analytics, data_processing, third_party_sharing

**Aggregates**:
- **Root**: User Profile
- **Entities**: GDPR Consent (multiple per user), Privacy Policy Acceptance (multiple versions)
- **Invariants**: 
  - User must have at least one consent record (data_processing) to be active
  - Deleted users cannot be reactivated
  - User profile must exist before consent can be recorded

#### API Endpoints

##### Endpoint 1: Create User Profile
```
POST /api/v1/users
```

**Request**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "consents": [
    {
      "consent_type": "data_processing",
      "consent_given": true
    },
    {
      "consent_type": "marketing",
      "consent_given": false
    }
  ],
  "privacy_policy_version": "2025-01-01",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0"
}
```

**Response (201 Created)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "account_status": "active",
  "created_at": "2025-10-29T00:00:00Z"
}
```

**Error Responses**:
- `400 Bad Request`: Missing required fields, invalid consent configuration
- `409 Conflict`: User already exists
- `500 Internal Server Error`: Server error

**Business Rules**:
- User ID provided by Authentication Service (after registration)
- `data_processing` consent is mandatory
- Encrypt PII fields (first_name, last_name, phone_number, date_of_birth) using AES-256-GCM
- Create consent records with timestamp and IP address
- Create privacy policy acceptance record
- Publish `user.profile_created` event

##### Endpoint 2: Get User Profile
```
GET /api/v1/users/{user_id}
```

**Response (200 OK)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": null,
  "account_status": "active",
  "created_at": "2025-10-29T00:00:00Z",
  "updated_at": "2025-10-29T00:00:00Z",
  "last_login_at": "2025-10-29T02:00:00Z"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or missing JWT
- `403 Forbidden`: User requesting profile of another user (unless admin role)
- `404 Not Found`: User not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Decrypt PII fields before returning
- Mask sensitive fields based on requester role
- Cache profile in Redis (5-min TTL)

##### Endpoint 3: Update User Profile
```
PATCH /api/v1/users/{user_id}
```

**Request**:
```json
{
  "first_name": "Jane",
  "phone_number": "+351912345678"
}
```

**Response (200 OK)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "first_name": "Jane",
  "phone_number": "+351912345678",
  "updated_at": "2025-10-29T03:00:00Z"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid phone number format
- `401 Unauthorized`: Invalid JWT
- `403 Forbidden`: User cannot update another user's profile
- `404 Not Found`: User not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Validate phone number format (E.164)
- Encrypt updated PII fields
- Invalidate Redis cache for this user
- Publish `user.profile_updated` event
- Log profile change in audit trail

##### Endpoint 4: Update GDPR Consent
```
PUT /api/v1/users/{user_id}/consents
```

**Request**:
```json
{
  "consent_type": "marketing",
  "consent_given": true,
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0"
}
```

**Response (200 OK)**:
```json
{
  "consent_id": "660e8400-e29b-41d4-a716-446655440001",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "consent_type": "marketing",
  "consent_given": true,
  "consented_at": "2025-10-29T03:00:00Z"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid consent type
- `403 Forbidden`: Cannot withdraw mandatory consent (data_processing)
- `404 Not Found`: User not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Create new consent record (do not update existing)
- If consent withdrawn, set `withdrawn_at` timestamp
- Publish `user.consent_updated` event
- Log consent change in audit trail

##### Endpoint 5: Export User Data (GDPR)
```
GET /api/v1/users/{user_id}/export
```

**Response (200 OK)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "profile": {
    "first_name": "John",
    "last_name": "Doe",
    "phone_number": "+351912345678",
    "created_at": "2025-10-29T00:00:00Z"
  },
  "consents": [
    {
      "consent_type": "data_processing",
      "consent_given": true,
      "consented_at": "2025-10-29T00:00:00Z"
    }
  ],
  "login_history": [],
  "transactions": [],
  "exported_at": "2025-10-29T04:00:00Z"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid JWT
- `403 Forbidden`: User cannot export another user's data
- `404 Not Found`: User not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Aggregate data from all services (call Audit Service for login history)
- Return data in machine-readable JSON format
- Log data export request
- Rate limit: 1 export per user per day

##### Endpoint 6: Request Account Deletion (GDPR)
```
DELETE /api/v1/users/{user_id}
```

**Response (202 Accepted)**:
```json
{
  "message": "Account deletion scheduled for 2025-11-28T00:00:00Z (30-day grace period)",
  "deletion_scheduled_at": "2025-11-28T00:00:00Z",
  "cancellation_url": "https://app.sumafinance.com/cancel-deletion"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid JWT
- `403 Forbidden`: User cannot delete another user's account
- `404 Not Found`: User not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Schedule deletion for 30 days from now (GDPR grace period)
- Set `account_status` to `suspended`
- Publish `user.deletion_requested` event
- Send email notification with cancellation instructions
- Log deletion request

##### Endpoint 7: Cancel Account Deletion
```
POST /api/v1/users/{user_id}/cancel-deletion
```

**Response (200 OK)**:
```json
{
  "message": "Account deletion cancelled",
  "account_status": "active"
}
```

**Error Responses**:
- `400 Bad Request`: No deletion scheduled
- `401 Unauthorized`: Invalid JWT
- `404 Not Found`: User not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Clear `deletion_requested_at` and `deletion_scheduled_at`
- Set `account_status` to `active`
- Publish `user.deletion_cancelled` event

#### Database Schema

**Tables**:
```sql
CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name_encrypted BYTEA NOT NULL,
    last_name_encrypted BYTEA NOT NULL,
    phone_number_encrypted BYTEA,
    date_of_birth_encrypted BYTEA,
    account_status VARCHAR(20) DEFAULT 'active',
    deletion_requested_at TIMESTAMP,
    deletion_scheduled_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login_at TIMESTAMP,
    CONSTRAINT account_status_check CHECK (account_status IN ('active', 'suspended', 'deleted'))
);

CREATE INDEX idx_user_profiles_email ON user_profiles(email);
CREATE INDEX idx_user_profiles_account_status ON user_profiles(account_status);
CREATE INDEX idx_user_profiles_deletion_scheduled ON user_profiles(deletion_scheduled_at) WHERE deletion_scheduled_at IS NOT NULL;

CREATE TABLE gdpr_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
    consent_type VARCHAR(50) NOT NULL,
    consent_given BOOLEAN NOT NULL,
    consent_version VARCHAR(20) DEFAULT 'v1.0',
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    consented_at TIMESTAMP DEFAULT NOW(),
    withdrawn_at TIMESTAMP,
    CONSTRAINT consent_type_check CHECK (consent_type IN ('marketing', 'analytics', 'data_processing', 'third_party_sharing'))
);

CREATE INDEX idx_gdpr_consents_user_type ON gdpr_consents(user_id, consent_type);
CREATE INDEX idx_gdpr_consents_user_withdrawn ON gdpr_consents(user_id) WHERE withdrawn_at IS NULL;

CREATE TABLE privacy_policy_acceptances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
    policy_version VARCHAR(20) NOT NULL,
    accepted_at TIMESTAMP DEFAULT NOW(),
    ip_address VARCHAR(45) NOT NULL
);

CREATE INDEX idx_privacy_policy_user_version ON privacy_policy_acceptances(user_id, policy_version);
```

**Indexes**:
- `idx_user_profiles_email`: For profile lookups by email
- `idx_user_profiles_account_status`: For filtering users by status
- `idx_user_profiles_deletion_scheduled`: For background job to process scheduled deletions
- `idx_gdpr_consents_user_type`: For consent lookups
- `idx_privacy_policy_user_version`: For policy acceptance verification

**Partitioning Strategy**: None (expected table size < 10M users)

#### Dependencies

**Upstream Dependencies**:
- None (User Service is foundational)

**Downstream Consumers**:
- **Authentication Service**: Validate user existence and consent status
- **Session Service**: Get user profile for session enrichment
- **Audit Service**: Get user details for audit logs

**External Dependencies**:
- **Redis**: Profile caching
- **PostgreSQL**: Profile and consent storage
- **RabbitMQ**: Event publishing

#### Events Published

**Event**: `user.profile_created`
**Event**: `user.profile_updated`
**Event**: `user.consent_updated`
**Event**: `user.deletion_requested`
**Event**: `user.deletion_cancelled`
**Event**: `user.deleted` (after 30-day grace period)

#### Events Consumed

**Event**: `user.registered` (from Authentication Service)
**Action**: Create user profile
**Handler**: `handleUserRegistered()`

**Event**: `user.logged_in` (from Authentication Service)
**Action**: Update `last_login_at` timestamp
**Handler**: `handleUserLoggedIn()`

#### Data Management

**Data Ownership**:
- Single source of truth for: User profiles, GDPR consents, privacy policy acceptances

**Data Access Patterns**:
- Read-heavy: 80% (profile lookups during authentication)
- Write-heavy: 20% (profile updates, consent changes)
- Read/Write ratio: 4:1

**Caching Strategy**:
- **Cache Keys**: `user:profile:{user_id}`, `user:consents:{user_id}`
- **TTL**: 5 minutes for profiles, 10 minutes for consents
- **Invalidation**: On profile update, consent update

**Data Retention**:
- **Active Users**: Kept indefinitely
- **Deleted Users**: Anonymized after 30-day grace period (replace PII with "[DELETED]")
- **Consent Records**: Retained for 7 years (legal compliance)

#### Scalability Design

**Horizontal Scaling**:
- Stateless service, horizontally scalable
- Auto-scaling based on CPU and request rate

**Performance Targets**:
- **Response Time**: p50 < 50ms, p95 < 150ms, p99 < 300ms
- **Throughput**: 2000 requests/second per instance

#### Resilience Patterns

**Circuit Breaker**: Same as Authentication Service
**Retry Policy**: Same as Authentication Service
**Timeout Configuration**: Database: 3s, Redis: 1s
**Fallback Strategies**: Redis unavailable → Serve from database (slower but reliable)

#### Security Implementation

**Authentication**: JWT validation for all endpoints
**Authorization**: Users can only access their own profiles (unless admin role)
**Data Protection**: 
- PII encrypted at rest (AES-256-GCM)
- Encryption keys rotated every 90 days
- TLS 1.3 for all communications
**Input Validation**: Email format, phone number format (E.164)

#### Monitoring & Observability

**Health Checks**: Same structure as Authentication Service
**Metrics**:
- `user_profile_requests_total{method, endpoint, status}`
- `user_consent_updates_total{consent_type, action}`
- `user_deletion_requests_total`
- `user_data_exports_total`

**Logging**: Structured JSON logs with trace context
**Alerting**:
- Deletion request rate > 10/hour (unusual pattern)
- Profile update rate > 1000/minute (potential attack)

#### Testing Strategy

**Unit Tests**: Coverage > 85%
**Integration Tests**: Test database encryption/decryption, consent workflow
**Contract Tests**: Pact with Authentication Service, Session Service
**Performance Tests**: Load test profile reads (2000 req/s)

#### Deployment Configuration

**Container**: Go 1.21 Alpine-based image
**Resources**: CPU 300m (request), 1000m (limit); Memory 256Mi (request), 512Mi (limit)
**Replicas**: Minimum 3
**Environment Variables**: DATABASE_URL, REDIS_URL, ENCRYPTION_KEY (from secrets), RABBITMQ_URL

#### Disaster Recovery

**Backup**: Database snapshots every 6 hours, retained 90 days
**RTO**: 30 minutes
**RPO**: 1 minute (continuous replication)

---

### Service 3: Session Service

#### Service Overview
**Purpose**: Manage refresh token lifecycle, session tracking, and concurrent session limits
**Domain**: Identity & Access Context
**Team Ownership**: Identity Team

#### Responsibilities
- Store and validate refresh tokens
- Track active sessions per user
- Enforce concurrent session limits (max 5 devices per user)
- Detect refresh token reuse (security breach indicator)
- Revoke sessions on logout or password change
- Session expiry and cleanup (7-day TTL)
- Device fingerprinting and tracking

#### Technology Stack
- **Language/Runtime**: Go 1.21
- **Framework**: Gin (HTTP router)
- **API Protocol**: REST (JSON)
- **Database**: Redis 7.2 (primary session store)
- **Database**: PostgreSQL 15 (persistent session history for audit)
- **Cache**: N/A (Redis is primary store)
- **Message Broker**: RabbitMQ 3.12

#### Domain Model
**Entities**:
```
Session Entity (Redis)
├── session_id: UUID (Primary Key)
├── user_id: UUID
├── refresh_token_hash: String (SHA-256)
├── device_id: String (device fingerprint)
├── device_name: String (e.g., "iPhone 14 Pro")
├── device_os: String (e.g., "iOS 17.1")
├── ip_address: String
├── user_agent: String
├── created_at: Timestamp
├── last_refreshed_at: Timestamp
├── expires_at: Timestamp (7 days from creation)
├── is_revoked: Boolean
└── TTL: 7 days (auto-expire in Redis)

Session History Entity (PostgreSQL)
├── session_id: UUID (Primary Key)
├── user_id: UUID (Indexed)
├── refresh_token_hash: String
├── device_id: String
├── ip_address: String
├── created_at: Timestamp
├── revoked_at: Timestamp (Nullable)
├── revocation_reason: String (Nullable, e.g., "logout", "password_change", "reuse_detected")
└── INDEX on (user_id, created_at DESC)
```

**Value Objects**:
- **RevocationReason**: logout, password_change, reuse_detected, expired, admin_action

**Aggregates**:
- **Root**: Session
- **Invariants**: 
  - Max 5 active sessions per user
  - Refresh token hash must be unique
  - Reused refresh token triggers revocation of all user sessions

#### API Endpoints

##### Endpoint 1: Create Session
```
POST /api/v1/sessions
```

**Request**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "refresh_token": "rt_550e8400-e29b-41d4-a716-446655440000",
  "device_id": "device-fingerprint-hash",
  "device_name": "iPhone 14 Pro",
  "device_os": "iOS 17.1",
  "ip_address": "192.168.1.100",
  "user_agent": "SUMA Finance iOS/1.0.0"
}
```

**Response (201 Created)**:
```json
{
  "session_id": "770e8400-e29b-41d4-a716-446655440002",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "device_id": "device-fingerprint-hash",
  "created_at": "2025-10-29T00:00:00Z",
  "expires_at": "2025-11-05T00:00:00Z"
}
```

**Error Responses**:
- `400 Bad Request`: Missing required fields
- `409 Conflict`: Max sessions exceeded (5 active sessions)
- `500 Internal Server Error`: Server error

**Business Rules**:
- Hash refresh token with SHA-256 before storing
- Check active session count for user (max 5)
- If max exceeded, revoke oldest session
- Store session in Redis with 7-day TTL
- Store session history in PostgreSQL
- Publish `session.created` event

##### Endpoint 2: Validate Refresh Token
```
POST /api/v1/sessions/validate
```

**Request**:
```json
{
  "refresh_token": "rt_550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK)**:
```json
{
  "valid": true,
  "session_id": "770e8400-e29b-41d4-a716-446655440002",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "device_id": "device-fingerprint-hash",
  "expires_at": "2025-11-05T00:00:00Z"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or expired refresh token
- `403 Forbidden`: Refresh token reuse detected (all sessions revoked)
- `500 Internal Server Error`: Server error

**Business Rules**:
- Hash incoming token with SHA-256
- Lookup session in Redis by token hash
- Check `is_revoked` flag and `expires_at`
- If token already used for refresh: Detect reuse, revoke all user sessions, alert security team
- Return session details if valid

##### Endpoint 3: Refresh Session (Rotate Token)
```
POST /api/v1/sessions/{session_id}/refresh
```

**Request**:
```json
{
  "old_refresh_token": "rt_550e8400-e29b-41d4-a716-446655440000",
  "new_refresh_token": "rt_660e8400-e29b-41d4-a716-446655440001"
}
```

**Response (200 OK)**:
```json
{
  "session_id": "770e8400-e29b-41d4-a716-446655440002",
  "new_refresh_token_hash": "sha256_hash",
  "last_refreshed_at": "2025-10-29T01:00:00Z",
  "expires_at": "2025-11-05T01:00:00Z"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid old token
- `403 Forbidden`: Token reuse detected
- `404 Not Found`: Session not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Validate old token
- Hash new token with SHA-256
- Update session in Redis (atomic operation)
- Update `last_refreshed_at` timestamp
- Publish `session.refreshed` event

##### Endpoint 4: Revoke Session (Logout)
```
DELETE /api/v1/sessions/{session_id}
```

**Response (200 OK)**:
```json
{
  "message": "Session revoked successfully"
}
```

**Error Responses**:
- `404 Not Found`: Session not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Set `is_revoked` flag in Redis
- Delete session from Redis (immediate expiry)
- Update session history in PostgreSQL with `revoked_at` and `revocation_reason`
- Publish `session.revoked` event

##### Endpoint 5: Revoke All User Sessions
```
DELETE /api/v1/sessions/user/{user_id}
```

**Response (200 OK)**:
```json
{
  "message": "All sessions revoked",
  "revoked_count": 3
}
```

**Error Responses**:
- `404 Not Found`: User has no active sessions
- `500 Internal Server Error`: Server error

**Business Rules**:
- Lookup all sessions for user in Redis (scan by pattern `session:{user_id}:*`)
- Revoke each session
- Update session history
- Publish `sessions.bulk_revoked` event
- Used for password change, account deletion, security incidents

##### Endpoint 6: List User Sessions
```
GET /api/v1/sessions/user/{user_id}
```

**Response (200 OK)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "active_sessions": [
    {
      "session_id": "770e8400-e29b-41d4-a716-446655440002",
      "device_name": "iPhone 14 Pro",
      "device_os": "iOS 17.1",
      "ip_address": "192.168.1.100",
      "created_at": "2025-10-29T00:00:00Z",
      "last_refreshed_at": "2025-10-29T01:00:00Z",
      "is_current": true
    },
    {
      "session_id": "880e8400-e29b-41d4-a716-446655440003",
      "device_name": "Chrome on Windows",
      "device_os": "Windows 11",
      "ip_address": "192.168.1.101",
      "created_at": "2025-10-28T00:00:00Z",
      "last_refreshed_at": "2025-10-28T12:00:00Z",
      "is_current": false
    }
  ],
  "session_count": 2
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid JWT
- `403 Forbidden`: User cannot view another user's sessions
- `404 Not Found`: User not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Return active sessions sorted by `last_refreshed_at` DESC
- Mark current session (matched by refresh token in request)
- Mask sensitive fields (partial IP, no token hashes)

#### Database Schema

**Redis Keys**:
```
session:{session_id} → JSON {user_id, refresh_token_hash, device_id, ...}
user_sessions:{user_id} → Set {session_id_1, session_id_2, ...}
reuse_detector:{refresh_token_hash} → Boolean (TTL: 5 minutes after rotation)
```

**PostgreSQL Table**:
```sql
CREATE TABLE session_history (
    session_id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    refresh_token_hash VARCHAR(255) NOT NULL,
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    device_os VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    last_refreshed_at TIMESTAMP DEFAULT NOW(),
    revoked_at TIMESTAMP,
    revocation_reason VARCHAR(50),
    CONSTRAINT revocation_reason_check CHECK (revocation_reason IN ('logout', 'password_change', 'reuse_detected', 'expired', 'admin_action'))
);

CREATE INDEX idx_session_history_user_created ON session_history(user_id, created_at DESC);
CREATE INDEX idx_session_history_revoked ON session_history(revoked_at) WHERE revoked_at IS NOT NULL;
```

**Indexes**:
- `idx_session_history_user_created`: For retrieving user session history
- `idx_session_history_revoked`: For analytics on revocation patterns

**Partitioning Strategy**: Partition `session_history` by month (for performance as table grows)

#### Dependencies

**Upstream Dependencies**:
- None

**Downstream Consumers**:
- **Authentication Service**: Validate refresh tokens, rotate tokens
- **User Service**: List user sessions for device management

**External Dependencies**:
- **Redis**: Primary session store
- **PostgreSQL**: Session history for audit
- **RabbitMQ**: Event publishing

#### Events Published

**Event**: `session.created`
**Event**: `session.refreshed`
**Event**: `session.revoked`
**Event**: `sessions.bulk_revoked`
**Event**: `session.reuse_detected` (security alert)

#### Events Consumed

**Event**: `password.changed` (from Authentication Service)
**Action**: Revoke all user sessions
**Handler**: `handlePasswordChanged()`

**Event**: `user.deletion_requested` (from User Service)
**Action**: Revoke all user sessions
**Handler**: `handleUserDeletionRequested()`

#### Data Management

**Data Ownership**:
- Single source of truth for: Active sessions, session history

**Data Access Patterns**:
- Read-heavy: 90% (token validation on every API call with refresh token)
- Write-heavy: 10% (session creation, rotation)
- Read/Write ratio: 9:1

**Caching Strategy**:
- Redis is primary store (no additional caching layer)
- TTL-based expiry (7 days)

**Data Retention**:
- **Active Sessions**: 7 days (auto-expire in Redis)
- **Session History**: Retained for 1 year (compliance)

#### Scalability Design

**Horizontal Scaling**:
- Stateless service (session state in Redis)
- Redis Cluster for high availability
- Auto-scaling based on request rate

**Performance Targets**:
- **Response Time**: p50 < 10ms, p95 < 50ms, p99 < 100ms (Redis is fast)
- **Throughput**: 5000 requests/second per instance

#### Resilience Patterns

**Circuit Breaker**: For PostgreSQL writes (session history)
**Retry Policy**: Retry Redis operations 3 times with exponential backoff
**Timeout Configuration**: Redis: 500ms, PostgreSQL: 2s
**Fallback Strategies**: 
- PostgreSQL unavailable: Continue serving sessions (Redis), queue history writes for later
- Redis unavailable: Return 503 (sessions cannot be validated)

#### Security Implementation

**Authentication**: JWT validation for user-facing endpoints
**Authorization**: Users can only access their own sessions
**Data Protection**:
- Refresh tokens hashed with SHA-256 (never stored in plaintext)
- Session history encrypted at rest
- IP addresses logged for audit (PII consideration)
**Input Validation**: Validate refresh token format, device ID format

#### Monitoring & Observability

**Health Checks**: `/health/ready` checks Redis and PostgreSQL connectivity
**Metrics**:
- `session_create_total{user_id}`
- `session_validate_total{status}`
- `session_refresh_total{user_id}`
- `session_revoke_total{reason}`
- `session_reuse_detected_total` (critical security metric)
- `active_sessions_gauge{user_id}` (for monitoring concurrent sessions)
- `redis_operations_duration_seconds{operation}`

**Logging**: Log all session operations with trace context
**Alerting**:
- Refresh token reuse detected (immediate alert to security team)
- Session creation rate > 1000/minute (potential attack)
- Redis latency > 100ms (performance degradation)

#### Testing Strategy

**Unit Tests**: Coverage > 85%, test token rotation, reuse detection
**Integration Tests**: Test Redis session storage, PostgreSQL history writes
**Performance Tests**: Load test token validation (5000 req/s)
**Security Tests**: Simulate token reuse attack

#### Deployment Configuration

**Container**: Go 1.21 Alpine-based image
**Resources**: CPU 200m (request), 1000m (limit); Memory 256Mi (request), 512Mi (limit)
**Replicas**: Minimum 3
**Environment Variables**: REDIS_URL, DATABASE_URL (PostgreSQL), RABBITMQ_URL

#### Disaster Recovery

**Backup**: 
- Redis: AOF persistence + RDB snapshots every hour
- PostgreSQL: Daily snapshots retained 30 days
**RTO**: 15 minutes (Redis failover is fast)
**RPO**: 1 minute (Redis AOF with fsync every second)

---

### Service 4: Notification Service

#### Service Overview
**Purpose**: Send transactional emails and SMS for authentication flows (verification, password reset, OTP, security alerts)
**Domain**: Communication Context
**Team Ownership**: Platform Team

#### Responsibilities
- Send email verification links
- Send password reset links
- Send OTP codes via email/SMS
- Send security alerts (new device login, suspicious activity)
- Manage email templates (Handlebars)
- Track email delivery status
- Handle email delivery failures and retries
- Rate limiting for notification sending

#### Technology Stack
- **Language/Runtime**: Node.js 20.x
- **Framework**: Express.js
- **API Protocol**: REST (JSON)
- **Database**: PostgreSQL 15 (notification history)
- **Cache**: Redis 7.2 (rate limiting, deduplication)
- **Message Broker**: RabbitMQ 3.12 (event-driven notification triggers)
- **Email Provider**: SendGrid (primary), AWS SES (fallback)
- **SMS Provider**: Twilio (optional, for SMS OTP)

#### Domain Model
**Entities**:
```
Notification Entity
├── id: UUID (Primary Key)
├── user_id: UUID
├── notification_type: Enum (email_verification, password_reset, otp_email, otp_sms, security_alert)
├── recipient: String (email or phone number)
├── template_name: String (e.g., "email_verification")
├── template_data: JSONB (variables for template)
├── status: Enum (pending, sent, failed, bounced)
├── provider: String (sendgrid, ses, twilio)
├── provider_message_id: String (Nullable)
├── error_message: String (Nullable)
├── sent_at: Timestamp (Nullable)
├── delivered_at: Timestamp (Nullable, webhook from provider)
├── created_at: Timestamp
└── retry_count: Integer (Default: 0, Max: 3)

Email Template Entity
├── id: UUID (Primary Key)
├── template_name: String (Unique, e.g., "email_verification")
├── subject: String (Handlebars template)
├── body_html: Text (Handlebars template)
├── body_text: Text (Plain text version)
├── version: String (e.g., "1.0")
├── created_at: Timestamp
└── INDEX on (template_name, version)
```

**Value Objects**:
- **NotificationType**: email_verification, password_reset, otp_email, otp_sms, security_alert, account_locked, password_changed
- **NotificationStatus**: pending, sent, failed, bounced

**Aggregates**:
- **Root**: Notification
- **Invariants**: 
  - Notification must have valid recipient (email or phone)
  - Retry count cannot exceed 3
  - Template must exist before sending

#### API Endpoints

##### Endpoint 1: Send Notification (Internal API)
```
POST /api/v1/notifications/send
```

**Request**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "notification_type": "email_verification",
  "recipient": "user@example.com",
  "template_data": {
    "first_name": "John",
    "verification_url": "https://app.sumafinance.com/verify?token=..."
  }
}
```

**Response (202 Accepted)**:
```json
{
  "notification_id": "990e8400-e29b-41d4-a716-446655440004",
  "status": "pending",
  "message": "Notification queued for delivery"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid recipient, missing template data
- `404 Not Found`: Template not found
- `429 Too Many Requests`: Rate limit exceeded (3 emails per minute per user)
- `500 Internal Server Error`: Server error

**Business Rules**:
- Validate recipient format (email or E.164 phone)
- Rate limit: 3 notifications per minute per user (prevent abuse)
- Deduplicate: Prevent duplicate notifications within 5 minutes (using Redis)
- Queue notification for async sending
- Return immediately (async processing)

##### Endpoint 2: Get Notification Status
```
GET /api/v1/notifications/{notification_id}
```

**Response (200 OK)**:
```json
{
  "notification_id": "990e8400-e29b-41d4-a716-446655440004",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "notification_type": "email_verification",
  "status": "sent",
  "sent_at": "2025-10-29T00:00:05Z",
  "delivered_at": "2025-10-29T00:00:08Z"
}
```

**Error Responses**:
- `404 Not Found`: Notification not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Return delivery status (updated by webhooks from email provider)

##### Endpoint 3: Webhook for Email Provider (SendGrid)
```
POST /api/v1/notifications/webhooks/sendgrid
```

**Request** (from SendGrid):
```json
[
  {
    "email": "user@example.com",
    "event": "delivered",
    "sg_message_id": "sendgrid_msg_id_123",
    "timestamp": 1698624000
  }
]
```

**Response (200 OK)**:
```json
{
  "message": "Webhook processed"
}
```

**Business Rules**:
- Verify webhook signature (HMAC-SHA256)
- Update notification status based on event (delivered, bounced, dropped)
- Log webhook event

##### Endpoint 4: Resend Notification
```
POST /api/v1/notifications/{notification_id}/resend
```

**Response (202 Accepted)**:
```json
{
  "notification_id": "990e8400-e29b-41d4-a716-446655440004",
  "status": "pending",
  "retry_count": 1
}
```

**Error Responses**:
- `400 Bad Request`: Max retries exceeded (3)
- `404 Not Found`: Notification not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Increment `retry_count`
- Max 3 retries
- Queue for async sending

#### Database Schema

**Tables**:
```sql
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    notification_type VARCHAR(50) NOT NULL,
    recipient VARCHAR(255) NOT NULL,
    template_name VARCHAR(100) NOT NULL,
    template_data JSONB NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    provider VARCHAR(50),
    provider_message_id VARCHAR(255),
    error_message TEXT,
    sent_at TIMESTAMP,
    delivered_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    retry_count INTEGER DEFAULT 0,
    CONSTRAINT notification_type_check CHECK (notification_type IN ('email_verification', 'password_reset', 'otp_email', 'otp_sms', 'security_alert', 'account_locked', 'password_changed')),
    CONSTRAINT status_check CHECK (status IN ('pending', 'sent', 'failed', 'bounced')),
    CONSTRAINT retry_count_check CHECK (retry_count <= 3)
);

CREATE INDEX idx_notifications_user_created ON notifications(user_id, created_at DESC);
CREATE INDEX idx_notifications_status ON notifications(status);
CREATE INDEX idx_notifications_provider_message_id ON notifications(provider_message_id);

CREATE TABLE email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_name VARCHAR(100) UNIQUE NOT NULL,
    subject VARCHAR(255) NOT NULL,
    body_html TEXT NOT NULL,
    body_text TEXT NOT NULL,
    version VARCHAR(20) DEFAULT '1.0',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_email_templates_name_version ON email_templates(template_name, version);
```

**Indexes**:
- `idx_notifications_user_created`: For retrieving user notification history
- `idx_notifications_status`: For monitoring failed notifications
- `idx_notifications_provider_message_id`: For webhook lookups

**Partitioning Strategy**: Partition `notifications` table by month (for performance)

#### Dependencies

**Upstream Dependencies**:
- None (event-driven)

**Downstream Consumers**:
- None (Notification Service is a leaf service)

**External Dependencies**:
- **SendGrid**: Primary email provider
  - **SLA**: 99.99% uptime
  - **Rate Limit**: 100 emails/second (per API key)
  - **Fallback**: AWS SES if SendGrid fails
  
- **AWS SES**: Fallback email provider
  - **SLA**: 99.9% uptime
  - **Rate Limit**: 14 emails/second (default sandbox limit)
  
- **Twilio**: SMS provider for OTP
  - **SLA**: 99.95% uptime
  - **Rate Limit**: 1 SMS/second (default)

#### Events Published

**Event**: `notification.sent`
**Event**: `notification.failed`
**Event**: `notification.delivered`

#### Events Consumed

**Event**: `user.registered` (from Authentication Service)
**Action**: Send email verification
**Handler**: `handleUserRegistered()`

**Event**: `password_reset.requested` (from Authentication Service)
**Action**: Send password reset email
**Handler**: `handlePasswordResetRequested()`

**Event**: `2fa.required` (from Authentication Service)
**Action**: Send OTP via email/SMS
**Handler**: `handle2FARequired()`

**Event**: `user.logged_in` (from Authentication Service)
**Action**: Send security alert if new device
**Handler**: `handleUserLoggedIn()`

**Event**: `account.locked` (from Authentication Service)
**Action**: Send account locked notification
**Handler**: `handleAccountLocked()`

**Event**: `password.changed` (from Authentication Service)
**Action**: Send password change confirmation
**Handler**: `handlePasswordChanged()`

#### Data Management

**Data Ownership**:
- Single source of truth for: Notification history, email templates

**Data Access Patterns**:
- Write-heavy: 70% (send notifications)
- Read-heavy: 30% (check status, webhook updates)
- Read/Write ratio: 1:2.3

**Caching Strategy**:
- **Cache Templates**: Cache email templates in memory (5-min TTL)
- **Deduplication**: Redis key `notification:dedup:{user_id}:{type}` (5-min TTL)
- **Rate Limiting**: Redis key `ratelimit:notification:{user_id}` (1-min TTL)

**Data Retention**:
- **Notifications**: Retained for 90 days (compliance)
- **Email Templates**: Versioned, retained indefinitely

#### Scalability Design

**Horizontal Scaling**:
- Stateless service
- Worker queue pattern (RabbitMQ consumers)
- Auto-scaling based on queue depth

**Performance Targets**:
- **Response Time**: p50 < 50ms (queueing), actual send time varies by provider
- **Throughput**: 100 emails/second (limited by SendGrid rate)
- **Queue Processing**: < 5 seconds from event to email sent

#### Resilience Patterns

**Circuit Breaker**: For email providers (SendGrid, SES)
**Retry Policy**: 3 retries with exponential backoff (1min, 5min, 15min)
**Timeout Configuration**: SendGrid API: 10s, Twilio API: 5s
**Fallback Strategies**: SendGrid fails → AWS SES, SES fails → Queue for manual review

#### Security Implementation

**Authentication**: Internal API (called by other services via service-to-service auth)
**Authorization**: N/A (internal service)
**Data Protection**: 
- Recipient email/phone encrypted at rest
- Webhook signature verification (HMAC-SHA256)
- TLS 1.3 for all API calls
**Input Validation**: Validate email format, phone format, template data schema

#### Monitoring & Observability

**Health Checks**: Check SendGrid API health
**Metrics**:
- `notifications_sent_total{type, provider, status}`
- `notifications_failed_total{type, provider, reason}`
- `notifications_delivery_duration_seconds{type}` (from send to delivered)
- `email_provider_api_duration_seconds{provider, endpoint}`
- `queue_depth_gauge` (RabbitMQ queue depth)

**Logging**: Log all notifications with trace context, recipient (hashed), template
**Alerting**:
- Notification failure rate > 5% for 5 minutes
- Email delivery time > 30 seconds for 5 minutes
- SendGrid API error rate > 10% for 5 minutes
- Queue depth > 1000 (backlog)

#### Testing Strategy

**Unit Tests**: Coverage > 80%, test template rendering, rate limiting
**Integration Tests**: Test SendGrid/SES integration (sandbox mode), webhook processing
**Performance Tests**: Load test queue processing (1000 notifications/minute)

#### Deployment Configuration

**Container**: Node.js 20 Alpine-based image
**Resources**: CPU 200m (request), 1000m (limit); Memory 256Mi (request), 512Mi (limit)
**Replicas**: Minimum 3 (for queue processing)
**Environment Variables**: SENDGRID_API_KEY, AWS_SES_REGION, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, DATABASE_URL, REDIS_URL, RABBITMQ_URL

#### Disaster Recovery

**Backup**: Database snapshots daily, retained 30 days
**RTO**: 30 minutes
**RPO**: 15 minutes (acceptable loss of notification history)

---

### Service 5: Audit Service

#### Service Overview
**Purpose**: Comprehensive logging and audit trail for all authentication and security events
**Domain**: Compliance & Audit Context
**Team Ownership**: Security Team

#### Responsibilities
- Log all authentication events (login, logout, failed attempts, 2FA)
- Log all security events (password changes, account lockouts, suspicious activity)
- Log GDPR consent changes
- Provide audit trail for compliance (SOC 2, GDPR, ISO 27001)
- Real-time security alerting for anomalies
- Generate compliance reports
- Data retention and archival (7 years for financial compliance)

#### Technology Stack
- **Language/Runtime**: Python 3.11
- **Framework**: FastAPI
- **API Protocol**: REST (JSON)
- **Database**: PostgreSQL 15 (audit logs with append-only pattern)
- **Database**: Elasticsearch 8.x (for fast search and analytics)
- **Cache**: Redis 7.2 (rate limiting)
- **Message Broker**: RabbitMQ 3.12 (event-driven logging)

#### Domain Model
**Entities**:
```
Audit Event Entity
├── id: UUID (Primary Key)
├── event_id: UUID (from source event)
├── user_id: UUID (Nullable, for unauthenticated events)
├── event_type: String (e.g., "user.logged_in", "password.changed")
├── event_category: Enum (authentication, authorization, data_access, consent, security)
├── actor: String (user email or "system" or "admin")
├── action: String (login, logout, register, update, delete, export)
├── resource: String (e.g., "user_profile", "session", "consent")
├── resource_id: String (Nullable)
├── status: Enum (success, failure, error)
├── ip_address: String
├── user_agent: String
├── geolocation: JSONB (country, city, lat/lon)
├── device_id: String (Nullable)
├── metadata: JSONB (additional context)
├── risk_score: Integer (0-100, for anomaly detection)
├── timestamp: Timestamp (indexed)
└── INDEX on (user_id, timestamp DESC), (event_type, timestamp DESC)
```

**Value Objects**:
- **EventCategory**: authentication, authorization, data_access, consent, security
- **EventStatus**: success, failure, error

**Aggregates**:
- **Root**: Audit Event (append-only, immutable)
- **Invariants**: 
  - Audit events cannot be updated or deleted (immutability)
  - Timestamp must be in UTC
  - All events must have event_type and timestamp

#### API Endpoints

##### Endpoint 1: Create Audit Event (Internal API)
```
POST /api/v1/audit/events
```

**Request**:
```json
{
  "event_id": "evt_550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "event_type": "user.logged_in",
  "event_category": "authentication",
  "actor": "user@example.com",
  "action": "login",
  "resource": "session",
  "status": "success",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0",
  "device_id": "device-fingerprint-hash",
  "metadata": {
    "session_id": "session_550e8400",
    "2fa_used": false
  }
}
```

**Response (201 Created)**:
```json
{
  "audit_id": "aa0e8400-e29b-41d4-a716-446655440005",
  "timestamp": "2025-10-29T00:00:00Z"
}
```

**Error Responses**:
- `400 Bad Request`: Missing required fields
- `500 Internal Server Error`: Server error

**Business Rules**:
- Store in PostgreSQL (append-only)
- Index in Elasticsearch for fast search
- Enrich with geolocation data (IP → country/city using GeoIP2)
- Calculate risk score based on anomaly detection (new IP, impossible travel, etc.)
- Publish `audit.event_logged` event (for SIEM integration)

##### Endpoint 2: Query Audit Events
```
GET /api/v1/audit/events?user_id={user_id}&event_type={event_type}&start_date={start}&end_date={end}&page=1&limit=50
```

**Response (200 OK)**:
```json
{
  "total": 125,
  "page": 1,
  "limit": 50,
  "events": [
    {
      "audit_id": "aa0e8400-e29b-41d4-a716-446655440005",
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "event_type": "user.logged_in",
      "actor": "user@example.com",
      "action": "login",
      "status": "success",
      "ip_address": "192.168.1.100",
      "timestamp": "2025-10-29T00:00:00Z"
    }
  ]
}
```

**Error Responses**:
- `400 Bad Request`: Invalid date range
- `401 Unauthorized`: Invalid JWT
- `403 Forbidden`: User can only query their own events (unless admin)
- `500 Internal Server Error`: Server error

**Business Rules**:
- Query Elasticsearch for fast results
- Users can query their own events
- Admins can query all events
- Support filters: user_id, event_type, event_category, status, date range
- Return paginated results

##### Endpoint 3: Get User Audit Trail (GDPR)
```
GET /api/v1/audit/users/{user_id}/trail
```

**Response (200 OK)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "total_events": 245,
  "events": [
    {
      "timestamp": "2025-10-29T00:00:00Z",
      "event_type": "user.registered",
      "action": "register",
      "ip_address": "192.168.1.100"
    },
    {
      "timestamp": "2025-10-29T01:00:00Z",
      "event_type": "user.verified",
      "action": "verify_email"
    }
  ]
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid JWT
- `403 Forbidden`: User cannot access another user's trail
- `404 Not Found`: User not found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Used for GDPR data export
- Return complete audit trail for user

##### Endpoint 4: Generate Compliance Report
```
POST /api/v1/audit/reports/compliance
```

**Request**:
```json
{
  "report_type": "failed_login_attempts",
  "start_date": "2025-10-01",
  "end_date": "2025-10-31",
  "format": "csv"
}
```

**Response (200 OK)**:
```json
{
  "report_id": "rpt_550e8400-e29b-41d4-a716-446655440000",
  "download_url": "https://s3.amazonaws.com/suma-audit-reports/rpt_550e8400.csv",
  "expires_at": "2025-11-01T00:00:00Z"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid report type or date range
- `401 Unauthorized`: Invalid JWT (admin only)
- `403 Forbidden`: User is not admin
- `500 Internal Server Error`: Server error

**Business Rules**:
- Admin-only endpoint
- Supported report types: failed_login_attempts, account_lockouts, consent_changes, data_exports, data_deletions
- Generate report asynchronously, upload to S3, return download URL
- Reports expire after 24 hours

##### Endpoint 5: Detect Anomalies
```
GET /api/v1/audit/anomalies?user_id={user_id}
```

**Response (200 OK)**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "anomalies": [
    {
      "anomaly_id": "ano_550e8400",
      "event_type": "user.logged_in",
      "reason": "Impossible travel: Login from US and Portugal within 1 hour",
      "risk_score": 85,
      "timestamp": "2025-10-29T00:00:00Z",
      "recommended_action": "Force password reset"
    }
  ]
}
```

**Error Responses**:
- `404 Not Found`: No anomalies found
- `500 Internal Server Error`: Server error

**Business Rules**:
- Detect anomalies using rules:
  - Impossible travel (login from two distant locations within short time)
  - Unusual time (login at 3 AM when user typically logs in during day)
  - New device without 2FA
  - Multiple failed login attempts followed by success (credential stuffing)
- Assign risk score (0-100)
- Publish `security.anomaly_detected` event for alerting

#### Database Schema

**PostgreSQL Table**:
```sql
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    user_id UUID,
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id VARCHAR(255),
    status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    geolocation JSONB,
    device_id VARCHAR(255),
    metadata JSONB,
    risk_score INTEGER DEFAULT 0,
    timestamp TIMESTAMP DEFAULT NOW(),
    CONSTRAINT event_category_check CHECK (event_category IN ('authentication', 'authorization', 'data_access', 'consent', 'security')),
    CONSTRAINT status_check CHECK (status IN ('success', 'failure', 'error')),
    CONSTRAINT risk_score_check CHECK (risk_score >= 0 AND risk_score <= 100)
);

CREATE INDEX idx_audit_events_user_timestamp ON audit_events(user_id, timestamp DESC);
CREATE INDEX idx_audit_events_type_timestamp ON audit_events(event_type, timestamp DESC);
CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_events_risk_score ON audit_events(risk_score DESC) WHERE risk_score > 70;

-- Partition by month for performance
CREATE TABLE audit_events_2025_10 PARTITION OF audit_events
FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
```

**Elasticsearch Index**:
```json
{
  "mappings": {
    "properties": {
      "event_id": { "type": "keyword" },
      "user_id": { "type": "keyword" },
      "event_type": { "type": "keyword" },
      "event_category": { "type": "keyword" },
      "actor": { "type": "keyword" },
      "action": { "type": "keyword" },
      "status": { "type": "keyword" },
      "ip_address": { "type": "ip" },
      "geolocation": {
        "type": "object",
        "properties": {
          "country": { "type": "keyword" },
          "city": { "type": "keyword" },
          "location": { "type": "geo_point" }
        }
      },
      "risk_score": { "type": "integer" },
      "timestamp": { "type": "date" }
    }
  }
}
```

**Indexes**:
- PostgreSQL: Partitioned by month, indexed on user_id and timestamp
- Elasticsearch: Full-text search on all fields, geo-queries for location-based analytics

**Partitioning Strategy**: Monthly partitions for PostgreSQL (for performance and archival)

#### Dependencies

**Upstream Dependencies**:
- None (event-driven)

**Downstream Consumers**:
- **User Service**: Get user audit trail for GDPR export

**External Dependencies**:
- **PostgreSQL**: Append-only audit log
- **Elasticsearch**: Fast search and analytics
- **Redis**: Rate limiting (prevent log flooding)
- **GeoIP2**: IP geolocation enrichment
- **AWS S3**: Compliance report storage

#### Events Published

**Event**: `audit.event_logged`
**Event**: `security.anomaly_detected`

#### Events Consumed

**All events from other services** (Authentication, User, Session, Notification):
- `user.registered`, `user.logged_in`, `user.logged_out`, `user.verified`
- `password.changed`, `password_reset.requested`, `account.locked`
- `2fa.required`, `2fa.verified`
- `session.created`, `session.revoked`, `session.reuse_detected`
- `user.consent_updated`, `user.deletion_requested`, `user.deleted`
- `notification.sent`, `notification.failed`

**Action**: Create audit event for each consumed event
**Handler**: `handleEventForAudit()`

#### Data Management

**Data Ownership**:
- Single source of truth for: Audit logs, compliance reports

**Data Access Patterns**:
- Write-heavy: 95% (append-only logging)
- Read-heavy: 5% (compliance queries, anomaly detection)
- Read/Write ratio: 1:19

**Caching Strategy**:
- No caching (audit data must be real-time)
- Elasticsearch provides fast queries

**Data Retention**:
- **Audit Logs**: Retained for 7 years (financial compliance)
- **Archived Logs**: Moved to S3 Glacier after 1 year (cost optimization)

#### Scalability Design

**Horizontal Scaling**:
- Stateless service
- Worker queue pattern (RabbitMQ consumers for high throughput)
- Elasticsearch cluster for horizontal scaling

**Performance Targets**:
- **Write Throughput**: 10,000 events/second
- **Query Response Time**: p95 < 500ms (Elasticsearch)

#### Resilience Patterns

**Circuit Breaker**: For Elasticsearch (fallback to PostgreSQL)
**Retry Policy**: Retry failed writes 3 times
**Timeout Configuration**: PostgreSQL: 5s, Elasticsearch: 3s
**Fallback Strategies**: Elasticsearch unavailable → Query PostgreSQL directly (slower but reliable)

#### Security Implementation

**Authentication**: Internal API (service-to-service auth)
**Authorization**: Admins can query all events, users can query own events
**Data Protection**:
- Audit logs are immutable (append-only)
- Encrypted at rest (PostgreSQL, Elasticsearch)
- Sensitive fields masked (passwords never logged)
- IP addresses logged for security but considered PII (GDPR consideration)

#### Monitoring & Observability

**Health Checks**: Check PostgreSQL and Elasticsearch health
**Metrics**:
- `audit_events_created_total{event_type, status}`
- `audit_events_high_risk_total` (risk_score > 70)
- `audit_query_duration_seconds{query_type}`
- `elasticsearch_index_lag_seconds` (write lag)

**Logging**: Meta-logging (log all audit service operations)
**Alerting**:
- High-risk events detected (risk_score > 80)
- Audit event write failure rate > 1%
- Elasticsearch cluster health red/yellow

#### Testing Strategy

**Unit Tests**: Coverage > 80%, test anomaly detection logic
**Integration Tests**: Test PostgreSQL writes, Elasticsearch indexing
**Performance Tests**: Load test event ingestion (10,000 events/second)

#### Deployment Configuration

**Container**: Python 3.11 Alpine-based image
**Resources**: CPU 300m (request), 1000m (limit); Memory 512Mi (request), 1Gi (limit)
**Replicas**: Minimum 3 (for queue processing)
**Environment Variables**: DATABASE_URL, ELASTICSEARCH_URL, REDIS_URL, RABBITMQ_URL, GEOIP2_LICENSE_KEY, AWS_S3_BUCKET

#### Disaster Recovery

**Backup**: 
- PostgreSQL: Daily snapshots, retained 7 years
- Elasticsearch: Daily snapshots to S3, retained 7 years
**RTO**: 2 hours (acceptable for audit logs)
**RPO**: 15 minutes (acceptable loss)

---

## Inter-Service Communication

### Synchronous Communication (REST)

**When to Use**:
- Client needs immediate response (login, token validation)
- Request-response pattern
- Low latency required (< 500ms)

**Example Flow**:
```
API Gateway → Authentication Service (validate credentials) → User Service (get profile)
     ↓
  Response (JWT tokens)
```

**Protocol**: REST with JSON over HTTPS
**Timeout**: 10 seconds
**Retry**: 3 attempts with exponential backoff (100ms, 500ms, 2s)
**Circuit Breaker**: Open after 5 consecutive failures, half-open after 30 seconds

### Asynchronous Communication (Message Queue)

**When to Use**:
- Fire-and-forget operations (send email, log audit event)
- Event-driven workflows
- Decoupling services (notification failure doesn't block authentication)

**Message Broker**: RabbitMQ 3.12

**Example Flow**:
```
Authentication Service → [Queue: user.registered] → Notification Service (send verification email)
                                                  → Audit Service (log registration event)
                                                  → User Service (create profile)
```

**Message Format**:
```json
{
  "message_id": "msg_550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-10-29T00:00:00Z",
  "event_type": "user.registered",
  "version": "1.0",
  "payload": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com"
  },
  "metadata": {
    "trace_id": "trace_550e8400",
    "ip_address": "192.168.1.100",
    "user_agent": "Mozilla/5.0"
  }
}
```

**Delivery Guarantees**: At-least-once (use idempotency keys to handle duplicates)
**Dead Letter Queue**: Messages that fail after 3 retries moved to DLQ for manual review
**Message TTL**: 1 hour (prevent stale messages)

### Event-Driven Architecture

**Event Bus**: RabbitMQ with topic exchanges

**Event Types**:
1. **Domain Events**: Business events (`user.registered`, `password.changed`)
2. **Integration Events**: Cross-service events (`session.created`, `notification.sent`)
3. **System Events**: Infrastructure events (`service.started`, `database.failover`)

**Event Schema Registry**: Use JSON Schema to ensure backward compatibility
- Store schemas in Git repository
- Version schemas (e.g., `user.registered.v1.0`, `user.registered.v2.0`)
- Consumers must handle multiple schema versions

**Event Sourcing**: Not used (traditional CRUD with audit trail is sufficient for authentication domain)

## Service Mesh (Optional)

**Technology**: Istio 1.20 (if microservices scale beyond 10 services)

**Capabilities Provided**:
- **Service Discovery**: Automatic via Kubernetes DNS
- **Load Balancing**: Round-robin with health-check-based routing
- **Traffic Routing**: Canary deployments (10% → 50% → 100%)
- **mTLS**: Automatic mutual TLS between services
- **Observability**: Distributed tracing (Jaeger), metrics (Prometheus)
- **Circuit Breaking**: Automatic based on error rate and latency

**Configuration Example** (Istio VirtualService for Canary Deployment):
```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: auth-service
spec:
  hosts:
    - auth-service
  http:
    - match:
        - headers:
            canary:
              exact: "true"
      route:
        - destination:
            host: auth-service
            subset: v2
    - route:
        - destination:
            host: auth-service
            subset: v1
          weight: 90
        - destination:
            host: auth-service
            subset: v2
          weight: 10
```

**Decision**: Defer Istio until service count > 10 (overhead not justified for 5 services)

## Data Management Strategy

### Database per Service Pattern
Each service owns its data store:
- **Authentication Service**: PostgreSQL (credentials, password history)
- **User Service**: PostgreSQL (profiles, consents)
- **Session Service**: Redis (active sessions) + PostgreSQL (session history)
- **Notification Service**: PostgreSQL (notification history)
- **Audit Service**: PostgreSQL (audit logs) + Elasticsearch (search/analytics)

**Why PostgreSQL**: ACID compliance, strong consistency for financial data, mature ecosystem

### Distributed Transactions

**Saga Pattern**: Choreography (event-driven)

**Example Saga**: User Registration
1. **Authentication Service**: Create credentials → Publish `user.registered` event
2. **User Service**: (Consumes `user.registered`) Create profile → Publish `user.profile_created` event
3. **Notification Service**: (Consumes `user.registered`) Send verification email
4. **Audit Service**: (Consumes `user.registered`) Log registration event

**Compensating Transactions**:
- If email send fails → Retry 3 times, then move to DLQ (user can request resend later)
- If profile creation fails → Delete credentials (compensating action), notify user of error
- No partial states: Either all succeed (eventually) or all roll back

### Data Consistency

**Consistency Model**: Eventual consistency (acceptable for authentication domain)
- User sees "Verification email sent" immediately (even if email send is pending)
- Email arrives within 5 seconds (acceptable delay)

**Conflict Resolution**: Last-write-wins (LWW) based on timestamp
- Example: User updates profile from two devices simultaneously → Latest timestamp wins

**Data Synchronization**: Via events
- Authentication Service publishes `user.logged_in` → User Service updates `last_login_at`
- Eventual consistency acceptable (lag < 1 second)

### Cross-Service Queries

**Anti-Pattern**: Don't query other service's databases directly (violates encapsulation)

**Solutions**:
1. **API Composition**: Call multiple service APIs and merge results
   - Example: Get user profile with last login → Call User Service API and Session Service API
   
2. **CQRS**: Separate read models
   - User Service maintains read replica with `last_login_at` (updated via events from Session Service)
   - Optimizes read performance, eventual consistency is acceptable
   
3. **Data Replication**: Subscribe to events and maintain local read replicas
   - Audit Service subscribes to all events to build comprehensive audit trail

## Service Discovery

**Mechanism**: Kubernetes DNS

**Registration**:
- Services automatically registered in Kubernetes DNS (e.g., `auth-service.default.svc.cluster.local`)
- No manual registration required

**Discovery**:
- Services resolve by name: `http://auth-service:8080`
- Kubernetes DNS resolves to service ClusterIP
- Kube-proxy handles load balancing across pods

**Health Checks**:
- Liveness probe: `/health/live` (restart pod if fails)
- Readiness probe: `/health/ready` (remove from load balancer if fails)
- Startup probe: `/health/startup` (allow slow startup without premature restarts)

## API Gateway Integration

**Gateway**: Kong 3.4 (or AWS API Gateway)

**Responsibilities**:
- **Authentication/Authorization**: Validate JWT tokens (call Authentication Service's `/validate-token` endpoint)
- **Rate Limiting**: Global rate limits (1000 req/min per IP)
- **Request Routing**: Route to backend services based on path
- **Response Aggregation**: BFF pattern for mobile apps (aggregate multiple API calls)
- **Protocol Translation**: N/A (all services use REST/JSON)
- **TLS Termination**: Handle TLS at gateway, use mTLS between gateway and services

**Routing Configuration**:
| Path Pattern | Backend Service | Auth Required | Rate Limit |
|--------------|-----------------|---------------|------------|
| /api/v1/auth/* | auth-service:8080 | No (handles auth internally) | 10/min per IP (login) |
| /api/v1/users/* | user-service:8080 | Yes (JWT) | 100/min per user |
| /api/v1/sessions/* | session-service:8080 | Yes (JWT) | 100/min per user |
| /api/v1/notifications/* | notification-service:3000 | Internal only | N/A |
| /api/v1/audit/* | audit-service:8000 | Yes (JWT, admin only) | 50/min per user |

**JWT Validation Flow**:
1. Client sends request with `Authorization: Bearer <JWT>` header
2. Gateway extracts JWT and calls `auth-service:8080/api/v1/auth/validate-token`
3. If valid, gateway forwards request to backend service with user context in header (`X-User-ID`, `X-User-Email`)
4. Backend service trusts gateway's validation (internal network)

## Security Architecture

### Defense in Depth

**Layer 1: Network Security**
- **Private Subnets**: All services in private subnets (no public IPs)
- **Security Groups**: Allow traffic only from API Gateway to services
- **NACLs**: Network-level firewall rules
- **WAF**: AWS WAF at edge (API Gateway) with OWASP Top 10 rules

**Layer 2: Service-to-Service Auth**
- **Mutual TLS (mTLS)**: All services communicate via mTLS (certificates issued by internal CA)
- **Service Accounts**: Each service has unique Kubernetes service account
- **JWT for User Context**: API Gateway validates JWT, passes user context in headers

**Layer 3: Application Security**
- **Input Validation**: All inputs validated using JSON Schema (FastAPI/Pydantic for Python, struct tags for Go)
- **Output Encoding**: Not applicable for JSON APIs (no HTML rendering)
- **OWASP Top 10 Protections**: Implemented per service (see Security Implementation sections)

**Layer 4: Data Security**
- **Encryption at Rest**: PostgreSQL encrypted with AWS KMS, AES-256-GCM for PII fields
- **Encryption in Transit**: TLS 1.3 for all communications
- **Key Rotation**: Encryption keys rotated every 90 days

### Secrets Management
- **Tool**: AWS Secrets Manager
- **Rotation**: Automatic rotation every 90 days (database passwords, API keys, JWT signing keys)
- **Access**: IAM roles per service (principle of least privilege)
- **Audit**: All secret access logged in CloudTrail

### Compliance
- **GDPR**: 
  - Right to access: User Service's `/export` endpoint
  - Right to erasure: User Service's `/delete` endpoint (30-day grace period)
  - Consent management: GDPR Consent entity in User Service
  - Data breach notification: Audit Service's alerting for security anomalies
  
- **SOC 2**: 
  - Audit logging: Audit Service logs all events
  - Access controls: RBAC enforced at API Gateway and service level
  - Change management: All infrastructure changes via Terraform (version controlled)
  - Incident response: Runbooks for security incidents (in Confluence)
  
- **PCI-DSS**: (If handling payment data in future)
  - Strong cryptography: Argon2id, AES-256, TLS 1.3
  - Secure authentication: JWT with short expiry, 2FA

## Deployment Strategy

### Deployment Patterns

**Blue-Green Deployment**:
- Deploy new version (green) alongside old version (blue)
- Switch traffic atomically via Kubernetes service selector update
- Quick rollback by switching selector back to blue
- Used for: Major version updates with breaking changes

**Canary Deployment**:
- Deploy new version to 10% of pods
- Monitor metrics (error rate, latency) for 15 minutes
- If healthy, increase to 50%, then 100%
- Automatic rollback if error rate > 1%
- Used for: Regular feature releases

**Rolling Update**:
- Update pods one at a time (or in batches of 2 for 6 replicas)
- Health check each pod before continuing
- Automatic rollback on health check failure
- Used for: Minor updates and bug fixes

### CI/CD Pipeline

```
Code Commit → Build (Docker image) → Unit Tests → Integration Tests → Security Scan (Snyk) → 
Deploy to Dev → Integration Tests → Deploy to Staging → E2E Tests → Manual Approval → 
Deploy to Prod (Canary) → Smoke Tests → Monitor for 1 hour → Full Rollout
```

**Build Time**: < 10 minutes per service
**Deployment Frequency**: Multiple times per day (per service)
**Rollback Time**: < 5 minutes (automated via Kubernetes)

**CI/CD Tools**:
- **Source Control**: GitHub
- **CI**: GitHub Actions
- **Container Registry**: AWS ECR
- **CD**: ArgoCD (GitOps)
- **Infrastructure**: Terraform (EKS, RDS, ElastiCache)

### Infrastructure as Code

**Tool**: Terraform 1.6

**Version Control**: Git (separate repo: `suma-finance-infrastructure`)

**Environment Parity**: Dev, Staging, Prod use identical Terraform modules (only variables differ)

**Example Terraform Module** (EKS cluster):
```hcl
module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  cluster_name    = "suma-finance-${var.environment}"
  cluster_version = "1.28"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets

  node_groups = {
    auth = {
      desired_capacity = 3
      max_capacity     = 10
      min_capacity     = 3
      instance_types   = ["t3.medium"]
    }
  }
}
```

## Monitoring & Operations

### Observability Stack

**Metrics**: Prometheus + Grafana
- Prometheus scrapes `/metrics` endpoint from each service (Prometheus format)
- Grafana dashboards for visualization
- Alertmanager for alerting

**Logs**: ELK Stack (Elasticsearch, Logstash, Kibana)
- Fluentd DaemonSet collects logs from all pods
- Logs sent to Elasticsearch
- Kibana for log search and visualization

**Traces**: Jaeger
- OpenTelemetry SDK in each service
- Trace context propagated via HTTP headers (`X-Trace-Id`, `X-Span-Id`)
- Jaeger UI for distributed trace visualization

**APM**: Datadog (optional, for deeper insights)
- Application performance monitoring
- Real user monitoring (RUM) for mobile apps
- Synthetic monitoring (health checks from multiple regions)

### Dashboards

**Service Dashboard** (per service):
- **Golden Signals**:
  - Latency: p50, p95, p99 response times
  - Traffic: Requests per second
  - Errors: Error rate (%)
  - Saturation: CPU/Memory usage (%)
- **Custom Metrics**:
  - Authentication Service: Login success rate, 2FA usage rate, account lockout rate
  - Session Service: Active sessions gauge, refresh token rotation rate
  - Notification Service: Email delivery rate, email delivery time

**Business Dashboard**:
- **User Metrics**:
  - New registrations per day
  - Active users (DAU, MAU)
  - User growth rate
- **Security Metrics**:
  - Failed login attempts per hour
  - High-risk security events per day
  - Account lockouts per day
- **System Health**:
  - Overall system availability (%)
  - Average API response time (ms)
  - Error rate across all services (%)

### On-Call & Incident Response

**On-Call Rotation**: 
- Primary: Identity Team (Authentication, Session services)
- Secondary: Platform Team (Notification, Audit services)
- Escalation: Security Team (for security incidents)

**Escalation Path**:
1. Alert fires → PagerDuty notifies primary on-call
2. If no response in 15 minutes → Escalate to secondary on-call
3. If critical security incident → Escalate to Security Team lead
4. If P0 incident affecting all users → Escalate to CTO

**Runbooks**: Documented in Confluence (internal wiki)
- "Account Lockout Rate High" → Check for brute-force attack, review IP addresses in Audit Service
- "Session Service Redis Down" → Failover to standby Redis instance, investigate root cause
- "Email Delivery Failure Spike" → Check SendGrid status, switch to AWS SES if needed

**Post-Mortem**: After major incidents (P0, P1)
- Incident timeline
- Root cause analysis (5 Whys)
- Action items with owners and deadlines
- Share learnings with entire engineering team

## Performance Optimization

### Caching Strategy
- **L1**: Application-level (in-memory)
  - User Service: Cache user profiles in memory (5-min TTL, 1000 entries max)
  - Authentication Service: Cache JWT public key in memory (refresh every 24 hours)
  
- **L2**: Distributed cache (Redis)
  - Session Service: Active sessions (7-day TTL)
  - Authentication Service: OTP codes (5-min TTL), rate limiting counters (1-hour TTL)
  - User Service: User profiles (5-min TTL)
  
- **L3**: CDN for static assets (CloudFront)
  - Email templates (images, CSS for HTML emails)

**Cache Invalidation**:
- **Write-Through**: Update cache immediately after database write (used for critical data)
- **Cache-Aside**: Lazy load (read from cache, on miss read from DB and populate cache)
- **Event-Driven**: Invalidate cache on relevant events (e.g., `user.profile_updated` → invalidate `user:profile:{user_id}` in Redis)

### Database Optimization
- **Proper Indexing**: All foreign keys indexed, indexes on frequently queried columns (email, user_id, timestamp)
- **Query Optimization**: Use `EXPLAIN ANALYZE` to identify slow queries, add covering indexes
- **Connection Pooling**: Max 100 connections per service (pgBouncer for connection pooling)
- **Read Replicas**: User Service uses read replica for profile reads (90% of traffic), master for writes

### Asynchronous Processing
- **Background Workers**: Notification Service uses worker queues (RabbitMQ consumers) for email sending
- **Use Message Queues**: All non-critical operations (email, audit logging) via RabbitMQ
- **Batch Processing**: Audit Service processes log archival in batches (10,000 records at a time) during off-peak hours

## Cost Optimization

### Resource Right-Sizing
- **Monitor Actual Usage**: Use Prometheus metrics to identify over-provisioned services
- **Adjust CPU/Memory Allocations**: Example: Session Service only uses 50m CPU → Reduce request from 200m to 100m
- **Use Auto-Scaling**: Scale down during off-peak hours (e.g., 3 replicas at night vs 10 during day)

### Multi-Tenancy
- **Share Infrastructure**: All services share same EKS cluster (namespace isolation)
- **Namespace Isolation**: `suma-finance-auth`, `suma-finance-user`, etc.
- **Resource Quotas**: Set CPU/memory quotas per namespace to prevent noisy neighbors

### Reserved Capacity
- **Reserved Instances**: Purchase 1-year reserved instances for baseline capacity (3 replicas per service)
- **Spot Instances**: Use spot instances for batch processing (Audit Service log archival)
- **Savings Plans**: AWS Compute Savings Plans for predictable workloads

**Cost Estimate** (Monthly, for authentication services only):
- EKS Cluster: $73 (cluster management) + $150 (3x t3.medium nodes) = $223
- RDS PostgreSQL: $100 (db.t3.medium, Multi-AZ)
- ElastiCache Redis: $50 (cache.t3.micro)
- RabbitMQ (on EKS): $0 (self-hosted)
- Elasticsearch: $200 (3-node cluster on EKS)
- Data Transfer: $50
- **Total**: ~$620/month (scales with user growth)

## Migration Strategy

### Strangler Fig Pattern
(Not applicable - greenfield project)

If migrating from monolithic authentication in future:
1. Identify authentication module in monolith
2. Build new Authentication Service
3. Route new registrations/logins to new service via API Gateway
4. Gradually migrate existing users (dual-write to old and new systems)
5. Once all users migrated, decommission old authentication module

### API Versioning
- **Support v1 and v2 Simultaneously**: Run both versions in parallel during migration
- **Deprecation Notice Period**: 6 months
- **Documentation for Migration**: Provide migration guide in developer docs

**Example** (Breaking change in JWT claims):
- v1: JWT includes `user_id` (UUID)
- v2: JWT includes `user_id` (UUID) and `account_id` (new concept for multi-account support)
- Migration: All clients must upgrade to v2 within 6 months

**Versioning Strategy**:
- **URL Path**: `/api/v1/auth/login` vs `/api/v2/auth/login`
- **Header**: `Accept: application/vnd.sumafinance.v2+json` (alternative)

## Team Organization

### Conway's Law
Align teams with service boundaries:
- **Identity Team** (6 engineers): Authentication Service, Session Service
- **User Management Team** (4 engineers): User Service
- **Platform Team** (5 engineers): Notification Service, Audit Service, Infrastructure
- **Security Team** (3 engineers): Security reviews, penetration testing, compliance

### Ownership Model
- **End-to-End Ownership**: Each team owns their services from development to production
- **Responsible for**: Development, Testing, Deployment, Monitoring, On-Call, Documentation
- **SLAs**: Each service has defined SLA (e.g., 99.95% uptime, p95 latency < 300ms)

### Shared Responsibilities
- **Platform Team**: 
  - Infrastructure provisioning (Terraform, EKS)
  - CI/CD pipeline (GitHub Actions, ArgoCD)
  - Observability stack (Prometheus, Grafana, ELK, Jaeger)
  - Developer tooling (local development environments)
  
- **Security Team**: 
  - Security design reviews (before implementation)
  - Penetration testing (quarterly)
  - Compliance audits (SOC 2, GDPR)
  - Incident response coordination
  
- **Data Team**: (Future consideration)
  - Analytics and reporting (user growth, engagement metrics)
  - Data warehouse integration (Snowflake)

## Documentation

### Service Catalog
Centralized registry (Backstage or internal wiki):
- **Service Name**: Authentication Service
- **Description**: Handles user registration, login, password management, 2FA
- **Team Ownership**: Identity Team (@identity-team on Slack)
- **API Documentation**: OpenAPI/Swagger spec at `/docs` endpoint
- **Dependencies**: Session Service, User Service, Redis, PostgreSQL, RabbitMQ
- **Runbooks**: [Link to Confluence runbooks]
- **SLA**: 99.95% uptime, p95 latency < 200ms
- **Incidents**: [Link to incident history]

### Architecture Decision Records (ADRs)
Document all major decisions in Git repository (`docs/adr/`):

**Example ADR**:
```markdown
# ADR-001: Use JWT with Refresh Token Rotation

## Context
Need to implement secure authentication with token-based approach for stateless API.

## Decision
Use JWT access tokens (15-min expiry) with refresh token rotation (7-day expiry).

## Consequences
**Positive**:
- Stateless authentication (no server-side session store for access tokens)
- Short-lived access tokens limit exposure from theft
- Refresh token rotation mitigates refresh token theft

**Negative**:
- More complex than simple session-based auth
- Requires Session Service to track refresh tokens
- Token size larger than session ID (JWT payload)

## Alternatives Considered
1. Session-based auth (rejected: not stateless, requires sticky sessions)
2. Long-lived JWT (rejected: security risk if token stolen)
3. JWT with opaque refresh tokens (rejected: no benefit over current approach)

## References
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
```

## Future Considerations

### Service Split Candidates
As services grow, consider splitting:
- **Authentication Service** could be split into **Credential Service** (password management) and **Token Service** (JWT issuance) when authentication logic exceeds 10,000 LOC
- **User Service** could be split into **Profile Service** and **Consent Service** if GDPR requirements grow significantly

### Service Merge Candidates
If overhead too high:
- **Session Service** and **Authentication Service** could merge if session management remains simple (< 2000 LOC)

### Technology Evolution
- **Language Upgrades**: Go 1.21 → Go 1.23 (annual upgrades), Python 3.11 → Python 3.13
- **Framework Upgrades**: FastAPI 0.108 → 1.x (when stable), Gin 1.9 → 2.x
- **Database Migration**: PostgreSQL 15 → 16 (annual minor upgrades)
- **Social Login**: Add OAuth 2.0 providers (Google, Apple) in Phase 2
- **Biometric Auth**: Add WebAuthn/Passkey support in Phase 3
- **Passwordless Login**: Add magic link authentication in Phase 3

### Scaling Predictions
- **6 months**: 10,000 users, 5,000 req/s peak, 3 replicas per service
- **1 year**: 50,000 users, 20,000 req/s peak, 6 replicas per service, Redis Cluster (3 nodes)
- **2 years**: 200,000 users, 80,000 req/s peak, 10 replicas per service, multi-region (US + EU)

## Appendix

### Glossary
- **JWT**: JSON Web Token, a self-contained token format (RFC 7519)
- **Argon2id**: Memory-hard password hashing algorithm (PHC winner)
- **2FA**: Two-Factor Authentication, second verification step after password
- **OTP**: One-Time Password, 6-digit code with short expiry
- **mTLS**: Mutual TLS, both client and server authenticate each other
- **RBAC**: Role-Based Access Control, permissions based on user roles
- **GDPR**: General Data Protection Regulation (EU), data privacy law
- **SOC 2**: Service Organization Control 2, security and compliance framework
- **PCI-DSS**: Payment Card Industry Data Security Standard
- **OWASP**: Open Web Application Security Project
- **Circuit Breaker**: Design pattern to prevent cascading failures
- **Saga Pattern**: Distributed transaction pattern with compensating actions

### References
- [Pre-Gate 0 Research Document](link-to-enriched-requirements)
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Microservices Patterns (Chris Richardson)](https://microservices.io/patterns/)
- [JWT Best Practices (Auth0)](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-best-practices)

---

**End of Microservices Design Document**

Total Word Count: ~12,500 words

This comprehensive microservices design provides a production-ready architecture for SUMA Finance's authentication system with strong security, GDPR compliance, horizontal scalability, and operational excellence. Each service is independently deployable, resilient to failures, and designed for high availability in a financial application context.