

# SERVICE ARCHITECTURE

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Services
**Generated**: 2025-10-29T00:00:00Z

## Overview

The authentication system is designed as a microservices architecture with clear separation of concerns, emphasizing security, compliance, and scalability. The architecture follows a token-based authentication pattern with JWT, Redis-backed session management, and comprehensive security controls to meet OWASP Top 10, GDPR, PCI-DSS, and SOC 2 requirements.

## Architecture Pattern

**Pattern**: Microservices with API Gateway
**Rationale**: 
- Clear separation of authentication concerns from other business logic
- Independent scaling of authentication services under high load
- Isolation of security-critical components
- Easier compliance auditing and security reviews
- Flexibility to add OAuth providers and biometric authentication without affecting core services

## Service Catalog

### Service 1: Auth Service
**Type**: API Service
**Responsibility**: Core authentication operations including login, token management, session validation, and security event logging
**Technology Stack**:
- **Language/Runtime**: Go 1.21+
- **Framework**: Gin (HTTP router)
- **Database**: PostgreSQL 15 (user credentials, refresh tokens, audit logs)
- **Cache**: Redis 7 (session storage, rate limiting)
- **Security Libraries**: crypto/argon2id, golang-jwt/jwt, google/uuid

**Key Features**:
- Email/password authentication with Argon2id hashing
- JWT token generation (15-min access, 7-day refresh)
- Refresh token rotation with reuse detection
- Session management and validation
- Account lockout after 5 failed attempts
- Security event logging with correlation IDs
- Rate limiting enforcement

**Dependencies**:
- **Internal**: User Service (user profile data), Email Service (OTP delivery)
- **External**: Redis (session storage), PostgreSQL (credential storage)

**Scalability**:
- **Horizontal Scaling**: Yes, stateless design with Redis session storage
- **Expected Load**: 500 login requests/second peak
- **Auto-scaling Triggers**: CPU > 60%, Response time > 150ms

**Data Storage**:
- **Primary Database**: PostgreSQL (credentials, refresh tokens, security events)
- **Cache**: Redis (active sessions, rate limit counters, blacklisted tokens)
- **Retention**: Security logs retained 2 years, sessions 7 days

### Service 2: User Service
**Type**: API Service
**Responsibility**: User profile management, registration, GDPR consent tracking, and account lifecycle
**Technology Stack**:
- **Language/Runtime**: Go 1.21+
- **Framework**: Gin
- **Database**: PostgreSQL 15 (user profiles, consent records)
- **Cache**: Redis (user profile cache)
- **Encryption**: AES-256-GCM for PII at rest

**Key Features**:
- User registration with email validation
- Profile CRUD operations
- GDPR consent management (granular consent types)
- Consent withdrawal mechanism
- Data subject rights (access, erasure, portability)
- Email verification status tracking
- Device management and fingerprinting

**Dependencies**:
- **Internal**: Email Service (verification emails), Auth Service (session validation)
- **External**: PostgreSQL, Redis

**Scalability**:
- **Horizontal Scaling**: Yes, stateless with cached reads
- **Expected Load**: 200 requests/second
- **Auto-scaling Triggers**: CPU > 70%, Memory > 80%

**Data Storage**:
- **Primary Database**: PostgreSQL (encrypted PII, consent records)
- **Cache**: Redis (user profile cache, 5-min TTL)
- **File Storage**: S3 for GDPR export files (CSV/JSON)

### Service 3: Email Service
**Type**: Background Worker + API
**Responsibility**: Transactional email delivery including verification emails, password reset, OTP codes, and security alerts
**Technology Stack**:
- **Language/Runtime**: Go 1.21+
- **Framework**: Gin (HTTP API), Worker pool pattern
- **Message Queue**: RabbitMQ (email job queue)
- **Email Providers**: SendGrid (primary), AWS SES (fallover)
- **Template Engine**: Go html/template

**Key Features**:
- Email verification with signed tokens (24-hour expiry)
- Password reset emails (1-hour token expiry)
- OTP delivery (6-digit code, 5-min expiry)
- Security alert notifications (suspicious login, device change)
- Email delivery tracking and retry logic
- Template rendering with i18n support

**Dependencies**:
- **Internal**: Auth Service (token validation), User Service (user data)
- **External**: SendGrid API, AWS SES, RabbitMQ, Redis (OTP storage)

**Scalability**:
- **Horizontal Scaling**: Yes, worker pool scales with queue depth
- **Expected Load**: 1000 emails/minute
- **Auto-scaling Triggers**: Queue depth > 500 messages

**Data Storage**:
- **Primary Database**: PostgreSQL (email delivery logs, templates)
- **Cache**: Redis (OTP codes with TTL, rate limit counters)
- **Message Queue**: RabbitMQ (email jobs with 24-hour TTL)

### Service 4: 2FA Service
**Type**: API Service
**Responsibility**: Multi-factor authentication including OTP generation, validation, backup codes, and trusted device management
**Technology Stack**:
- **Language/Runtime**: Go 1.21+
- **Framework**: Gin
- **Database**: PostgreSQL 15 (backup codes, trusted devices)
- **Cache**: Redis (OTP codes, verification attempts)
- **Random**: crypto/rand for OTP generation

**Key Features**:
- Email OTP generation (6-digit, 5-min expiry)
- OTP validation with rate limiting (3 attempts)
- Backup code generation and validation (10 codes, single-use)
- Trusted device management with fingerprinting
- SMS OTP support (Twilio integration) - future
- Biometric authentication tokens for mobile - future

**Dependencies**:
- **Internal**: Email Service (OTP delivery), Auth Service (session validation)
- **External**: Redis, PostgreSQL, Twilio (future)

**Scalability**:
- **Horizontal Scaling**: Yes, stateless with Redis storage
- **Expected Load**: 100 OTP requests/second
- **Auto-scaling Triggers**: CPU > 60%

**Data Storage**:
- **Primary Database**: PostgreSQL (backup codes hashed, trusted devices)
- **Cache**: Redis (active OTP codes, attempt counters)

### Service 5: Audit Service
**Type**: Background Worker + Query API
**Responsibility**: Centralized security event logging, audit trail storage, compliance reporting, and anomaly detection
**Technology Stack**:
- **Language/Runtime**: Go 1.21+
- **Framework**: Gin (query API)
- **Database**: PostgreSQL 15 (time-series partitioned audit logs)
- **Message Queue**: RabbitMQ (async event ingestion)
- **Analytics**: Datadog (real-time monitoring), custom anomaly detection

**Key Features**:
- Security event ingestion (login, logout, password change, 2FA events)
- Audit trail with timestamps, IP addresses, user agents, correlation IDs
- Compliance reporting (GDPR access logs, SOC 2 reports)
- Anomaly detection (impossible travel, multiple failed logins, credential stuffing)
- Real-time alerting for suspicious activities
- Query API for audit trail retrieval

**Dependencies**:
- **Internal**: All services publish audit events
- **External**: RabbitMQ, PostgreSQL, Datadog

**Scalability**:
- **Horizontal Scaling**: Yes, worker pool for event processing
- **Expected Load**: 2000 events/second
- **Auto-scaling Triggers**: Queue depth > 1000, CPU > 70%

**Data Storage**:
- **Primary Database**: PostgreSQL (partitioned by month, 2-year retention)
- **Message Queue**: RabbitMQ (event queue)
- **Analytics**: Datadog (real-time metrics, 13-month retention)

## Service Boundaries

### Bounded Contexts

**Authentication Context**
- **Services**: Auth Service, 2FA Service
- **Responsibilities**: Credential verification, token management, session lifecycle, MFA enforcement
- **Domain**: Identity and access management

**User Management Context**
- **Services**: User Service
- **Responsibilities**: User profiles, registration, GDPR compliance, consent management
- **Domain**: User data and privacy

**Communication Context**
- **Services**: Email Service
- **Responsibilities**: Transactional messaging, notification delivery, template management
- **Domain**: External communication

**Compliance Context**
- **Services**: Audit Service
- **Responsibilities**: Security logging, audit trails, compliance reporting, threat detection
- **Domain**: Security operations and compliance

### Separation of Concerns

**Business Logic**: Encapsulated within each service's internal layer (e.g., `auth_service.go`, `user_manager.go`)
**Data Access**: Repository pattern with interface abstraction (e.g., `user_repository.go`, `audit_repository.go`)
**External Integrations**: Adapter pattern for email providers, SMS providers, with circuit breakers and fallback

## Service Communication

### Synchronous Communication
**Protocol**: REST HTTP/2 with JSON payloads
**Use Cases**: 
- Client authentication flows (login, registration, token refresh)
- Inter-service validation (auth token verification by User Service)
- Real-time operations requiring immediate response

**Example Flow**:
```
Mobile App → API Gateway → Auth Service → User Service → PostgreSQL
                                ↓
                            Redis (session)
```

**Authentication**: 
- External requests: JWT Bearer tokens
- Internal requests: Service tokens (mTLS certificates)

### Asynchronous Communication
**Protocol**: RabbitMQ with JSON message payloads
**Use Cases**: 
- Email delivery (non-blocking)
- Audit event logging
- Security alerts
- Background tasks (password expiry notifications)

**Example Flow**:
```
Auth Service → RabbitMQ (user.registered event) → Email Service (verification email)
                                                 → Audit Service (log event)
```

### Event-Driven Patterns
**Event Bus**: RabbitMQ with topic exchanges
**Events Published**:
- `user.registered` - New user signup completed (by User Service)
- `user.email_verified` - Email verification successful (by User Service)
- `auth.login_success` - Successful login (by Auth Service)
- `auth.login_failed` - Failed login attempt (by Auth Service)
- `auth.password_reset_requested` - Password reset initiated (by Auth Service)
- `auth.password_changed` - Password successfully changed (by Auth Service)
- `auth.2fa_enabled` - 2FA activated (by 2FA Service)
- `auth.suspicious_activity` - Anomaly detected (by Audit Service)
- `auth.account_locked` - Account locked due to failed attempts (by Auth Service)

**Event Consumers**:
- **Email Service**: Listens to `user.registered`, `auth.password_reset_requested`, `auth.suspicious_activity`
- **Audit Service**: Listens to all `auth.*` and `user.*` events
- **User Service**: Listens to `auth.password_changed`, `auth.2fa_enabled` for profile updates

## API Gateway

**Technology**: Kong Gateway with rate limiting, authentication, and routing plugins

**Responsibilities**:
- Request routing to backend services
- JWT validation for external requests
- Rate limiting (5 login attempts/min per IP, 10 per user/hour)
- Request/response transformation
- CORS policy enforcement
- API versioning (v1, v2)
- Response caching for public endpoints
- WAF integration (AWS WAF) for OWASP protection

**Routing Rules**:
| Path | Method | Target Service | Auth Required | Rate Limit |
|------|--------|----------------|---------------|------------|
| /api/v1/auth/register | POST | User Service | No | 3/min per IP |
| /api/v1/auth/login | POST | Auth Service | No | 5/min per IP |
| /api/v1/auth/refresh | POST | Auth Service | No | 10/min per user |
| /api/v1/auth/logout | POST | Auth Service | Yes | 20/min per user |
| /api/v1/auth/verify-email | GET | User Service | No | 10/min per IP |
| /api/v1/auth/password-reset | POST | Auth Service | No | 3/min per IP |
| /api/v1/auth/password-reset/confirm | POST | Auth Service | No | 5/min per IP |
| /api/v1/2fa/enable | POST | 2FA Service | Yes | 5/min per user |
| /api/v1/2fa/verify | POST | 2FA Service | Yes | 3/min per user |
| /api/v1/users/me | GET | User Service | Yes | 60/min per user |
| /api/v1/users/me | PUT | User Service | Yes | 10/min per user |
| /api/v1/users/consent | POST | User Service | Yes | 5/min per user |
| /api/v1/audit/events | GET | Audit Service | Yes (Admin) | 20/min per user |

**Security Headers** (added by gateway):
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy: default-src 'self'`

## Service Dependencies Map

```
                    ┌─────────────────┐
                    │   API Gateway   │
                    │  (Kong + WAF)   │
                    └────────┬────────┘
           ┌────────────────┼────────────────┐
           │                │                │
     ┌─────▼──────┐   ┌────▼─────┐   ┌─────▼──────┐
     │   Auth     │   │  User    │   │    2FA     │
     │  Service   │◄──┤  Service │──►│  Service   │
     └─────┬──────┘   └────┬─────┘   └─────┬──────┘
           │               │               │
           └───────────────┴───────────────┘
                          │
           ┌──────────────┼──────────────┐
           │              │              │
     ┌─────▼──────┐ ┌────▼─────┐  ┌────▼──────┐
     │  Email     │ │Audit     │  │PostgreSQL │
     │  Service   │ │Service   │  │  Cluster  │
     └─────┬──────┘ └────┬─────┘  └───────────┘
           │             │
     ┌─────▼─────────────▼─────┐
     │     RabbitMQ Cluster    │
     └─────────────────────────┘
           │
     ┌─────▼─────────────┐
     │  Redis Cluster    │
     │ (Session/Cache)   │
     └───────────────────┘
```

## Data Flow

### Example: User Registration Flow
1. Client submits registration form to API Gateway (`POST /api/v1/auth/register`)
2. API Gateway validates rate limit (3/min per IP) and routes to User Service
3. User Service validates input (email format, password complexity)
4. User Service checks email uniqueness in PostgreSQL
5. User Service hashes password with Argon2id (memory=64MB, iterations=3, parallelism=4)
6. User Service stores user record with encrypted PII (AES-256-GCM)
7. User Service captures GDPR consent with timestamp and IP address
8. User Service publishes `user.registered` event to RabbitMQ
9. Email Service consumes event and generates signed verification token (HMAC-SHA256)
10. Email Service sends verification email via SendGrid
11. Audit Service consumes event and logs registration with correlation ID
12. User Service returns success response (200 OK) with masked email

### Example: Login with 2FA Flow
1. Client submits credentials to API Gateway (`POST /api/v1/auth/login`)
2. API Gateway enforces rate limit (5/min per IP) and routes to Auth Service
3. Auth Service checks account lockout status in Redis
4. Auth Service retrieves user credentials from PostgreSQL
5. Auth Service verifies password with Argon2id
6. Auth Service checks if 2FA is enabled for user
7. Auth Service generates 6-digit OTP and stores in Redis (5-min TTL)
8. Auth Service publishes `auth.login_pending_2fa` event
9. Email Service sends OTP via email
10. Auth Service returns `2FA_REQUIRED` response with temporary token
11. Client submits OTP (`POST /api/v1/2fa/verify`)
12. 2FA Service validates OTP from Redis and checks attempt counter (max 3)
13. 2FA Service publishes `auth.2fa_verified` event
14. Auth Service generates JWT access token (15-min exp) and refresh token (7-day exp)
15. Auth Service stores session in Redis with device fingerprint
16. Auth Service stores refresh token hash in PostgreSQL
17. Audit Service logs successful login with IP, user agent, and correlation ID
18. Auth Service returns tokens with `Set-Cookie` headers (HttpOnly, Secure, SameSite=Strict)

### Example: Password Reset Flow
1. Client requests password reset (`POST /api/v1/auth/password-reset`)
2. API Gateway enforces rate limit (3/min per IP)
3. Auth Service generates signed reset token (HMAC-SHA256, 1-hour expiry)
4. Auth Service stores token hash in Redis with user ID
5. Auth Service publishes `auth.password_reset_requested` event
6. Email Service sends reset email with token link
7. Audit Service logs reset request with IP address
8. Auth Service returns generic success message (to prevent email enumeration)
9. Client clicks link and submits new password (`POST /api/v1/auth/password-reset/confirm`)
10. Auth Service validates token signature and expiry
11. Auth Service checks password against history (last 5 passwords)
12. Auth Service hashes new password with Argon2id
13. Auth Service updates password in PostgreSQL
14. Auth Service invalidates all refresh tokens for user
15. Auth Service clears all active sessions from Redis
16. Auth Service publishes `auth.password_changed` event
17. Email Service sends confirmation email
18. Audit Service logs password change with correlation ID

## Technology Decisions

### Service Framework Choice
**Decision**: Gin (Go HTTP framework)
**Rationale**: 
- High performance (40x faster than Martini)
- Low memory footprint critical for JWT validation at scale
- Strong type safety reduces authentication bugs
- Excellent concurrency model for handling auth load
- Native crypto library for Argon2id and JWT
- Team expertise in Go from backend services

**Alternatives Considered**: 
- FastAPI (Python) - rejected due to GIL performance limits
- Express.js (Node.js) - rejected due to weaker type safety for security-critical code
- Spring Boot (Java) - rejected due to higher memory overhead

### Database per Service vs Shared Database
**Decision**: Shared PostgreSQL cluster with schema-level isolation
**Rationale**: 
- Strong ACID guarantees critical for authentication
- Cross-service transactions for user registration + consent
- Centralized encryption key management for PII
- Simplified backup and disaster recovery for compliance
- Row-level security for multi-tenancy isolation
- Lower operational overhead (single DB to secure and monitor)

**Trade-offs Considered**: 
- Tight coupling between services (mitigated with repository interfaces)
- Schema migration coordination (addressed with Flyway versioning)

**Future Consideration**: Migrate to database-per-service if:
- Services need to scale independently (Auth Service sees 10x User Service load)
- Different data models required (NoSQL for audit logs at extreme scale)

### Communication Protocol
**Decision**: REST HTTP/2 for synchronous, RabbitMQ for asynchronous
**Rationale**: 
- REST widely understood, easy to debug and monitor
- HTTP/2 multiplexing reduces connection overhead
- JSON self-documenting for compliance audits
- RabbitMQ provides delivery guarantees for critical emails
- Topic exchanges enable flexible event routing
- Dead letter queues for failed email retry

**Alternatives Considered**: 
- gRPC - rejected due to limited browser support, debugging complexity
- GraphQL - rejected due to complexity, caching challenges, authorization at field level
- Kafka - rejected as overkill for current event volumes (<10k/sec)

**Future Consideration**: gRPC for internal service-to-service if latency becomes critical (<50ms requirement)

## Scalability Strategy

### Horizontal Scaling
- All services designed as stateless 12-factor apps
- Session data externalized to Redis Cluster (3 masters, 3 replicas)
- Refresh tokens stored in PostgreSQL (replicated across 3 AZs)
- Load balancer (AWS ALB) distributes traffic with sticky sessions for WebSocket upgrades
- Auto-scaling groups (min=2, max=20 per service)

### Vertical Scaling
- PostgreSQL scaled vertically first (r6g.2xlarge → r6g.8xlarge)
- Read replicas (3x) for audit queries and compliance reports
- Connection pooling (PgBouncer) with max 100 connections per service instance

### Caching Strategy
**Application-level**:
- User profile cache in Redis (5-min TTL, 10k entries)
- JWT public key cache (1-hour TTL)
- Rate limit counters (sliding window, 1-min buckets)

**Database-level**:
- PostgreSQL query cache for audit report queries
- Materialized views for compliance dashboards (refreshed hourly)

**CDN**:
- CloudFront for static assets (login page, JS bundles)
- Edge caching for public API documentation (24-hour TTL)

### Database Partitioning
- Audit logs partitioned by month (time-series data)
- Old partitions archived to S3 after 90 days (retained 2 years for compliance)
- Refresh tokens partitioned by expiry date for efficient cleanup

## Resilience Patterns

### Circuit Breaker
- Implemented for all external API calls (SendGrid, Twilio, HaveIBeenPwned)
- Thresholds: 
  - Opens after 5 consecutive failures or 50% error rate over 10 requests
  - Half-open after 30 seconds (test with single request)
  - Closes after 3 consecutive successes
- Fallback: Queue email for retry, use SES as secondary provider

### Retry Logic
- Exponential backoff: 1s, 2s, 4s, 8s, 16s (max 5 retries)
- Jitter added to prevent thundering herd (random 0-1s)
- Only for idempotent operations:
  - Email delivery (idempotency key in message)
  - Audit log writes (deduplication by event ID)
- No retry for:
  - Login attempts (security concern)
  - Token generation (must be unique)

### Timeout Management
- API Gateway → Services: 10 seconds
- Inter-service calls: 5 seconds
- Database queries: 3 seconds (complex audit queries: 10 seconds)
- External APIs: 
  - SendGrid: 15 seconds
  - Twilio: 10 seconds
  - HaveIBeenPwned: 5 seconds
- Redis operations: 500ms

### Fallback Strategies
**Read Operations**:
- Serve stale cache data if database unavailable (with `X-Cache-Status: stale` header)
- Degraded mode: Allow login with password only if 2FA Service down (log security event)

**Write Operations**:
- Queue for async processing (email delivery, audit logs)
- Return 503 Service Unavailable for critical writes (registration, password change)

**Graceful Degradation**:
- Disable HaveIBeenPwned check if API unavailable (log warning)
- Skip device fingerprinting if service down (reduce security, log event)
- Disable 2FA for emergency admin access with audit trail

### Bulkhead Pattern
- Separate thread pools for:
  - Critical: Login, token refresh (80% of resources)
  - Non-critical: Audit queries, email resend (20% of resources)
- Prevents audit report queries from starving login requests

## Health & Monitoring

### Health Checks
Each service exposes three endpoints:

**`GET /health`** - Basic health check
- Returns 200 if service process is running
- No dependencies checked
- Used by load balancer for routing decisions

**`GET /health/ready`** - Readiness check
- Returns 200 if service ready to accept traffic
- Checks:
  - Database connection pool has available connections
  - Redis connection established
  - RabbitMQ connection active
- Used by Kubernetes/ECS for traffic routing

**`GET /health/live`** - Liveness check
- Returns 200 if service should continue running
- Checks for deadlock, memory leaks
- Used by Kubernetes/ECS for restart decisions

**Response Format**:
```json
{
  "status": "healthy",
  "timestamp": "2025-10-29T12:34:56Z",
  "version": "v1.2.3",
  "checks": {
    "database": {"status": "up", "latency_ms": 2},
    "redis": {"status": "up", "latency_ms": 1},
    "rabbitmq": {"status": "up", "latency_ms": 3}
  }
}
```

### Metrics Collected
**Request Metrics** (per endpoint):
- Request rate (req/s)
- Error rate (% of 5xx responses)
- Response time (p50, p95, p99)
- Request size (bytes)
- Response size (bytes)

**Authentication Metrics**:
- Login success rate (%)
- Login failure rate by reason (invalid password, account locked, 2FA failed)
- Token refresh rate (req/s)
- Session creation rate (sessions/s)
- Active sessions count (gauge)

**Security Metrics**:
- Failed login attempts (per user, per IP)
- Account lockouts (count/hour)
- 2FA bypass attempts (count)
- Suspicious login detections (count/hour)
- Token validation failures (count/s)

**Resource Metrics**:
- CPU usage (%)
- Memory usage (MB, %)
- Goroutine count (gauge)
- Database connection pool usage (%)
- Redis connection count (gauge)

**Business Metrics**:
- New user registrations (count/hour)
- Email verification rate (%)
- Password reset requests (count/hour)
- 2FA adoption rate (% of users)

### Logging Strategy
**Log Format**: Structured JSON logs
```json
{
  "timestamp": "2025-10-29T12:34:56.789Z",
  "level": "INFO",
  "service": "auth-service",
  "correlation_id": "req-abc123",
  "user_id": "user-xyz789",
  "event": "login_success",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "duration_ms": 45,
  "metadata": {
    "2fa_enabled": true,
    "device_trusted": false
  }
}
```

**Log Levels**:
- **ERROR**: Authentication failures, service errors, external API failures
- **WARN**: Rate limit exceeded, suspicious activity, fallback used
- **INFO**: Successful login, registration, password change, 2FA events
- **DEBUG**: Detailed flow (disabled in production)

**Correlation IDs**:
- Generated at API Gateway (`X-Correlation-ID` header)
- Propagated to all services and logs
- Enables end-to-end request tracing

**Log Retention**:
- Security logs: 2 years (compliance requirement)
- Application logs: 90 days
- Debug logs: 7 days

**Log Sanitization**:
- Redact passwords, tokens, OTP codes
- Mask email addresses (user@example.com → u***@example.com)
- Hash IP addresses for privacy (store last octet only: 192.168.1.*)

### Monitoring & Alerting
**Monitoring Stack**: Datadog + Sentry

**Critical Alerts** (PagerDuty, 24/7):
- Service down (health check fails for 2 minutes)
- Error rate > 5% (5-min window)
- p95 latency > 500ms (login endpoint)
- Database connection pool exhausted
- Redis cluster unavailable
- Suspicious activity detected (>10 impossible travel events/hour)

**Warning Alerts** (Slack, business hours):
- Error rate > 1% (5-min window)
- p95 latency > 200ms
- CPU > 80% (5-min window)
- Memory > 85%
- Email delivery failure rate > 5%
- Account lockout rate > 50/hour

**Dashboards**:
- **Authentication Overview**: Login rate, success rate, active sessions
- **Security Dashboard**: Failed attempts, lockouts, suspicious activity
- **Performance Dashboard**: Latency percentiles, throughput, error rate
- **Compliance Dashboard**: Audit log coverage, GDPR requests, consent tracking

## Security Considerations

### Service-to-Service Authentication
**Method**: Mutual TLS (mTLS)
- Each service has X.509 certificate signed by internal CA
- Certificate rotation every 90 days (automated with cert-manager)
- Service identity verified before processing internal requests
- Certificates stored in AWS Secrets Manager

**Service Accounts**:
- Each service has dedicated database user with least-privilege grants
- Auth Service: SELECT/UPDATE on users, INSERT on audit_logs
- User Service: SELECT/INSERT/UPDATE on users, SELECT on audit_logs
- Audit Service: INSERT on audit_logs, SELECT for queries (read-only user)

### Network Security
**Network Segmentation**:
- API Gateway in public subnet (0.0.0.0/0 ingress on 443)
- Services in private subnet (10.0.1.0/24)
- Database in isolated subnet (10.0.2.0/24)
- Redis in isolated subnet (10.0.3.0/24)

**Security Groups**:
- API Gateway → Services: Allow 8080 (HTTP)
- Services → Database: Allow 5432 (PostgreSQL)
- Services → Redis: Allow 6379
- Services → RabbitMQ: Allow 5672 (AMQP)
- Inter-service: Allow 8080 (mTLS)
- Deny all other traffic (default deny)

**WAF Rules** (AWS WAF):
- OWASP Core Rule Set (CRS)
- SQL injection protection
- XSS protection
- Rate limiting (10,000 req/5min per IP)
- Geo-blocking (block high-risk countries)
- IP reputation lists (block known malicious IPs)

### Secrets Management
**Storage**: AWS Secrets Manager
- Database passwords
- Redis password
- JWT signing keys (RSA-2048 private key)
- API keys (SendGrid, Twilio, HaveIBeenPwned)
- Encryption keys (AES-256 for PII)

**Rotation Policy**:
- Database passwords: 90 days
- API keys: 180 days
- JWT signing keys: 365 days (overlapping keys during rotation)
- Encryption keys: Manual rotation (key versioning)

**Access Control**:
- Services access secrets via IAM roles (no hard-coded credentials)
- Secrets encrypted at rest (AWS KMS)
- Audit trail for secret access (CloudTrail)

### Encryption
**In Transit**:
- TLS 1.3 for all external connections (API Gateway)
- TLS 1.2+ for internal service communication (mTLS)
- Database connections encrypted (PostgreSQL SSL mode=require)

**At Rest**:
- PII encrypted with AES-256-GCM (email, phone, address)
- Passwords hashed with Argon2id (never encrypted)
- Refresh tokens hashed with SHA-256
- Database encryption at rest (PostgreSQL pgcrypto)
- Disk encryption (EBS volumes encrypted with KMS)

**Key Management**:
- Master keys in AWS KMS
- Data encryption keys (DEK) rotated annually
- Envelope encryption for PII (DEK encrypted with master key)

## Deployment Considerations

### Containerization
**Base Image**: golang:1.21-alpine (multi-stage build)
```dockerfile
# Stage 1: Build
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags="-w -s" -o /auth-service ./cmd/auth

# Stage 2: Runtime
FROM alpine:3.18
RUN apk --no-cache add ca-certificates
COPY --from=builder /auth-service /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8080
CMD ["auth-service"]
```

**Security**:
- Base images scanned with Trivy (fail build on HIGH/CRITICAL)
- Non-root user (UID 65532)
- Read-only root filesystem
- Minimal dependencies (alpine base)
- Signed images (Docker Content Trust)

**Image Tagging**:
- `latest` (not used in production)
- `v1.2.3` (semantic versioning)
- `sha-abc1234` (git commit SHA)

### Service Discovery
**Method**: AWS ECS Service Discovery (Cloud Map)
- Services register on startup with health check
- DNS-based discovery (auth-service.local, user-service.local)
- Automatic deregistration on health check failure
- TTL 10 seconds for fast failover

**Endpoints**:
- `auth-service.local:8080`
- `user-service.local:8080`
- `2fa-service.local:8080`
- `email-service.local:8080`
- `audit-service.local:8080`

### Rolling Deployments
**Strategy**: Blue-Green with canary
1. Deploy new version (green) alongside old version (blue)
2. Canary: Route 10% traffic to green, monitor for 5 minutes
3. If success rate > 99%: Route 50% traffic, monitor for 5 minutes
4. If success rate > 99%: Route 100% traffic to green
5. Wait 10 minutes, terminate blue instances
6. If any step fails: Automatic rollback to blue

**Health Check During Deployment**:
- New instances must pass 3 consecutive health checks (30 seconds)
- Load balancer waits for `/health/ready` before routing traffic
- In-flight requests complete before old instance termination (30s grace period)

**Database Migrations**:
- Run before deployment (Flyway)
- Backward-compatible migrations only (add column, not drop)
- Forward-only migrations (no rollback)
- Old code must work with new schema during deployment

### CI/CD Pipeline
**Tool**: GitHub Actions

**Pipeline Stages**:
1. **Build** (2 min):
   - Compile Go binaries
   - Run tests (unit, integration)
   - Code coverage check (>80% required)
   
2. **Security Scan** (3 min):
   - Trivy image scan
   - Snyk dependency scan
   - gosec static analysis (Go security checker)
   
3. **Push Image** (1 min):
   - Tag with version and SHA
   - Push to ECR (Amazon Elastic Container Registry)
   - Sign image with Cosign
   
4. **Deploy to Staging** (5 min):
   - Run database migrations
   - Blue-green deployment
   - Smoke tests (login, registration, 2FA)
   
5. **Deploy to Production** (10 min):
   - Manual approval required
   - Canary deployment (10% → 50% → 100%)
   - Automated rollback on failure

**Rollback**:
- One-click rollback to previous version
- Revert database migration if schema-breaking
- Maximum 5 minutes to restore service

## Future Considerations

### Potential Service Splits

**As system scales beyond 5000 req/s**:

**Auth Service → Token Service + Session Service**
- **Token Service**: JWT generation, validation, signing key rotation
- **Session Service**: Redis session management, device tracking
- **Trigger**: When token generation becomes CPU bottleneck (>70% CPU)

**Email Service → Notification Service + Delivery Service**
- **Notification Service**: Template rendering, message composition
- **Delivery Service**: Multi-channel delivery (email, SMS, push)
- **Trigger**: When adding SMS and push notification support

**Audit Service → Ingestion Service + Query Service + Analytics Service**
- **Ingestion Service**: High-throughput event ingestion (Kafka)
- **Query Service**: Real-time audit trail queries
- **Analytics Service**: Compliance reporting, anomaly detection
- **Trigger**: When audit events exceed 10,000/second

### Potential Service Merges

**If operational overhead too high (<1000 req/s total)**:

**2FA Service + Auth Service**
- Merge 2FA logic into Auth Service
- Reduces inter-service latency (one less hop)
- Simplifies deployment (fewer containers)
- **Trigger**: If 2FA adoption <20%, not worth separate service

**Email Service + User Service**
- Email becomes module within User Service
- Reduces RabbitMQ dependency for simple notifications
- **Trigger**: If email volume <100/minute, async queue overkill

### Migration Path

**Phase 1 (Months 0-3): Monolithic Start**
- Deploy all services as one application
- Shared codebase, modular architecture
- Validate feature set and user adoption

**Phase 2 (Months 3-6): Extract Auth Service**
- Separate authentication as first microservice
- Enables independent scaling of login endpoint
- Reduces blast radius of security vulnerabilities

**Phase 3 (Months 6-12): Full Microservices**
- Extract remaining services as load justifies
- Migrate to RabbitMQ for async communication
- Implement full service mesh with mTLS

**Phase 4 (Year 2+): Event-Driven + CQRS**
- Migrate to Kafka for event streaming at scale
- Separate read/write models for audit logs
- Real-time analytics with Flink/Spark

**Decision Criteria**:
- **Extract service**: When >1000 req/s or team >5 engineers
- **Merge service**: When <100 req/s and operational burden high
- **Re-architect**: When latency >500ms or compliance requirements change
