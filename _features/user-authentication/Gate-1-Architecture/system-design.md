---
layout: default
title: System Design
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

# System Design - User Registration & Authentication

## 1. System Design Overview

### System Purpose and Scope
The User Registration & Authentication system provides secure identity management for the SUMA Finance application. It handles user onboarding, authentication, session management, and access control for all platform users.

### Design Goals and Objectives
- **Security First**: Implement industry-standard authentication mechanisms with zero-trust principles
- **User Experience**: Seamless registration and login flows with minimal friction
- **Scalability**: Support 100,000+ concurrent users with sub-200ms authentication response times
- **Compliance**: GDPR-compliant data handling and PSD2-ready authentication flows
- **Multi-Channel**: Support web, mobile (iOS/Android), and API-based authentication

### Key Quality Attributes

| Attribute | Target | Measurement |
|-----------|--------|-------------|
| **Performance** | < 150ms authentication latency (p95) | Response time monitoring |
| **Availability** | 99.9% uptime | SLA monitoring |
| **Scalability** | 100K concurrent sessions | Load testing |
| **Security** | Zero critical vulnerabilities | Security scanning |
| **Reliability** | < 0.1% failed authentication rate | Error rate monitoring |

### Technology Stack Summary

**Backend**
- Go 1.21+ (authentication service)
- PostgreSQL 15+ (user data store)
- Redis 7+ (session cache, rate limiting)
- JWT for stateless authentication

**Frontend**
- React 18+ with TypeScript
- React Native (iOS/Android)
- Secure storage libraries (react-native-keychain)

**Infrastructure**
- Docker containers
- Kubernetes orchestration
- AWS/Azure cloud platform
- CloudFront/Azure CDN

### High-Level System Diagram

```mermaid
graph TB
    subgraph "Client Layer"
        WebApp[Web Application]
        MobileApp[Mobile App iOS/Android]
        ThirdParty[Third-Party API Clients]
    end
    
    subgraph "API Gateway"
        Gateway[API Gateway<br/>Rate Limiting, Routing]
    end
    
    subgraph "Application Layer"
        AuthService[Authentication Service<br/>Go]
        UserService[User Service<br/>Go]
        SessionManager[Session Manager<br/>Go]
    end
    
    subgraph "Data Layer"
        PostgreSQL[(PostgreSQL<br/>User Database)]
        Redis[(Redis<br/>Session Cache)]
        Vault[HashiCorp Vault<br/>Secrets]
    end
    
    subgraph "External Services"
        EmailService[Email Service<br/>SendGrid]
        SMSService[SMS Service<br/>Twilio]
        Analytics[Analytics<br/>Mixpanel]
    end
    
    WebApp --> Gateway
    MobileApp --> Gateway
    ThirdParty --> Gateway
    
    Gateway --> AuthService
    Gateway --> UserService
    
    AuthService --> SessionManager
    AuthService --> PostgreSQL
    AuthService --> Redis
    AuthService --> Vault
    
    UserService --> PostgreSQL
    UserService --> EmailService
    UserService --> SMSService
    
    AuthService --> Analytics
    UserService --> Analytics
```

## 2. System Requirements

### Functional Requirements Summary

#### Core Features and Capabilities
1. **User Registration**
   - Email/password registration
   - Email verification
   - Password strength validation
   - GDPR consent collection
   - Profile creation

2. **User Authentication**
   - Email/password login
   - JWT-based session management
   - Multi-factor authentication (TOTP, SMS)
   - Password reset flow
   - Remember me functionality

3. **User Management**
   - Profile updates
   - Password change
   - Email change with verification
   - Account deletion (GDPR right to be forgotten)
   - Session management (view/revoke active sessions)

4. **OAuth 2.0 Social Login**
   - Google Sign-In
   - Apple Sign-In
   - Facebook Login

#### User Roles and Personas
- **End User**: Standard platform user with basic access
- **Premium User**: Enhanced features, longer session duration
- **Admin User**: Administrative access to user management
- **System Service**: Machine-to-machine authentication

#### Use Cases
1. New user registers with email and password
2. User logs in with credentials
3. User enables two-factor authentication
4. User resets forgotten password
5. User logs in with Google account
6. User views and revokes active sessions
7. Admin reviews user access logs
8. User deletes their account

### Non-Functional Requirements

#### Performance Requirements
- **Authentication Latency**: < 150ms (p95), < 100ms (p50)
- **Registration Latency**: < 500ms (p95)
- **Token Validation**: < 10ms (in-memory/cache)
- **Throughput**: 10,000 requests/second peak load
- **Concurrent Sessions**: 100,000+ active sessions

#### Scalability Requirements
- **Horizontal Scaling**: Stateless services, auto-scale 2-20 pods
- **Database**: Read replicas for user lookups (70% reads, 30% writes)
- **Cache Hit Ratio**: > 90% for session validation
- **User Growth**: Support 1M+ registered users in first year

#### Availability Requirements
- **Uptime SLA**: 99.9% (< 43 minutes downtime/month)
- **Multi-AZ Deployment**: Active-active configuration
- **Failover Time**: < 30 seconds
- **Data Replication**: Synchronous replication for critical data

#### Security Requirements
- **Password Storage**: Argon2id hashing (OWASP recommended)
- **Token Expiration**: Access tokens 15min, refresh tokens 30 days
- **Rate Limiting**: 5 failed attempts → 15min lockout
- **Encryption**: TLS 1.3 in transit, AES-256 at rest
- **Session Security**: HttpOnly, Secure, SameSite=Strict cookies
- **MFA Support**: TOTP (RFC 6238) and SMS-based

#### Compliance Requirements
- **GDPR**: Data portability, right to deletion, consent management
- **PSD2**: Strong Customer Authentication (SCA) ready
- **SOC 2**: Audit logging for all authentication events
- **Password Policy**: NIST SP 800-63B guidelines

### Constraints

#### Technical Constraints
- Must integrate with existing PostgreSQL database
- JWT tokens must be verifiable without database lookups (stateless)
- Mobile apps must support offline token refresh
- Maximum session payload size: 4KB

#### Business Constraints
- Must support legacy API clients during migration (6-month dual-stack)
- Email verification required for fintech compliance
- No third-party authentication SDKs with restrictive licenses

#### Time and Budget Constraints
- MVP authentication: 4 weeks
- OAuth integration: 2 weeks
- MFA implementation: 2 weeks
- Security audit and hardening: 1 week

## 3. System Components

### Frontend Application

#### Web Application (React)
**Responsibilities:**
- Render registration and login forms
- Client-side validation (password strength, email format)
- Store JWT tokens in httpOnly cookies (preferred) or localStorage
- Refresh token rotation
- Session timeout warnings
- MFA enrollment and verification UI

**Key Components:**
- `AuthProvider` - React context for authentication state
- `LoginForm` - Email/password login
- `RegisterForm` - User registration
- `MFASetup` - TOTP QR code enrollment
- `PasswordReset` - Forgot password flow
- `SessionManager` - View/revoke active sessions

#### Mobile Application (React Native)
**Responsibilities:**
- Native biometric authentication (Face ID, Touch ID)
- Secure token storage (react-native-keychain)
- Deep linking for email verification
- Push notifications for security alerts
- Offline token refresh capability

**Key Components:**
- `BiometricAuth` - Native biometric prompts
- `SecureStorage` - Encrypted token storage
- `DeepLinkHandler` - Email verification links
- `PushNotificationHandler` - Security alerts

#### Admin Dashboard
**Responsibilities:**
- User search and management
- View authentication logs
- Reset user passwords (with audit trail)
- Manage user roles and permissions
- Security dashboard (failed login attempts, suspicious activity)

### Backend Services

#### Authentication Service (Go)
**Responsibilities:**
- User registration and validation
- Login credential verification
- JWT token generation and validation
- Password hashing and comparison
- MFA enrollment and verification
- Session management
- Rate limiting and brute-force protection

**API Endpoints:**
```
POST   /api/v1/auth/register
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
POST   /api/v1/auth/refresh
POST   /api/v1/auth/verify-email
POST   /api/v1/auth/reset-password/request
POST   /api/v1/auth/reset-password/confirm
POST   /api/v1/auth/mfa/enroll
POST   /api/v1/auth/mfa/verify
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/:sessionId
```

**Service Boundaries:**
- Does NOT handle user profile management (delegated to User Service)
- Does NOT send emails directly (delegates to Email Service)
- Focuses solely on authentication and session lifecycle

#### User Service (Go)
**Responsibilities:**
- User profile CRUD operations
- Email/phone number uniqueness validation
- User search and listing (admin)
- Account deletion (GDPR compliance)
- User metadata management

**API Endpoints:**
```
GET    /api/v1/users/me
PUT    /api/v1/users/me
PATCH  /api/v1/users/me/email
PATCH  /api/v1/users/me/password
DELETE /api/v1/users/me
GET    /api/v1/users/:userId (admin)
GET    /api/v1/users (admin)
```

#### Session Manager (Go)
**Responsibilities:**
- Active session tracking in Redis
- Session expiration and cleanup
- Concurrent session limits (max 5 devices)
- Session revocation
- Device fingerprinting

### Data Stores

#### Primary Database (PostgreSQL)
**Tables:**
- `users` - Core user data (email, hashed password, created_at)
- `user_profiles` - Extended profile information
- `mfa_secrets` - TOTP secrets (encrypted)
- `password_reset_tokens` - Time-limited reset tokens
- `email_verification_tokens` - Email verification tokens
- `audit_logs` - Authentication events (login, logout, failed attempts)

**Replication:**
- Primary write instance
- 2 read replicas for user lookups
- Synchronous replication to standby for failover

#### Cache Layer (Redis)
**Data Structures:**
- `session:{sessionId}` - Session metadata (hash, 30-day TTL)
- `rate_limit:{ip}:{endpoint}` - Rate limiting counters (sorted set)
- `user_lockout:{userId}` - Temporary account lockouts (string, 15min TTL)
- `refresh_token:{tokenId}` - Refresh token metadata (hash, 30-day TTL)
- `email_verification:{token}` - Verification token cache (string, 24hr TTL)

**Configuration:**
- Redis Cluster (3 master, 3 replica nodes)
- Persistence: AOF + RDB snapshots
- Eviction policy: allkeys-lru

#### Secrets Vault (HashiCorp Vault)
**Stored Secrets:**
- JWT signing keys (RS256 private key)
- Database credentials
- Email service API keys
- SMS service API keys
- OAuth client secrets

**Access Pattern:**
- Services authenticate via Kubernetes service accounts
- Secrets rotated every 90 days
- Audit logging enabled

### External Services

#### Email Service (SendGrid)
**Use Cases:**
- Welcome email after registration
- Email verification links
- Password reset links
- Security alerts (new device login)
- MFA backup codes

**Integration:**
- Async job queue (Bull) for email sending
- Retry logic: 3 attempts with exponential backoff
- Template management in SendGrid dashboard

#### SMS Service (Twilio)
**Use Cases:**
- SMS-based MFA codes
- Phone number verification
- Security alerts for high-risk actions

**Integration:**
- Direct API calls for time-sensitive messages
- Fallback to email if SMS fails
- Rate limiting: max 3 SMS per hour per user

#### Analytics Service (Mixpanel)
**Tracked Events:**
- User registration (with UTM parameters)
- Login success/failure
- MFA enrollment
- Password reset requests
- OAuth login method used

**Data Privacy:**
- PII (email, phone) excluded from events
- User ID hashed before sending
- GDPR-compliant data processing agreement

## 4. API Design

### RESTful API Endpoints

#### Authentication Endpoints

**POST /api/v1/auth/register**
```json
Request:
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd!",
  "firstName": "John",
  "lastName": "Doe",
  "gdprConsent": true,
  "termsAccepted": true
}

Response (201 Created):
{
  "userId": "usr_01HGW3X9K2YN5Z8QRST6VWXYZ",
  "email": "user@example.com",
  "emailVerified": false,
  "message": "Registration successful. Please verify your email."
}

Errors:
400 - Validation error (weak password, invalid email)
409 - Email already exists
422 - Missing required consent
429 - Too many registration attempts
```

**POST /api/v1/auth/login**
```json
Request:
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd!",
  "rememberMe": true,
  "deviceFingerprint": "fp_hash_123"
}

Response (200 OK):
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "rt_01HGW3XABCDEFGHIJKLMNOPQRS",
  "tokenType": "Bearer",
  "expiresIn": 900,
  "user": {
    "userId": "usr_01HGW3X9K2YN5Z8QRST6VWXYZ",
    "email": "user@example.com",
    "firstName": "John",
    "mfaEnabled": false
  }
}

Response (200 OK - MFA Required):
{
  "mfaRequired": true,
  "mfaToken": "mfa_tmp_token_123",
  "mfaMethods": ["totp", "sms"]
}

Errors:
401 - Invalid credentials
403 - Account locked due to failed attempts
423 - Email not verified
429 - Rate limit exceeded
```

**POST /api/v1/auth/mfa/verify**
```json
Request:
{
  "mfaToken": "mfa_tmp_token_123",
  "code": "123456",
  "method": "totp"
}

Response (200 OK):
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "rt_01HGW3XABCDEFGHIJKLMNOPQRS",
  "tokenType": "Bearer",
  "expiresIn": 900
}

Errors:
401 - Invalid MFA code
410 - MFA token expired
429 - Too many failed attempts
```

**POST /api/v1/auth/refresh**
```json
Request:
{
  "refreshToken": "rt_01HGW3XABCDEFGHIJKLMNOPQRS"
}

Response (200 OK):
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "rt_NEW_TOKEN_456",
  "tokenType": "Bearer",
  "expiresIn": 900
}

Errors:
401 - Invalid or expired refresh token
403 - Token revoked
```

**POST /api/v1/auth/logout**
```json
Request Headers:
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

Request Body:
{
  "allDevices": false
}

Response (204 No Content)

Errors:
401 - Invalid access token
```

**POST /api/v1/auth/verify-email**
```json
Request:
{
  "token": "evt_01HGW3XVERIFYTOKEN123"
}

Response (200 OK):
{
  "message": "Email verified successfully",
  "emailVerified": true
}

Errors:
400 - Invalid token format
404 - Token not found or expired
410 - Email already verified
```

**POST /api/v1/auth/reset-password/request**
```json
Request:
{
  "email": "user@example.com"
}

Response (200 OK):
{
  "message": "If the email exists, a password reset link has been sent."
}

Note: Always returns 200 to prevent email enumeration

Errors:
429 - Too many reset requests
```

**POST /api/v1/auth/reset-password/confirm**
```json
Request:
{
  "token": "prt_01HGW3XRESETTOKEN123",
  "newPassword": "NewSecureP@ssw0rd!"
}

Response (200 OK):
{
  "message": "Password reset successful"
}

Errors:
400 - Weak password
404 - Invalid or expired token
422 - Password same as old password
```

#### Session Management Endpoints

**GET /api/v1/auth/sessions**
```json
Request Headers:
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

Response (200 OK):
{
  "sessions": [
    {
      "sessionId": "ses_01HGW3XCURRENT",
      "deviceType": "web",
      "browser": "Chrome 120.0",
      "os": "Windows 10",
      "ipAddress": "192.168.1.100",
      "location": "Lisbon, Portugal",
      "createdAt": "2025-01-15T10:30:00Z",
      "lastActivity": "2025-01-15T14:45:00Z",
      "current": true
    },
    {
      "sessionId": "ses_01HGW3XMOBILE",
      "deviceType": "mobile",
      "browser": "Mobile App",
      "os": "iOS 17.2",
      "ipAddress": "192.168.1.101",
      "location": "Lisbon, Portugal",
      "createdAt": "2025-01-14T08:00:00Z",
      "lastActivity": "2025-01-15T09:00:00Z",
      "current": false
    }
  ],
  "totalSessions": 2
}
```

**DELETE /api/v1/auth/sessions/:sessionId**
```json
Request Headers:
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

Response (204 No Content)

Errors:
403 - Cannot revoke current session (use logout)
404 - Session not found
```

### API Versioning
- URL-based versioning: `/api/v1/`, `/api/v2/`
- Version sunset policy: 6 months notice before deprecation
- Maintain v1 for legacy clients during transition

### API Gateway Configuration

**Rate Limiting Rules:**
```yaml
endpoints:
  - path: /api/v1/auth/login
    rate_limit:
      per_ip: 5 requests / 15 minutes
      per_user: 10 requests / 15 minutes
  
  - path: /api/v1/auth/register
    rate_limit:
      per_ip: 3 requests / 1 hour
  
  - path: /api/v1/auth/refresh
    rate_limit:
      per_token: 1 request / 5 minutes
  
  - path: /api/v1/auth/reset-password/request
    rate_limit:
      per_ip: 3 requests / 1 hour
```

**Request/Response Transformation:**
- Add `X-Request-ID` header for tracing
- Sanitize error messages (no stack traces in production)
- Add security headers (CSP, HSTS, X-Frame-Options)

### API Documentation

**OpenAPI 3.0 Specification:**
```yaml
openapi: 3.0.0
info:
  title: SUMA Finance Authentication API
  version: 1.0.0
  description: User registration and authentication endpoints

servers:
  - url: https://api.sumafinance.com/v1
    description: Production
  - url: https://api.staging.sumafinance.com/v1
    description: Staging

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

paths:
  /auth/login:
    post:
      summary: Authenticate user
      operationId: login
      tags: [Authentication]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'
```

**Documentation Portal:**
- Hosted on `https://developers.sumafinance.com`
- Interactive API explorer (Swagger UI)
- Code examples in Go, JavaScript, Python
- Authentication flow tutorials

## 5. Authentication and Authorization Design

### Authentication Flow

#### User Registration Flow
```mermaid
sequenceDiagram
    participant User
    participant WebApp
    participant APIGateway
    participant AuthService
    participant UserService
    participant PostgreSQL
    participant EmailService
    
    User->>WebApp: Fill registration form
    WebApp->>WebApp: Client-side validation
    WebApp->>APIGateway: POST /auth/register
    APIGateway->>APIGateway: Rate limit check
    APIGateway->>AuthService: Forward request
    
    AuthService->>AuthService: Validate input
    AuthService->>AuthService: Check password strength
    AuthService->>PostgreSQL: Check email uniqueness
    
    alt Email exists
        PostgreSQL-->>AuthService: Email found
        AuthService-->>WebApp: 409 Conflict
    else Email unique
        PostgreSQL-->>AuthService: Email available
        AuthService->>AuthService: Hash password (Argon2id)
        AuthService->>PostgreSQL: INSERT user record
        AuthService->>PostgreSQL: INSERT verification token
        AuthService->>EmailService: Send verification email
        AuthService-->>WebApp: 201 Created
        WebApp-->>User: Show "Check your email" message
    end
    
    User->>User: Open email
    User->>WebApp: Click verification link
    WebApp->>AuthService: POST /auth/verify-email
    AuthService->>PostgreSQL: Validate token
    AuthService->>PostgreSQL: UPDATE user.email_verified = true
    AuthService-->>WebApp: 200 OK
    WebApp-->>User: Email verified, redirect to login
```

#### Login Flow (Without MFA)
```mermaid
sequenceDiagram
    participant User
    participant WebApp
    participant APIGateway
    participant AuthService
    participant PostgreSQL
    participant Redis
    participant Analytics
    
    User->>WebApp: Enter email/password
    WebApp->>APIGateway: POST /auth/login
    APIGateway->>APIGateway: Rate limit check (5/15min)
    APIGateway->>AuthService: Forward request
    
    AuthService->>Redis: Check lockout status
    alt Account locked
        Redis-->>AuthService: Locked until timestamp
        AuthService-->>WebApp: 403 Forbidden
    else Not locked
        AuthService->>PostgreSQL: SELECT user by email
        
        alt User not found
            PostgreSQL-->>AuthService: No user
            AuthService->>AuthService: Timing-safe comparison
            AuthService-->>WebApp: 401 Unauthorized
        else User found
            PostgreSQL-->>AuthService: User record
            AuthService->>AuthService: Verify password (Argon2id)
            
            alt Invalid password
                AuthService->>Redis: Increment failed attempts
                AuthService->>PostgreSQL: Log failed attempt
                
                alt Failed attempts >= 5
                    AuthService->>Redis: SET lockout (15min TTL)
                    AuthService-->>WebApp: 403 Account locked
                else
                    AuthService-->>WebApp: 401 Unauthorized
                end
            else Valid password
                AuthService->>AuthService: Generate JWT (access + refresh)
                AuthService->>Redis: Store session metadata
                AuthService->>PostgreSQL: Log successful login
                AuthService->>Analytics: Track login event
                AuthService-->>WebApp: 200 OK + tokens
                WebApp->>WebApp: Store tokens (httpOnly cookie)
                WebApp-->>User: Redirect to dashboard
            end
        end
    end
```

#### Login Flow (With MFA)
```mermaid
sequenceDiagram
    participant User
    participant WebApp
    participant AuthService
    participant PostgreSQL
    participant Redis
    
    User->>WebApp: Enter email/password
    WebApp->>AuthService: POST /auth/login
    AuthService->>PostgreSQL: Verify credentials
    PostgreSQL-->>AuthService: User has MFA enabled
    
    AuthService->>AuthService: Generate temporary MFA token
    AuthService->>Redis: Store MFA token (5min TTL)
    AuthService-->>WebApp: 200 OK {mfaRequired: true, mfaToken}
    
    WebApp-->>User: Show MFA code input
    User->>WebApp: Enter TOTP code
    WebApp->>AuthService: POST /auth/mfa/verify
    AuthService->>Redis: Retrieve MFA token metadata
    AuthService->>PostgreSQL: Get user's TOTP secret
    AuthService->>AuthService: Validate TOTP code (30s window)
    
    alt Invalid code
        AuthService->>Redis: Increment MFA failed attempts
        AuthService-->>WebApp: 401 Invalid code
    else Valid code
        AuthService->>AuthService: Generate JWT tokens
        AuthService->>Redis: Store session
        AuthService-->>WebApp: 200 OK + tokens
        WebApp-->>User: Redirect to dashboard
    end
```

#### Password Reset Flow
```mermaid
sequenceDiagram
    participant User
    participant WebApp
    participant AuthService
    participant PostgreSQL
    participant Redis
    participant EmailService
    
    User->>WebApp: Click "Forgot Password"
    WebApp-->>User: Enter email form
    User->>WebApp: Submit email
    WebApp->>AuthService: POST /auth/reset-password/request
    
    AuthService->>PostgreSQL: SELECT user by email
    
    alt User exists
        PostgreSQL-->>AuthService: User record
        AuthService->>AuthService: Generate reset token (UUID)
        AuthService->>PostgreSQL: INSERT password_reset_token (1hr TTL)
        AuthService->>EmailService: Send reset email with link
    else User not found
        Note over AuthService: Still return 200 (prevent enumeration)
    end
    
    AuthService-->>WebApp: 200 OK "Check your email"
    
    User->>User: Open email
    User->>WebApp: Click reset link
    WebApp-->>User: New password form
    User->>WebApp: Enter new password
    WebApp->>AuthService: POST /auth/reset-password/confirm
    
    AuthService->>PostgreSQL: Validate reset token
    alt Token invalid/expired
        PostgreSQL-->>AuthService: Token not found
        AuthService-->>WebApp: 404 Invalid token
    else Token valid
        PostgreSQL-->>AuthService: Token valid
        AuthService->>AuthService: Hash new password (Argon2id)
        AuthService->>PostgreSQL: UPDATE user password
        AuthService->>PostgreSQL: DELETE reset token
        AuthService->>Redis: Revoke all user sessions
        AuthService->>EmailService: Send "password changed" notification
        AuthService-->>WebApp: 200 OK
        WebApp-->>User: Redirect to login
    end
```

### Token-Based Authentication

#### JWT Structure

**Access Token (15-minute expiration):**
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key_2025_01"
  },
  "payload": {
    "sub": "usr_01HGW3X9K2YN5Z8QRST6VWXYZ",
    "email": "user@example.com",
    "role": "user",
    "permissions": ["read:profile", "write:profile"],
    "sessionId": "ses_01HGW3XCURRENT",
    "mfaVerified": true,
    "iat": 1705324800,
    "exp": 1705325700,
    "iss": "https://api.sumafinance.com",
    "aud": "sumafinance-web"
  },
  "signature": "..."
}
```

**Refresh Token (30-day expiration):**
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key_2025_01"
  },
  "payload": {
    "sub": "usr_01HGW3X9K2YN5Z8QRST6VWXYZ",
    "tokenId": "rt_01HGW3XABCDEFGHIJKLMNOPQRS",
    "sessionId": "ses_01HGW3XCURRENT",
    "type": "refresh",
    "iat": 1705324800,
    "exp": 1707916800,
    "iss": "https://api.sumafinance.com"
  },
  "signature": "..."
}
```

#### Token Validation Flow
```mermaid
graph TD
    A[Incoming Request] --> B{Has Authorization Header?}
    B -->|No| C[401 Unauthorized]
    B -->|Yes| D[Extract Bearer Token]
    D --> E[Verify JWT Signature]
    E --> F{Valid Signature?}
    F -->|No| G[401 Invalid Token]
    F -->|Yes| H{Token Expired?}
    H -->|Yes| I[401 Token Expired]
    H -->|No| J[Check Redis Blacklist]
    J --> K{Token Revoked?}
    K -->|Yes| L[401 Token Revoked]
    K -->|No| M[Extract Claims]
    M --> N[Attach User Context]
    N --> O[Proceed to Handler]
```

#### Token Refresh Flow
```mermaid
sequenceDiagram
    participant WebApp
    participant AuthService
    participant Redis
    participant PostgreSQL
    
    WebApp->>AuthService: POST /auth/refresh + refresh_token
    AuthService->>AuthService: Verify JWT signature
    AuthService->>AuthService: Check expiration
    
    alt Token expired
        AuthService-->>WebApp: 401 Token expired
        WebApp-->>WebApp: Redirect to login
    else Token valid
        AuthService->>Redis: Check if token revoked
        
        alt Token revoked
            Redis-->>AuthService: Token in blacklist
            AuthService-->>WebApp: 403 Token revoked
        else Token active
            AuthService->>PostgreSQL: Get user record
            AuthService->>AuthService: Generate new access token
            AuthService->>AuthService: Generate new refresh token
            AuthService->>Redis: Revoke old refresh token
            AuthService->>Redis: Store new session
            AuthService-->>WebApp: 200 OK + new tokens
            WebApp->>WebApp: Update stored tokens
        end
    end
```

### OAuth 2.0 Integration

#### Google Sign-In Flow
```mermaid
sequenceDiagram
    participant User
    participant WebApp
    participant GoogleOAuth
    participant AuthService
    participant PostgreSQL
    
    User->>WebApp: Click "Sign in with Google"
    WebApp->>GoogleOAuth: Redirect to Google consent screen
    User->>GoogleOAuth: Approve permissions
    GoogleOAuth->>WebApp: Redirect with authorization code
    
    WebApp->>AuthService: POST /auth/oauth/google/callback + code
    AuthService->>GoogleOAuth: Exchange code for tokens
    GoogleOAuth-->>AuthService: Access token + ID token
    
    AuthService->>GoogleOAuth: GET /userinfo
    GoogleOAuth-->>AuthService: User profile (email, name, picture)
    
    AuthService->>PostgreSQL: SELECT user by email
    
    alt User exists
        PostgreSQL-->>AuthService: Existing user
        AuthService->>PostgreSQL: UPDATE last_login
    else User not found
        AuthService->>PostgreSQL: INSERT new user (email_verified=true)
        AuthService->>PostgreSQL: INSERT oauth_link (provider=google)
    end
    
    AuthService->>AuthService: Generate JWT tokens
    AuthService->>Redis: Store session
    AuthService-->>WebApp: 200 OK + tokens
    WebApp-->>User: Redirect to dashboard
```

#### OAuth Provider Configuration
```go
type OAuthProvider struct {
    Provider      string
    ClientID      string
    ClientSecret  string
    RedirectURI   string
    Scopes        []string
    AuthURL       string
    TokenURL      string
    UserInfoURL   string
}

var providers = map[string]OAuthProvider{
    "google": {
        Provider:     "google",
        ClientID:     env.Get("GOOGLE_CLIENT_ID"),
        ClientSecret: env.Get("GOOGLE_CLIENT_SECRET"),
        RedirectURI:  "https://app.sumafinance.com/auth/callback/google",
        Scopes:       []string{"openid", "email", "profile"},
        AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
        TokenURL:     "https://oauth2.googleapis.com/token",
        UserInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    "apple": {
        Provider:     "apple",
        ClientID:     env.Get("APPLE_CLIENT_ID"),
        ClientSecret: generateAppleSecret(), // JWT signed with private key
        RedirectURI:  "https://app.sumafinance.com/auth/callback/apple",
        Scopes:       []string{"name", "email"},
        AuthURL:      "https://appleid.apple.com/auth/authorize",
        TokenURL:     "https://appleid.apple.com/auth/token",
    },
}
```

### Authorization Model (RBAC)

#### Role Definitions
```yaml
roles:
  user:
    permissions:
      - read:own_profile
      - write:own_profile
      - read:own_transactions
      - write:own_transactions
  
  premium_user:
    inherits: user
    permissions:
      - read:advanced_analytics
      - export:own_data
  
  admin:
    permissions:
      - read:all_users
      - write:all_users
      - delete:users
      - read:audit_logs
      - manage:roles
  
  system:
    permissions:
      - write:system_logs
      - read:all_resources
```

#### Permission Checking Middleware
```go
func RequirePermission(permission string) gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract user from JWT claims (attached by auth middleware)
        user := c.MustGet("user").(UserClaims)
        
        // Check if user has permission
        if !hasPermission(user.Role, permission) {
            c.JSON(403, gin.H{
                "error": "Forbidden",
                "message": "Insufficient permissions",
                "required": permission,
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// Usage
router.GET("/api/v1/users", 
    AuthMiddleware(),
    RequirePermission("read:all_users"),
    userController.ListUsers,
)
```

#### Resource Ownership Validation
```go
func RequireOwnership() gin.HandlerFunc {
    return func(c *gin.Context) {
        user := c.MustGet("user").(UserClaims)
        resourceUserID := c.Param("userId")
        
        // Admins can access any resource
        if user.Role == "admin" {
            c.Next()
            return
        }
        
        // Users can only access their own resources
        if user.Sub != resourceUserID {
            c.JSON(403, gin.H{
                "error": "Forbidden",
                "message": "Cannot access another user's resource",
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

### Session Management

#### Session Storage (Redis)
```go
type Session struct {
    SessionID     string    `json:"sessionId"`
    UserID        string    `json:"userId"`
    DeviceType    string    `json:"deviceType"`     // web, mobile, tablet
    Browser       string    `json:"browser"`
    OS            string    `json:"os"`
    IPAddress     string    `json:"ipAddress"`
    Location      string    `json:"location"`
    CreatedAt     time.Time `json:"createdAt"`
    LastActivity  time.Time `json:"lastActivity"`
    ExpiresAt     time.Time `json:"expiresAt"`
}

// Redis key: session:{sessionId}
// TTL: 30 days (sliding window updated on activity)

func StoreSession(ctx context.Context, session Session) error {
    key := fmt.Sprintf("session:%s", session.SessionID)
    data, _ := json.Marshal(session)
    
    // Store session with TTL
    err := redisClient.Set(ctx, key, data, 30*24*time.Hour).Err()
    if err != nil {
        return err
    }
    
    // Add to user's session set
    userSessionsKey := fmt.Sprintf("user_sessions:%s", session.UserID)
    return redisClient.SAdd(ctx, userSessionsKey, session.SessionID).Err()
}
```

#### Session Expiration and Renewal
```go
func UpdateSessionActivity(ctx context.Context, sessionID string) error {
    key := fmt.Sprintf("session:%s", sessionID)
    
    // Get session
    data, err := redisClient.Get(ctx, key).Result()
    if err != nil {
        return err
    }
    
    var session Session
    json.Unmarshal([]byte(data), &session)
    
    // Update last activity
    session.LastActivity = time.Now()
    
    // Renew TTL (sliding window)
    updatedData, _ := json.Marshal(session)
    return redisClient.Set(ctx, key, updatedData, 30*24*time.Hour).Err()
}
```

#### Concurrent Session Limits
```go
const MaxConcurrentSessions = 5

func EnforceSessionLimit(ctx context.Context, userID string, newSessionID string) error {
    userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)
    
    // Get all user sessions
    sessionIDs, err := redisClient.SMembers(ctx, userSessionsKey).Result()
    if err != nil {
        return err
    }
    
    // If under limit, allow new session
    if len(sessionIDs) < MaxConcurrentSessions {
        return nil
    }
    
    // Find oldest session and revoke it
    oldestSession := findOldestSession(ctx, sessionIDs)
    return RevokeSession(ctx, oldestSession.SessionID)
}
```

## 6. Data Model and Database Design

### Entity-Relationship Diagram
```mermaid
erDiagram
    users ||--o{ user_profiles : has
    users ||--o{ mfa_secrets : has
    users ||--o{ password_reset_tokens : has
    users ||--o{ email_verification_tokens : has
    users ||--o{ oauth_links : has
    users ||--o{ audit_logs : generates
    users ||--o{ sessions : has
    
    users {
        uuid id PK
        string email UK
        string password_hash
        boolean email_verified
        timestamp created_at
        timestamp updated_at
        timestamp deleted_at
    }
    
    user_profiles {
        uuid id PK
        uuid user_id FK
        string first_name
        string last_name
        string phone_number
        string avatar_url
        json preferences
        timestamp created_at
        timestamp updated_at
    }
    
    mfa_secrets {
        uuid id PK
        uuid user_id FK
        string secret_encrypted
        boolean enabled
        json backup_codes
        timestamp created_at
    }
    
    oauth_links {
        uuid id PK
        uuid user_id FK
        string provider
        string provider_user_id
        json profile_data
        timestamp created_at
    }
    
    password_reset_tokens {
        uuid id PK
        uuid user_id FK
        string token_hash
        timestamp expires_at
        boolean used
        timestamp created_at
    }
    
    email_verification_tokens {
        uuid id PK
        uuid user_id FK
        string token_hash
        timestamp expires_at
        boolean used
        timestamp created_at
    }
    
    audit_logs {
        uuid id PK
        uuid user_id FK
        string event_type
        json event_data
        string ip_address
        string user_agent
        timestamp created_at
    }
    
    sessions {
        uuid id PK
        uuid user_id FK
        string refresh_token_hash
        string device_fingerprint
        json metadata
        timestamp expires_at
        timestamp created_at
    }
```

### Database Schema

#### users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP NULL,
    
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users(created_at);
```

#### user_profiles Table
```sql
CREATE TABLE user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone_number VARCHAR(20),
    avatar_url TEXT,
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_profiles_user_id ON user_profiles(user_id);
```

#### mfa_secrets Table
```sql
CREATE TABLE mfa_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    backup_codes JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_secrets_user_id ON mfa_secrets(user_id) WHERE enabled = TRUE;
```

#### oauth_links Table
```sql
CREATE TABLE oauth_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    profile_data JSONB DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_oauth_links_user_id ON oauth_links(user_id);
CREATE INDEX idx_oauth_links_provider ON oauth_links(provider, provider_user_id);
```

#### password_reset_tokens Table
```sql
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_reset_tokens_hash ON password_reset_tokens(token_hash) 
    WHERE used = FALSE AND expires_at > NOW();
CREATE INDEX idx_password_reset_tokens_expires ON password_reset_tokens(expires_at);
```

#### email_verification_tokens Table
```sql
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_verification_tokens_hash ON email_verification_tokens(token_hash)
    WHERE used = FALSE AND expires_at > NOW();
```

#### audit_logs Table
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    event_data JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type, created_at DESC);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Partition by month for efficient archival
CREATE TABLE audit_logs_y2025m01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
```

#### sessions Table (PostgreSQL backup for Redis)
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL UNIQUE,
    device_fingerprint VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id, created_at DESC);
CREATE INDEX idx_sessions_refresh_token ON sessions(refresh_token_hash) 
    WHERE expires_at > NOW();
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

### Data Access Patterns

#### High-Frequency Queries (Hot Path)
```go
// 1. Login - Verify credentials (70% of all queries)
func GetUserByEmail(email string) (*User, error) {
    query := `
        SELECT id, email, password_hash, email_verified, role
        FROM users
        WHERE email = $1 AND deleted_at IS NULL
    `
    // Index: idx_users_email (unique, partial)
}

// 2. Token validation - Check if user exists
func GetUserByID(userID string) (*User, error) {
    query := `SELECT id, email, role FROM users WHERE id = $1`
    // Primary key lookup - fastest
}

// 3. Check MFA status
func GetMFASecret(userID string) (*MFASecret, error) {
    query := `
        SELECT secret_encrypted, enabled
        FROM mfa_secrets
        WHERE user_id = $1 AND enabled = TRUE
    `
    // Index: idx_mfa_secrets_user_id (unique, partial)
}
```

#### Write Patterns
```go
// Registration (transactional)
func RegisterUser(user User, profile UserProfile) error {
    tx, _ := db.Begin()
    defer tx.Rollback()
    
    // Insert user
    _, err := tx.Exec(`
        INSERT INTO users (email, password_hash, email_verified)
        VALUES ($1, $2, FALSE)
        RETURNING id
    `, user.Email, user.PasswordHash)
    
    // Insert profile
    _, err = tx.Exec(`
        INSERT INTO user_profiles (user_id, first_name, last_name)
        VALUES ($1, $2, $3)
    `, user.ID, profile.FirstName, profile.LastName)
    
    // Insert verification token
    _, err = tx.Exec(`
        INSERT INTO email_verification_tokens (user_id, token_hash)
        VALUES ($1, $2)
    `, user.ID, tokenHash)
    
    return tx.Commit()
}
```

### Index Optimization Strategy

**Priority 1: Authentication Hot Path**
- `idx_users_email` - Partial index on active users only
- `idx_mfa_secrets_user_id` - Partial index on enabled MFA only
- Primary key indexes on all tables

**Priority 2: Session Management**
- `idx_sessions_refresh_token` - Partial index on active tokens
- `idx_sessions_user_id` - Composite with created_at for sorting

**Priority 3: Audit and Compliance**
- `idx_audit_logs_user_id` - Composite with created_at DESC
- `idx_audit_logs_event_type` - For security investigations

### Database Scaling

#### Read Replicas
```yaml
topology:
  primary:
    instance: db-primary.sumafinance.com
    role: write
    connections: 50
  
  replicas:
    - instance: db-replica-1.sumafinance.com
      role: read
      connections: 100
      lag_tolerance: 100ms
    
    - instance: db-replica-2.sumafinance.com
      role: read
      connections: 100
      lag_tolerance: 100ms

routing:
  write_operations:
    - INSERT users
    - UPDATE users
    - DELETE sessions
    target: primary
  
  read_operations:
    - SELECT users WHERE email
    - SELECT user_profiles
    - SELECT audit_logs
    target: replicas (round-robin)
```

#### Connection Pooling
```go
dbConfig := &pgxpool.Config{
    MaxConns:          100,
    MinConns:          10,
    MaxConnLifetime:   time.Hour,
    MaxConnIdleTime:   30 * time.Minute,
    HealthCheckPeriod: time.Minute,
}

pool, err := pgxpool.ConnectConfig(context.Background(), dbConfig)
```

### Data Migration Strategy

#### Schema Versioning (golang-migrate)
```bash
migrations/
├── 000001_create_users_table.up.sql
├── 000001_create_users_table.down.sql
├── 000002_create_user_profiles_table.up.sql
├── 000002_create_user_profiles_table.down.sql
├── 000003_add_mfa_support.up.sql
├── 000003_add_mfa_support.down.sql
```

#### Zero-Downtime Migration Pattern
```sql
-- Step 1: Add new column (nullable)
ALTER TABLE users ADD COLUMN new_email VARCHAR(255);

-- Step 2: Deploy code that writes to both columns
-- (application deployment)

-- Step 3: Backfill data
UPDATE users SET new_email = email WHERE new_email IS NULL;

-- Step 4: Add constraint
ALTER TABLE users ALTER COLUMN new_email SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT unique_new_email UNIQUE (new_email);

-- Step 5: Deploy code that reads from new column

-- Step 6: Drop old column
ALTER TABLE users DROP COLUMN email;
ALTER TABLE users RENAME COLUMN new_email TO email;
```

## 7. Caching Strategy

### Cache Layers

#### CDN for Static Assets
- **Cloudflare/CloudFront** for HTML, CSS, JS, images
- **Cache-Control headers**: `public, max-age=31536000, immutable` for versioned assets
- **Purge strategy**: Automated on deployment via CI/CD

#### Application-Level Cache (Redis)

**Session Cache (Hot Path)**
```go
// Key: session:{sessionId}
// TTL: 30 days (sliding window)
// Data: Full session metadata (JSON)

type SessionCache struct {
    SessionID    string    `json:"sessionId"`
    UserID       string    `json:"userId"`
    Role         string    `json:"role"`
    Permissions  []string  `json:"permissions"`
    MFAVerified  bool      `json:"mfaVerified"`
    LastActivity time.Time `json:"lastActivity"`
}

func GetSession(sessionID string) (*SessionCache, error) {
    key := fmt.Sprintf("session:%s", sessionID)
    data, err := redisClient.Get(ctx, key).Result()
    if err == redis.Nil {
        return nil, ErrSessionNotFound
    }
    
    var session SessionCache
    json.Unmarshal([]byte(data), &session)
    return &session, nil
}
```

**User Cache**
```go
// Key: user:{userId}
// TTL: 1 hour
// Data: User profile + permissions

func GetUserCached(userID string) (*User, error) {
    key := fmt.Sprintf("user:%s", userID)
    
    // Try cache first
    cached, err := redisClient.Get(ctx, key).Result()
    if err == nil {
        var user User
        json.Unmarshal([]byte(cached), &user)
        return &user, nil
    }
    
    // Cache miss - fetch from DB
    user, err := db.GetUserByID(userID)
    if err != nil {
        return nil, err
    }
    
    // Store in cache
    data, _ := json.Marshal(user)
    redisClient.Set(ctx, key, data, 1*time.Hour)
    
    return user, nil
}
```

**Rate Limiting Cache**
```go
// Key: rate_limit:{ip}:{endpoint}
// TTL: Sliding window (15 minutes)
// Data: Request count

func CheckRateLimit(ip string, endpoint string) (bool, error) {
    key := fmt.Sprintf("rate_limit:%s:%s", ip, endpoint)
    
    // Increment counter
    count, err := redisClient.Incr(ctx, key).Result()
    if err != nil {
        return false, err
    }
    
    // Set expiration on first request
    if count == 1 {
        redisClient.Expire(ctx, key, 15*time.Minute)
    }
    
    // Check limit (5 requests per 15 minutes for login)
    if endpoint == "/auth/login" && count > 5 {
        return false, nil // Rate limited
    }
    
    return true, nil
}
```

### Cache Patterns

#### Cache-Aside (Lazy Loading)
```go
func GetUserProfile(userID string) (*UserProfile, error) {
    // 1. Check cache
    cacheKey := fmt.Sprintf("profile:%s", userID)
    cached, err := redisClient.Get(ctx, cacheKey).Result()
    
    if err == nil {
        // Cache hit
        var profile UserProfile
        json.Unmarshal([]byte(cached), &profile)
        return &profile, nil
    }
    
    // 2. Cache miss - fetch from database
    profile, err := db.GetUserProfile(userID)
    if err != nil {
        return nil, err
    }
    
    // 3. Store in cache for next time
    data, _ := json.Marshal(profile)
    redisClient.Set(ctx, cacheKey, data, 1*time.Hour)
    
    return profile, nil
}
```

#### Write-Through Cache
```go
func UpdateUserProfile(userID string, updates UserProfile) error {
    // 1. Update database
    err := db.UpdateUserProfile(userID, updates)
    if err != nil {
        return err
    }
    
    // 2. Update cache immediately
    cacheKey := fmt.Sprintf("profile:%s", userID)
    data, _ := json.Marshal(updates)
    redisClient.Set(ctx, cacheKey, data, 1*time.Hour)
    
    return nil
}
```

#### Refresh-Ahead Cache (Sessions)
```go
func RefreshSessionCache(sessionID string) error {
    key := fmt.Sprintf("session:%s", sessionID)
    
    // Get current TTL
    ttl := redisClient.TTL(ctx, key).Val()
    
    // If less than 5 minutes remaining, refresh
    if ttl < 5*time.Minute {
        // Fetch fresh data from DB
        session, err := db.GetSession(sessionID)
        if err != nil {
            return err
        }
        
        // Reset cache with full TTL
        data, _ := json.Marshal(session)
        redisClient.Set(ctx, key, data, 30*24*time.Hour)
    }
    
    return nil
}
```

### Cache Invalidation

#### Event-Based Invalidation
```go
// When user updates profile
func OnProfileUpdate(userID string) {
    keys := []string{
        fmt.Sprintf("user:%s", userID),
        fmt.Sprintf("profile:%s", userID),
    }
    
    for _, key := range keys {
        redisClient.Del(ctx, key)
    }
}

// When password changed - revoke all sessions
func OnPasswordChange(userID string) {
    // Invalidate all sessions
    pattern := fmt.Sprintf("session:*:user:%s", userID)
    iter := redisClient.Scan(ctx, 0, pattern, 0).Iterator()
    
    for iter.Next(ctx) {
        redisClient.Del(ctx, iter.Val())
    }
}
```

#### TTL-Based Expiration
```go
cacheTTLs := map[string]time.Duration{
    "session":   30 * 24 * time.Hour, // 30 days
    "user":      1 * time.Hour,
    "profile":   1 * time.Hour,
    "mfa":       5 * time.Minute,
    "ratelimit": 15 * time.Minute,
}
```

#### Manual Cache Purge (Admin)
```go
// POST /api/v1/admin/cache/purge
func PurgeCacheHandler(c *gin.Context) {
    var req struct {
        Pattern string `json:"pattern"` // e.g., "user:*"
    }
    c.BindJSON(&req)
    
    iter := redisClient.Scan(ctx, 0, req.Pattern, 0).Iterator()
    count := 0
    
    for iter.Next(ctx) {
        redisClient.Del(ctx, iter.Val())
        count++
    }
    
    c.JSON(200, gin.H{"purged": count})
}
```

### Cache Keys Naming Convention

```
Format: {resource}:{identifier}[:sub-resource]

Examples:
- session:ses_01HGW3XCURRENT
- user:usr_01HGW3X9K2YN5Z8QRST6VWXYZ
- profile:usr_01HGW3X9K2YN5Z8QRST6VWXYZ
- rate_limit:192.168.1.100:/auth/login
- mfa:usr_01HGW3X9K2YN5Z8QRST6VWXYZ
- user_sessions:usr_01HGW3X9K2YN5Z8QRST6VWXYZ (set of session IDs)
- lockout:usr_01HGW3X9K2YN5Z8QRST6VWXYZ
```

## 8. Security Design

### Data Encryption

#### Encryption at Rest

**Database Encryption (PostgreSQL)**
```yaml
encryption:
  method: Transparent Data Encryption (TDE)
  provider: AWS RDS / Azure SQL Database
  algorithm: AES-256
  key_rotation: 90 days
  
columns_with_additional_encryption:
  - table: mfa_secrets
    column: secret_encrypted
    method: Application-level (Vault transit engine)
  
  - table: users
    column: password_hash
    method: Argon2id (not encrypted, but hashed)
```

**File Storage Encryption (S3/Azure Blob)**
```yaml
encryption:
  method: Server-Side Encryption (SSE-KMS)
  key_management: AWS KMS / Azure Key Vault
  algorithm: AES-256
  bucket_policy: Enforce encryption for all objects
```

#### Encryption in Transit
```yaml
tls_configuration:
  minimum_version: TLS 1.3
  preferred_ciphers:
    - TLS_AES_256_GCM_SHA384
    - TLS_CHACHA20_POLY1305_SHA256
  
  certificate:
    provider: Let's Encrypt / DigiCert
    renewal: Automated (90 days before expiration)
    validation: DNS-01 challenge
  
  hsts_header:
    max_age: 31536000
    include_subdomains: true
    preload: true
```

#### Key Management (HashiCorp Vault)
```yaml
vault_configuration:
  secrets_engine: kv-v2
  
  secrets:
    jwt_signing_key:
      path: secret/auth/jwt-private-key
      rotation: 90 days
      algorithm: RS256 (4096-bit)
    
    database_credentials:
      path: database/creds/auth-service
      dynamic: true
      ttl: 24 hours
    
    encryption_keys:
      path: transit/keys/mfa-secrets
      type: aes256-gcm96
      rotation: 90 days
  
  authentication:
    method: Kubernetes service account
    role: auth-service
```

### Input Validation

#### Server-Side Validation (Go)
```go
type RegisterRequest struct {
    Email           string `json:"email" binding:"required,email,max=255"`
    Password        string `json:"password" binding:"required,min=12,max=128"`
    FirstName       string `json:"firstName" binding:"required,max=100"`
    LastName        string `json:"lastName" binding:"required,max=100"`
    GDPRConsent     bool   `json:"gdprConsent" binding:"required,eq=true"`
    TermsAccepted   bool   `json:"termsAccepted" binding:"required,eq=true"`
}

func ValidatePassword(password string) error {
    // NIST SP 800-63B guidelines
    if len(password) < 12 {
        return errors.New("password must be at least 12 characters")
    }
    
    // Check for common passwords (use zxcvbn or similar)
    strength := zxcvbn.PasswordStrength(password, []string{})
    if strength.Score < 3 {
        return errors.New("password is too weak")
    }
    
    // Check against breached password database (HaveIBeenPwned API)
    if isPasswordBreached(password) {
        return errors.New("password found in data breach database")
    }
    
    return nil
}
```

#### SQL Injection Prevention
```go
// ALWAYS use parameterized queries
func GetUserByEmail(email string) (*User, error) {
    query := `SELECT id, email FROM users WHERE email = $1`
    row := db.QueryRow(query, email) // $1 placeholder - SAFE
    
    // NEVER concatenate user input
    // BAD: query := "SELECT * FROM users WHERE email = '" + email + "'"
}
```

#### XSS Prevention
```go
import "html"

func SanitizeInput(input string) string {
    // HTML entity encoding for display
    return html.EscapeString(input)
}

// Response headers (set globally)
func SecurityHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("Content-Security-Policy", 
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Next()
    }
}
```

#### CSRF Protection
```go
// Use double-submit cookie pattern
func CSRFMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.Method != "GET" {
            cookieToken := c.Cookie("csrf_token")
            headerToken := c.GetHeader("X-CSRF-Token")
            
            if cookieToken != headerToken {
                c.JSON(403, gin.H{"error": "Invalid CSRF token"})
                c.Abort()
                return
            }
        }
        c.Next()
    }
}
```

### Rate Limiting

#### Per-IP Rate Limits (Redis)
```go
type RateLimiter struct {
    redisClient *redis.Client
}

func (rl *RateLimiter) CheckLimit(ip string, endpoint string, limit int, window time.Duration) (bool, error) {
    key := fmt.Sprintf("rate_limit:%s:%s", ip, endpoint)
    
    // Sliding window counter
    now := time.Now().Unix()
    windowStart := now - int64(window.Seconds())
    
    pipe := rl.redisClient.Pipeline()
    
    // Remove old entries
    pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))
    
    // Add current request
    pipe.ZAdd(ctx, key, &redis.Z{Score: float64(now), Member: now})
    
    // Count requests in window
    count := pipe.ZCard(ctx, key)
    
    // Set expiration
    pipe.Expire(ctx, key, window)
    
    _, err := pipe.Exec(ctx)
    if err != nil {
        return false, err
    }
    
    if count.Val() > int64(limit) {
        return false, nil // Rate limited
    }
    
    return true, nil
}

// Usage in middleware
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        ip := c.ClientIP()
        endpoint := c.Request.URL.Path
        
        limits := map[string]struct{ limit int; window time.Duration }{
            "/api/v1/auth/login":    {5, 15 * time.Minute},
            "/api/v1/auth/register": {3, 1 * time.Hour},
            "/api/v1/auth/refresh":  {10, 15 * time.Minute},
        }
        
        if config, exists := limits[endpoint]; exists {
            allowed, _ := limiter.CheckLimit(ip, endpoint, config.limit, config.window)
            if !allowed {
                c.JSON(429, gin.H{
                    "error": "Rate limit exceeded",
                    "retry_after": config.window.Seconds(),
                })
                c.Abort()
                return
            }
        }
        
        c.Next()
    }
}
```

### Security Headers

```go
func SecurityHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Content Security Policy
        c.Header("Content-Security-Policy", 
            "default-src 'self'; "+
            "script-src 'self' 'unsafe-inline' https://cdn.sumafinance.com; "+
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
            "img-src 'self' data: https:; "+
            "font-src 'self' https://fonts.gstatic.com; "+
            "connect-src 'self' https://api.sumafinance.com; "+
            "frame-ancestors 'none'")
        
        // Strict Transport Security
        c.Header("Strict-Transport-Security", 
            "max-age=31536000; includeSubDomains; preload")
        
        // XSS Protection
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        
        // Referrer Policy
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        
        // Permissions Policy
        c.Header("Permissions-Policy", 
            "geolocation=(), microphone=(), camera=()")
        
        c.Next()
    }
}
```

### Secret Management

#### Environment Variables (Development)
```bash
# .env (never commit to git)
JWT_PRIVATE_KEY_PATH=/secrets/jwt-private-key.pem
DATABASE_URL=postgresql://user:pass@localhost:5432/sumafinance
REDIS_URL=redis://localhost:6379
VAULT_ADDR=https://vault.sumafinance.com
```

#### HashiCorp Vault (Production)
```go
func LoadSecretsFromVault() (*Config, error) {
    client, err := vault.NewClient(&vault.Config{
        Address: os.Getenv("VAULT_ADDR"),
    })
    
    // Authenticate using Kubernetes service account
    client.SetToken(os.Getenv("VAULT_TOKEN"))
    
    // Read JWT signing key
    secret, err := client.Logical().Read("secret/auth/jwt-private-key")
    jwtKey := secret.Data["key"].(string)
    
    // Read database credentials (dynamically generated)
    dbCreds, err := client.Logical().Read("database/creds/auth-service")
    dbUser := dbCreds.Data["username"].(string)
    dbPass := dbCreds.Data["password"].(string)
    
    return &Config{
        JWTPrivateKey: jwtKey,
        DBUser:        dbUser,
        DBPassword:    dbPass,
    }, nil
}
```

#### Secret Rotation
```go
// Automatic rotation every 90 days
func RotateJWTKey() error {
    // Generate new RSA key pair
    privateKey, _ := rsa.GenerateKey(rand.Reader, 4096)
    
    // Store in Vault
    client.Logical().Write("secret/auth/jwt-private-key", map[string]interface{}{
        "key": encodePrivateKey(privateKey),
        "generated_at": time.Now().Unix(),
    })
    
    // Keep old key for 7 days (grace period for token validation)
    client.Logical().Write("secret/auth/jwt-private-key-old", oldKey)
    
    return nil
}
```

## 9. Logging and Monitoring

### Logging Architecture

#### Structured Logging (JSON)
```go
import "go.uber.org/zap"

logger, _ := zap.NewProduction()

// Authentication event
logger.Info("user_login",
    zap.String("user_id", "usr_01HGW3X9K2YN5Z8QRST6VWXYZ"),
    zap.String("email", "user@example.com"),
    zap.String("ip_address", "192.168.1.100"),
    zap.String("user_agent", "Mozilla/5.0..."),
    zap.Bool("mfa_verified", true),
    zap.Duration("latency_ms", 125*time.Millisecond),
)

// Failed login attempt
logger.Warn("login_failed",
    zap.String("email", "user@example.com"),
    zap.String("ip_address", "192.168.1.100"),
    zap.String("reason", "invalid_password"),
    zap.Int("failed_attempts", 3),
)

// Security alert
logger.Error("suspicious_activity",
    zap.String("user_id", "usr_01HGW3X9K2YN5Z8QRST6VWXYZ"),
    zap.String("event", "multiple_failed_mfa"),
    zap.Int("attempts", 5),
    zap.String("ip_address", "192.168.1.100"),
)
```

#### Log Aggregation (ELK Stack)
```yaml
log_pipeline:
  collection:
    agent: Filebeat
    source: /var/log/auth-service/*.log
    format: JSON
  
  processing:
    tool: Logstash
    filters:
      - grok: Parse structured logs
      - geoip: Enrich with location data
      - anonymize: Mask PII (email, IP)
  
  storage:
    tool: Elasticsearch
    indices:
      - auth-logs-{YYYY.MM.DD}
    retention: 90 days
    replicas: 2
  
  visualization:
    tool: Kibana
    dashboards:
      - Authentication Overview
      - Failed Login Attempts
      - MFA Enrollment Trends
      - Security Alerts
```

#### Sensitive Data Masking
```go
func MaskEmail(email string) string {
    parts := strings.Split(email, "@")
    if len(parts) != 2 {
        return "***"
    }
    
    username := parts[0]
    domain := parts[1]
    
    if len(username) <= 3 {
        return "***@" + domain
    }
    
    return username[:2] + "***@" + domain
}

func MaskIP(ip string) string {
    parts := strings.Split(ip, ".")
    if len(parts) == 4 {
        return fmt.Sprintf("%s.%s.***.***", parts[0], parts[1])
    }
    return "***"
}

// Usage in logging
logger.Info("user_login",
    zap.String("email_masked", MaskEmail(email)),
    zap.String("ip_masked", MaskIP(ipAddress)),
)
```

### Monitoring Metrics

#### Application Metrics (Prometheus)
```go
var (
    loginAttempts = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_login_attempts_total",
            Help: "Total number of login attempts",
        },
        []string{"status", "mfa_required"},
    )
    
    loginDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "auth_login_duration_seconds",
            Help:    "Login request duration",
            Buckets: prometheus.DefBuckets,
        },
        []string{"status"},
    )
    
    activeSessionsGauge = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "auth_active_sessions",
            Help: "Number of active user sessions",
        },
    )
    
    mfaEnrollments = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "auth_mfa_enrollments_total",
            Help: "Total MFA enrollments",
        },
    )
)

// Usage
func LoginHandler(c *gin.Context) {
    start := time.Now()
    
    // ... authentication logic ...
    
    loginAttempts.WithLabelValues("success", "false").Inc()
    loginDuration.WithLabelValues("success").Observe(time.Since(start).Seconds())
}
```

#### Infrastructure Metrics
```yaml
metrics:
  auth_service:
    - http_requests_total{service="auth",endpoint="/api/v1/auth/login"}
    - http_request_duration_seconds{service="auth"}
    - http_requests_in_flight{service="auth"}
    - go_memstats_alloc_bytes{service="auth"}
    - go_goroutines{service="auth"}
  
  postgresql:
    - pg_stat_database_tup_fetched{database="sumafinance"}
    - pg_stat_database_tup_inserted{database="sumafinance"}
    - pg_stat_database_xact_commit{database="sumafinance"}
    - pg_locks_count{database="sumafinance"}
  
  redis:
    - redis_connected_clients
    - redis_used_memory_bytes
    - redis_commands_processed_total
    - redis_keyspace_hits_total
    - redis_keyspace_misses_total
```

#### Business Metrics (Mixpanel)
```javascript
// Track registration
mixpanel.track('User Registered', {
  user_id: user.id,
  signup_method: 'email', // or 'google', 'apple'
  utm_source: 'facebook',
  utm_campaign: 'winter_2025',
  country: 'Portugal',
});

// Track login
mixpanel.track('User Logged In', {
  user_id: user.id,
  login_method: 'email',
  mfa_enabled: true,
  device_type: 'web',
});

// Track MFA enrollment
mixpanel.track('MFA Enrolled', {
  user_id: user.id,
  mfa_method: 'totp',
  days_since_registration: 5,
});
```

### Distributed Tracing (OpenTelemetry)

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/trace"
)

func LoginHandler(c *gin.Context) {
    ctx := c.Request.Context()
    tracer := otel.Tracer("auth-service")
    
    ctx, span := tracer.Start(ctx, "LoginHandler")
    defer span.End()
    
    // Verify credentials
    ctx, credSpan := tracer.Start(ctx, "VerifyCredentials")
    user, err := verifyCredentials(ctx, email, password)
    credSpan.End()
    
    if err != nil {
        span.SetAttributes(attribute.String("error", "invalid_credentials"))
        return
    }
    
    // Check MFA
    ctx, mfaSpan := tracer.Start(ctx, "CheckMFA")
    mfaRequired := checkMFARequired(ctx, user.ID)
    mfaSpan.End()
    
    // Generate tokens
    ctx, tokenSpan := tracer.Start(ctx, "GenerateTokens")
    tokens := generateJWT(ctx, user)
    tokenSpan.End()
    
    span.SetAttributes(
        attribute.String("user_id", user.ID),
        attribute.Bool("mfa_required", mfaRequired),
    )
}
```

### Alerting

#### Alert Rules (Prometheus Alertmanager)
```yaml
groups:
  - name: authentication_alerts
    interval: 30s
    rules:
      - alert: HighFailedLoginRate
        expr: |
          rate(auth_login_attempts_total{status="failed"}[5m]) > 10
        for: 5m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "High failed login rate detected"
          description: "{{ $value }} failed logins per second in the last 5 minutes"
      
      - alert: AuthServiceDown
        expr: up{service="auth"} == 0
        for: 1m
        labels:
          severity: critical
          team: platform
        annotations:
          summary: "Auth service is down"
          description: "Auth service has been down for more than 1 minute"
      
      - alert: DatabaseConnectionPoolExhausted
        expr: |
          pg_stat_database_numbackends{database="sumafinance"} > 90
        for: 2m
        labels:
          severity: critical
          team: database
        annotations:
          summary: "Database connection pool near capacity"
          description: "{{ $value }} active connections (max 100)"
      
      - alert: SuspiciousMFAFailures
        expr: |
          rate(auth_mfa_verify_attempts_total{status="failed"}[5m]) > 5
        for: 3m
        labels:
          severity: warning
          team: security
        annotations:
          summary: "High MFA failure rate - possible attack"
          description: "{{ $value }} MFA failures per second"
```

#### Alert Channels
```yaml
alertmanager_config:
  receivers:
    - name: security_team
      slack_configs:
        - channel: '#security-alerts'
          api_url: 'https://hooks.slack.com/services/...'
          title: 'Security Alert'
      
      pagerduty_configs:
        - service_key: 'xxx'
          severity: '{{ .CommonLabels.severity }}'
    
    - name: platform_team
      slack_configs:
        - channel: '#platform-alerts'
          api_url: 'https://hooks.slack.com/services/...'
      
      email_configs:
        - to: 'platform@sumafinance.com'
  
  route:
    receiver: platform_team
    group_by: ['alertname']
    group_wait: 10s
    group_interval: 10s
    repeat_interval: 12h
    
    routes:
      - match:
          team: security
        receiver: security_team
        group_wait: 0s
        repeat_interval: 1h
```

## 10. Error Handling

### Error Types

```go
// Domain errors
var (
    ErrInvalidCredentials   = errors.New("invalid email or password")
    ErrEmailNotVerified     = errors.New("email not verified")
    ErrAccountLocked        = errors.New("account locked due to failed attempts")
    ErrInvalidMFACode       = errors.New("invalid MFA code")
    ErrTokenExpired         = errors.New("token expired")
    ErrTokenRevoked         = errors.New("token revoked")
    ErrWeakPassword         = errors.New("password does not meet requirements")
    ErrEmailAlreadyExists   = errors.New("email already registered")
    ErrRateLimitExceeded    = errors.New("rate limit exceeded")
)

// Error categories
type ErrorCategory string

const (
    ErrCategoryAuth       ErrorCategory = "authentication"
    ErrCategoryValidation ErrorCategory = "validation"
    ErrCategoryDatabase   ErrorCategory = "database"
    ErrCategoryExternal   ErrorCategory = "external_service"
    ErrCategoryInternal   ErrorCategory = "internal"
)
```

### Error Response Format

```go
type ErrorResponse struct {
    Error     string            `json:"error"`
    Message   string            `json:"message"`
    Code      string            `json:"code"`
    RequestID string            `json:"requestId"`
    Timestamp string            `json:"timestamp"`
    Details   map[string]string `json:"details,omitempty"`
}

func HandleError(c *gin.Context, err error, category ErrorCategory) {
    requestID := c.GetString("request_id")
    
    var statusCode int
    var errorCode string
    var message string
    
    switch {
    case errors.Is(err, ErrInvalidCredentials):
        statusCode = 401
        errorCode = "