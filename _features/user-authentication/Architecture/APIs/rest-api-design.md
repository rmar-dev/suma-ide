


# REST API DESIGN

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: APIs
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

The SUMA Finance Authentication API provides a comprehensive, security-hardened REST API for user registration, authentication, and session management in a fintech context. The API implements industry-leading security practices including JWT-based authentication with refresh token rotation, email-based two-factor authentication, GDPR-compliant consent management, and comprehensive audit logging. 

This API design follows RESTful principles and implements OWASP Top 10 2021 security controls, GDPR requirements, and PCI-DSS authentication standards. Key capabilities include secure user registration with email verification, multi-factor authentication, password reset flows, session management with Redis-backed storage, and device tracking for fraud detection.

The API is designed for high-performance fintech applications with response times under 200ms, supporting 1000 req/s throughput with 99.95% availability. All endpoints enforce strict rate limiting, input validation, and comprehensive security logging to protect against common attack vectors including brute force, credential stuffing, and account enumeration.

## API Design Principles

### RESTful Standards
- **Resource-Oriented**: URIs represent resources (users, sessions, auth tokens), not actions
- **HTTP Methods**: Proper use of GET (retrieve), POST (create), PUT (replace), PATCH (update), DELETE (remove)
- **Stateless**: Each request contains all necessary information (JWT token, no server-side sessions except Redis cache)
- **HATEOAS**: Responses include links to related resources and next actions
- **Idempotent**: Safe operations (GET, PUT, DELETE) can be repeated without side effects

### API Maturity Level
**Level**: Level 2 - HTTP Verbs and Status Codes with partial Level 3 (HATEOAS for critical flows)

**Rationale**: Level 2 provides the right balance of REST maturity for authentication APIs. Full HATEOAS (Level 3) is implemented for multi-step authentication flows (registration → email verification → login, password reset flow) to guide clients through complex state transitions. This approach ensures security-critical workflows are clearly defined while maintaining API simplicity for standard CRUD operations.

### Design Philosophy
- **Security-first**: Every endpoint designed with OWASP Top 10 and fintech security requirements in mind
- **Simple and intuitive**: Clear, predictable endpoint naming and behavior
- **Consistent naming conventions**: Plural nouns, snake_case parameters, kebab-case URIs
- **Predictable error responses**: Standardized error format with detailed validation feedback
- **Developer-friendly**: Comprehensive examples, clear documentation, helpful error messages
- **Versioned and backwards-compatible**: URI versioning with 12-month deprecation policy

## API Versioning Strategy

### Versioning Approach
**Method**: URI Path Versioning (`/api/v1/resource`)

**Alternatives Considered**:
- **Header Versioning** (`Accept: application/vnd.suma.v1+json`): Rejected due to poor visibility and caching complexity
- **Query Parameter** (`/api/resource?version=1`): Rejected as not RESTful and complicates routing
- **Hostname** (`v1.api.suma.finance`): Rejected due to SSL certificate management overhead

**Version Lifecycle**:
- New versions introduced only with breaking changes (auth flow changes, token format changes)
- Old versions supported for minimum 12 months after new version release
- Deprecation warnings sent via `Deprecation` and `Sunset` HTTP headers 6 months before sunset
- Version sunset with 6-month notice via email, dashboard notifications, and API headers
- Critical security patches applied to all supported versions

**Current Versions**:
- **v1**: Current stable version (this document)
- **v2**: Not yet planned

## Base URL

### Environments
- **Production**: `https://api.suma.finance/v1`
- **Staging**: `https://staging-api.suma.finance/v1`
- **Development**: `https://dev-api.suma.finance/v1`
- **Local**: `http://localhost:8080/v1`

## Authentication & Authorization

### Authentication Method
**Type**: Bearer Token (JWT) with Refresh Token Rotation

**Token Acquisition**:
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!@#"
}
```

**Response**:
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "auth_session",
    "attributes": {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI1LTAxIn0...",
      "token_type": "Bearer",
      "expires_in": 900,
      "refresh_token": "rt_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
      "refresh_expires_in": 604800,
      "requires_2fa": false,
      "user_id": "550e8400-e29b-41d4-a716-446655440000"
    },
    "links": {
      "refresh": "/api/v1/auth/refresh",
      "logout": "/api/v1/auth/logout",
      "user_profile": "/api/v1/users/me"
    }
  },
  "meta": {
    "timestamp": "2025-10-29T10:30:00Z"
  }
}
```

**Token Usage**:
```http
GET /api/v1/users/me
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI1LTAxIn0...
```

### JWT Token Structure

**Header**:
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2025-01"
}
```

**Payload**:
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": true,
  "roles": ["user"],
  "permissions": ["auth:login", "profile:read", "profile:write"],
  "session_id": "session-uuid",
  "device_id": "device-fingerprint-hash",
  "iat": 1735467000,
  "exp": 1735467900,
  "nbf": 1735467000,
  "iss": "https://api.suma.finance",
  "aud": "suma-finance-app"
}
```

**Signature**: RSA-SHA256 signature using RS256 algorithm

**Token Expiration**:
- **Access Token**: 15 minutes (900 seconds)
- **Refresh Token**: 7 days (604800 seconds)

### JWT Security Features
- **Short-lived access tokens**: 15-minute expiration reduces window of token compromise
- **Refresh token rotation**: New refresh token issued on each use, old token invalidated
- **Refresh token reuse detection**: If old refresh token is used, entire token family is revoked
- **Key rotation**: JWT signing keys rotated every 90 days
- **Algorithm whitelist**: Only RS256 allowed, prevents algorithm confusion attacks
- **Session binding**: Tokens bound to session ID stored in Redis

### Authorization Model

**Role-Based Access Control (RBAC)**:
- **admin**: Full system access, user management, security settings
- **user**: Standard authenticated user operations
- **guest**: Unauthenticated access (registration, password reset only)

**Permission Format**: `resource:action`
- Examples: `auth:login`, `profile:read`, `profile:write`, `users:manage`, `audit:view`

**Endpoint Authorization**:
| Endpoint | Authentication | Required Permission | Roles |
|----------|----------------|-------------------|-------|
| POST /api/v1/auth/register | No | public | none |
| POST /api/v1/auth/login | No | public | none |
| POST /api/v1/auth/refresh | Yes | authenticated | all |
| POST /api/v1/auth/logout | Yes | authenticated | all |
| GET /api/v1/users/me | Yes | `profile:read` | user, admin |
| PATCH /api/v1/users/me | Yes | `profile:write` | user, admin |
| GET /api/v1/users | Yes | `users:manage` | admin |
| GET /api/v1/auth/audit-log | Yes | `audit:view` | admin |

## Request/Response Standards

### Request Headers

**Required Headers**:
```http
Content-Type: application/json
Accept: application/json
```

**Authentication Headers** (for protected endpoints):
```http
Authorization: Bearer {access_token}
```

**Optional Headers**:
```http
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Correlation-ID: correlation-uuid-for-tracing
Accept-Language: en-US
User-Agent: SUMA-iOS/1.2.3 (iPhone; iOS 17.0)
X-Device-ID: device-fingerprint-hash
X-Client-IP: 203.0.113.42 (forwarded by proxy)
Idempotency-Key: idempotent-request-uuid
```

### Response Headers

**Standard Headers**:
```http
Content-Type: application/json; charset=utf-8
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Correlation-ID: correlation-uuid
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
X-RateLimit-Reset: 1735467060
Cache-Control: no-store, no-cache, must-revalidate, private
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'none'
```

### Response Format

**Success Response Structure**:
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "user",
    "attributes": {
      "email": "user@example.com",
      "email_verified": true,
      "two_factor_enabled": false,
      "created_at": "2025-01-15T10:30:00Z",
      "updated_at": "2025-10-29T10:30:00Z",
      "last_login_at": "2025-10-29T10:30:00Z"
    },
    "relationships": {
      "sessions": {
        "links": {
          "related": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000/sessions"
        },
        "meta": {
          "count": 2
        }
      },
      "devices": {
        "links": {
          "related": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000/devices"
        },
        "meta": {
          "count": 3
        }
      }
    },
    "links": {
      "self": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000"
    }
  },
  "meta": {
    "timestamp": "2025-10-29T10:30:00Z",
    "version": "1.0"
  }
}
```

**Error Response Structure**:
```json
{
  "errors": [
    {
      "id": "error-550e8400-e29b-41d4-a716-446655440000",
      "status": "422",
      "code": "VALIDATION_ERROR",
      "title": "Validation Failed",
      "detail": "Password must be at least 12 characters and contain uppercase, lowercase, number, and special character",
      "source": {
        "pointer": "/data/attributes/password",
        "parameter": "password"
      },
      "meta": {
        "timestamp": "2025-10-29T10:30:00Z",
        "request_id": "request-550e8400-e29b-41d4-a716-446655440000",
        "validation_rules": {
          "min_length": 12,
          "requires_uppercase": true,
          "requires_lowercase": true,
          "requires_number": true,
          "requires_special": true
        }
      }
    }
  ]
}
```

**Multi-Error Response** (multiple validation errors):
```json
{
  "errors": [
    {
      "status": "422",
      "code": "VALIDATION_ERROR",
      "title": "Validation Failed",
      "detail": "Email format is invalid",
      "source": {
        "pointer": "/data/attributes/email"
      }
    },
    {
      "status": "422",
      "code": "VALIDATION_ERROR",
      "title": "Validation Failed",
      "detail": "Password must be at least 12 characters",
      "source": {
        "pointer": "/data/attributes/password"
      }
    }
  ]
}
```

## HTTP Status Codes

### Success Codes (2xx)
- **200 OK**: Successful GET, PATCH (user profile update, password change)
- **201 Created**: Successful POST creating a resource (registration, 2FA setup)
- **202 Accepted**: Request accepted for async processing (email sending queued)
- **204 No Content**: Successful DELETE (logout, session deletion, device removal)

### Client Error Codes (4xx)
- **400 Bad Request**: Malformed request body, invalid JSON
- **401 Unauthorized**: Missing, invalid, or expired authentication token
- **403 Forbidden**: Authenticated but not authorized (insufficient permissions, account locked)
- **404 Not Found**: Resource doesn't exist (user not found, session not found)
- **405 Method Not Allowed**: HTTP method not supported for endpoint
- **409 Conflict**: Resource conflict (email already registered, session already exists)
- **410 Gone**: Resource permanently deleted (user account deleted)
- **422 Unprocessable Entity**: Validation error (password too weak, invalid email format)
- **429 Too Many Requests**: Rate limit exceeded (too many login attempts, OTP requests)

### Server Error Codes (5xx)
- **500 Internal Server Error**: Unexpected server error (database error, uncaught exception)
- **502 Bad Gateway**: Upstream service error (Redis unavailable, email service down)
- **503 Service Unavailable**: Service temporarily unavailable (maintenance mode, overload)
- **504 Gateway Timeout**: Upstream service timeout (Redis timeout, email service timeout)

## Resource Definitions

### Resource: Authentication

#### POST /api/v1/auth/register
**Description**: Register a new user account with email verification

**Authentication**: No
**Authorization**: Public endpoint

**Request Body**:
```json
{
  "data": {
    "type": "user_registration",
    "attributes": {
      "email": "newuser@example.com",
      "password": "SecurePass123!@#",
      "password_confirmation": "SecurePass123!@#",
      "consents": {
        "terms_of_service": true,
        "privacy_policy": true,
        "marketing_emails": false
      },
      "metadata": {
        "device_id": "device-fingerprint-hash",
        "user_agent": "SUMA-iOS/1.2.3",
        "ip_address": "203.0.113.42"
      }
    }
  }
}
```

**Validation Rules**:
- **email**: Required, valid email format (RFC 5322), max 255 chars, unique (case-insensitive)
- **password**: Required, min 12 chars, max 128 chars, must contain uppercase, lowercase, number, special character
- **password_confirmation**: Required, must match password
- **consents.terms_of_service**: Required, must be true
- **consents.privacy_policy**: Required, must be true
- **consents.marketing_emails**: Optional, boolean

**Password Complexity Requirements**:
- Minimum 12 characters
- At least 1 uppercase letter (A-Z)
- At least 1 lowercase letter (a-z)
- At least 1 number (0-9)
- At least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
- Not in common password list (checked against HaveIBeenPwned database)
- Not contain user's email or name

**Example Response** (201 Created):
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "user",
    "attributes": {
      "email": "newuser@example.com",
      "email_verified": false,
      "status": "pending_verification",
      "created_at": "2025-10-29T10:30:00Z",
      "updated_at": "2025-10-29T10:30:00Z"
    },
    "links": {
      "self": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000",
      "verify_email": "/api/v1/auth/verify-email",
      "resend_verification": "/api/v1/auth/resend-verification"
    }
  },
  "meta": {
    "message": "Registration successful. Please check your email to verify your account.",
    "verification_email_sent": true,
    "timestamp": "2025-10-29T10:30:00Z"
  }
}
```

**Email Verification Process**:
1. System generates a cryptographically signed verification token (HMAC-SHA256)
2. Token valid for 24 hours
3. Email sent to user with verification link: `https://app.suma.finance/verify?token={token}`
4. User clicks link, frontend calls `POST /api/v1/auth/verify-email` with token

**Error Responses**:

**409 Conflict - Email Already Registered**:
```json
{
  "errors": [
    {
      "status": "409",
      "code": "EMAIL_ALREADY_EXISTS",
      "title": "Email Already Registered",
      "detail": "An account with this email address already exists",
      "source": {
        "pointer": "/data/attributes/email"
      },
      "links": {
        "login": "/api/v1/auth/login",
        "password_reset": "/api/v1/auth/password-reset/request"
      }
    }
  ]
}
```

**Note on Email Enumeration Prevention**: To prevent account enumeration attacks, the API returns the same response time and message format regardless of whether the email exists. The 409 response is only returned if the email is already registered AND the request comes from the same IP/device that registered the account (tracked via device fingerprint).

**422 Unprocessable Entity - Validation Errors**:
```json
{
  "errors": [
    {
      "status": "422",
      "code": "VALIDATION_ERROR",
      "title": "Validation Failed",
      "detail": "Password must be at least 12 characters and contain uppercase, lowercase, number, and special character",
      "source": {
        "pointer": "/data/attributes/password"
      },
      "meta": {
        "validation_rules": {
          "min_length": 12,
          "requires_uppercase": true,
          "requires_lowercase": true,
          "requires_number": true,
          "requires_special": true
        }
      }
    },
    {
      "status": "422",
      "code": "WEAK_PASSWORD",
      "title": "Password Compromised",
      "detail": "This password has been found in a data breach and cannot be used",
      "source": {
        "pointer": "/data/attributes/password"
      }
    }
  ]
}
```

**Rate Limiting**:
- 5 registration attempts per IP address per hour
- 3 registration attempts per email address per day
- Returns 429 Too Many Requests when exceeded

#### POST /api/v1/auth/verify-email
**Description**: Verify email address with token from verification email

**Authentication**: No
**Authorization**: Public endpoint

**Request Body**:
```json
{
  "data": {
    "type": "email_verification",
    "attributes": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiNTUwZTg0MDAtZTI5Yi00MWQ0LWE3MTYtNDQ2NjU1NDQwMDAwIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoxNzM1NTUzNDAwfQ.signature"
    }
  }
}
```

**Validation Rules**:
- **token**: Required, valid JWT format, not expired, signature valid, user exists

**Example Response** (200 OK):
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "user",
    "attributes": {
      "email": "newuser@example.com",
      "email_verified": true,
      "status": "active",
      "email_verified_at": "2025-10-29T10:35:00Z"
    },
    "links": {
      "self": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000",
      "login": "/api/v1/auth/login"
    }
  },
  "meta": {
    "message": "Email verified successfully. You can now log in.",
    "timestamp": "2025-10-29T10:35:00Z"
  }
}
```

**Error Responses**:

**400 Bad Request - Invalid or Expired Token**:
```json
{
  "errors": [
    {
      "status": "400",
      "code": "INVALID_VERIFICATION_TOKEN",
      "title": "Invalid Verification Token",
      "detail": "The verification token is invalid or has expired",
      "links": {
        "resend_verification": "/api/v1/auth/resend-verification"
      }
    }
  ]
}
```

**409 Conflict - Already Verified**:
```json
{
  "errors": [
    {
      "status": "409",
      "code": "EMAIL_ALREADY_VERIFIED",
      "title": "Email Already Verified",
      "detail": "This email address has already been verified",
      "links": {
        "login": "/api/v1/auth/login"
      }
    }
  ]
}
```

#### POST /api/v1/auth/resend-verification
**Description**: Resend email verification email

**Authentication**: No
**Authorization**: Public endpoint

**Request Body**:
```json
{
  "data": {
    "type": "verification_resend",
    "attributes": {
      "email": "newuser@example.com"
    }
  }
}
```

**Example Response** (200 OK):
```json
{
  "meta": {
    "message": "If an account with this email exists and is not verified, a verification email has been sent.",
    "timestamp": "2025-10-29T10:40:00Z"
  }
}
```

**Note on Email Enumeration Prevention**: The API always returns 200 OK with the same message regardless of whether the email exists or is already verified. This prevents attackers from enumerating registered email addresses.

**Rate Limiting**:
- 3 resend attempts per email per hour
- 10 resend attempts per IP address per hour

#### POST /api/v1/auth/login
**Description**: Authenticate user and receive access/refresh tokens

**Authentication**: No
**Authorization**: Public endpoint

**Request Body**:
```json
{
  "data": {
    "type": "login",
    "attributes": {
      "email": "user@example.com",
      "password": "SecurePass123!@#",
      "device_id": "device-fingerprint-hash",
      "device_name": "iPhone 14 Pro",
      "remember_me": true
    }
  }
}
```

**Validation Rules**:
- **email**: Required, valid email format
- **password**: Required
- **device_id**: Optional, used for device tracking and session management
- **device_name**: Optional, human-readable device name
- **remember_me**: Optional, boolean (extends refresh token expiry to 30 days if true)

**Example Response - Success Without 2FA** (200 OK):
```json
{
  "data": {
    "id": "session-550e8400-e29b-41d4-a716-446655440000",
    "type": "auth_session",
    "attributes": {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI1LTAxIn0...",
      "token_type": "Bearer",
      "expires_in": 900,
      "refresh_token": "rt_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
      "refresh_expires_in": 604800,
      "requires_2fa": false,
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "session_id": "session-550e8400-e29b-41d4-a716-446655440000"
    },
    "relationships": {
      "user": {
        "data": {
          "type": "user",
          "id": "550e8400-e29b-41d4-a716-446655440000"
        },
        "links": {
          "related": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000"
        }
      }
    },
    "links": {
      "self": "/api/v1/auth/sessions/session-550e8400-e29b-41d4-a716-446655440000",
      "refresh": "/api/v1/auth/refresh",
      "logout": "/api/v1/auth/logout"
    }
  },
  "meta": {
    "timestamp": "2025-10-29T10:30:00Z",
    "last_login_at": "2025-10-28T14:20:00Z",
    "login_ip": "203.0.113.42",
    "device_trusted": true
  }
}
```

**Example Response - Requires 2FA** (200 OK):
```json
{
  "data": {
    "id": "2fa-challenge-uuid",
    "type": "2fa_challenge",
    "attributes": {
      "requires_2fa": true,
      "challenge_id": "2fa-challenge-uuid",
      "challenge_expires_at": "2025-10-29T10:35:00Z",
      "2fa_methods": ["email_otp"],
      "otp_sent_to": "u***r@example.com"
    },
    "links": {
      "verify_2fa": "/api/v1/auth/verify-2fa"
    }
  },
  "meta": {
    "message": "Two-factor authentication required. Please check your email for the verification code.",
    "timestamp": "2025-10-29T10:30:00Z"
  }
}
```

**Error Responses**:

**401 Unauthorized - Invalid Credentials**:
```json
{
  "errors": [
    {
      "status": "401",
      "code": "INVALID_CREDENTIALS",
      "title": "Invalid Credentials",
      "detail": "The email or password you entered is incorrect",
      "meta": {
        "failed_attempts": 2,
        "remaining_attempts": 3,
        "lockout_warning": "Account will be locked after 3 more failed attempts"
      }
    }
  ]
}
```

**403 Forbidden - Account Locked**:
```json
{
  "errors": [
    {
      "status": "403",
      "code": "ACCOUNT_LOCKED",
      "title": "Account Locked",
      "detail": "Your account has been locked due to multiple failed login attempts. Please try again in 15 minutes or reset your password.",
      "meta": {
        "locked_until": "2025-10-29T10:45:00Z",
        "lockout_duration_seconds": 900
      },
      "links": {
        "password_reset": "/api/v1/auth/password-reset/request"
      }
    }
  ]
}
```

**403 Forbidden - Email Not Verified**:
```json
{
  "errors": [
    {
      "status": "403",
      "code": "EMAIL_NOT_VERIFIED",
      "title": "Email Not Verified",
      "detail": "Please verify your email address before logging in",
      "links": {
        "resend_verification": "/api/v1/auth/resend-verification"
      }
    }
  ]
}
```

**429 Too Many Requests - Rate Limit Exceeded**:
```json
{
  "errors": [
    {
      "status": "429",
      "code": "RATE_LIMIT_EXCEEDED",
      "title": "Too Many Login Attempts",
      "detail": "You have exceeded the maximum number of login attempts. Please try again later.",
      "meta": {
        "retry_after_seconds": 60
      }
    }
  ]
}
```

**Rate Limiting**:
- 5 login attempts per IP address per minute
- 10 login attempts per email per hour
- Account lockout: 5 failed attempts locks account for 15 minutes

**Security Events Logged**:
- Successful login (user_id, ip, device_id, timestamp)
- Failed login attempt (email, ip, device_id, reason, timestamp)
- Account lockout (user_id, ip, locked_until, timestamp)
- Suspicious login (impossible travel, new device, new location)

#### POST /api/v1/auth/verify-2fa
**Description**: Verify two-factor authentication code

**Authentication**: No (challenge_id serves as temporary auth)
**Authorization**: Public endpoint with rate limiting

**Request Body**:
```json
{
  "data": {
    "type": "2fa_verification",
    "attributes": {
      "challenge_id": "2fa-challenge-uuid",
      "otp_code": "123456"
    }
  }
}
```

**Validation Rules**:
- **challenge_id**: Required, valid UUID, not expired
- **otp_code**: Required, 6 digits, matches stored OTP

**Example Response** (200 OK):
```json
{
  "data": {
    "id": "session-550e8400-e29b-41d4-a716-446655440000",
    "type": "auth_session",
    "attributes": {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI1LTAxIn0...",
      "token_type": "Bearer",
      "expires_in": 900,
      "refresh_token": "rt_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
      "refresh_expires_in": 604800,
      "user_id": "550e8400-e29b-41d4-a716-446655440000",
      "session_id": "session-550e8400-e29b-41d4-a716-446655440000"
    },
    "links": {
      "refresh": "/api/v1/auth/refresh",
      "logout": "/api/v1/auth/logout"
    }
  },
  "meta": {
    "message": "Two-factor authentication successful",
    "timestamp": "2025-10-29T10:35:00Z"
  }
}
```

**Error Responses**:

**401 Unauthorized - Invalid OTP**:
```json
{
  "errors": [
    {
      "status": "401",
      "code": "INVALID_OTP",
      "title": "Invalid Verification Code",
      "detail": "The verification code you entered is incorrect",
      "meta": {
        "remaining_attempts": 2,
        "challenge_expires_at": "2025-10-29T10:35:00Z"
      }
    }
  ]
}
```

**Rate Limiting**:
- 5 OTP verification attempts per challenge
- After 5 failed attempts, challenge is invalidated and user must restart login

#### POST /api/v1/auth/refresh
**Description**: Refresh access token using refresh token

**Authentication**: Yes (refresh token in body)
**Authorization**: Valid refresh token required

**Request Body**:
```json
{
  "data": {
    "type": "token_refresh",
    "attributes": {
      "refresh_token": "rt_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    }
  }
}
```

**Example Response** (200 OK):
```json
{
  "data": {
    "id": "session-550e8400-e29b-41d4-a716-446655440000",
    "type": "auth_session",
    "attributes": {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI1LTAxIn0...",
      "token_type": "Bearer",
      "expires_in": 900,
      "refresh_token": "rt_z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4",
      "refresh_expires_in": 604800
    }
  },
  "meta": {
    "timestamp": "2025-10-29T10:45:00Z",
    "token_rotated": true
  }
}
```

**Refresh Token Rotation**:
- Each refresh returns a new refresh token
- Old refresh token is invalidated immediately
- If old refresh token is reused, entire token family is revoked (indicates token theft)

**Error Responses**:

**401 Unauthorized - Invalid Refresh Token**:
```json
{
  "errors": [
    {
      "status": "401",
      "code": "INVALID_REFRESH_TOKEN",
      "title": "Invalid Refresh Token",
      "detail": "The refresh token is invalid or has expired. Please log in again.",
      "links": {
        "login": "/api/v1/auth/login"
      }
    }
  ]
}
```

**401 Unauthorized - Token Reuse Detected**:
```json
{
  "errors": [
    {
      "status": "401",
      "code": "TOKEN_REUSE_DETECTED",
      "title": "Token Reuse Detected",
      "detail": "This refresh token has already been used. All sessions have been terminated for security. Please log in again.",
      "meta": {
        "sessions_revoked": 3,
        "security_alert": "If this wasn't you, please change your password immediately"
      },
      "links": {
        "login": "/api/v1/auth/login",
        "password_reset": "/api/v1/auth/password-reset/request"
      }
    }
  ]
}
```

**Rate Limiting**:
- 100 refresh requests per user per hour

#### POST /api/v1/auth/logout
**Description**: Logout user and invalidate current session

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Request Body** (optional):
```json
{
  "data": {
    "type": "logout",
    "attributes": {
      "all_sessions": false
    }
  }
}
```

**Parameters**:
- **all_sessions**: Optional, boolean. If true, logs out all sessions for this user. Default: false.

**Example Response** (204 No Content):
```http
HTTP/1.1 204 No Content
X-Request-ID: request-uuid
```

**Alternative Response with Body** (200 OK):
```json
{
  "meta": {
    "message": "Logged out successfully",
    "sessions_terminated": 1,
    "timestamp": "2025-10-29T11:00:00Z"
  }
}
```

**Logout Behavior**:
- Invalidates current access token (added to Redis blacklist until expiry)
- Invalidates current refresh token
- Removes session from Redis
- Logs security event

#### POST /api/v1/auth/password-reset/request
**Description**: Request password reset email

**Authentication**: No
**Authorization**: Public endpoint

**Request Body**:
```json
{
  "data": {
    "type": "password_reset_request",
    "attributes": {
      "email": "user@example.com"
    }
  }
}
```

**Example Response** (200 OK):
```json
{
  "meta": {
    "message": "If an account with this email exists, a password reset email has been sent.",
    "timestamp": "2025-10-29T11:00:00Z"
  }
}
```

**Email Enumeration Prevention**: Always returns 200 OK with the same message regardless of whether the email exists.

**Password Reset Token**:
- Cryptographically signed token (HMAC-SHA256)
- Valid for 1 hour
- Single-use (invalidated after password reset)
- Includes user_id, email, expiry timestamp

**Rate Limiting**:
- 3 password reset requests per email per hour
- 10 password reset requests per IP per hour

#### POST /api/v1/auth/password-reset/verify
**Description**: Verify password reset token validity

**Authentication**: No
**Authorization**: Public endpoint

**Request Body**:
```json
{
  "data": {
    "type": "password_reset_verification",
    "attributes": {
      "token": "reset-token-from-email"
    }
  }
}
```

**Example Response** (200 OK):
```json
{
  "data": {
    "type": "password_reset_token",
    "attributes": {
      "token_valid": true,
      "expires_at": "2025-10-29T12:00:00Z"
    },
    "links": {
      "reset_password": "/api/v1/auth/password-reset/confirm"
    }
  }
}
```

**Error Responses**:

**400 Bad Request - Invalid or Expired Token**:
```json
{
  "errors": [
    {
      "status": "400",
      "code": "INVALID_RESET_TOKEN",
      "title": "Invalid Reset Token",
      "detail": "The password reset token is invalid or has expired",
      "links": {
        "request_reset": "/api/v1/auth/password-reset/request"
      }
    }
  ]
}
```

#### POST /api/v1/auth/password-reset/confirm
**Description**: Reset password with token

**Authentication**: No
**Authorization**: Valid reset token required

**Request Body**:
```json
{
  "data": {
    "type": "password_reset",
    "attributes": {
      "token": "reset-token-from-email",
      "new_password": "NewSecurePass123!@#",
      "new_password_confirmation": "NewSecurePass123!@#"
    }
  }
}
```

**Validation Rules**:
- **token**: Required, valid format, not expired, not used
- **new_password**: Required, meets password complexity requirements
- **new_password_confirmation**: Required, matches new_password
- **new_password**: Must not match any of last 5 passwords (password history)

**Example Response** (200 OK):
```json
{
  "data": {
    "type": "password_reset_success",
    "attributes": {
      "password_changed": true,
      "all_sessions_terminated": true
    },
    "links": {
      "login": "/api/v1/auth/login"
    }
  },
  "meta": {
    "message": "Password reset successful. All existing sessions have been terminated. Please log in with your new password.",
    "timestamp": "2025-10-29T11:30:00Z"
  }
}
```

**Security Actions on Password Reset**:
- Password updated with Argon2id hash
- All existing sessions terminated
- All refresh tokens invalidated
- Password history updated
- Security event logged
- Email notification sent to user

**Error Responses**:

**422 Unprocessable Entity - Password Reuse**:
```json
{
  "errors": [
    {
      "status": "422",
      "code": "PASSWORD_REUSED",
      "title": "Password Previously Used",
      "detail": "This password has been used recently. Please choose a different password.",
      "source": {
        "pointer": "/data/attributes/new_password"
      },
      "meta": {
        "password_history_count": 5
      }
    }
  ]
}
```

### Resource: Users

#### GET /api/v1/users/me
**Description**: Get current authenticated user's profile

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Query Parameters**: None

**Example Request**:
```http
GET /api/v1/users/me
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0yMDI1LTAxIn0...
```

**Example Response** (200 OK):
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "user",
    "attributes": {
      "email": "user@example.com",
      "email_verified": true,
      "email_verified_at": "2025-01-15T10:35:00Z",
      "two_factor_enabled": true,
      "status": "active",
      "created_at": "2025-01-15T10:30:00Z",
      "updated_at": "2025-10-29T10:30:00Z",
      "last_login_at": "2025-10-29T10:30:00Z",
      "last_password_change_at": "2025-09-01T08:00:00Z"
    },
    "relationships": {
      "sessions": {
        "links": {
          "related": "/api/v1/users/me/sessions"
        },
        "meta": {
          "count": 2
        }
      },
      "devices": {
        "links": {
          "related": "/api/v1/users/me/devices"
        },
        "meta": {
          "count": 3
        }
      }
    },
    "links": {
      "self": "/api/v1/users/me",
      "update": "/api/v1/users/me",
      "change_password": "/api/v1/users/me/password",
      "enable_2fa": "/api/v1/users/me/2fa/enable"
    }
  },
  "meta": {
    "timestamp": "2025-10-29T11:00:00Z"
  }
}
```

**Error Responses**:

**401 Unauthorized - Missing or Invalid Token**:
```json
{
  "errors": [
    {
      "status": "401",
      "code": "AUTHENTICATION_REQUIRED",
      "title": "Authentication Required",
      "detail": "You must be authenticated to access this resource",
      "links": {
        "login": "/api/v1/auth/login"
      }
    }
  ]
}
```

#### PATCH /api/v1/users/me
**Description**: Update current user's profile (limited fields)

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Request Body**:
```json
{
  "data": {
    "type": "user",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "attributes": {
      "email": "newemail@example.com"
    }
  }
}
```

**Updatable Fields**:
- **email**: Changing email requires re-verification (sends verification email to new address)

**Note**: This is a minimal profile update endpoint. Additional profile fields (name, phone, address) would be added here in a real implementation.

**Example Response** (200 OK):
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "user",
    "attributes": {
      "email": "newemail@example.com",
      "email_verified": false,
      "updated_at": "2025-10-29T11:15:00Z"
    },
    "links": {
      "verify_email": "/api/v1/auth/verify-email",
      "resend_verification": "/api/v1/auth/resend-verification"
    }
  },
  "meta": {
    "message": "Email updated. Please verify your new email address.",
    "verification_email_sent": true,
    "timestamp": "2025-10-29T11:15:00Z"
  }
}
```

**Email Change Security**:
- Verification email sent to new address
- Email change not finalized until verified
- Notification email sent to old address
- Security event logged

#### POST /api/v1/users/me/password
**Description**: Change password for authenticated user

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Request Body**:
```json
{
  "data": {
    "type": "password_change",
    "attributes": {
      "current_password": "OldSecurePass123!@#",
      "new_password": "NewSecurePass456!@#",
      "new_password_confirmation": "NewSecurePass456!@#"
    }
  }
}
```

**Validation Rules**:
- **current_password**: Required, must match user's current password
- **new_password**: Required, meets password complexity requirements, not in password history
- **new_password_confirmation**: Required, matches new_password

**Example Response** (200 OK):
```json
{
  "data": {
    "type": "password_change_success",
    "attributes": {
      "password_changed": true,
      "last_password_change_at": "2025-10-29T11:20:00Z"
    }
  },
  "meta": {
    "message": "Password changed successfully. You will remain logged in on this device.",
    "timestamp": "2025-10-29T11:20:00Z"
  }
}
```

**Security Actions on Password Change**:
- Password updated with Argon2id hash
- Current session remains active
- All other sessions terminated
- All other refresh tokens invalidated
- Password history updated
- Security event logged
- Email notification sent to user

**Error Responses**:

**401 Unauthorized - Incorrect Current Password**:
```json
{
  "errors": [
    {
      "status": "401",
      "code": "INVALID_CURRENT_PASSWORD",
      "title": "Incorrect Password",
      "detail": "The current password you entered is incorrect",
      "source": {
        "pointer": "/data/attributes/current_password"
      }
    }
  ]
}
```

### Resource: Two-Factor Authentication

#### POST /api/v1/users/me/2fa/enable
**Description**: Enable two-factor authentication (email OTP)

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Request Body** (optional):
```json
{
  "data": {
    "type": "2fa_enable",
    "attributes": {
      "method": "email_otp"
    }
  }
}
```

**Example Response** (200 OK):
```json
{
  "data": {
    "type": "2fa_setup",
    "attributes": {
      "two_factor_enabled": true,
      "method": "email_otp",
      "backup_codes": [
        "ABCD-1234-EFGH",
        "IJKL-5678-MNOP",
        "QRST-9012-UVWX",
        "YZAB-3456-CDEF",
        "GHIJ-7890-KLMN"
      ],
      "backup_codes_expires_at": "2026-10-29T11:25:00Z"
    },
    "links": {
      "disable_2fa": "/api/v1/users/me/2fa/disable",
      "regenerate_backup_codes": "/api/v1/users/me/2fa/backup-codes/regenerate"
    }
  },
  "meta": {
    "message": "Two-factor authentication enabled successfully. Save your backup codes in a secure location.",
    "timestamp": "2025-10-29T11:25:00Z"
  }
}
```

**Backup Codes**:
- 5 single-use backup codes generated
- Each code can be used once as alternative to OTP
- Valid for 1 year
- User should save codes securely

#### POST /api/v1/users/me/2fa/disable
**Description**: Disable two-factor authentication

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Request Body**:
```json
{
  "data": {
    "type": "2fa_disable",
    "attributes": {
      "password": "SecurePass123!@#"
    }
  }
}
```

**Validation Rules**:
- **password**: Required, must match user's current password (security confirmation)

**Example Response** (200 OK):
```json
{
  "data": {
    "type": "2fa_status",
    "attributes": {
      "two_factor_enabled": false
    }
  },
  "meta": {
    "message": "Two-factor authentication disabled",
    "timestamp": "2025-10-29T11:30:00Z"
  }
}
```

**Security Actions**:
- 2FA disabled
- All backup codes invalidated
- Security event logged
- Email notification sent to user

### Resource: Sessions

#### GET /api/v1/users/me/sessions
**Description**: List all active sessions for current user

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Example Response** (200 OK):
```json
{
  "data": [
    {
      "id": "session-550e8400-e29b-41d4-a716-446655440000",
      "type": "session",
      "attributes": {
        "device_name": "iPhone 14 Pro",
        "device_id": "device-fingerprint-hash-1",
        "ip_address": "203.0.113.42",
        "location": "Lisbon, Portugal",
        "user_agent": "SUMA-iOS/1.2.3 (iPhone; iOS 17.0)",
        "is_current": true,
        "created_at": "2025-10-29T10:30:00Z",
        "last_activity_at": "2025-10-29T11:00:00Z",
        "expires_at": "2025-11-05T10:30:00Z"
      },
      "links": {
        "self": "/api/v1/users/me/sessions/session-550e8400-e29b-41d4-a716-446655440000",
        "revoke": "/api/v1/users/me/sessions/session-550e8400-e29b-41d4-a716-446655440000"
      }
    },
    {
      "id": "session-660f9511-f3ac-52e5-b827-557766551111",
      "type": "session",
      "attributes": {
        "device_name": "MacBook Pro",
        "device_id": "device-fingerprint-hash-2",
        "ip_address": "198.51.100.23",
        "location": "Porto, Portugal",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "is_current": false,
        "created_at": "2025-10-28T14:20:00Z",
        "last_activity_at": "2025-10-29T09:15:00Z",
        "expires_at": "2025-11-04T14:20:00Z"
      },
      "links": {
        "self": "/api/v1/users/me/sessions/session-660f9511-f3ac-52e5-b827-557766551111",
        "revoke": "/api/v1/users/me/sessions/session-660f9511-f3ac-52e5-b827-557766551111"
      }
    }
  ],
  "meta": {
    "total": 2,
    "timestamp": "2025-10-29T11:35:00Z"
  }
}
```

#### DELETE /api/v1/users/me/sessions/{session_id}
**Description**: Revoke a specific session (remote logout)

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| session_id | uuid | Yes | Session ID to revoke |

**Example Response** (204 No Content):
```http
HTTP/1.1 204 No Content
```

**Security Actions**:
- Session invalidated in Redis
- Refresh token invalidated
- Access token blacklisted
- Security event logged

### Resource: Devices

#### GET /api/v1/users/me/devices
**Description**: List all known devices for current user

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Example Response** (200 OK):
```json
{
  "data": [
    {
      "id": "device-550e8400-e29b-41d4-a716-446655440000",
      "type": "device",
      "attributes": {
        "device_id": "device-fingerprint-hash-1",
        "device_name": "iPhone 14 Pro",
        "device_type": "mobile",
        "os": "iOS 17.0",
        "browser": "SUMA-iOS/1.2.3",
        "is_trusted": true,
        "first_seen_at": "2025-01-15T10:30:00Z",
        "last_seen_at": "2025-10-29T11:00:00Z",
        "last_ip": "203.0.113.42",
        "last_location": "Lisbon, Portugal"
      },
      "links": {
        "self": "/api/v1/users/me/devices/device-550e8400-e29b-41d4-a716-446655440000",
        "remove": "/api/v1/users/me/devices/device-550e8400-e29b-41d4-a716-446655440000"
      }
    },
    {
      "id": "device-660f9511-f3ac-52e5-b827-557766551111",
      "type": "device",
      "attributes": {
        "device_id": "device-fingerprint-hash-2",
        "device_name": "MacBook Pro",
        "device_type": "desktop",
        "os": "macOS 14.0",
        "browser": "Chrome 120.0",
        "is_trusted": true,
        "first_seen_at": "2025-01-20T08:00:00Z",
        "last_seen_at": "2025-10-29T09:15:00Z",
        "last_ip": "198.51.100.23",
        "last_location": "Porto, Portugal"
      },
      "links": {
        "self": "/api/v1/users/me/devices/device-660f9511-f3ac-52e5-b827-557766551111",
        "remove": "/api/v1/users/me/devices/device-660f9511-f3ac-52e5-b827-557766551111"
      }
    }
  ],
  "meta": {
    "total": 2,
    "timestamp": "2025-10-29T11:40:00Z"
  }
}
```

#### DELETE /api/v1/users/me/devices/{device_id}
**Description**: Remove a trusted device

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| device_id | uuid | Yes | Device ID to remove |

**Example Response** (204 No Content):
```http
HTTP/1.1 204 No Content
```

**Security Actions**:
- Device removed from trusted devices
- All sessions on this device terminated
- User will be prompted for 2FA on next login from this device
- Security event logged

### Resource: Audit Log (Admin Only)

#### GET /api/v1/users/me/audit-log
**Description**: Get security audit log for current user

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Query Parameters**:
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| page | integer | No | 1 | Page number |
| per_page | integer | No | 20 | Items per page (max 100) |
| event_type | string | No | all | Filter by event type |
| start_date | ISO8601 | No | 30 days ago | Start date |
| end_date | ISO8601 | No | now | End date |

**Event Types**:
- `login.success`
- `login.failed`
- `login.2fa_success`
- `login.2fa_failed`
- `logout`
- `password.changed`
- `password.reset`
- `email.changed`
- `email.verified`
- `2fa.enabled`
- `2fa.disabled`
- `session.created`
- `session.revoked`
- `device.added`
- `device.removed`
- `account.locked`
- `account.unlocked`

**Example Response** (200 OK):
```json
{
  "data": [
    {
      "id": "event-550e8400-e29b-41d4-a716-446655440000",
      "type": "audit_event",
      "attributes": {
        "event_type": "login.success",
        "timestamp": "2025-10-29T10:30:00Z",
        "ip_address": "203.0.113.42",
        "location": "Lisbon, Portugal",
        "device_id": "device-fingerprint-hash-1",
        "device_name": "iPhone 14 Pro",
        "user_agent": "SUMA-iOS/1.2.3",
        "metadata": {
          "2fa_used": false,
          "remember_me": true
        }
      }
    },
    {
      "id": "event-660f9511-f3ac-52e5-b827-557766551111",
      "type": "audit_event",
      "attributes": {
        "event_type": "password.changed",
        "timestamp": "2025-09-01T08:00:00Z",
        "ip_address": "198.51.100.23",
        "location": "Porto, Portugal",
        "device_id": "device-fingerprint-hash-2",
        "device_name": "MacBook Pro",
        "user_agent": "Chrome/120.0",
        "metadata": {
          "sessions_terminated": 2
        }
      }
    }
  ],
  "meta": {
    "total": 156,
    "page": 1,
    "per_page": 20,
    "total_pages": 8,
    "timestamp": "2025-10-29T11:45:00Z"
  },
  "links": {
    "self": "/api/v1/users/me/audit-log?page=1",
    "next": "/api/v1/users/me/audit-log?page=2",
    "last": "/api/v1/users/me/audit-log?page=8"
  }
}
```

### Resource: GDPR Consent

#### GET /api/v1/users/me/consents
**Description**: Get user's GDPR consent history

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Example Response** (200 OK):
```json
{
  "data": [
    {
      "id": "consent-550e8400-e29b-41d4-a716-446655440000",
      "type": "consent",
      "attributes": {
        "consent_type": "terms_of_service",
        "version": "1.0",
        "consented": true,
        "consented_at": "2025-01-15T10:30:00Z",
        "ip_address": "203.0.113.42",
        "withdrawn": false
      },
      "links": {
        "document": "https://suma.finance/legal/terms-v1.0.pdf"
      }
    },
    {
      "id": "consent-660f9511-f3ac-52e5-b827-557766551111",
      "type": "consent",
      "attributes": {
        "consent_type": "privacy_policy",
        "version": "1.0",
        "consented": true,
        "consented_at": "2025-01-15T10:30:00Z",
        "ip_address": "203.0.113.42",
        "withdrawn": false
      },
      "links": {
        "document": "https://suma.finance/legal/privacy-v1.0.pdf"
      }
    },
    {
      "id": "consent-770fa622-g4bd-63f6-c938-668877662222",
      "type": "consent",
      "attributes": {
        "consent_type": "marketing_emails",
        "version": "1.0",
        "consented": false,
        "consented_at": null,
        "withdrawn": false
      }
    }
  ],
  "meta": {
    "total": 3,
    "timestamp": "2025-10-29T11:50:00Z"
  }
}
```

#### POST /api/v1/users/me/consents/withdraw
**Description**: Withdraw consent for marketing or optional data processing

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Request Body**:
```json
{
  "data": {
    "type": "consent_withdrawal",
    "attributes": {
      "consent_type": "marketing_emails"
    }
  }
}
```

**Example Response** (200 OK):
```json
{
  "data": {
    "id": "consent-770fa622-g4bd-63f6-c938-668877662222",
    "type": "consent",
    "attributes": {
      "consent_type": "marketing_emails",
      "consented": false,
      "withdrawn": true,
      "withdrawn_at": "2025-10-29T11:55:00Z"
    }
  },
  "meta": {
    "message": "Consent withdrawn successfully",
    "timestamp": "2025-10-29T11:55:00Z"
  }
}
```

#### POST /api/v1/users/me/data-export
**Description**: Request GDPR data export (right to data portability)

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Request Body** (optional):
```json
{
  "data": {
    "type": "data_export_request",
    "attributes": {
      "format": "json"
    }
  }
}
```

**Supported Formats**:
- `json` (default)
- `csv`
- `xml`

**Example Response** (202 Accepted):
```json
{
  "data": {
    "id": "export-job-550e8400-e29b-41d4-a716-446655440000",
    "type": "data_export_job",
    "attributes": {
      "status": "pending",
      "format": "json",
      "created_at": "2025-10-29T12:00:00Z",
      "estimated_completion": "2025-10-29T12:10:00Z"
    },
    "links": {
      "self": "/api/v1/users/me/data-export/export-job-550e8400-e29b-41d4-a716-446655440000",
      "status": "/api/v1/users/me/data-export/export-job-550e8400-e29b-41d4-a716-446655440000/status"
    }
  },
  "meta": {
    "message": "Data export request accepted. You will receive an email when your export is ready.",
    "timestamp": "2025-10-29T12:00:00Z"
  }
}
```

**Data Export Contents**:
- User profile data
- Consent history
- Audit log (all security events)
- Session history
- Device history
- Any additional user data

**Export Delivery**:
- Secure download link sent via email
- Link valid for 7 days
- Encrypted zip file with password sent separately

#### DELETE /api/v1/users/me
**Description**: Request account deletion (right to erasure)

**Authentication**: Yes (Bearer token)
**Authorization**: Authenticated user

**Request Body**:
```json
{
  "data": {
    "type": "account_deletion",
    "attributes": {
      "password": "SecurePass123!@#",
      "reason": "No longer using the service"
    }
  }
}
```

**Validation Rules**:
- **password**: Required, must match user's current password
- **reason**: Optional, user feedback

**Example Response** (202 Accepted):
```json
{
  "data": {
    "type": "account_deletion_request",
    "attributes": {
      "deletion_scheduled_at": "2025-11-05T12:00:00Z",
      "grace_period_days": 7
    },
    "links": {
      "cancel_deletion": "/api/v1/users/me/cancel-deletion"
    }
  },
  "meta": {
    "message": "Account deletion scheduled. You have 7 days to cancel this request.",
    "timestamp": "2025-10-29T12:00:00Z"
  }
}
```

**Account Deletion Process**:
1. Account marked for deletion
2. 7-day grace period (user can cancel)
3. After grace period, account permanently deleted
4. All user data erased (except legal retention requirements)
5. All sessions terminated immediately
6. Confirmation email sent

**Data Retention**:
- Audit logs retained for 90 days (security/fraud detection)
- Financial transaction records retained per legal requirements
- Anonymized analytics retained indefinitely

## Pagination

### Offset-Based Pagination
**When to Use**: Simple use cases, known total count needed (audit logs, session lists)

**Parameters**:
- `page`: Page number (1-indexed)
- `per_page`: Items per page (max 100, default 20)

**Example**:
```http
GET /api/v1/users/me/audit-log?page=2&per_page=50
```

**Response**:
```json
{
  "data": [...],
  "meta": {
    "total": 1000,
    "page": 2,
    "per_page": 50,
    "total_pages": 20
  },
  "links": {
    "self": "/api/v1/users/me/audit-log?page=2&per_page=50",
    "first": "/api/v1/users/me/audit-log?page=1&per_page=50",
    "prev": "/api/v1/users/me/audit-log?page=1&per_page=50",
    "next": "/api/v1/users/me/audit-log?page=3&per_page=50",
    "last": "/api/v1/users/me/audit-log?page=20&per_page=50"
  }
}
```

## Filtering

### Query Parameter Filters
**Format**: `filter[field]=value`

**Example**:
```http
GET /api/v1/users/me/audit-log?filter[event_type]=login.success&filter[start_date]=2025-10-01
```

**Supported Operators**:
- Exact match: `filter[event_type]=login.success`
- Date range: `filter[start_date]=2025-10-01&filter[end_date]=2025-10-31`

## Sorting

### Sort Parameter
**Format**: `sort=field1,-field2` (prefix with `-` for descending)

**Example**:
```http
GET /api/v1/users/me/audit-log?sort=-timestamp
```

Sorts by `timestamp` descending (most recent first).

## Rate Limiting

### Rate Limit Headers
```http
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 4
X-RateLimit-Reset: 1735467060
Retry-After: 60
```

### Rate Limit Tiers

#### Authentication Endpoints
| Endpoint | Rate Limit | Scope |
|----------|-----------|-------|
| POST /api/v1/auth/register | 5/hour | per IP |
| POST /api/v1/auth/login | 5/min, 10/hour | per IP, per email |
| POST /api/v1/auth/verify-2fa | 5 attempts | per challenge |
| POST /api/v1/auth/refresh | 100/hour | per user |
| POST /api/v1/auth/password-reset/request | 3/hour | per email |
| POST /api/v1/auth/resend-verification | 3/hour | per email |

#### User Endpoints
| Endpoint | Rate Limit | Scope |
|----------|-----------|-------|
| GET /api/v1/users/me | 100/min | per user |
| PATCH /api/v1/users/me | 10/hour | per user |
| POST /api/v1/users/me/password | 5/hour | per user |
| POST /api/v1/users/me/2fa/* | 10/hour | per user |

### Rate Limit Exceeded Response
```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1735467060
Retry-After: 60

{
  "errors": [
    {
      "status": "429",
      "code": "RATE_LIMIT_EXCEEDED",
      "title": "Rate Limit Exceeded",
      "detail": "Too many login attempts. Please try again in 1 minute.",
      "meta": {
        "retry_after_seconds": 60,
        "rate_limit": "5 per minute"
      }
    }
  ]
}
```

## Caching

### Cache Headers

**No Caching for Authentication APIs**:
```http
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Expires: 0
```

**Rationale**: Authentication responses contain sensitive data (tokens, user info) and must never be cached.

## Idempotency

### Idempotency Key
**Usage**: Include `Idempotency-Key` header for critical POST requests (registration, password reset)

```http
POST /api/v1/auth/register
Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
Content-Type: application/json
```

**Behavior**:
- Server stores idempotency key and response for 24 hours
- Duplicate requests with same key return cached response (200 OK instead of 201 Created)
- Prevents duplicate registrations, password resets

**Applicable Endpoints**:
- POST /api/v1/auth/register
- POST /api/v1/auth/password-reset/request
- POST /api/v1/users/me/data-export

## CORS Configuration

### Allowed Origins
- `https://app.suma.finance`
- `https://staging.suma.finance`
- `https://localhost:3000` (development only)

### CORS Headers
```http
Access-Control-Allow-Origin: https://app.suma.finance
Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type, X-Request-ID, Idempotency-Key
Access-Control-Max-Age: 86400
Access-Control-Allow-Credentials: false
```

**Note**: `Access-Control-Allow-Credentials` is `false` because we use Bearer tokens (not cookies).

## Compression

### Supported Compression
- gzip
- br (Brotli) - preferred for modern clients

**Request**:
```http
Accept-Encoding: br, gzip
```

**Response**:
```http
Content-Encoding: br
Vary: Accept-Encoding
```

## Content Negotiation

### Supported Media Types
- `application/json` (only supported format for this API)

**Request**:
```http
Accept: application/json
```

**Response**:
```http
Content-Type: application/json; charset=utf-8
```

## Error Handling

### Error Categories

1. **Validation Errors (422)**: Invalid input data
   - Password too weak
   - Invalid email format
   - Missing required fields
   - Password mismatch

2. **Authentication Errors (401)**: Missing/invalid credentials
   - Missing authorization header
   - Invalid or expired access token
   - Invalid refresh token
   - Incorrect password

3. **Authorization Errors (403)**: Insufficient permissions
   - Account locked
   - Email not verified
   - Insufficient permissions

4. **Not Found Errors (404)**: Resource doesn't exist
   - User not found
   - Session not found
   - Device not found

5. **Conflict Errors (409)**: Resource conflict
   - Email already registered
   - Email already verified

6. **Rate Limit Errors (429)**: Too many requests
   - Login attempts exceeded
   - Password reset requests exceeded
   - OTP verification attempts exceeded

7. **Server Errors (500)**: Internal server error
   - Database error
   - Redis unavailable
   - Email service down

### Error Response Standard
```json
{
  "errors": [
    {
      "id": "error-550e8400-e29b-41d4-a716-446655440000",
      "status": "422",
      "code": "VALIDATION_ERROR",
      "title": "Validation Failed",
      "detail": "Specific error message explaining what went wrong",
      "source": {
        "pointer": "/data/attributes/password",
        "parameter": "password"
      },
      "meta": {
        "timestamp": "2025-10-29T10:30:00Z",
        "request_id": "request-550e8400-e29b-41d4-a716-446655440000",
        "validation_rules": {
          "min_length": 12
        }
      },
      "links": {
        "about": "https://docs.suma.finance/errors/VALIDATION_ERROR",
        "help": "/api/v1/auth/register"
      }
    }
  ]
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| VALIDATION_ERROR | 422 | Input validation failed |
| WEAK_PASSWORD | 422 | Password doesn't meet complexity requirements |
| PASSWORD_REUSED | 422 | Password was used recently |
| EMAIL_ALREADY_EXISTS | 409 | Email already registered |
| EMAIL_ALREADY_VERIFIED | 409 | Email already verified |
| INVALID_CREDENTIALS | 401 | Email or password incorrect |
| INVALID_TOKEN | 401 | JWT token invalid or expired |
| INVALID_REFRESH_TOKEN | 401 | Refresh token invalid or expired |
| TOKEN_REUSE_DETECTED | 401 | Refresh token reused (security breach) |
| INVALID_OTP | 401 | 2FA OTP code incorrect |
| INVALID_VERIFICATION_TOKEN | 400 | Email verification token invalid |
| INVALID_RESET_TOKEN | 400 | Password reset token invalid |
| INVALID_CURRENT_PASSWORD | 401 | Current password incorrect |
| AUTHENTICATION_REQUIRED | 401 | Missing or invalid bearer token |
| ACCOUNT_LOCKED | 403 | Account locked due to failed attempts |
| EMAIL_NOT_VERIFIED | 403 | Email not verified |
| INSUFFICIENT_PERMISSIONS | 403 | Not authorized for this operation |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Server error |
| SERVICE_UNAVAILABLE | 503 | Service temporarily unavailable |

## Security Considerations

### Input Validation
- **Schema Validation**: All inputs validated against JSON schemas
- **Type Validation**: Strict type checking (string, integer, boolean)
- **Format Validation**: Email (RFC 5322), password complexity, UUID format
- **Length Limits**: Email max 255 chars, password 12-128 chars
- **Whitelist Validation**: Only expected fields accepted
- **Reject Unexpected Fields**: Extra fields in request body rejected

### SQL Injection Prevention
- **Prepared Statements**: All database queries use parameterized queries
- **ORM**: Use Go ORM (GORM) with automatic query parameterization
- **No String Concatenation**: Never concatenate user input into SQL

### XSS Prevention
- **JSON Encoding**: All responses JSON-encoded
- **Content-Type Header**: Always `application/json`
- **No HTML**: Never return HTML in responses
- **No Script Tags**: Never reflect user input in responses

### CSRF Protection
- **Stateless JWT**: Not applicable for stateless APIs
- **No Cookies**: No session cookies used
- **Custom Headers**: `Authorization` header required

### Password Security
- **Hashing Algorithm**: Argon2id (memory-hard, OWASP recommended)
- **Salt**: Unique salt per password (automatic with Argon2id)
- **Complexity Requirements**: Min 12 chars, uppercase, lowercase, number, special
- **Breach Detection**: Check against HaveIBeenPwned database
- **Password History**: Last 5 passwords stored (hashed)

### Token Security
- **Algorithm**: RS256 (RSA-SHA256, asymmetric)
- **Key Length**: 2048-bit RSA keys
- **Key Rotation**: Keys rotated every 90 days
- **Short Expiry**: Access tokens 15 minutes
- **Refresh Token Rotation**: New refresh token on each use
- **Reuse Detection**: Old refresh token usage triggers revocation
- **Secure Storage**: Refresh tokens hashed in database

### HTTPS Only
- **Enforce HTTPS**: Redirect HTTP to HTTPS in production
- **HSTS Header**: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- **TLS 1.3**: Only TLS 1.3 and TLS 1.2 allowed
- **Certificate Pinning**: Mobile apps pin certificates

### Security Headers
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'none'
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Account Lockout
- **Failed Attempts**: 5 failed login attempts
- **Lockout Duration**: 15 minutes
- **Unlock Methods**: Wait 15 minutes or reset password
- **Admin Unlock**: Admins can manually unlock accounts

### Brute Force Protection
- **Rate Limiting**: 5 login attempts per minute per IP
- **Progressive Delays**: Increasing delay after each failed attempt
- **CAPTCHA**: Show CAPTCHA after 3 failed attempts (frontend)
- **IP Blocking**: Automatic IP blocking after 50 failed attempts

### Session Management
- **Session Storage**: Redis with TTL
- **Session Timeout**: 15 minutes idle, 8 hours absolute
- **Concurrent Sessions**: Max 5 sessions per user
- **Session Binding**: Tokens bound to device fingerprint
- **Session Revocation**: User can revoke any session

### Audit Logging
- **Comprehensive Logging**: All authentication events logged
- **Log Fields**: timestamp, user_id, event_type, ip_address, device_id, user_agent, result
- **Retention**: Logs retained for 90 days
- **Monitoring**: Real-time alerts for suspicious activity
- **Immutable Logs**: Logs cannot be modified or deleted

## API Documentation

### OpenAPI/Swagger Specification
- **Version**: OpenAPI 3.1.0
- **Generation**: Generated from Go code annotations
- **Hosting**: `https://docs.suma.finance/api/v1`
- **Interactive Explorer**: Swagger UI at `https://docs.suma.finance/api/explorer`

### Documentation Sections
1. **Getting Started Guide**: Quick start tutorial
2. **Authentication Tutorial**: Complete auth flow walkthrough
3. **API Reference**: Auto-generated from OpenAPI spec
4. **Code Examples**: Examples in Go, JavaScript, Python, Swift
5. **Error Reference**: Detailed error code documentation
6. **Changelog**: Version history and breaking changes
7. **Migration Guides**: Guides for upgrading between versions

### Code Examples

**Registration Example (JavaScript)**:
```javascript
const response = await fetch('https://api.suma.finance/v1/auth/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    data: {
      type: 'user_registration',
      attributes: {
        email: 'user@example.com',
        password: 'SecurePass123!@#',
        password_confirmation: 'SecurePass123!@#',
        consents: {
          terms_of_service: true,
          privacy_policy: true,
          marketing_emails: false
        }
      }
    }
  })
});

const result = await response.json();
```

**Login with JWT Example (Swift)**:
```swift
let loginRequest = LoginRequest(
  email: "user@example.com",
  password: "SecurePass123!@#"
)

let response = try await api.auth.login(request: loginRequest)
let accessToken = response.data.attributes.accessToken

// Store token securely in Keychain
try keychain.set(accessToken, key: "access_token")
```

## Testing Strategy

### API Contract Testing
- **OpenAPI Validation**: Validate all responses against OpenAPI schema
- **Consumer-Driven Contracts**: Use Pact for contract testing
- **Schema Evolution**: Test backwards compatibility

### Integration Testing
- **Complete Workflows**: Test full registration → login → logout flow
- **Error Scenarios**: Test all error responses
- **Rate Limiting**: Test rate limit enforcement
- **Token Refresh**: Test refresh token rotation and re
