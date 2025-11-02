

# SERVICE COMMUNICATION DESIGN

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Services
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

The SUMA Finance authentication system implements a secure, high-performance communication architecture designed for fintech applications with strict compliance requirements (GDPR, PCI-DSS, SOC2, ISO 27001). The system employs a hybrid communication strategy combining synchronous REST APIs for immediate authentication responses, asynchronous message queues for email notifications and audit logging, and Redis-based caching for session management and OTP storage. All service-to-service communication is secured with mutual TLS and JWT-based service authentication, with comprehensive distributed tracing, structured logging, and circuit breakers to ensure 99.95% availability. The architecture supports horizontal scaling to handle 1000 req/s on authentication endpoints with sub-200ms response times while maintaining strict security controls including rate limiting, idempotent operations, and end-to-end encryption for all sensitive data.

The communication design prioritizes resilience with exponential backoff retry strategies, dead letter queues for failed messages, and graceful degradation patterns. Security monitoring and audit trails are baked into every communication layer, with real-time alerting for suspicious authentication patterns. The system integrates with SendGrid for transactional emails, Redis ElastiCache for session storage, and Datadog for observability, following event-driven patterns for GDPR consent tracking and security event logging to enable comprehensive compliance reporting and incident response.

## Communication Principles

### Design Philosophy
- **Loose Coupling**: Services depend on contracts, not implementations. Authentication service defines OpenAPI contracts; consuming services generate clients from specifications.
- **Protocol Agnostic**: Services use REST for external APIs, gRPC for high-performance internal calls, message queues for async workflows, and Redis for state management.
- **Versioned Contracts**: All REST APIs versioned (v1, v2), Protocol Buffers for gRPC include version fields, message schemas registered in central repository.
- **Resilient Communication**: Circuit breakers for all external dependencies, exponential backoff retries, timeout enforcement, fallback strategies for non-critical services.
- **Observable**: Every request includes trace context (W3C Trace Context), structured logs with correlation IDs, Datadog APM for distributed tracing, Prometheus metrics for communication health.

### Communication Patterns

| Pattern | Use Case | Protocol | Example |
|---------|----------|----------|---------|
| Synchronous Request-Response | User login, registration, token validation | REST/HTTPS | POST /api/v1/auth/login returns JWT immediately |
| Synchronous Request-Response | Service-to-service user validation | gRPC | Auth service validates user permissions via User service |
| Asynchronous Messaging | Email verification, password reset emails | RabbitMQ | Registration triggers email.verification.requested event |
| Asynchronous Messaging | Security audit logging | RabbitMQ | Login event published to audit.security.login queue |
| Event-Driven | GDPR consent changes, account status updates | Event Bus | user.consent.updated event consumed by multiple services |
| Caching/State Management | Session storage, OTP storage, rate limiting | Redis | JWT refresh tokens cached with 7-day TTL |
| Streaming | Real-time security alerts (admin dashboard) | WebSocket | Live feed of suspicious login attempts |

## Synchronous Communication

### REST API Communication

#### Protocol Specification
- **Protocol**: HTTPS only (TLS 1.3 enforced), HTTP/2 enabled for performance
- **Data Format**: JSON (application/json)
- **Character Encoding**: UTF-8
- **Compression**: gzip enabled for responses > 1KB
- **CORS**: Configured for frontend domains (https://app.sumafinance.com, https://mobile.sumafinance.com)
- **Security Headers**: CSP, HSTS (max-age=31536000), X-Frame-Options: DENY, X-Content-Type-Options: nosniff

#### API Standards

**Endpoint Naming Conventions**:
```
/api/v{version}/{domain}/{resource}/{id}/{action}

Authentication Endpoints:
POST   /api/v1/auth/register              # User registration
POST   /api/v1/auth/login                 # Email/password login
POST   /api/v1/auth/logout                # Logout current session
POST   /api/v1/auth/refresh               # Refresh access token
POST   /api/v1/auth/verify-email          # Verify email with token
POST   /api/v1/auth/resend-verification   # Resend verification email
POST   /api/v1/auth/forgot-password       # Request password reset
POST   /api/v1/auth/reset-password        # Reset password with token
POST   /api/v1/auth/enable-2fa            # Enable two-factor auth
POST   /api/v1/auth/verify-2fa            # Verify 2FA OTP code
POST   /api/v1/auth/disable-2fa           # Disable 2FA
GET    /api/v1/auth/sessions              # List active sessions
DELETE /api/v1/auth/sessions/{id}         # Terminate specific session

User Management Endpoints:
GET    /api/v1/users/me                   # Get current user profile
PUT    /api/v1/users/me                   # Update profile
GET    /api/v1/users/me/consents          # Get GDPR consents
PUT    /api/v1/users/me/consents          # Update consents
GET    /api/v1/users/me/devices           # List trusted devices
DELETE /api/v1/users/me/devices/{id}      # Remove device
GET    /api/v1/users/me/audit-log         # User activity history

Internal Service Endpoints (not exposed publicly):
POST   /internal/v1/auth/validate-token   # Validate JWT (service-to-service)
GET    /internal/v1/users/{id}            # Get user by ID
GET    /internal/v1/users/{id}/permissions # Get user permissions
POST   /internal/v1/audit/log             # Log security event
```

**HTTP Methods**:
- `GET`: Retrieve resource(s) - Idempotent, cacheable (cache-control headers set)
- `POST`: Create resource, trigger action - Not idempotent (use Idempotency-Key header)
- `PUT`: Update/replace resource - Idempotent
- `PATCH`: Partial update - Not guaranteed idempotent
- `DELETE`: Remove resource - Idempotent

**Status Codes**:
- `200 OK`: Successful GET, PUT, PATCH (with response body)
- `201 Created`: Successful POST (user registration, session creation) - includes Location header
- `204 No Content`: Successful DELETE, logout
- `400 Bad Request`: Invalid input (malformed JSON, missing required fields)
- `401 Unauthorized`: Missing or invalid JWT, expired token
- `403 Forbidden`: Valid token but insufficient permissions (e.g., non-admin accessing admin endpoint)
- `404 Not Found`: Resource doesn't exist (user, session, device)
- `409 Conflict`: Email already registered, concurrent modification
- `422 Unprocessable Entity`: Validation error (weak password, invalid email format)
- `429 Too Many Requests`: Rate limit exceeded (5 login attempts/min, 10 registration/hour)
- `500 Internal Server Error`: Unexpected server error (database connection failure)
- `502 Bad Gateway`: Upstream service error (email service unavailable)
- `503 Service Unavailable`: Service temporarily down (maintenance mode, circuit breaker open)
- `504 Gateway Timeout`: Upstream service timeout (external OAuth provider)

#### Request/Response Format

**Standard Request Headers**:
```http
# User-facing requests
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
Accept: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Device-ID: device-fingerprint-hash-12345
X-Client-Version: ios/2.1.0
User-Agent: SumaFinance-iOS/2.1.0 (iPhone14,2; iOS 17.2)
Accept-Language: en-US,en;q=0.9
X-Timezone: America/Los_Angeles

# Service-to-service requests (internal)
Authorization: Bearer service-token-auth-to-user-service
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Correlation-ID: 650e8400-e29b-41d4-a716-446655440000
X-Service-Name: auth-service
X-Service-Version: 1.2.3
Content-Type: application/json
Accept: application/json
```

**Standard Response Headers**:
```http
Content-Type: application/json; charset=utf-8
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Correlation-ID: 650e8400-e29b-41d4-a716-446655440000
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704024000
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'
X-Response-Time-Ms: 45
```

**Success Response Format - User Registration**:
```json
{
  "data": {
    "user": {
      "id": "usr_7d8e9f0a1b2c3d4e",
      "email": "user@example.com",
      "email_verified": false,
      "name": "John Doe",
      "created_at": "2024-01-15T10:30:00Z",
      "two_factor_enabled": false,
      "profile": {
        "phone": null,
        "date_of_birth": null,
        "country": "US"
      },
      "consents": {
        "terms_accepted": true,
        "terms_accepted_at": "2024-01-15T10:30:00Z",
        "privacy_policy_accepted": true,
        "privacy_policy_accepted_at": "2024-01-15T10:30:00Z",
        "marketing_emails": false
      }
    },
    "session": {
      "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refresh_token": "rt_a1b2c3d4e5f6g7h8i9j0",
      "token_type": "Bearer",
      "expires_in": 900,
      "refresh_expires_in": 604800
    }
  },
  "meta": {
    "timestamp": "2024-01-15T10:30:00.123Z",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Success Response Format - Login with 2FA Required**:
```json
{
  "data": {
    "requires_2fa": true,
    "two_factor_token": "2fa_temp_token_12345",
    "expires_in": 300,
    "delivery_method": "email",
    "masked_delivery_target": "j***@example.com"
  },
  "meta": {
    "timestamp": "2024-01-15T10:32:00.123Z",
    "request_id": "650e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Error Response Format**:
```json
{
  "errors": [
    {
      "id": "err_550e8400-e29b-41d4-a716-446655440000",
      "status": "422",
      "code": "WEAK_PASSWORD",
      "title": "Password Does Not Meet Security Requirements",
      "detail": "Password must be at least 12 characters and include uppercase, lowercase, number, and special character",
      "source": {
        "pointer": "/data/password",
        "parameter": null
      },
      "meta": {
        "requirements": {
          "min_length": 12,
          "requires_uppercase": true,
          "requires_lowercase": true,
          "requires_number": true,
          "requires_special": true
        }
      }
    }
  ],
  "meta": {
    "timestamp": "2024-01-15T10:30:00.123Z",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Error Response Format - Account Locked**:
```json
{
  "errors": [
    {
      "id": "err_750e8400-e29b-41d4-a716-446655440000",
      "status": "403",
      "code": "ACCOUNT_LOCKED",
      "title": "Account Temporarily Locked",
      "detail": "Account locked due to multiple failed login attempts. Try again in 15 minutes or contact support.",
      "source": null,
      "meta": {
        "locked_until": "2024-01-15T10:45:00Z",
        "reason": "max_failed_attempts",
        "failed_attempts": 5,
        "support_email": "support@sumafinance.com"
      }
    }
  ],
  "meta": {
    "timestamp": "2024-01-15T10:30:00.123Z",
    "request_id": "850e8400-e29b-41d4-a716-446655440000"
  }
}
```

**Paginated Response Format - Active Sessions**:
```json
{
  "data": [
    {
      "id": "sess_abc123",
      "device": {
        "id": "dev_xyz789",
        "name": "iPhone 14 Pro",
        "type": "mobile",
        "os": "iOS 17.2",
        "browser": "Safari 17.0"
      },
      "ip_address": "192.0.2.1",
      "location": {
        "city": "San Francisco",
        "region": "California",
        "country": "US"
      },
      "created_at": "2024-01-15T10:30:00Z",
      "last_activity": "2024-01-15T12:15:00Z",
      "is_current": true
    }
  ],
  "meta": {
    "total": 3,
    "page": 1,
    "per_page": 20,
    "total_pages": 1
  },
  "links": {
    "self": "/api/v1/auth/sessions?page=1",
    "first": "/api/v1/auth/sessions?page=1",
    "prev": null,
    "next": null,
    "last": "/api/v1/auth/sessions?page=1"
  }
}
```

#### Service-to-Service REST Communication

**Example: API Gateway → Auth Service (Token Validation)**

**Request**:
```http
POST /internal/v1/auth/validate-token HTTP/1.1
Host: auth-service.internal:3001
Authorization: Bearer service_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Correlation-ID: 650e8400-e29b-41d4-a716-446655440000
X-Service-Name: api-gateway
Content-Type: application/json

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "required_permissions": ["transactions:read"],
  "include_user_details": true
}
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Response-Time-Ms: 8

{
  "valid": true,
  "user": {
    "id": "usr_7d8e9f0a1b2c3d4e",
    "email": "user@example.com",
    "email_verified": true,
    "roles": ["user"],
    "permissions": ["transactions:read", "transactions:write", "profile:read"],
    "two_factor_enabled": true,
    "account_status": "active"
  },
  "session": {
    "id": "sess_abc123",
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2024-01-15T10:45:00Z",
    "device_id": "dev_xyz789"
  },
  "token_claims": {
    "sub": "usr_7d8e9f0a1b2c3d4e",
    "iss": "auth-service",
    "aud": "suma-finance-api",
    "exp": 1704025500,
    "iat": 1704024600,
    "jti": "token-uuid"
  }
}
```

**Example: Auth Service → User Service (Get User Permissions)**

**Request**:
```http
GET /internal/v1/users/usr_7d8e9f0a1b2c3d4e/permissions HTTP/1.1
Host: user-service.internal:3002
Authorization: Bearer service_token_xyz
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-Correlation-ID: 650e8400-e29b-41d4-a716-446655440000
X-Service-Name: auth-service
Accept: application/json
```

**Response**:
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-ID: 550e8400-e29b-41d4-a716-446655440000
Cache-Control: private, max-age=60

{
  "data": {
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "roles": ["user", "premium"],
    "permissions": [
      "transactions:read",
      "transactions:write",
      "profile:read",
      "profile:update",
      "exports:create"
    ],
    "feature_flags": {
      "biometric_auth": true,
      "social_login": true,
      "advanced_reports": true
    }
  }
}
```

#### Timeout Configuration

| Call Type | Timeout | Retry | Circuit Breaker |
|-----------|---------|-------|-----------------|
| User login/registration | 5s | No | No |
| Token validation (internal) | 2s | Yes (2x) | Yes (5 failures) |
| User service lookup | 3s | Yes (2x) | Yes (5 failures) |
| Email service (SendGrid) | 10s | Yes (3x) | Yes (10 failures) |
| Redis session lookup | 500ms | Yes (2x) | No |
| Database query | 5s | No | No |
| Password breach check (HaveIBeenPwned) | 3s | Yes (2x) | Yes (graceful degradation) |
| OAuth provider (Google/Apple) | 10s | Yes (3x) | Yes (10 failures) |
| Health check | 1s | No | No |

#### Retry Strategy

**Exponential Backoff with Jitter**:
```javascript
// Retry configuration for service-to-service calls
const retryConfig = {
  maxAttempts: 3,
  baseDelay: 100, // milliseconds
  maxDelay: 5000, // milliseconds
  retryableStatusCodes: [408, 429, 500, 502, 503, 504],
  retryableErrors: ['ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED', 'ENETUNREACH']
};

function calculateDelay(attemptNumber) {
  const baseDelay = 100;
  const maxDelay = 5000;
  const exponentialDelay = Math.min(baseDelay * Math.pow(2, attemptNumber), maxDelay);
  const jitter = Math.random() * exponentialDelay * 0.1; // 10% jitter
  return Math.floor(exponentialDelay + jitter);
}

// Example retry logic
async function callServiceWithRetry(serviceFn, config = retryConfig) {
  let lastError;
  
  for (let attempt = 0; attempt < config.maxAttempts; attempt++) {
    try {
      const result = await serviceFn();
      
      // Log successful retry
      if (attempt > 0) {
        logger.info('Retry succeeded', { attempt, service: serviceFn.name });
      }
      
      return result;
    } catch (error) {
      lastError = error;
      
      const shouldRetry = 
        attempt < config.maxAttempts - 1 &&
        (config.retryableStatusCodes.includes(error.statusCode) ||
         config.retryableErrors.includes(error.code));
      
      if (!shouldRetry) {
        throw error;
      }
      
      const delay = calculateDelay(attempt);
      logger.warn('Retrying after error', {
        attempt: attempt + 1,
        delay,
        error: error.message,
        statusCode: error.statusCode
      });
      
      await sleep(delay);
    }
  }
  
  throw lastError;
}
```

**Idempotency Implementation**:
```http
# Client sends idempotency key for non-idempotent operations
POST /api/v1/auth/register
Idempotency-Key: idem_550e8400-e29b-41d4-a716-446655440000
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "name": "John Doe"
}

# Server stores key and response for 24 hours
# Duplicate request within 24 hours returns cached response with 200 OK
# After 24 hours, key expires and new registration allowed
```

**Idempotency Storage (Redis)**:
```javascript
// Store idempotency key and response
await redis.setex(
  `idempotency:${idempotencyKey}`,
  86400, // 24 hours
  JSON.stringify({
    status: 201,
    response: responseBody,
    timestamp: new Date().toISOString()
  })
);

// Check for duplicate request
const cached = await redis.get(`idempotency:${idempotencyKey}`);
if (cached) {
  const { status, response } = JSON.parse(cached);
  return res.status(status).json(response);
}
```

### gRPC Communication

#### When to Use gRPC
- **High-performance service-to-service communication**: Auth service to User service for permission checks (sub-10ms latency)
- **Frequent internal calls**: Token validation, session lookups (thousands per second)
- **Strong typing required**: Protocol Buffers ensure contract compliance
- **Language-agnostic contracts**: Go backend, Python ML services, Node.js workers
- **Not used for**: Client-to-server (web/mobile use REST), external integrations

#### Protocol Buffer Definition

**auth_service.proto**:
```protobuf
syntax = "proto3";

package suma.auth.v1;

import "google/protobuf/timestamp.proto";

service AuthService {
  // Validate JWT token and return user context
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
  
  // Get user session details
  rpc GetSession(GetSessionRequest) returns (GetSessionResponse);
  
  // Revoke refresh token
  rpc RevokeToken(RevokeTokenRequest) returns (RevokeTokenResponse);
  
  // Check if user has specific permissions
  rpc CheckPermissions(CheckPermissionsRequest) returns (CheckPermissionsResponse);
  
  // Get multiple users (batch operation)
  rpc GetUsers(GetUsersRequest) returns (stream User);
}

message User {
  string id = 1;
  string email = 2;
  bool email_verified = 3;
  string name = 4;
  UserStatus status = 5;
  repeated string roles = 6;
  repeated string permissions = 7;
  bool two_factor_enabled = 8;
  google.protobuf.Timestamp created_at = 9;
  google.protobuf.Timestamp updated_at = 10;
}

enum UserStatus {
  USER_STATUS_UNSPECIFIED = 0;
  USER_STATUS_ACTIVE = 1;
  USER_STATUS_INACTIVE = 2;
  USER_STATUS_SUSPENDED = 3;
  USER_STATUS_LOCKED = 4;
}

message ValidateTokenRequest {
  string access_token = 1;
  repeated string required_permissions = 2;
  bool include_user_details = 3;
}

message ValidateTokenResponse {
  bool valid = 1;
  User user = 2;
  Session session = 3;
  TokenClaims token_claims = 4;
  Error error = 5;
}

message Session {
  string id = 1;
  string user_id = 2;
  string device_id = 3;
  string ip_address = 4;
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp last_activity = 6;
  google.protobuf.Timestamp expires_at = 7;
}

message TokenClaims {
  string subject = 1;
  string issuer = 2;
  string audience = 3;
  int64 expires_at = 4;
  int64 issued_at = 5;
  string jti = 6;
}

message GetSessionRequest {
  string session_id = 1;
}

message GetSessionResponse {
  Session session = 1;
  Error error = 2;
}

message RevokeTokenRequest {
  string refresh_token = 1;
  string reason = 2;
}

message RevokeTokenResponse {
  bool success = 1;
  Error error = 2;
}

message CheckPermissionsRequest {
  string user_id = 1;
  repeated string permissions = 2;
}

message CheckPermissionsResponse {
  bool has_all_permissions = 1;
  repeated string granted_permissions = 2;
  repeated string denied_permissions = 3;
}

message GetUsersRequest {
  repeated string user_ids = 1;
}

message Error {
  string code = 1;
  string message = 2;
  repeated ErrorDetail details = 3;
}

message ErrorDetail {
  string field = 1;
  string issue = 2;
}
```

#### gRPC Interceptors

**Client Interceptor** (Authentication, Logging, Metrics, Tracing):
```go
// Go implementation
func ClientInterceptor(
    ctx context.Context,
    method string,
    req interface{},
    reply interface{},
    cc *grpc.ClientConn,
    invoker grpc.UnaryInvoker,
    opts ...grpc.CallOption,
) error {
    startTime := time.Now()
    
    // Add service authentication token
    ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+getServiceToken())
    
    // Add tracing context
    traceID := getTraceID(ctx)
    spanID := generateSpanID()
    ctx = metadata.AppendToOutgoingContext(ctx,
        "x-trace-id", traceID,
        "x-span-id", spanID,
        "x-service-name", "auth-service",
    )
    
    // Add request ID
    requestID := getOrCreateRequestID(ctx)
    ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", requestID)
    
    // Call the RPC method
    err := invoker(ctx, method, req, reply, cc, opts...)
    
    duration := time.Since(startTime)
    
    // Log and record metrics
    if err != nil {
        logger.Error("gRPC call failed",
            "method", method,
            "duration_ms", duration.Milliseconds(),
            "error", err.Error(),
            "trace_id", traceID,
        )
        metrics.Counter("grpc.client.errors").Inc(
            "method", method,
            "code", status.Code(err).String(),
        )
    } else {
        logger.Info("gRPC call succeeded",
            "method", method,
            "duration_ms", duration.Milliseconds(),
            "trace_id", traceID,
        )
    }
    
    metrics.Histogram("grpc.client.duration").Observe(
        duration.Seconds(),
        "method", method,
        "success", err == nil,
    )
    
    return err
}
```

**Server Interceptor** (Authentication, Logging, Rate Limiting):
```go
func ServerInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    startTime := time.Now()
    
    // Extract metadata
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, status.Error(codes.InvalidArgument, "missing metadata")
    }
    
    // Validate service authentication
    authHeader := md.Get("authorization")
    if len(authHeader) == 0 {
        return nil, status.Error(codes.Unauthenticated, "missing authorization")
    }
    
    token := strings.TrimPrefix(authHeader[0], "Bearer ")
    serviceName, err := validateServiceToken(token)
    if err != nil {
        return nil, status.Error(codes.Unauthenticated, "invalid service token")
    }
    
    // Extract trace context
    traceID := getMetadataValue(md, "x-trace-id")
    spanID := getMetadataValue(md, "x-span-id")
    requestID := getMetadataValue(md, "x-request-id")
    
    // Add to context for handlers
    ctx = context.WithValue(ctx, "trace_id", traceID)
    ctx = context.WithValue(ctx, "request_id", requestID)
    ctx = context.WithValue(ctx, "service_name", serviceName)
    
    // Rate limiting (per service)
    if !rateLimiter.Allow(serviceName, info.FullMethod) {
        return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
    }
    
    // Call handler
    resp, err := handler(ctx, req)
    
    duration := time.Since(startTime)
    
    // Log
    if err != nil {
        logger.Error("gRPC request failed",
            "method", info.FullMethod,
            "service", serviceName,
            "duration_ms", duration.Milliseconds(),
            "error", err.Error(),
            "trace_id", traceID,
        )
    } else {
        logger.Info("gRPC request succeeded",
            "method", info.FullMethod,
            "service", serviceName,
            "duration_ms", duration.Milliseconds(),
            "trace_id", traceID,
        )
    }
    
    // Metrics
    metrics.Counter("grpc.server.requests").Inc(
        "method", info.FullMethod,
        "service", serviceName,
        "code", status.Code(err).String(),
    )
    
    metrics.Histogram("grpc.server.duration").Observe(
        duration.Seconds(),
        "method", info.FullMethod,
    )
    
    return resp, err
}
```

## Asynchronous Communication

### Message Queue Communication

#### Message Broker Selection
**Technology**: RabbitMQ (primary), AWS SQS (fallback for async tasks)

**Selection Rationale**:
- **RabbitMQ**: 
  - Flexible routing (topic exchanges for event types)
  - Priority queues for urgent emails (password reset > marketing)
  - Dead letter queues for failed message handling
  - Supports delayed message delivery (retry with backoff)
  - On-premise deployment (data sovereignty for GDPR)
  - High availability with clustering
  - Proven fintech reliability

- **AWS SQS** (Secondary):
  - Managed service (reduced operational overhead)
  - Infinite scaling for high-volume periods
  - Used for non-critical async tasks (analytics events)
  - Integration with AWS services (Lambda, SNS)

#### Queue Architecture

**RabbitMQ Exchange and Queue Structure**:
```
Exchanges:
├── auth.events (topic exchange)
│   ├── auth.user.registered → [user-registered-queue, audit-queue, analytics-queue]
│   ├── auth.user.login → [audit-queue, device-tracking-queue]
│   ├── auth.user.logout → [audit-queue]
│   ├── auth.password.reset.requested → [password-reset-email-queue, audit-queue]
│   ├── auth.password.changed → [password-change-notification-queue, audit-queue]
│   ├── auth.2fa.enabled → [audit-queue, notification-queue]
│   ├── auth.2fa.verified → [audit-queue]
│   ├── auth.account.locked → [account-locked-email-queue, audit-queue, alert-queue]
│   ├── auth.session.created → [audit-queue, device-tracking-queue]
│   └── auth.session.terminated → [audit-queue]
│
├── email.tasks (topic exchange, priority-enabled)
│   ├── email.verification → [email-verification-queue] (priority: 7)
│   ├── email.password-reset → [email-password-reset-queue] (priority: 8)
│   ├── email.2fa-otp → [email-2fa-queue] (priority: 9)
│   ├── email.security-alert → [email-security-alert-queue] (priority: 10)
│   └── email.notification → [email-notification-queue] (priority: 5)
│
├── gdpr.events (topic exchange)
│   ├── gdpr.consent.granted → [consent-tracking-queue, audit-queue]
│   ├── gdpr.consent.withdrawn → [consent-tracking-queue, audit-queue, data-deletion-queue]
│   ├── gdpr.data.export.requested → [data-export-queue]
│   └── gdpr.data.deletion.requested → [data-deletion-queue, audit-queue]
│
├── security.events (topic exchange)
│   ├── security.suspicious.login → [security-alert-queue, ml-fraud-detection-queue]
│   ├── security.impossible.travel → [security-alert-queue, ml-fraud-detection-queue]
│   ├── security.multiple.failures → [security-alert-queue]
│   └── security.new.device → [device-verification-queue, notification-queue]
│
└── dead-letter-exchange (fanout exchange)
    └── [dead-letter-queue]

Queues:
├── user-registered-queue (consumers: User Service)
├── audit-queue (consumers: Audit Service) - ALL security events
├── analytics-queue (consumers: Analytics Service)
├── password-reset-email-queue (consumers: Email Service)
├── password-change-notification-queue (consumers: Email Service)
├── email-verification-queue (consumers: Email Service)
├── email-2fa-queue (consumers: Email Service)
├── email-security-alert-queue (consumers: Email Service)
├── account-locked-email-queue (consumers: Email Service)
├── notification-queue (consumers: Notification Service)
├── device-tracking-queue (consumers: Device Service)
├── security-alert-queue (consumers: Security Monitoring Service)
├── ml-fraud-detection-queue (consumers: ML Service)
├── consent-tracking-queue (consumers: GDPR Compliance Service)
├── data-export-queue (consumers: Data Export Service)
├── data-deletion-queue (consumers: Data Deletion Service)
└── dead-letter-queue (consumers: Error Handler Service)
```

#### Message Format Standard

**Message Envelope** (All messages follow this structure):
```json
{
  "metadata": {
    "message_id": "msg_550e8400-e29b-41d4-a716-446655440000",
    "correlation_id": "corr_650e8400-e29b-41d4-a716-446655440000",
    "causation_id": "cause_750e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-01-15T10:30:00.123Z",
    "version": "1.0",
    "type": "auth.user.registered",
    "source": "auth-service",
    "source_version": "1.2.3",
    "content_type": "application/json",
    "schema_version": "1.0"
  },
  "payload": {
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "email": "user@example.com",
    "name": "John Doe",
    "registered_at": "2024-01-15T10:30:00Z",
    "registration_source": "web",
    "email_verified": false,
    "consents": {
      "terms_accepted": true,
      "privacy_policy_accepted": true,
      "marketing_emails": false
    }
  },
  "context": {
    "trace_id": "trace_850e8400-e29b-41d4-a716-446655440000",
    "span_id": "span_950e8400",
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "tenant_id": null,
    "request_id": "req_a50e8400-e29b-41d4-a716-446655440000",
    "ip_address": "192.0.2.1",
    "user_agent": "SumaFinance-Web/1.0.0",
    "device_id": "dev_xyz789"
  }
}
```

**Example: Password Reset Requested Event**:
```json
{
  "metadata": {
    "message_id": "msg_b60e8400-e29b-41d4-a716-446655440000",
    "correlation_id": "corr_c70e8400-e29b-41d4-a716-446655440000",
    "causation_id": null,
    "timestamp": "2024-01-15T11:00:00.456Z",
    "version": "1.0",
    "type": "auth.password.reset.requested",
    "source": "auth-service",
    "source_version": "1.2.3",
    "content_type": "application/json",
    "schema_version": "1.0"
  },
  "payload": {
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "email": "user@example.com",
    "reset_token": "rst_d80e8400-e29b-41d4-a716-446655440000",
    "reset_token_expires_at": "2024-01-15T12:00:00Z",
    "reset_url": "https://app.sumafinance.com/reset-password?token=rst_d80e8400...",
    "requested_at": "2024-01-15T11:00:00Z",
    "ip_address": "192.0.2.1"
  },
  "context": {
    "trace_id": "trace_e90e8400-e29b-41d4-a716-446655440000",
    "span_id": "span_f00e8400",
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "tenant_id": null,
    "request_id": "req_110e8400-e29b-41d4-a716-446655440000",
    "ip_address": "192.0.2.1",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "device_id": null
  }
}
```

#### Publishing Messages

**Publisher Code Pattern (Go)**:
```go
type MessagePublisher struct {
    channel *amqp.Channel
    serviceName string
    serviceVersion string
}

func (p *MessagePublisher) Publish(ctx context.Context, exchange, routingKey string, payload interface{}, options PublishOptions) error {
    // Generate message metadata
    message := Message{
        Metadata: MessageMetadata{
            MessageID:     generateUUID(),
            CorrelationID: getCorrelationID(ctx, options.CorrelationID),
            CausationID:   options.CausationID,
            Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
            Version:       "1.0",
            Type:          routingKey,
            Source:        p.serviceName,
            SourceVersion: p.serviceVersion,
            ContentType:   "application/json",
            SchemaVersion: options.SchemaVersion,
        },
        Payload: payload,
        Context: MessageContext{
            TraceID:    getTraceID(ctx),
            SpanID:     generateSpanID(),
            UserID:     getUserID(ctx),
            TenantID:   getTenantID(ctx),
            RequestID:  getRequestID(ctx),
            IPAddress:  getIPAddress(ctx),
            UserAgent:  getUserAgent(ctx),
            DeviceID:   getDeviceID(ctx),
        },
    }
    
    // Serialize message
    body, err := json.Marshal(message)
    if err != nil {
        return fmt.Errorf("failed to marshal message: %w", err)
    }
    
    // Publish with options
    err = p.channel.Publish(
        exchange,
        routingKey,
        false, // mandatory
        false, // immediate
        amqp.Publishing{
            ContentType:  "application/json",
            Body:         body,
            DeliveryMode: amqp.Persistent, // Survive broker restart
            Priority:     options.Priority,
            Expiration:   options.TTL,
            MessageId:    message.Metadata.MessageID,
            Timestamp:    time.Now(),
            Headers: amqp.Table{
                "x-trace-id":      message.Context.TraceID,
                "x-correlation-id": message.Metadata.CorrelationID,
            },
        },
    )
    
    if err != nil {
        logger.Error("Failed to publish message",
            "exchange", exchange,
            "routing_key", routingKey,
            "message_id", message.Metadata.MessageID,
            "error", err,
        )
        metrics.Counter("messages.publish.errors").Inc("exchange", exchange, "routing_key", routingKey)
        return err
    }
    
    logger.Info("Message published",
        "exchange", exchange,
        "routing_key", routingKey,
        "message_id", message.Metadata.MessageID,
        "trace_id", message.Context.TraceID,
    )
    
    metrics.Counter("messages.published").Inc("exchange", exchange, "routing_key", routingKey)
    
    return nil
}

// Usage example
func (s *AuthService) PublishUserRegisteredEvent(ctx context.Context, user *User) error {
    return s.publisher.Publish(ctx,
        "auth.events",
        "auth.user.registered",
        map[string]interface{}{
            "user_id":             user.ID,
            "email":               user.Email,
            "name":                user.Name,
            "registered_at":       user.CreatedAt,
            "registration_source": user.RegistrationSource,
            "email_verified":      user.EmailVerified,
            "consents":            user.Consents,
        },
        PublishOptions{
            Priority:      5,
            TTL:           "86400000", // 24 hours
            SchemaVersion: "1.0",
        },
    )
}
```

#### Consuming Messages

**Consumer Code Pattern (Go)**:
```go
type MessageConsumer struct {
    channel      *amqp.Channel
    queue        string
    handler      MessageHandler
    maxRetries   int
    redis        *redis.Client
}

type MessageHandler func(context.Context, Message) error

func (c *MessageConsumer) Consume(ctx context.Context) error {
    msgs, err := c.channel.Consume(
        c.queue,
        "",    // consumer tag
        false, // auto-ack (manual acknowledgment for reliability)
        false, // exclusive
        false, // no-local
        false, // no-wait
        nil,   // args
    )
    if err != nil {
        return fmt.Errorf("failed to register consumer: %w", err)
    }
    
    logger.Info("Starting message consumer", "queue", c.queue)
    
    for {
        select {
        case <-ctx.Done():
            logger.Info("Consumer shutting down", "queue", c.queue)
            return ctx.Err()
        case msg := <-msgs:
            c.processMessage(ctx, msg)
        }
    }
}

func (c *MessageConsumer) processMessage(ctx context.Context, msg amqp.Delivery) {
    startTime := time.Now()
    
    // Parse message
    var message Message
    if err := json.Unmarshal(msg.Body, &message); err != nil {
        logger.Error("Failed to unmarshal message", "error", err)
        msg.Nack(false, false) // Don't requeue malformed messages
        return
    }
    
    // Set trace context
    ctx = context.WithValue(ctx, "trace_id", message.Context.TraceID)
    ctx = context.WithValue(ctx, "request_id", message.Context.RequestID)
    ctx = context.WithValue(ctx, "message_id", message.Metadata.MessageID)
    
    logger := logger.With(
        "message_id", message.Metadata.MessageID,
        "trace_id", message.Context.TraceID,
        "type", message.Metadata.Type,
    )
    
    // Idempotency check
    processed, err := c.isMessageProcessed(message.Metadata.MessageID)
    if err != nil {
        logger.Error("Failed to check idempotency", "error", err)
        // Continue processing - better to risk duplicate than lose message
    } else if processed {
        logger.Info("Duplicate message, skipping", "message_id", message.Metadata.MessageID)
        msg.Ack(false)
        metrics.Counter("messages.duplicate").Inc("queue", c.queue)
        return
    }
    
    // Process message
    err = c.handler(ctx, message)
    
    duration := time.Since(startTime)
    
    if err != nil {
        logger.Error("Message processing failed",
            "error", err,
            "duration_ms", duration.Milliseconds(),
        )
        
        metrics.Counter("messages.processed").Inc("queue", c.queue, "status", "error")
        metrics.Histogram("messages.processing.duration").Observe(
            duration.Seconds(),
            "queue", c.queue,
            "status", "error",
        )
        
        // Retry logic
        retryCount := c.getRetryCount(msg)
        
        if retryCount < c.maxRetries {
            // Requeue with delay
            c.requeueWithDelay(msg, message, retryCount+1)
            msg.Ack(false) // Ack original message
        } else {
            // Send to dead letter queue
            logger.Error("Max retries exceeded, sending to DLQ",
                "message_id", message.Metadata.MessageID,
                "retries", retryCount,
            )
            c.sendToDeadLetterQueue(msg, message, err)
            msg.Ack(false)
            
            // Alert on critical failures
            if c.isCriticalQueue() {
                alerting.Send(Alert{
                    Severity: "high",
                    Title:    "Message processing failed after max retries",
                    Details: map[string]interface{}{
                        "queue":      c.queue,
                        "message_id": message.Metadata.MessageID,
                        "error":      err.Error(),
                    },
                })
            }
        }
        
        return
    }
    
    // Mark as processed (idempotency)
    if err := c.markMessageProcessed(message.Metadata.MessageID); err != nil {
        logger.Warn("Failed to mark message as processed", "error", err)
        // Continue - already processed successfully
    }
    
    // Acknowledge message
    msg.Ack(false)
    
    logger.Info("Message processed successfully",
        "duration_ms", duration.Milliseconds(),
    )
    
    metrics.Counter("messages.processed").Inc("queue", c.queue, "status", "success")
    metrics.Histogram("messages.processing.duration").Observe(
        duration.Seconds(),
        "queue", c.queue,
        "status", "success",
    )
}

func (c *MessageConsumer) getRetryCount(msg amqp.Delivery) int {
    if msg.Headers == nil {
        return 0
    }
    if count, ok := msg.Headers["x-retry-count"].(int32); ok {
        return int(count)
    }
    return 0
}

func (c *MessageConsumer) requeueWithDelay(msg amqp.Delivery, message Message, retryCount int) {
    // Exponential backoff: 2^retryCount seconds, max 5 minutes
    delaySec := int(math.Min(math.Pow(2, float64(retryCount)), 300))
    delayMs := delaySec * 1000
    
    headers := amqp.Table{
        "x-retry-count": int32(retryCount),
        "x-delay":       int32(delayMs),
        "x-first-death-reason": "processing-error",
    }
    
    // Merge existing headers
    for k, v := range msg.Headers {
        if k != "x-retry-count" && k != "x-delay" {
            headers[k] = v
        }
    }
    
    err := c.channel.Publish(
        msg.Exchange,
        msg.RoutingKey,
        false,
        false,
        amqp.Publishing{
            ContentType:  msg.ContentType,
            Body:         msg.Body,
            DeliveryMode: amqp.Persistent,
            Priority:     msg.Priority,
            Headers:      headers,
        },
    )
    
    if err != nil {
        logger.Error("Failed to requeue message", "error", err, "message_id", message.Metadata.MessageID)
    } else {
        logger.Info("Message requeued with delay",
            "message_id", message.Metadata.MessageID,
            "retry_count", retryCount,
            "delay_sec", delaySec,
        )
    }
}

func (c *MessageConsumer) sendToDeadLetterQueue(msg amqp.Delivery, message Message, processingErr error) {
    headers := amqp.Table{
        "x-original-exchange":     msg.Exchange,
        "x-original-routing-key":  msg.RoutingKey,
        "x-original-queue":        c.queue,
        "x-death-reason":          processingErr.Error(),
        "x-death-timestamp":       time.Now().Unix(),
        "x-retry-count":           c.getRetryCount(msg),
    }
    
    err := c.channel.Publish(
        "dead-letter-exchange",
        "dead-letter",
        false,
        false,
        amqp.Publishing{
            ContentType:  msg.ContentType,
            Body:         msg.Body,
            DeliveryMode: amqp.Persistent,
            Headers:      headers,
        },
    )
    
    if err != nil {
        logger.Error("Failed to send message to DLQ", "error", err, "message_id", message.Metadata.MessageID)
    }
}

func (c *MessageConsumer) isMessageProcessed(messageID string) (bool, error) {
    exists, err := c.redis.Exists(context.Background(), fmt.Sprintf("processed:%s", messageID)).Result()
    return exists == 1, err
}

func (c *MessageConsumer) markMessageProcessed(messageID string) error {
    return c.redis.SetEX(
        context.Background(),
        fmt.Sprintf("processed:%s", messageID),
        time.Now().Unix(),
        7*24*time.Hour, // 7 days
    ).Err()
}
```

#### Message Delivery Guarantees

**At-Least-Once Delivery** (Used for SUMA Finance):
- Messages acknowledged after successful processing
- May be delivered multiple times (network issues, consumer restarts)
- **Requires idempotent consumers** (handled via Redis deduplication)
- **Use cases**: All authentication events, email notifications, audit logs
- **Benefits**: No message loss, simple implementation, high reliability

**Idempotency Implementation**:
```sql
-- PostgreSQL deduplication table (alternative to Redis)
CREATE TABLE processed_messages (
    message_id UUID PRIMARY KEY,
    queue_name VARCHAR(255) NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    handler VARCHAR(255) NOT NULL,
    result JSONB,
    processing_time_ms INTEGER
);

CREATE INDEX idx_processed_messages_queue ON processed_messages(queue_name, processed_at);
CREATE INDEX idx_processed_messages_cleanup ON processed_messages(processed_at);

-- Cleanup job (run daily)
DELETE FROM processed_messages WHERE processed_at < NOW() - INTERVAL '7 days';
```

**Redis-based Idempotency** (Preferred for performance):
```go
func (s *EmailService) HandleVerificationEmail(ctx context.Context, msg Message) error {
    messageID := msg.Metadata.MessageID
    
    // Check if already processed
    key := fmt.Sprintf("processed:email:%s", messageID)
    exists, err := s.redis.Exists(ctx, key).Result()
    if err != nil {
        // Log error but continue (prefer duplicate over lost message)
        logger.Warn("Failed to check idempotency", "error", err)
    } else if exists == 1 {
        logger.Info("Email already sent, skipping", "message_id", messageID)
        return nil
    }
    
    // Send email
    err = s.sendVerificationEmail(ctx, msg.Payload)
    if err != nil {
        return fmt.Errorf("failed to send email: %w", err)
    }
    
    // Mark as processed (7 days TTL)
    err = s.redis.SetEX(ctx, key, time.Now().Unix(), 7*24*time.Hour).Err()
    if err != nil {
        logger.Warn("Failed to mark message as processed", "error", err)
    }
    
    return nil
}
```

### Event-Driven Communication

#### Event Types

**Domain Events** (Internal to Auth Service):
- **Naming**: Past tense, domain-centric (`UserRegistered`, `PasswordChanged`, `SessionCreated`)
- **Purpose**: Represent state changes within authentication domain
- **Data**: Minimal (ID, timestamp, key fields only)
- **Immutable**: Never modified after publication
- **Examples**: `UserLoggedIn`, `TwoFactorEnabled`, `AccountLocked`

**Integration Events** (Cross-Service Communication):
- **Naming**: Past tense, integration-focused (`auth.user.registered`, `auth.password.reset.requested`)
- **Purpose**: Notify other services of authentication events
- **Data**: Denormalized to avoid additional queries (include user email, name)
- **Versioned**: Support backward compatibility (`version: "1.0"`, `schema_version: "1.0"`)
- **Examples**: `auth.user.registered`, `auth.account.locked`, `gdpr.consent.withdrawn`

**Example Domain Event** (Internal):
```json
{
  "event_id": "evt_550e8400-e29b-41d4-a716-446655440000",
  "event_type": "UserRegistered",
  "aggregate_id": "usr_7d8e9f0a1b2c3d4e",
  "aggregate_type": "User",
  "aggregate_version": 1,
  "timestamp": "2024-01-15T10:30:00.123Z",
  "data": {
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "email": "user@example.com"
  }
}
```

**Example Integration Event** (Cross-Service):
```json
{
  "event_id": "evt_650e8400-e29b-41d4-a716-446655440000",
  "event_type": "auth.user.registered",
  "version": "1.0",
  "timestamp": "2024-01-15T10:30:00.123Z",
  "source": "auth-service",
  "data": {
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "email": "user@example.com",
    "name": "John Doe",
    "email_verified": false,
    "registration_source": "web",
    "registered_at": "2024-01-15T10:30:00Z",
    "consents": {
      "terms_accepted": true,
      "privacy_policy_accepted": true,
      "marketing_emails": false
    }
  },
  "metadata": {
    "trace_id": "trace_850e8400-e29b-41d4-a716-446655440000",
    "ip_address": "192.0.2.1",
    "user_agent": "SumaFinance-Web/1.0.0"
  }
}
```

#### Event Schema Registry

**Purpose**: Ensure schema compatibility across versions, prevent breaking changes

**Schema Storage**: Git repository (`schemas/auth/v1/user-registered.json`) + Schema Registry service (future)

**Schema Evolution Rules**:
1. **Can add optional fields**: `"required": ["user_id", "email"]` (name is optional)
2. **Cannot remove required fields**: Always keep in `required` array
3. **Cannot change field types**: `email` must always be `string`
4. **Cannot rename fields**: Add new field, deprecate old (both present during transition)
5. **Versioning**: Increment schema version for breaking changes (`v1` → `v2`)

**Example JSON Schema**:
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://schemas.sumafinance.com/auth/v1/user-registered.json",
  "title": "UserRegistered",
  "description": "Event published when a new user registers",
  "version": "1.0",
  "type": "object",
  "required": ["event_id", "event_type", "version", "timestamp", "source", "data"],
  "properties": {
    "event_id": {
      "type": "string",
      "format": "uuid",
      "description": "Unique event identifier"
    },
    "event_type": {
      "type": "string",
      "const": "auth.user.registered"
    },
    "version": {
      "type": "string",
      "pattern": "^\\d+\\.\\d+$",
      "description": "Schema version (major.minor)"
    },
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp"
    },
    "source": {
      "type": "string",
      "description": "Service that published the event"
    },
    "data": {
      "type": "object",
      "required": ["user_id", "email", "registered_at"],
      "properties": {
        "user_id": {
          "type": "string",
          "pattern": "^usr_[a-zA-Z0-9]+$"
        },
        "email": {
          "type": "string",
          "format": "email"
        },
        "name": {
          "type": "string",
          "minLength": 1,
          "maxLength": 255
        },
        "email_verified": {
          "type": "boolean"
        },
        "registration_source": {
          "type": "string",
          "enum": ["web", "mobile", "api"]
        },
        "registered_at": {
          "type": "string",
          "format": "date-time"
        },
        "consents": {
          "type": "object",
          "properties": {
            "terms_accepted": {"type": "boolean"},
            "privacy_policy_accepted": {"type": "boolean"},
            "marketing_emails": {"type": "boolean"}
          }
        }
      }
    },
    "metadata": {
      "type": "object",
      "properties": {
        "trace_id": {"type": "string"},
        "ip_address": {"type": "string", "format": "ipv4"},
        "user_agent": {"type": "string"}
      }
    }
  }
}
```

**Schema Validation (Go)**:
```go
import "github.com/xeipuuv/gojsonschema"

func validateEvent(event interface{}, schemaPath string) error {
    schemaLoader := gojsonschema.NewReferenceLoader(fmt.Sprintf("file://%s", schemaPath))
    documentLoader := gojsonschema.NewGoLoader(event)
    
    result, err := gojsonschema.Validate(schemaLoader, documentLoader)
    if err != nil {
        return fmt.Errorf("schema validation error: %w", err)
    }
    
    if !result.Valid() {
        var errors []string
        for _, err := range result.Errors() {
            errors = append(errors, err.String())
        }
        return fmt.Errorf("event validation failed: %s", strings.Join(errors, "; "))
    }
    
    return nil
}

// Validate before publishing
func (p *EventPublisher) Publish(event Event) error {
    schemaPath := fmt.Sprintf("schemas/%s/%s.json", event.Source, event.EventType)
    if err := validateEvent(event, schemaPath); err != nil {
        logger.Error("Event validation failed", "error", err, "event_type", event.EventType)
        metrics.Counter("events.validation.errors").Inc("event_type", event.EventType)
        return err
    }
    
    return p.publishToQueue(event)
}
```

### WebSocket/Server-Sent Events

#### When to Use
- **Real-time security dashboard**: Admin monitoring of suspicious login attempts
- **Live session management**: User sees active sessions update in real-time
- **Security alerts**: Instant notification of new device login, impossible travel
- **Not used for**: Authentication itself (REST), bulk operations (use async queues)

#### WebSocket Protocol

**Connection Establishment**:
```javascript
// Client (Admin Dashboard)
const ws = new WebSocket('wss://api.sumafinance.com/v1/admin/security/stream');

ws.onopen = () => {
  console.log('WebSocket connected');
  
  // Send authentication
  ws.send(JSON.stringify({
    type: 'authenticate',
    token: localStorage.getItem('admin_jwt')
  }));
  
  // Subscribe to security events
  ws.send(JSON.stringify({
    type: 'subscribe',
    channels: ['security.suspicious_login', 'security.account_locked', 'security.new_device']
  }));
};

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  handleSecurityEvent(message);
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
  metrics.increment('websocket.errors');
};

ws.onclose = (event) => {
  console.log('WebSocket closed', event.code, event.reason);
  
  if (event.code !== 1000) { // Not normal closure
    // Reconnect with exponential backoff
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
    setTimeout(() => connectWebSocket(), delay);
    reconnectAttempts++;
  }
};

// Heartbeat to keep connection alive
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: 'ping' }));
  }
}, 30000); // Every 30 seconds
```

**Server Implementation (Go)**:
```go
func (s *SecurityService) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
    // Upgrade connection
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        logger.Error("WebSocket upgrade failed", "error", err)
        return
    }
    defer conn.Close()
    
    // Authenticate
    authenticated := false
    var adminID string
    
    // Read authentication message (5 second timeout)
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    _, authMsg, err := conn.ReadMessage()
    if err != nil {
        conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(4001, "Authentication timeout"))
        return
    }
    
    var authReq AuthRequest
    if err := json.Unmarshal(authMsg, &authReq); err != nil || authReq.Type != "authenticate" {
        conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(4002, "Invalid authentication"))
        return
    }
    
    // Validate admin JWT
    claims, err := s.validateAdminToken(authReq.Token)
    if err != nil {
        conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(4003, "Invalid token"))
        return
    }
    
    adminID = claims.UserID
    authenticated = true
    conn.SetReadDeadline(time.Time{}) // Remove deadline
    
    // Send authentication success
    conn.WriteJSON(map[string]interface{}{
        "type": "authenticated",
        "admin_id": adminID,
    })
    
    // Subscribe to Redis pub/sub for security events
    pubsub := s.redis.Subscribe(ctx, "security:suspicious_login", "security:account_locked", "security:new_device")
    defer pubsub.Close()
    
    // Handle messages
    go func() {
        for {
            msg, err := pubsub.ReceiveMessage(ctx)
            if err != nil {
                return
            }
            
            // Forward to WebSocket
            conn.WriteJSON(map[string]interface{}{
                "type": "security_event",
                "channel": msg.Channel,
                "data": json.RawMessage(msg.Payload),
                "timestamp": time.Now().UTC(),
            })
        }
    }()
    
    // Handle client messages (ping, subscription changes)
    for {
        _, message, err := conn.ReadMessage()
        if err != nil {
            logger.Info("WebSocket closed", "admin_id", adminID, "error", err)
            break
        }
        
        var req ClientMessage
        if err := json.Unmarshal(message, &req); err != nil {
            continue
        }
        
        switch req.Type {
        case "ping":
            conn.WriteJSON(map[string]string{"type": "pong"})
        case "subscribe":
            // Update subscriptions
        }
    }
}
```

**Message Format**:
```json
{
  "type": "security_event",
  "id": "evt_550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:00.123Z",
  "channel": "security.suspicious_login",
  "data": {
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "email": "user@example.com",
    "ip_address": "192.0.2.1",
    "location": {
      "city": "Moscow",
      "country": "RU"
    },
    "reason": "impossible_travel",
    "details": "Login from Moscow 2 hours after login from San Francisco",
    "risk_score": 95,
    "action_taken": "blocked"
  }
}
```

## API Contracts & Documentation

### Contract-First Development

**Workflow**:
1. **Define Contract**: Write OpenAPI specification for REST, .proto for gRPC
2. **Review Contract**: Team reviews API design before implementation
3. **Generate Code**: Use openapi-generator (REST), protoc (gRPC) to generate stubs
4. **Implement Server**: Fill in generated server stubs with business logic
5. **Generate Clients**: Generate client SDKs for consumers
6. **Run Contract Tests**: Validate implementation matches contract

### OpenAPI Specification

**auth-api-v1.yaml** (Excerpt):
```yaml
openapi: 3.0.3
info:
  title: SUMA Finance Authentication API
  version: 1.0.0
  description: |
    Secure authentication API for SUMA Finance.
    Supports email/password registration, JWT-based authentication, 2FA, password reset, and session management.
  contact:
    name: SUMA Finance API Team
    email: api@sumafinance.com
  license:
    name: Proprietary
servers:
  - url: https://api.sumafinance.com/v1
    description: Production
  - url: https://staging-api.sumafinance.com/v1
    description: Staging
  - url: http://localhost:3000/v1
    description: Local Development
tags:
  - name: Authentication
    description: User authentication endpoints
  - name: Registration
    description: User registration and email verification
  - name: Sessions
    description: Session management
  - name: 2FA
    description: Two-factor authentication
paths:
  /auth/register:
    post:
      summary: Register new user
      operationId: registerUser
      tags:
        - Registration
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterRequest'
            example:
              email: user@example.com
              password: SecurePass123!
              name: John Doe
              consents:
                terms_accepted: true
                privacy_policy_accepted: true
                marketing_emails: false
      responses:
        '201':
          description: User registered successfully
          headers:
            X-Request-ID:
              schema:
                type: string
                format: uuid
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegisterResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '409':
          $ref: '#/components/responses/Conflict'
        '422':
          $ref: '#/components/responses/ValidationError'
        '429':
          $ref: '#/components/responses/RateLimited'
        '500':
          $ref: '#/components/responses/InternalError'
      security: []
      x-ratelimit:
        limit: 10
        window: 3600
  
  /auth/login:
    post:
      summary: Login with email and password
      operationId: login
      tags:
        - Authentication
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Login successful (or 2FA required)
          content:
            application/json:
              schema:
                oneOf:
                  - $ref: '#/components/schemas/LoginResponse'
                  - $ref: '#/components/schemas/TwoFactorRequiredResponse'
        '401':
          $ref: '#/components/responses/Unauthorized'
        '403':
          $ref: '#/components/responses/AccountLocked'
        '429':
          $ref: '#/components/responses/RateLimited'
      security: []
      x-ratelimit:
        limit: 5
        window: 60

components:
  schemas:
    RegisterRequest:
      type: object
      required:
        - email
        - password
        - name
        - consents
      properties:
        email:
          type: string
          format: email
          example: user@example.com
        password:
          type: string
          format: password
          minLength: 12
          example: SecurePass123!
        name:
          type: string
          minLength: 1
          maxLength: 255
          example: John Doe
        consents:
          $ref: '#/components/schemas/Consents'
    
    RegisterResponse:
      type: object
      properties:
        data:
          type: object
          properties:
            user:
              $ref: '#/components/schemas/User'
            session:
              $ref: '#/components/schemas/Session'
        meta:
          $ref: '#/components/schemas/ResponseMeta'
    
    User:
      type: object
      properties:
        id:
          type: string
          example: usr_7d8e9f0a1b2c3d4e
        email:
          type: string
          format: email
        email_verified:
          type: boolean
        name:
          type: string
        created_at:
          type: string
          format: date-time
        two_factor_enabled:
          type: boolean
    
    Session:
      type: object
      properties:
        access_token:
          type: string
          example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
        refresh_token:
          type: string
          example: rt_a1b2c3d4e5f6g7h8i9j0
        token_type:
          type: string
          example: Bearer
        expires_in:
          type: integer
          description: Access token expiration in seconds
          example: 900
        refresh_expires_in:
          type: integer
          description: Refresh token expiration in seconds
          example: 604800
    
    Error:
      type: object
      properties:
        errors:
          type: array
          items:
            type: object
            properties:
              id:
                type: string
                format: uuid
              status:
                type: string
              code:
                type: string
              title:
                type: string
              detail:
                type: string
              source:
                type: object
                properties:
                  pointer:
                    type: string
              meta:
                type: object
        meta:
          $ref: '#/components/schemas/ResponseMeta'
  
  responses:
    BadRequest:
      description: Invalid request
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
    Unauthorized:
      description: Invalid credentials
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
    AccountLocked:
      description: Account temporarily locked
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
    RateLimited:
      description: Too many requests
      headers:
        X-RateLimit-Limit:
          schema:
            type: integer
        X-RateLimit-Remaining:
          schema:
            type: integer
        X-RateLimit-Reset:
          schema:
            type: integer
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
  
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: JWT access token

security:
  - bearerAuth: []
```

### Contract Testing

**Consumer-Driven Contracts** (Pact):
```javascript
// Consumer test (API Gateway tests Auth Service contract)
const { Pact } = require('@pact-foundation/pact');

describe('Auth Service Contract', () => {
  const provider = new Pact({
    consumer: 'api-gateway',
    provider: 'auth-service',
  });

  beforeAll(() => provider.setup());
  afterAll(() => provider.finalize());

  it('validates JWT token successfully', async () => {
    await provider.addInteraction({
      state: 'valid JWT token exists',
      uponReceiving: 'a request to validate token',
      withRequest: {
        method: 'POST',
        path: '/internal/v1/auth/validate-token',
        headers: {
          'Authorization': 'Bearer service_token',
          'Content-Type': 'application/json',
        },
        body: {
          access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          required_permissions: ['transactions:read'],
        },
      },
      willRespondWith: {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
        },
        body: {
          valid: true,
          user: {
            id: Matchers.string('usr_7d8e9f0a1b2c3d4e'),
            email: Matchers.email('user@example.com'),
            roles: Matchers.eachLike('user'),
            permissions: Matchers.eachLike('transactions:read'),
          },
        },
      },
    });

    const authService = new AuthServiceClient('http://localhost:8080');
    const result = await authService.validateToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', ['transactions:read']);
    
    expect(result.valid).toBe(true);
    expect(result.user.id).toMatch(/^usr_/);
  });
});
```

## Circuit Breaker Pattern

### Implementation

**Circuit States**:
1. **Closed**: Normal operation (all requests allowed)
2. **Open**: Failures exceeded threshold (all requests fail immediately for 30 seconds)
3. **Half-Open**: Testing recovery (1 request allowed to check if service recovered)

**Configuration**:
```go
type CircuitBreakerConfig struct {
    FailureThreshold         int           // Open after 5 consecutive failures
    SuccessThreshold         int           // Close after 2 successes in half-open
    Timeout                  time.Duration // 30 seconds before trying half-open
    VolumeThreshold          int           // Minimum 10 requests before checking
    ErrorThresholdPercentage int           // Open if >50% fail
    MonitoringPeriod         time.Duration // Rolling window of 10 seconds
}

var DefaultConfig = CircuitBreakerConfig{
    FailureThreshold:         5,
    SuccessThreshold:         2,
    Timeout:                  30 * time.Second,
    VolumeThreshold:          10,
    ErrorThresholdPercentage: 50,
    MonitoringPeriod:         10 * time.Second,
}
```

**Circuit Breaker Implementation (Go)**:
```go
type CircuitBreaker struct {
    name         string
    state        State
    failureCount int
    successCount int
    lastFailure  time.Time
    config       CircuitBreakerConfig
    mutex        sync.RWMutex
    metrics      *CircuitBreakerMetrics
}

type State string

const (
    StateClosed   State = "CLOSED"
    StateOpen     State = "OPEN"
    StateHalfOpen State = "HALF_OPEN"
)

func NewCircuitBreaker(name string, config CircuitBreakerConfig) *CircuitBreaker {
    return &CircuitBreaker{
        name:    name,
        state:   StateClosed,
        config:  config,
        metrics: NewCircuitBreakerMetrics(name),
    }
}

func (cb *CircuitBreaker) Execute(fn func() (interface{}, error)) (interface{}, error) {
    cb.mutex.RLock()
    state := cb.state
    cb.mutex.RUnlock()
    
    if state == StateOpen {
        // Check if timeout elapsed
        if time.Since(cb.lastFailure) > cb.config.Timeout {
            cb.transitionToHalfOpen()
        } else {
            cb.metrics.RecordRejection()
            return nil, ErrCircuitBreakerOpen
        }
    }
    
    if state == StateHalfOpen {
        // Only allow one request at a time in half-open
        if !cb.tryAcquireHalfOpenPermit() {
            cb.metrics.RecordRejection()
            return nil, ErrCircuitBreakerOpen
        }
    }
    
    // Execute function
    result, err := fn()
    
    if err != nil {
        cb.onFailure(err)
        return nil, err
    }
    
    cb.onSuccess()
    return result, nil
}

func (cb *CircuitBreaker) onSuccess() {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    cb.failureCount = 0
    cb.metrics.RecordSuccess()
    
    if cb.state == StateHalfOpen {
        cb.successCount++
        if cb.successCount >= cb.config.SuccessThreshold {
            cb.transitionToClosed()
            logger.Info("Circuit breaker closed", "name", cb.name)
        }
    }
}

func (cb *CircuitBreaker) onFailure(err error) {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    cb.failureCount++
    cb.lastFailure = time.Now()
    cb.metrics.RecordFailure()
    
    if cb.state == StateHalfOpen {
        cb.transitionToOpen()
        logger.Warn("Circuit breaker reopened", "name", cb.name, "error", err)
        return
    }
    
    if cb.failureCount >= cb.config.FailureThreshold {
        cb.transitionToOpen()
        logger.Error("Circuit breaker opened", "name", cb.name, "failures", cb.failureCount)
        
        // Send alert
        alerting.Send(Alert{
            Severity: "warning",
            Title:    fmt.Sprintf("Circuit breaker opened: %s", cb.name),
            Details: map[string]interface{}{
                "name":           cb.name,
                "failure_count":  cb.failureCount,
                "last_error":     err.Error(),
            },
        })
    }
}

func (cb *CircuitBreaker) transitionToOpen() {
    cb.state = StateOpen
    cb.successCount = 0
    cb.metrics.SetState(StateOpen)
}

func (cb *CircuitBreaker) transitionToHalfOpen() {
    cb.mutex.Lock()
    defer cb.mutex.Unlock()
    
    cb.state = StateHalfOpen
    cb.successCount = 0
    cb.metrics.SetState(StateHalfOpen)
    logger.Info("Circuit breaker half-open", "name", cb.name)
}

func (cb *CircuitBreaker) transitionToClosed() {
    cb.state = StateClosed
    cb.failureCount = 0
    cb.successCount = 0
    cb.metrics.SetState(StateClosed)
}

// Usage
var emailServiceBreaker = NewCircuitBreaker("email-service", DefaultConfig)

func SendVerificationEmail(ctx context.Context, email string, token string) error {
    result, err := emailServiceBreaker.Execute(func() (interface{}, error) {
        return nil, sendgrid.Send(ctx, VerificationEmail{
            To:    email,
            Token: token,
        })
    })
    
    return err
}
```

## Service Mesh Integration

### Service Mesh Benefits (Future Enhancement)
- **Service Discovery**: Automatic discovery of auth-service, user-service instances
- **Load Balancing**: Client-side load balancing with health checks
- **Traffic Management**: Canary deployments (10% traffic to new auth-service version)
- **Mutual TLS (mTLS)**: Automatic encryption of service-to-service communication
- **Observability**: Automatic metrics, traces, logs for all communication
- **Circuit Breaking**: Declarative circuit breaker configuration
- **Fault Injection**: Test resilience by injecting delays, errors

### Configuration Example (Istio)

**Virtual Service** (Canary Deployment):
```yaml
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: auth-service
  namespace: suma-finance
spec:
  hosts:
    - auth-service.suma-finance.svc.cluster.local
  http:
    - match:
        - headers:
            x-canary:
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

**Destination Rule** (Circuit Breaker, mTLS):
```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: auth-service
  namespace: suma-finance
spec:
  host: auth-service.suma-finance.svc.cluster.local
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL # mTLS enabled
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 50
        http2MaxRequests: 100
        maxRequestsPerConnection: 2
    outlierDetection:
      consecutiveErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
      minHealthPercent: 50
    loadBalancer:
      simple: LEAST_REQUEST
  subsets:
    - name: v1
      labels:
        version: v1
    - name: v2
      labels:
        version: v2
```

## Monitoring & Observability

### Communication Metrics

**REST API Metrics** (Prometheus):
```prometheus
# Request rate
http_requests_total{service="auth-service", endpoint="/api/v1/auth/login", method="POST", status="200"} 1500
http_requests_total{service="auth-service", endpoint="/api/v1/auth/login", method="POST", status="401"} 45

# Request duration (histogram)
http_request_duration_seconds_bucket{service="auth-service", endpoint="/api/v1/auth/login", le="0.1"} 1200
http_request_duration_seconds_bucket{service="auth-service", endpoint="/api/v1/auth/login", le="0.2"} 1450
http_request_duration_seconds_bucket{service="auth-service", endpoint="/api/v1/auth/login", le="0.5"} 1500

# In-flight requests
http_requests_in_flight{service="auth-service", endpoint="/api/v1/auth/login"} 5
```

**Message Queue Metrics**:
```prometheus
# Messages published
messages_published_total{exchange="auth.events", routing_key="auth.user.registered"} 2500

# Messages consumed
messages_consumed_total{queue="email-verification-queue", status="success"} 2480
messages_consumed_total{queue="email-verification-queue", status="error"} 20

# Message processing duration
message_processing_duration_seconds{queue="email-verification-queue", p50="0.05", p95="0.15", p99="0.3"}

# Queue depth
message_queue_depth{queue="email-verification-queue"} 15
message_queue_depth{queue="dead-letter-queue"} 3
```

**Circuit Breaker Metrics**:
```prometheus
# Circuit breaker state (0=closed, 1=open, 2=half-open)
circuit_breaker_state{service="auth-service", dependency="email-service"} 0

# Failures
circuit_breaker_failures_total{service="auth-service", dependency="email-service"} 125

# Rejections
circuit_breaker_rejections_total{service="auth-service", dependency="email-service"} 0
```

### Distributed Tracing

**W3C Trace Context Propagation**:
```http
# Request headers
traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
tracestate: suma=correlationid:550e8400-e29b-41d4-a716-446655440000

# Format: version-trace_id-parent_span_id-trace_flags
# 00: Version
# 0af7651916cd43dd8448eb211c80319c: Trace ID (32 hex chars)
# b7ad6b7169203331: Parent Span ID (16 hex chars)
# 01: Trace flags (01 = sampled)
```

**Span Creation (Go with OpenTelemetry)**:
```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/codes"
)

func (s *AuthService) ValidateToken(ctx context.Context, token string) (*User, error) {
    tracer := otel.Tracer("auth-service")
    ctx, span := tracer.Start(ctx, "ValidateToken",
        trace.WithSpanKind(trace.SpanKindInternal),
        trace.WithAttributes(
            attribute.String("service", "auth-service"),
            attribute.String("operation", "validate_token"),
        ),
    )
    defer span.End()
    
    // Extract user ID from token
    span.SetAttributes(attribute.String("user_id", userID))
    
    // Call user service
    ctx, childSpan := tracer.Start(ctx, "GetUserPermissions",
        trace.WithSpanKind(trace.SpanKindClient),
        trace.WithAttributes(
            attribute.String("downstream.service", "user-service"),
            attribute.String("rpc.method", "GetUserPermissions"),
        ),
    )
    
    permissions, err := s.userServiceClient.GetUserPermissions(ctx, userID)
    childSpan.End()
    
    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, err.Error())
        return nil, err
    }
    
    span.SetAttributes(attribute.Int("permissions.count", len(permissions)))
    span.SetStatus(codes.Ok, "token validated successfully")
    
    return user, nil
}
```

### Structured Logging

**Log Format** (JSON):
```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "level": "INFO",
  "service": "auth-service",
  "service_version": "1.2.3",
  "environment": "production",
  "trace_id": "0af7651916cd43dd8448eb211c80319c",
  "span_id": "b7ad6b7169203331",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "correlation_id": "650e8400-e29b-41d4-a716-446655440000",
  "user_id": "usr_7d8e9f0a1b2c3d4e",
  "ip_address": "192.0.2.1",
  "message": "User login successful",
  "context": {
    "endpoint": "/api/v1/auth/login",
    "method": "POST",
    "status_code": 200,
    "duration_ms": 45,
    "email": "user@example.com",
    "two_factor_required": false
  }
}
```

**Security Audit Log** (Special format for compliance):
```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "level": "AUDIT",
  "service": "auth-service",
  "event_type": "security.login.success",
  "actor": {
    "user_id": "usr_7d8e9f0a1b2c3d4e",
    "email": "user@example.com",
    "ip_address": "192.0.2.1",
    "user_agent": "SumaFinance-iOS/2.1.0",
    "device_id": "dev_xyz789"
  },
  "action": {
    "type": "login",
    "resource": "user_account",
    "result": "success"
  },
  "context": {
    "trace_id": "0af7651916cd43dd8448eb211c80319c",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "session_id": "sess_abc123",
    "location": {
      "city": "San Francisco",
      "region": "California",
      "country": "US"
    }
  },
  "compliance": {
    "gdpr_applicable": true,
    "pci_dss_applicable": false,
    "retention_days": 2555
  }
}
```

## Security Considerations

### Service-to-Service Authentication

**Mutual TLS (mTLS)** (Future with Service Mesh):
- Each service has unique certificate signed by internal CA
- Certificates include service identity (CN=auth-service.suma-finance.svc)
- Automatic certificate rotation every 90 days
- Revocation via CRL or OCSP

**Service JWT Tokens** (Current Implementation):
```go
// Generate service token
func GenerateServiceToken(serviceName string) (string, error) {
    now := time.Now()
    claims := ServiceClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            Issuer:    "auth-service",
            Subject:   serviceName,
            Audience:  []string{"internal-services"},
            ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
            IssuedAt:  jwt.NewNumericDate(now),
            ID:        generateUUID(),
        },
        ServiceName: serviceName,
        Permissions: getServicePermissions(serviceName),
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(serviceTokenSecret)
}

// Validate service token
func ValidateServiceToken(tokenString string) (*ServiceClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &ServiceClaims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return serviceTokenSecret, nil
    })
    
    if err != nil {
        return nil, err
    }
    
    if claims, ok := token.Claims.(*ServiceClaims); ok && token.Valid {
        return claims, nil
    }
    
    return nil, errors.New("invalid token")
}
```

### API Security

**Rate Limiting** (Per-IP, Per-User, Per-API-Key):
```go
// Redis-based rate limiter
func (rl *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
    now := time.Now().Unix()
    windowStart := now - int64(window.Seconds())
    
    pipe := rl.redis.Pipeline()
    
    // Remove old entries
    pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))
    
    // Add current request
    pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: generateUUID()})
    
    // Count requests in window
    pipe.ZCard(ctx, key)
    
    // Set expiration
    pipe.Expire(ctx, key, window)
    
    results, err := pipe.Exec(ctx)
    if err != nil {
        return false, err
    }
    
    count := results[2].(*redis.IntCmd).Val()
    
    return count <= int64(limit), nil
}

// Usage in middleware
func RateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Per-IP rate limit
        ip := getClientIP(r)
        allowed, err := rateLimiter.Allow(r.Context(), fmt.Sprintf("ip:%s:%s", ip, r.URL.Path), 100, time.Minute)
        
        if err != nil {
            http.Error(w, "Rate limiter error", http.StatusInternalServerError)
            return
        }
        
        if !allowed {
            w.Header().Set("X-RateLimit-Limit", "100")
            w.Header().Set("X-RateLimit-Remaining", "0")
            w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

**Input Validation**:
```go
// Validate registration request
func ValidateRegistrationRequest(req RegisterRequest) []ValidationError {
    var errors []ValidationError
    
    // Email validation
    if !isValidEmail(req.Email) {
        errors = append(errors, ValidationError{
            Field: "email",
            Code:  "INVALID_EMAIL",
            Message: "Email address is invalid",
        })
    }
    
    // Password strength validation
    if len(req.Password) < 12 {
        errors = append(errors, ValidationError{
            Field: "password",
            Code: "PASSWORD_TOO_SHORT",
            Message: "Password must be at least 12 characters",
        })
    }
    
    if !hasUppercase(req.Password) || !hasLowercase(req.Password) || !hasNumber(req.Password) || !hasSpecialChar(req.Password) {
        errors = append(errors, ValidationError{
            Field: "password",
            Code: "WEAK_PASSWORD",
            Message: "Password must include uppercase, lowercase, number, and special character",
        })
    }
    
    // Check password breach (HaveIBeenPwned)
    breached, err := checkPasswordBreach(req.Password)
    if err == nil && breached {
        errors = append(errors, ValidationError{
            Field: "password",
            Code: "PASSWORD_BREACHED",
            Message: "This password has been exposed in a data breach. Please choose a different password.",
        })
    }
    
    return errors
}
```

## Testing Strategy

### Unit Tests
- Test message handlers in isolation with mocked dependencies
- Test JWT token generation/validation logic
- Test password hashing and validation
- Test rate limiter logic

### Integration Tests
- Test REST API endpoints with real database (test container)
- Test message publishing to RabbitMQ and consumption
- Test Redis session storage and retrieval
- Test service-to-service gRPC calls

### Contract Tests
- Consumer-driven contracts (Pact) between Auth Service and User Service
- Verify OpenAPI specification matches implementation
- Run on every PR to prevent breaking changes

### End-to-End Tests
- Test complete registration flow (web → API → email)
- Test login flow with 2FA
- Test password reset flow
- Run in staging environment before production deployment

## Documentation

### API Documentation
- **OpenAPI Specification**: Hosted at https://api.sumafinance.com/docs (Swagger UI)
- **Generated from Code**: Using Go annotations with swaggo
- **Examples**: Include curl examples, SDKs for JavaScript, Python
- **Tutorials**: Step-by-step guides for common workflows

### Message Documentation
- **Event Catalog**: Central registry of all events with schemas
- **Message Flow Diagrams**: Visual representation of event flows
- **Consumer Responsibilities**: Document which services consume which events
- **Versioning Guidelines**: How to evolve schemas without breaking consumers

### Runbooks
- **Troubleshooting**: Common issues (token expired, rate limited, circuit breaker open)
- **Tracing Requests**: How to find logs/traces for a specific request ID
- **Replaying Failed Messages**: How to retry messages from dead letter queue
- **Scaling Services**: How to add more instances of auth-service

## Appendix

### Communication Decision Matrix

| Scenario | Pattern | Protocol | Rationale |
|----------|---------|----------|-----------|
| User registration | Sync | REST/HTTPS | Immediate response needed, user waits for confirmation |
| Email verification send | Async | RabbitMQ | Fire-and-forget, decouple auth service from email service |
| User login (no 2FA) | Sync | REST/HTTPS | Immediate response with JWT tokens |
| User login (with 2FA) | Sync | REST/HTTPS | Two-step process, user waits for OTP |
| Token validation (internal) | Sync | gRPC | High performance needed (thousands per second), strong typing |
| Security audit logging | Async | RabbitMQ | Decouple logging from main flow, ensure delivery |
| Session lookup | Sync | Redis | Sub-10ms latency required, cache hit ratio >95% |
| Password reset request | Async | RabbitMQ | Email sending can be delayed, don't block user |
| GDPR consent tracking | Event | RabbitMQ | Multiple consumers need to know (audit, analytics, compliance) |
| Real-time security alerts (admin) | Streaming | WebSocket | Live dashboard for security team |
| User permissions check | Sync | gRPC | Fast response needed, called on every API request |

### Error Code Registry

| Code | HTTP Status | Description | User Action | Retry |
|------|-------------|-------------|-------------|-------|
| `VALIDATION_ERROR` | 422 | Input validation failed | Fix input and retry | No |
| `WEAK_PASSWORD` | 422 | Password doesn't meet security requirements | Use stronger password | No |
| `EMAIL_ALREADY_REGISTERED` | 409 | Email already exists | Use different email or login | No |
| `INVALID_CREDENTIALS` | 401 | Email or password incorrect | Check credentials | No |
| `ACCOUNT_LOCKED` | 403 | Too many failed login attempts | Wait 15 minutes or contact support | After lockout expires |
| `EMAIL_NOT_VERIFIED` | 403 | Email not yet verified | Check email and verify | No |
| `TOKEN_EXPIRED` | 401 | JWT access token expired | Use refresh token to get new access token | No |
| `REFRESH_TOKEN_INVALID` | 401 | Refresh token invalid or revoked | Re-authenticate | No |
| `2FA_REQUIRED` | 200 | Two-factor authentication required | Enter OTP code | No |
| `2FA_CODE_INVALID` | 401 | OTP code incorrect or expired | Request new code | No |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests | Wait before retrying | After rate limit resets |
| `SERVICE_UNAVAILABLE` | 503 | Auth service temporarily down | Retry with exponential backoff | Yes |
| `UPSTREAM_SERVICE_ERROR` | 502 | User service or email service error | Retry with backoff | Yes |
| `INTERNAL_ERROR` | 500 | Unexpected server error | Contact support if persists | Yes |

### Glossary

- **Access Token**: Short-lived JWT (15 minutes) used to authenticate API requests
- **Refresh Token**: Long-lived token (7 days) used to obtain new access tokens
- **Idempotency**: Property where operation can be applied multiple times without changing result
- **Circuit Breaker**: Pattern to prevent cascading failures by failing fast when dependency is down
- **Dead Letter Queue**: Queue for messages that failed processing after max retries
- **Service Mesh**: Infrastructure layer for service-to-service communication (traffic management, security, observability)
- **mTLS**: Mutual TLS where both client and server authenticate each other with certificates
- **At-Least-Once Delivery**: Guarantee that message is delivered one or more times (may duplicate)
- **Exactly-Once Delivery**: Guarantee that message is delivered exactly once (complex, performance overhead)
- **Consumer-Driven Contract**: Contract testing approach where consumer defines expected API behavior
- **W3C Trace Context**: Standard for propagating trace context across services (traceparent header)
- **OpenTelemetry**: Observability framework for collecting metrics, traces, logs
- **gRPC**: High-performance RPC framework using Protocol Buffers
- **Protocol Buffers**: Language-agnostic serialization format (smaller, faster than JSON)
- **Event Sourcing**: Pattern where state changes are stored as sequence of events
- **CQRS**: Command Query Responsibility Segregation (separate read and write models)
