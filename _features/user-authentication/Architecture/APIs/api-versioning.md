# API VERSIONING STRATEGY

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: APIs
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

The SUMA Finance authentication system requires a robust API versioning strategy that balances innovation with stability. Given the fintech context and GDPR/PCI-DSS compliance requirements, we must maintain strict backward compatibility guarantees while enabling continuous security improvements. This strategy adopts **URI Path Versioning** as the primary method, providing clear visibility and simple routing for authentication endpoints that handle sensitive user credentials and financial data.

Our versioning philosophy prioritizes security updates and compliance requirements over feature velocity. Authentication APIs will support N and N-1 versions concurrently with a **minimum 12-month deprecation period** for breaking changes. Non-breaking security patches will be backported to all supported versions. The strategy includes comprehensive migration tooling, automated version monitoring, and clear communication channels to ensure zero-downtime transitions for client applications.

This document establishes the versioning lifecycle, breaking change definitions, deprecation procedures, and migration patterns specific to authentication flows including registration, login, JWT management, 2FA, password resets, and session handling. Special attention is given to security implications of version transitions and compliance audit requirements.

## Versioning Philosophy

### Principles
- **Backward Compatibility**: Never break existing authentication flows without extensive notice and migration support
- **Security First**: Security patches apply to all supported versions; critical vulnerabilities trigger immediate coordinated updates
- **Predictable Evolution**: Use semantic versioning with clear changelog and migration documentation
- **Deprecation Grace Period**: Minimum 12 months notice for breaking changes, 6 months for security-recommended updates
- **Multiple Version Support**: Support current (v2) and previous (v1) versions; deprecate v1 only when <5% traffic remains
- **Clear Communication**: 90-day advance notice for new versions; monthly deprecation reminders; emergency security notifications
- **Smooth Migration**: Provide migration scripts, SDK updates, compatibility testing tools, and dedicated support channel
- **Compliance Preservation**: Maintain GDPR/PCI-DSS compliance across all active versions

### Semantic Versioning
**Format**: `vMAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes (incompatible API changes requiring client code modifications)
- **MINOR**: New features (backward-compatible functionality additions)
- **PATCH**: Bug fixes (backward-compatible fixes and security patches)

**Examples**:
- `v1.0.0` → `v1.1.0`: Added biometric authentication endpoint (minor)
- `v1.1.0` → `v1.1.1`: Fixed JWT refresh token race condition (patch)
- `v1.1.1` → `v1.2.0`: Added OAuth 2.0 social login (minor)
- `v1.2.0` → `v2.0.0`: Changed JWT payload structure for enhanced security (major)

**Security Patch Policy**:
- Critical vulnerabilities (CVSS ≥ 9.0): Emergency patch to all versions within 24 hours
- High severity (CVSS 7.0-8.9): Patch within 7 days
- Medium severity (CVSS 4.0-6.9): Patch within 30 days
- All security patches increment PATCH version

## Versioning Methods

### Method 1: URI Path Versioning (Recommended)

**Format**: `/api/v{major}/auth/resource`

**Examples**:
```
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
GET  /api/v1/auth/verify-email
POST /api/v1/auth/forgot-password

POST /api/v2/auth/register
POST /api/v2/auth/login
POST /api/v2/auth/refresh
GET  /api/v2/auth/verify-email
POST /api/v2/auth/forgot-password
```

**Pros**:
- Clear and visible - security teams can easily audit API versions in use
- Easy to route - separate controllers per version simplify security patches
- Cacheable - CDN/WAF can cache based on URI path
- Browser-friendly - works with CORS, OAuth callbacks, email verification links
- Simple to implement - straightforward middleware routing in Go
- Compliance-friendly - audit logs clearly show which version clients use

**Cons**:
- Pollutes URI space - multiple endpoints for same resource
- Requires routing changes - updates to ingress/load balancer configuration

**Implementation (Go with Gin)**:
```go
// main.go
func main() {
    router := gin.Default()
    
    // V1 authentication routes
    v1 := router.Group("/api/v1/auth")
    {
        v1.POST("/register", v1Controllers.Register)
        v1.POST("/login", v1Controllers.Login)
        v1.POST("/refresh", v1Controllers.RefreshToken)
        v1.POST("/logout", v1Controllers.Logout)
        v1.GET("/verify-email", v1Controllers.VerifyEmail)
        v1.POST("/forgot-password", v1Controllers.ForgotPassword)
        v1.POST("/reset-password", v1Controllers.ResetPassword)
        v1.POST("/enable-2fa", v1Controllers.Enable2FA)
        v1.POST("/verify-2fa", v1Controllers.Verify2FA)
    }
    
    // V2 authentication routes (enhanced security)
    v2 := router.Group("/api/v2/auth")
    {
        v2.POST("/register", v2Controllers.Register)
        v2.POST("/login", v2Controllers.Login)
        v2.POST("/refresh", v2Controllers.RefreshToken)
        v2.POST("/logout", v2Controllers.Logout)
        v2.GET("/verify-email", v2Controllers.VerifyEmail)
        v2.POST("/forgot-password", v2Controllers.ForgotPassword)
        v2.POST("/reset-password", v2Controllers.ResetPassword)
        v2.POST("/enable-2fa", v2Controllers.Enable2FA)
        v2.POST("/verify-2fa", v2Controllers.Verify2FA)
        v2.POST("/oauth/google", v2Controllers.OAuthGoogle)
        v2.POST("/oauth/apple", v2Controllers.OAuthApple)
        v2.POST("/biometric/register", v2Controllers.RegisterBiometric)
    }
    
    router.Run(":8080")
}
```

### Method 2: Header Versioning

**Format**: `Accept: application/vnd.suma.v2+json`

**Examples**:
```http
POST /api/auth/login
Accept: application/vnd.suma.v1+json
Content-Type: application/json

POST /api/auth/login
Accept: application/vnd.suma.v2+json
Content-Type: application/json
```

**Pros**:
- Clean URIs - single endpoint for all versions
- Content negotiation - RESTful approach
- Version hidden from URL - reduces accidental version leakage

**Cons**:
- Not browser-friendly - difficult to test in browsers, problematic for OAuth callbacks
- Hidden from URL - harder to debug, difficult for security audits
- Harder to cache - CDN/WAF must inspect headers
- More complex routing - requires custom middleware to parse Accept headers
- OAuth complications - OAuth providers expect stable callback URIs

**Not Recommended for Authentication APIs** due to browser compatibility and OAuth callback requirements.

### Method 3: Query Parameter Versioning

**Format**: `/api/auth/login?version=2`

**Pros**:
- Simple implementation
- Visible in logs
- Easy to test

**Cons**:
- Pollutes query string
- Caching complications - must cache different query parameters separately
- Not RESTful - version is not a resource property
- Security risk - version parameter could be manipulated
- OAuth complications - query parameters in callback URLs

**Not Recommended** for authentication APIs.

### Method 4: Hostname Versioning

**Format**: `https://v2-api.sumafinance.com/auth/login`

**Pros**:
- Complete isolation - separate infrastructure per version
- Independent scaling - scale v1 and v2 independently
- Clear separation - no routing logic needed
- Security isolation - vulnerabilities in v1 don't affect v2

**Cons**:
- Multiple domains - separate SSL certificates, DNS configuration
- Complex infrastructure - duplicate deployments, load balancers
- Higher costs - redundant infrastructure
- OAuth complications - different domains for callbacks

**Use Case**: Major platform rewrites or complete authentication system overhauls (e.g., migrating from session-based to token-based authentication).

### Chosen Method: URI Path Versioning

**Rationale**: 
- Best balance of visibility, simplicity, and developer experience
- OAuth/email verification callback compatibility
- Clear for security audits and compliance reviews
- Simple CDN/WAF integration for rate limiting and threat detection
- Straightforward routing in Go with minimal middleware complexity
- Works seamlessly with React Native mobile apps
- Aligns with industry standards (Stripe, Twilio, GitHub APIs use URI versioning)

## Version Lifecycle

### Version States

1. **Beta**: New version in testing (`v2-beta`)
   - Available at `/api/v2-beta/auth/*`
   - No SLA guarantees
   - May have breaking changes between beta releases
   - For early adopters and internal testing
   - Not covered by compliance certifications
   - Rate limits: 50% of production limits
   - Documented as experimental in API docs

2. **Stable**: Production-ready version (`v2`)
   - Full SLA support: 99.95% uptime
   - No breaking changes without major version increment
   - Recommended for new integrations
   - Full compliance certifications (GDPR, PCI-DSS, SOC 2)
   - Production rate limits: 1000 req/s
   - 24/7 support for critical issues
   - Security patches backported

3. **Deprecated**: Old version being phased out (`v1 deprecated`)
   - Still supported with full SLA
   - No new features added
   - Security patches only (critical/high severity)
   - Deprecation warnings in response headers
   - Migration guide available in documentation
   - 12-month deprecation period minimum
   - Monthly email reminders to clients still using version
   - Compliance certifications maintained

4. **Sunset**: Version removed (`v1 sunset`)
   - No longer available
   - Returns `410 Gone` with migration instructions
   - Redirect headers to current version
   - Emergency support available (72 hours) for critical clients
   - Compliance audit records retained for 7 years

### Version Timeline

```
Month 0:  v2-beta released (v1 Stable)
          - Internal testing phase
          - Select partners invited to beta
          - Beta documentation published

Month 3:  v2 becomes Stable (v1 Stable)
          - v2 promoted to production
          - Full SLA coverage begins
          - v1 remains stable, no deprecation yet

Month 6:  v1 marked Deprecated (v2 Stable)
          - Deprecation announcement sent to all API clients
          - Deprecation headers added to v1 responses
          - Migration guide published
          - Dedicated migration support channel opened

Month 12: Migration progress review
          - Client migration status assessed
          - Extensions offered to clients with >100K MAU
          - Final migration webinar conducted

Month 18: v1 Sunset (v2 Stable)
          - v1 endpoints return 410 Gone
          - Emergency support available for 72 hours
          - v3-beta released (if planned)

Month 21: v3-beta testing
Month 24: v3 becomes Stable, v2 remains Stable
Month 30: v2 marked Deprecated (v3 Stable)
```

### Version Support Policy

- **Current Version (v2)**: Full support, new features, security patches, compliance updates
- **Previous Version (v1, stable)**: Full support, security patches, no new features
- **Deprecated Version (v1, deprecated)**: Security critical fixes only (CVSS ≥ 7.0), no feature updates
- **Sunset Version**: Not supported, returns 410 Gone with migration instructions

**Support SLA**:
- **Stable versions**: P0 (auth down) < 15 min response, P1 (degraded) < 1 hour, P2 (bugs) < 24 hours
- **Deprecated versions**: P0 < 30 min response, P1 < 2 hours, P2 not supported
- **Beta versions**: Best-effort support, no SLA guarantees

## Breaking vs Non-Breaking Changes

### Breaking Changes (Require New Major Version)

**Response Structure Changes**:
- Removing fields from response (e.g., removing `user.email` field)
- Renaming fields (e.g., `user_id` → `userId`)
- Changing field types (e.g., `user.id` from `int` to `string`)
- Changing status codes (e.g., 401 → 403 for invalid credentials)
- Removing endpoints (e.g., deprecating `/api/v1/auth/login-legacy`)
- Changing error response format

**Request Changes**:
- Removing request parameters (e.g., removing `device_id` parameter)
- Making optional parameters required (e.g., `device_id` becomes mandatory)
- Changing parameter types (e.g., `remember_me` from boolean to integer)
- Changing validation rules (more restrictive, e.g., password min length 8 → 12)
- Changing HTTP methods (e.g., GET → POST)

**Behavior Changes**:
- Changing JWT payload structure
- Changing token expiration logic
- Changing password hashing algorithm (Argon2id parameters)
- Changing session management behavior (e.g., single session → multi-session)
- Changing authentication flow (e.g., adding mandatory 2FA)
- Changing rate limiting behavior (stricter limits)

**Security Changes (Often Breaking)**:
- Enforcing HTTPS-only (if previously allowed HTTP)
- Changing CORS policy (more restrictive origins)
- Changing cookie settings (SameSite=None → SameSite=Strict)
- Requiring new authentication headers
- Changing encryption algorithms

**Example Breaking Change (v1 → v2)**:
```javascript
// v1: Login response returns flat user object
POST /api/v1/auth/login
Request:
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

Response (200 OK):
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user_id": 12345,
  "email": "user@example.com",
  "name": "John Doe"
}

// v2: Login response returns nested structure (BREAKING)
POST /api/v2/auth/login
Request:
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "device_id": "optional-device-fingerprint"
}

Response (200 OK):
{
  "tokens": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_expires_in": 604800
  },
  "user": {
    "id": "usr_12345",
    "email": "user@example.com",
    "name": "John Doe",
    "email_verified": true,
    "two_factor_enabled": false
  },
  "session": {
    "session_id": "sess_abc123",
    "device_id": "dev_xyz789",
    "created_at": "2025-10-29T10:00:00Z"
  }
}
```

**Migration Impact**: Clients must update response parsing logic, handle nested objects, and adapt to string-based user IDs.

### Non-Breaking Changes (Can Add to Current Version)

**Additive Response Changes**:
- Adding new optional fields to response
- Adding new endpoints
- Adding new optional query parameters
- Adding new HTTP methods to existing endpoints (if backward compatible)
- Adding new error codes (clients should handle unknown codes gracefully)

**Relaxed Validation**:
- Making required parameters optional
- Relaxing validation rules (e.g., password min length 12 → 8)
- Accepting additional values for enums

**Performance Improvements**:
- Improving response time
- Reducing payload size (without removing fields)
- Adding compression support

**Security Enhancements (Non-Breaking)**:
- Adding optional security headers
- Supporting additional authentication methods (as alternatives)
- Strengthening rate limiting (within documented limits)
- Adding optional 2FA (when not mandatory)

**Example Non-Breaking Change (v2.0 → v2.1)**:
```javascript
// v2.0: Original login response
POST /api/v2/auth/login
Response (200 OK):
{
  "tokens": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc..."
  },
  "user": {
    "id": "usr_12345",
    "email": "user@example.com"
  }
}

// v2.1: Added optional fields (NON-BREAKING)
POST /api/v2/auth/login
Response (200 OK):
{
  "tokens": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    "scope": "read:profile write:profile"  // NEW OPTIONAL FIELD
  },
  "user": {
    "id": "usr_12345",
    "email": "user@example.com",
    "profile_picture": "https://cdn.suma.com/avatars/12345.jpg",  // NEW OPTIONAL FIELD
    "last_login": "2025-10-28T15:30:00Z"  // NEW OPTIONAL FIELD
  }
}
```

**Migration Impact**: None. Existing clients ignore new fields. New clients can opt-in to use new fields.

### Ambiguous Changes (Context-Dependent)

**Adding Required Security Features**:
- Adding mandatory 2FA: Breaking (requires client support)
- Adding optional 2FA: Non-breaking (clients can ignore)

**Changing Default Behavior**:
- Changing default token expiration: Non-breaking if within documented range
- Changing default rate limits: Breaking if exceeds documented limits

**When in Doubt**: Treat as breaking change and increment major version. Better to be conservative with authentication APIs.

## Version Header Strategy

### Request Headers

**Version Indication** (redundant with URI, used for validation):
```http
POST /api/v2/auth/login
Content-Type: application/json
Accept: application/json
X-API-Version: 2
X-Client-Id: mobile-app-ios-v1.2.3
X-Device-Id: a1b2c3d4e5f6
User-Agent: SUMA-Finance-iOS/1.2.3
```

**Feature Flags** (for beta features in stable versions):
```http
POST /api/v2/auth/login
X-Feature-Flags: biometric-auth,passkey-support
```

**Security Headers** (required):
```http
POST /api/v2/auth/login
X-Request-ID: req_550e8400-e29b-41d4-a716-446655440000
X-Forwarded-For: 203.0.113.42
X-CSRF-Token: csrf_token_value
```

### Response Headers

**Version Information** (always included):
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-API-Version: 2
X-API-Deprecated: false
X-API-Sunset-Date: null
X-API-Latest-Version: 2
X-Rate-Limit-Limit: 1000
X-Rate-Limit-Remaining: 995
X-Rate-Limit-Reset: 1698580800
X-Request-ID: req_550e8400-e29b-41d4-a716-446655440000
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'
```

**Deprecation Warning** (for deprecated versions):
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-API-Version: 1
X-API-Deprecated: true
X-API-Deprecation-Date: 2024-06-01
X-API-Sunset-Date: 2025-06-01
X-API-Latest-Version: 2
Warning: 299 - "API version 1 is deprecated and will be sunset on 2025-06-01. Please migrate to v2. See https://docs.sumafinance.com/api/migration/v1-to-v2"
Link: <https://docs.sumafinance.com/api/migration/v1-to-v2>; rel="deprecation"
Link: <https://api.sumafinance.com/v2/auth/login>; rel="alternate"
Sunset: Sat, 01 Jun 2025 00:00:00 GMT
```

**Sunset Response** (410 Gone):
```http
HTTP/1.1 410 Gone
Content-Type: application/json
X-API-Version: 1
X-API-Deprecated: true
X-API-Sunset-Date: 2025-06-01
X-API-Latest-Version: 2
Link: <https://docs.sumafinance.com/api/migration/v1-to-v2>; rel="deprecation"
Link: <https://api.sumafinance.com/v2/auth/login>; rel="alternate"

{
  "error": {
    "code": "VERSION_SUNSET",
    "message": "API version 1 was sunset on 2025-06-01 and is no longer available",
    "sunset_date": "2025-06-01T00:00:00Z",
    "deprecation_announcement_date": "2024-06-01T00:00:00Z",
    "migration_guide_url": "https://docs.sumafinance.com/api/migration/v1-to-v2",
    "current_version": {
      "version": 2,
      "base_url": "https://api.sumafinance.com/v2",
      "documentation_url": "https://docs.sumafinance.com/api/v2"
    },
    "support": {
      "email": "api-support@sumafinance.com",
      "emergency_migration_window": "72 hours from sunset date"
    }
  }
}
```

**Rate Limit Exceeded Response** (429):
```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-API-Version: 2
X-Rate-Limit-Limit: 1000
X-Rate-Limit-Remaining: 0
X-Rate-Limit-Reset: 1698580800
Retry-After: 60

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Maximum 1000 requests per hour.",
    "retry_after_seconds": 60,
    "rate_limit": {
      "limit": 1000,
      "remaining": 0,
      "reset_at": "2025-10-29T11:00:00Z"
    }
  }
}
```

## Migration Strategies

### Strategy 1: Adapter Pattern (Recommended for v1 → v2)

**Convert v2 requests to v1 format internally, then adapt responses back to v2**:

```go
// adapters/auth_adapter.go
package adapters

import (
    "github.com/sumafinance/backend/internal/models"
    v1models "github.com/sumafinance/backend/internal/v1/models"
    v2models "github.com/sumafinance/backend/internal/v2/models"
)

type AuthAdapter struct {
    v1Service *v1services.AuthService
}

// AdaptLoginRequest converts v2 login request to v1 format
func (a *AuthAdapter) AdaptLoginRequest(v2Req *v2models.LoginRequest) *v1models.LoginRequest {
    return &v1models.LoginRequest{
        Email:    v2Req.Email,
        Password: v2Req.Password,
        // v2 adds device_id, but v1 doesn't support it - safely ignore
    }
}

// AdaptLoginResponse converts v1 login response to v2 format
func (a *AuthAdapter) AdaptLoginResponse(v1Resp *v1models.LoginResponse) *v2models.LoginResponse {
    return &v2models.LoginResponse{
        Tokens: v2models.TokenSet{
            AccessToken:       v1Resp.AccessToken,
            RefreshToken:      v1Resp.RefreshToken,
            TokenType:         v1Resp.TokenType,
            ExpiresIn:         v1Resp.ExpiresIn,
            RefreshExpiresIn:  604800, // Default 7 days
        },
        User: v2models.User{
            ID:            fmt.Sprintf("usr_%d", v1Resp.UserID),
            Email:         v1Resp.Email,
            Name:          v1Resp.Name,
            EmailVerified: true, // Assume verified in v1
            TwoFactorEnabled: false,
        },
        Session: v2models.Session{
            SessionID: generateSessionID(),
            CreatedAt: time.Now(),
        },
    }
}

// V2 controller using adapter
func (c *V2AuthController) Login(ctx *gin.Context) {
    var req v2models.LoginRequest
    if err := ctx.ShouldBindJSON(&req); err != nil {
        ctx.JSON(400, gin.H{"error": "Invalid request"})
        return
    }

    // Adapt v2 request to v1
    v1Req := c.adapter.AdaptLoginRequest(&req)

    // Call v1 business logic
    v1Resp, err := c.v1Service.Login(v1Req)
    if err != nil {
        ctx.JSON(401, gin.H{"error": err.Error()})
        return
    }

    // Adapt v1 response to v2
    v2Resp := c.adapter.AdaptLoginResponse(v1Resp)

    ctx.JSON(200, v2Resp)
}
```

**Pros**:
- Reuse existing v1 business logic (battle-tested)
- Consistent behavior across versions
- Easy to maintain during transition period

**Cons**:
- Performance overhead from double conversion
- Cannot leverage v2-specific optimizations
- Temporary solution only

**Use Case**: Initial v2 release while migrating business logic.

### Strategy 2: Shared Business Logic (Recommended for Long-Term)

**Different controllers, same service layer**:

```go
// services/auth_service.go (shared)
package services

type AuthService struct {
    repo       *repositories.UserRepository
    jwtService *JWTService
    cache      *redis.Client
}

func (s *AuthService) AuthenticateUser(email, password string) (*models.User, error) {
    user, err := s.repo.FindByEmail(email)
    if err != nil {
        return nil, ErrUserNotFound
    }

    if !s.verifyPassword(user.PasswordHash, password) {
        return nil, ErrInvalidCredentials
    }

    return user, nil
}

func (s *AuthService) GenerateTokens(user *models.User, deviceID string) (*TokenPair, error) {
    accessToken, err := s.jwtService.GenerateAccessToken(user)
    if err != nil {
        return nil, err
    }

    refreshToken, err := s.jwtService.GenerateRefreshToken(user, deviceID)
    if err != nil {
        return nil, err
    }

    return &TokenPair{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
    }, nil
}

// V1 controller (simple response format)
func (c *V1AuthController) Login(ctx *gin.Context) {
    var req v1models.LoginRequest
    if err := ctx.ShouldBindJSON(&req); err != nil {
        ctx.JSON(400, gin.H{"error": "Invalid request"})
        return
    }

    user, err := c.authService.AuthenticateUser(req.Email, req.Password)
    if err != nil {
        ctx.JSON(401, gin.H{"error": err.Error()})
        return
    }

    tokens, err := c.authService.GenerateTokens(user, "")
    if err != nil {
        ctx.JSON(500, gin.H{"error": "Token generation failed"})
        return
    }

    // V1 response format (flat)
    ctx.JSON(200, gin.H{
        "access_token":  tokens.AccessToken,
        "refresh_token": tokens.RefreshToken,
        "token_type":    "Bearer",
        "expires_in":    900,
        "user_id":       user.ID,
        "email":         user.Email,
        "name":          user.Name,
    })
}

// V2 controller (nested response format)
func (c *V2AuthController) Login(ctx *gin.Context) {
    var req v2models.LoginRequest
    if err := ctx.ShouldBindJSON(&req); err != nil {
        ctx.JSON(400, v2ErrorResponse("INVALID_REQUEST", err.Error()))
        return
    }

    user, err := c.authService.AuthenticateUser(req.Email, req.Password)
    if err != nil {
        ctx.JSON(401, v2ErrorResponse("AUTH_FAILED", err.Error()))
        return
    }

    tokens, err := c.authService.GenerateTokens(user, req.DeviceID)
    if err != nil {
        ctx.JSON(500, v2ErrorResponse("TOKEN_ERROR", "Token generation failed"))
        return
    }

    // V2 response format (nested)
    ctx.JSON(200, gin.H{
        "tokens": gin.H{
            "access_token":        tokens.AccessToken,
            "refresh_token":       tokens.RefreshToken,
            "token_type":          "Bearer",
            "expires_in":          900,
            "refresh_expires_in":  604800,
        },
        "user": gin.H{
            "id":                 fmt.Sprintf("usr_%d", user.ID),
            "email":              user.Email,
            "name":               user.Name,
            "email_verified":     user.EmailVerified,
            "two_factor_enabled": user.TwoFactorEnabled,
        },
        "session": gin.H{
            "session_id": tokens.SessionID,
            "device_id":  req.DeviceID,
            "created_at": time.Now(),
        },
    })
}
```

**Pros**:
- No performance overhead
- Consistent business logic and security
- Easy to add version-specific features
- Clean separation of concerns

**Cons**:
- Requires careful service layer design
- More upfront architecture work

**Use Case**: Production-ready v2 with independent implementations.

### Strategy 3: Feature Flags (Beta Features in Stable Version)

**Gradual rollout of new features without version bump**:

```go
// middleware/feature_flags.go
package middleware

func FeatureFlagMiddleware() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        flags := ctx.GetHeader("X-Feature-Flags")
        ctx.Set("feature_flags", parseFlags(flags))
        ctx.Next()
    }
}

func parseFlags(header string) map[string]bool {
    flags := make(map[string]bool)
    for _, flag := range strings.Split(header, ",") {
        flags[strings.TrimSpace(flag)] = true
    }
    return flags
}

// controllers/auth_controller.go
func (c *V2AuthController) Login(ctx *gin.Context) {
    flags := ctx.MustGet("feature_flags").(map[string]bool)

    var req v2models.LoginRequest
    if err := ctx.ShouldBindJSON(&req); err != nil {
        ctx.JSON(400, gin.H{"error": "Invalid request"})
        return
    }

    user, err := c.authService.AuthenticateUser(req.Email, req.Password)
    if err != nil {
        ctx.JSON(401, gin.H{"error": err.Error()})
        return
    }

    tokens, err := c.authService.GenerateTokens(user, req.DeviceID)
    if err != nil {
        ctx.JSON(500, gin.H{"error": "Token generation failed"})
        return
    }

    response := gin.H{
        "tokens": gin.H{
            "access_token":  tokens.AccessToken,
            "refresh_token": tokens.RefreshToken,
        },
        "user": gin.H{
            "id":    user.ID,
            "email": user.Email,
        },
    }

    // Beta feature: Include device trust score
    if flags["device-trust-score"] {
        trustScore, _ := c.deviceService.CalculateTrustScore(req.DeviceID)
        response["device"] = gin.H{
            "trust_score": trustScore,
            "trusted":     trustScore > 0.8,
        }
    }

    // Beta feature: Include security recommendations
    if flags["security-recommendations"] {
        recommendations := c.securityService.GetRecommendations(user)
        response["security"] = gin.H{
            "recommendations": recommendations,
        }
    }

    ctx.JSON(200, response)
}
```

**Feature Flag Header**:
```http
POST /api/v2/auth/login
X-Feature-Flags: device-trust-score,security-recommendations
```

**Pros**:
- Test features in production without new version
- Gradual rollout to subset of users
- Easy rollback if issues detected
- A/B testing capability

**Cons**:
- Increases code complexity
- Must maintain feature flag infrastructure
- Risk of flag proliferation

**Use Case**: Beta testing of v2.1 features before promoting to stable.

## GraphQL Versioning

While SUMA Finance primarily uses REST for authentication APIs, GraphQL may be used for data queries. Here's the versioning strategy:

### Field Deprecation (Preferred)

```graphql
type User {
  id: ID!
  name: String!

  # Deprecated field (v1 compatibility)
  email: String! @deprecated(reason: "Use emailAddress instead. This field will be removed on 2025-06-01. See migration guide: https://docs.sumafinance.com/graphql/migration")

  # New field (v2)
  emailAddress: String!

  # Deprecated field
  userId: Int! @deprecated(reason: "Use id instead (now string-based). Removed on 2025-06-01.")

  # Enhanced security fields (v2)
  emailVerified: Boolean!
  twoFactorEnabled: Boolean!
  lastPasswordChange: DateTime

  # Deprecated authentication method
  legacyAuthToken: String @deprecated(reason: "Use JWT access tokens via REST API. Removed on 2025-06-01.")
}

type Query {
  # Current endpoint
  me: User!

  # Deprecated endpoint
  currentUser: User! @deprecated(reason: "Use 'me' query instead. Removed on 2025-06-01.")

  # Version-specific queries (if needed)
  userV2: User!
}
```

**Query with Deprecated Fields**:
```graphql
query GetUser {
  me {
    id
    name
    emailAddress
    emailVerified
    twoFactorEnabled
  }
}
```

**Deprecation Warning in Response**:
```json
{
  "data": {
    "me": {
      "id": "usr_12345",
      "name": "John Doe",
      "emailAddress": "john@example.com"
    }
  },
  "extensions": {
    "deprecations": [
      {
        "field": "User.email",
        "reason": "Use emailAddress instead",
        "sunsetDate": "2025-06-01"
      }
    ]
  }
}
```

### Schema Versioning (Alternative for Major Rewrites)

```graphql
# Schema v1
type User {
  id: Int!
  name: String!
  email: String!
}

# Schema v2 (separate types)
type UserV2 {
  id: String!
  name: String!
  emailAddress: String!
  emailVerified: Boolean!
  twoFactorEnabled: Boolean!
}

type Query {
  # V1 queries
  user(id: Int!): User
  currentUser: User

  # V2 queries
  userV2(id: String!): UserV2
  me: UserV2
}
```

**Access via different endpoints**:
```
POST /graphql/v1
POST /graphql/v2
```

**Use Case**: Complete schema overhaul (e.g., changing all IDs from Int to String).

## Deprecation Process

### Step 1: Announce (Month 0)

**Actions**:
1. Publish deprecation notice on developer portal
2. Update API documentation with deprecation warnings
3. Send email to all registered API clients
4. Add deprecation headers to v1 responses
5. Create comprehensive migration guide
6. Open dedicated Slack/Discord channel for migration support
7. Schedule migration webinar

**Deprecation Announcement Email Template**:
```
Subject: IMPORTANT: SUMA Finance API v1 Deprecation Notice

Dear SUMA Finance API Developer,

We are announcing the deprecation of API version 1 (v1), effective June 1, 2024.

TIMELINE:
- June 1, 2024: v1 marked as deprecated (still fully functional)
- June 1, 2025: v1 will be sunset and no longer available (12 months from today)

WHAT'S CHANGING:
API version 2 (v2) introduces enhanced security features and improved response formats:
- Nested response structure with tokens, user, and session objects
- String-based user IDs (usr_xxxxx format) for better scalability
- Enhanced JWT payload with device tracking
- Support for biometric authentication and OAuth 2.0
- Improved error handling with detailed error codes

BREAKING CHANGES:
- Response format changed from flat to nested structure
- User ID type changed from integer to string
- Token expiration fields added
- Email field renamed to emailAddress

MIGRATION GUIDE:
Comprehensive migration documentation available at:
https://docs.sumafinance.com/api/migration/v1-to-v2

MIGRATION SUPPORT:
- Documentation: https://docs.sumafinance.com/api/v2
- Migration webinar: June 15, 2024 at 10:00 AM UTC
- Support channel: #api-migration on Discord
- Email support: api-migration@sumafinance.com
- Priority support: Available for high-volume integrations

TESTING YOUR MIGRATION:
1. Review migration guide and breaking changes list
2. Update API base URL from /api/v1 to /api/v2
3. Update response parsing logic for nested structure
4. Test in sandbox environment: https://sandbox.api.sumafinance.com
5. Monitor error rates during rollout

NEED HELP?
Our team is here to assist with your migration:
- Email: api-migration@sumafinance.com
- Schedule 1:1 call: https://calendly.com/suma-api-support
- Join migration webinar: https://suma.com/webinar-v2-migration

We appreciate your partnership and apologize for any inconvenience.

Best regards,
SUMA Finance API Team

---
API Client ID: client_abc123
Current Usage: ~50,000 requests/month on v1
```

**Developer Portal Banner**:
```
⚠️ API v1 is deprecated and will be sunset on June 1, 2025.
   Migrate to v2 now: [Migration Guide] [Schedule Support Call]
```

### Step 2: Monitor (Months 1-11)

**Monitoring Metrics**:
- Track v1 vs v2 usage per client
- Identify clients with >10K monthly requests still on v1
- Monitor error rates during migration
- Track migration completion percentage

**Monthly Monitoring Query (PostgreSQL)**:
```sql
-- Track API version usage by client
SELECT
  api_key,
  api_version,
  client_name,
  COUNT(*) as request_count,
  COUNT(*) FILTER (WHERE status_code >= 400) as error_count,
  MAX(request_timestamp) as last_request,
  MIN(request_timestamp) as first_request
FROM api_request_logs
WHERE request_timestamp > NOW() - INTERVAL '30 days'
GROUP BY api_key, api_version, client_name
ORDER BY api_version ASC, request_count DESC;

-- Identify clients still heavily using v1
SELECT
  api_key,
  client_name,
  client_email,
  COUNT(*) as v1_requests,
  MAX(request_timestamp) as last_v1_request,
  CASE
    WHEN MAX(request_timestamp) > NOW() - INTERVAL '7 days' THEN 'Active'
    WHEN MAX(request_timestamp) > NOW() - INTERVAL '30 days' THEN 'Declining'
    ELSE 'Inactive'
  END as status
FROM api_request_logs
WHERE api_version = 'v1'
  AND request_timestamp > NOW() - INTERVAL '90 days'
GROUP BY api_key, client_name, client_email
HAVING COUNT(*) > 10000
ORDER BY v1_requests DESC;
```

**Automated Reminders**:
```go
// jobs/deprecation_reminder.go
package jobs

func SendDeprecationReminders() {
    clients := getClientsStillOnV1()

    for _, client := range clients {
        monthsUntilSunset := calculateMonthsUntilSunset()

        template := selectEmailTemplate(monthsUntilSunset, client.RequestCount)

        sendEmail(client.Email, template, map[string]interface{}{
            "ClientName":         client.Name,
            "MonthsUntilSunset":  monthsUntilSunset,
            "CurrentUsage":       client.RequestCount,
            "MigrationGuideURL":  "https://docs.sumafinance.com/api/migration/v1-to-v2",
            "SupportEmail":       "api-migration@sumafinance.com",
        })

        logReminderSent(client.APIKey, monthsUntilSunset)
    }
}

func selectEmailTemplate(monthsRemaining int, usage int) string {
    if monthsRemaining <= 1 {
        return "final_warning_template"
    } else if monthsRemaining <= 3 {
        return "urgent_reminder_template"
    } else if usage > 100000 {
        return "high_volume_reminder_template"
    }
    return "standard_reminder_template"
}
```

**Monthly Email Reminder Schedule**:
- Month 1-6: Informational reminders (every 2 months)
- Month 7-9: Standard reminders (monthly)
- Month 10-11: Urgent reminders (bi-weekly)
- Month 11.5: Final warning (weekly)

### Step 3: Final Warning (Month 11+)

**Final Warning Email (30 days before sunset)**:
```
Subject: URGENT: SUMA Finance API v1 Sunset in 30 Days

Dear SUMA Finance API Developer,

This is a FINAL WARNING that API version 1 will be sunset in 30 days on June 1, 2025.

CURRENT STATUS:
- Your application is making ~50,000 requests/month to v1 endpoints
- Last v1 request: May 28, 2025
- Migration status: NOT STARTED

IMMEDIATE ACTION REQUIRED:
After June 1, 2025, all v1 endpoints will return "410 Gone" and your application will stop working.

EMERGENCY MIGRATION SUPPORT:
We are offering expedited support for critical migrations:
1. Schedule emergency call: https://calendly.com/suma-api-emergency
2. Email: api-emergency@sumafinance.com (response within 2 hours)
3. Phone: +1-555-API-HELP (24/7 emergency line)

MIGRATION STEPS:
1. Update base URL: /api/v1 → /api/v2
2. Update response parsing (see guide)
3. Test in sandbox
4. Deploy to production
5. Verify with monitoring

TESTING SUNSET BEHAVIOR:
Test how your app handles 410 responses:
curl https://sandbox.api.sumafinance.com/api/v1/auth/login \
  -H "X-Simulate-Sunset: true"

EXTENSION REQUEST:
If you require additional time due to exceptional circumstances:
- Contact: api-extensions@sumafinance.com
- Include: Business justification, estimated migration timeline
- Extensions granted on case-by-case basis (max 30 days)

This is your last reminder. Please act now to avoid service disruption.

Best regards,
SUMA Finance API Team
```

**Developer Portal Alert**:
```
🚨 CRITICAL: API v1 sunsets in 30 days!
   Your app will stop working on June 1, 2025.
   [Migrate Now] [Emergency Support] [Request Extension]
```

### Step 4: Sunset (Month 12)

**Sunset Implementation**:
```go
// middleware/version_sunset.go
package middleware

func VersionSunsetMiddleware() gin.HandlerFunc {
    sunsetVersions := map[string]time.Time{
        "v1": time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
    }

    return func(ctx *gin.Context) {
        version := extractVersionFromPath(ctx.Request.URL.Path)

        if sunsetDate, isSunset := sunsetVersions[version]; isSunset {
            if time.Now().After(sunsetDate) {
                ctx.Header("X-API-Version", version)
                ctx.Header("X-API-Deprecated", "true")
                ctx.Header("X-API-Sunset-Date", sunsetDate.Format(time.RFC3339))
                ctx.Header("X-API-Latest-Version", "2")
                ctx.Header("Link", "<https://docs.sumafinance.com/api/migration/v1-to-v2>; rel=\"deprecation\"")
                ctx.Header("Link", "<https://api.sumafinance.com/v2>; rel=\"alternate\"")

                ctx.JSON(410, gin.H{
                    "error": gin.H{
                        "code":    "VERSION_SUNSET",
                        "message": fmt.Sprintf("API version %s was sunset on %s and is no longer available", version, sunsetDate.Format("2006-01-02")),
                        "sunset_date": sunsetDate.Format(time.RFC3339),
                        "deprecation_announcement_date": sunsetDate.AddDate(0, -12, 0).Format(time.RFC3339),
                        "migration_guide_url": "https://docs.sumafinance.com/api/migration/v1-to-v2",
                        "current_version": gin.H{
                            "version":           2,
                            "base_url":          "https://api.sumafinance.com/v2",
                            "documentation_url": "https://docs.sumafinance.com/api/v2",
                        },
                        "support": gin.H{
                            "email": "api-support@sumafinance.com",
                            "emergency_migration_window": "72 hours",
                            "emergency_phone": "+1-555-API-HELP",
                        },
                    },
                })

                // Log sunset access for monitoring
                logSunsetAccess(ctx, version)

                ctx.Abort()
                return
            }
        }

        ctx.Next()
    }
}

func extractVersionFromPath(path string) string {
    re := regexp.MustCompile(`/api/(v\d+)/`)
    matches := re.FindStringSubmatch(path)
    if len(matches) > 1 {
        return matches[1]
    }
    return ""
}
```

**Emergency Grace Period (72 hours)**:
```go
// Allow emergency access for critical clients during first 72 hours
func (m *VersionSunsetMiddleware) checkEmergencyAccess(apiKey string, version string) bool {
    sunsetDate := getSunsetDate(version)
    hoursSinceSunset := time.Since(sunsetDate).Hours()

    if hoursSinceSunset <= 72 {
        if isApprovedForEmergencyAccess(apiKey) {
            logEmergencyAccess(apiKey, version)
            return true
        }
    }

    return false
}
```

**Monitoring Post-Sunset**:
- Track 410 responses per client
- Identify clients still attempting v1 requests
- Proactive outreach to clients with errors
- Monitor social media for migration issues

## Documentation Strategy

### Version-Specific Documentation

**URL Structure**:
```
https://docs.sumafinance.com/
├── api/
│   ├── v1/
│   │   ├── getting-started
│   │   ├── authentication
│   │   ├── endpoints/
│   │   │   ├── register
│   │   │   ├── login
│   │   │   ├── refresh-token
│   │   │   └── ...
│   │   └── [DEPRECATED BANNER]
│   ├── v2/
│   │   ├── getting-started
│   │   ├── authentication
│   │   ├── endpoints/
│   │   │   ├── register
│   │   │   ├── login
│   │   │   ├── refresh-token
│   │   │   ├── oauth
│   │   │   └── ...
│   │   └── [CURRENT VERSION]
│   ├── migration/
│   │   ├── v1-to-v2/
│   │   │   ├── overview
│   │   │   ├── breaking-changes
│   │   │   ├── step-by-step-guide
│   │   │   ├── code-examples
│   │   │   └── faq
│   │   └── ...
│   ├── changelog
│   └── versioning-policy
```

### Migration Guide Template

```markdown
# Migrating from API v1 to v2

## Overview
This guide helps you migrate from SUMA Finance API v1 to v2. The migration typically takes 2-4 hours for a standard integration.

**Estimated Timeline**:
- Planning & Review: 30 minutes
- Code Updates: 1-2 hours
- Testing: 1 hour
- Deployment: 30 minutes

**Support**: Contact api-migration@sumafinance.com for assistance.

---

## Breaking Changes

### 1. Response Format Changed

API v2 introduces nested response structure for better organization and future extensibility.

**v1 Response (Flat)**:
\`\`\`json
POST /api/v1/auth/login

{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user_id": 12345,
  "email": "user@example.com",
  "name": "John Doe"
}
\`\`\`

**v2 Response (Nested)**:
\`\`\`json
POST /api/v2/auth/login

{
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_expires_in": 604800
  },
  "user": {
    "id": "usr_12345",
    "email": "user@example.com",
    "name": "John Doe",
    "email_verified": true,
    "two_factor_enabled": false
  },
  "session": {
    "session_id": "sess_abc123xyz",
    "device_id": "dev_xyz789",
    "created_at": "2025-10-29T10:30:00Z"
  }
}
\`\`\`

**Migration Steps**:

**JavaScript/TypeScript**:
\`\`\`typescript
// Before (v1)
const response = await fetch('https://api.sumafinance.com/api/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});

const data = await response.json();
const accessToken = data.access_token;
const userId = data.user_id;

// After (v2)
const response = await fetch('https://api.sumafinance.com/api/v2/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});

const data = await response.json();
const accessToken = data.tokens.access_token;
const userId = data.user.id;
\`\`\`

**Go**:
\`\`\`go
// Before (v1)
type V1LoginResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    UserID       int    `json:"user_id"`
    Email        string `json:"email"`
}

// After (v2)
type V2LoginResponse struct {
    Tokens struct {
        AccessToken       string `json:"access_token"`
        RefreshToken      string `json:"refresh_token"`
        ExpiresIn         int    `json:"expires_in"`
        RefreshExpiresIn  int    `json:"refresh_expires_in"`
    } `json:"tokens"`
    User struct {
        ID               string `json:"id"`
        Email            string `json:"email"`
        Name             string `json:"name"`
        EmailVerified    bool   `json:"email_verified"`
        TwoFactorEnabled bool   `json:"two_factor_enabled"`
    } `json:"user"`
    Session struct {
        SessionID string    `json:"session_id"`
        DeviceID  string    `json:"device_id"`
        CreatedAt time.Time `json:"created_at"`
    } `json:"session"`
}
\`\`\`

---

### 2. User ID Type Changed

**v1**: User IDs were integers (`12345`)
**v2**: User IDs are strings with prefix (`"usr_12345"`)

**Rationale**: String-based IDs provide better scalability, security (no sequential enumeration), and support for distributed systems.

**Migration**:
\`\`\`typescript
// Before
const userId: number = 12345;
const apiUrl = \`/api/v1/users/\${userId}\`;

// After
const userId: string = "usr_12345";
const apiUrl = \`/api/v2/users/\${userId}\`;
\`\`\`

**Database Migration** (if you store user IDs):
\`\`\`sql
-- Option 1: Add new column, migrate data, drop old column
ALTER TABLE app_users ADD COLUMN suma_user_id_v2 VARCHAR(50);
UPDATE app_users SET suma_user_id_v2 = CONCAT('usr_', suma_user_id_v1::TEXT);
-- After migration complete:
-- ALTER TABLE app_users DROP COLUMN suma_user_id_v1;
-- ALTER TABLE app_users RENAME COLUMN suma_user_id_v2 TO suma_user_id;

-- Option 2: Keep both during transition
ALTER TABLE app_users ADD COLUMN suma_user_id_v2 VARCHAR(50);
CREATE INDEX idx_suma_user_id_v2 ON app_users(suma_user_id_v2);
\`\`\`

---

### 3. New Token Expiration Fields

**v2 Addition**: `refresh_expires_in` field added to indicate refresh token expiration.

**v1**:
\`\`\`json
{
  "expires_in": 900  // Only access token expiration
}
\`\`\`

**v2**:
\`\`\`json
{
  "tokens": {
    "expires_in": 900,           // Access token: 15 minutes
    "refresh_expires_in": 604800 // Refresh token: 7 days
  }
}
\`\`\`

**Migration**:
\`\`\`typescript
// Track both expiration times
const accessTokenExpiresAt = Date.now() + (data.tokens.expires_in * 1000);
const refreshTokenExpiresAt = Date.now() + (data.tokens.refresh_expires_in * 1000);

// Implement proactive refresh before expiration
if (Date.now() > accessTokenExpiresAt - 60000) { // Refresh 1 min before expiry
  await refreshAccessToken();
}
\`\`\`

---

### 4. Error Response Format Standardized

**v1** (inconsistent error format):
\`\`\`json
{
  "error": "Invalid credentials"
}
\`\`\`

**v2** (consistent error format):
\`\`\`json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "The email or password you entered is incorrect",
    "details": {
      "field": "password",
      "attempts_remaining": 4
    },
    "documentation_url": "https://docs.sumafinance.com/errors/INVALID_CREDENTIALS"
  }
}
\`\`\`

**Migration**:
\`\`\`typescript
// Before
if (response.error) {
  console.error(response.error);
}

// After
if (response.error) {
  console.error(\`\${response.error.code}: \${response.error.message}\`);

  // Handle specific error codes
  switch (response.error.code) {
    case 'INVALID_CREDENTIALS':
      showError('Invalid email or password');
      break;
    case 'ACCOUNT_LOCKED':
      showError('Account locked. Try again in 15 minutes.');
      break;
    case 'EMAIL_NOT_VERIFIED':
      showError('Please verify your email first');
      break;
    default:
      showError(response.error.message);
  }
}
\`\`\`

---

### 5. New Required Header: X-Client-Id

**v2 Requirement**: All requests must include `X-Client-Id` header for analytics and rate limiting.

**Format**: `{platform}-{app}-{version}`

**Examples**:
- `web-dashboard-v1.2.3`
- `mobile-ios-v2.0.1`
- `mobile-android-v2.0.1`
- `backend-service-v1.0.0`

**Migration**:
\`\`\`typescript
const headers = {
  'Content-Type': 'application/json',
  'X-Client-Id': 'web-dashboard-v1.2.3'  // NEW REQUIRED
};

fetch('https://api.sumafinance.com/api/v2/auth/login', {
  method: 'POST',
  headers,
  body: JSON.stringify({ email, password })
});
\`\`\`

---

## Step-by-Step Migration Guide

### Step 1: Review Changes (15 min)
1. Read this entire migration guide
2. Review breaking changes list
3. Identify affected code in your application
4. Check your current API usage dashboard

### Step 2: Update Base URL (5 min)
\`\`\`typescript
// Before
const API_BASE_URL = 'https://api.sumafinance.com/api/v1';

// After
const API_BASE_URL = 'https://api.sumafinance.com/api/v2';
\`\`\`

### Step 3: Update Response Parsing (30-60 min)

**Create v2 type definitions**:
\`\`\`typescript
// types/auth.ts
export interface TokenSet {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  refresh_expires_in: number;
}

export interface User {
  id: string;
  email: string;
  name: string;
  email_verified: boolean;
  two_factor_enabled: boolean;
}

export interface Session {
  session_id: string;
  device_id?: string;
  created_at: string;
}

export interface LoginResponse {
  tokens: TokenSet;
  user: User;
  session: Session;
}
\`\`\`

**Update API client**:
\`\`\`typescript
// api/auth.ts
export async function login(email: string, password: string): Promise<LoginResponse> {
  const response = await fetch(\`\${API_BASE_URL}/auth/login\`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Client-Id': getClientId()
    },
    body: JSON.stringify({ email, password })
  });

  if (!response.ok) {
    const error = await response.json();
    throw new AuthError(error.error.code, error.error.message);
  }

  return await response.json();
}
\`\`\`

### Step 4: Update Token Storage (15 min)
\`\`\`typescript
// Before
localStorage.setItem('access_token', data.access_token);
localStorage.setItem('user_id', data.user_id.toString());

// After
localStorage.setItem('access_token', data.tokens.access_token);
localStorage.setItem('refresh_token', data.tokens.refresh_token);
localStorage.setItem('user_id', data.user.id);
localStorage.setItem('token_expires_at', (Date.now() + data.tokens.expires_in * 1000).toString());
\`\`\`

### Step 5: Test in Sandbox (30-60 min)

**Sandbox Environment**:
- Base URL: `https://sandbox.api.sumafinance.com/api/v2`
- Use test credentials from developer portal
- Sandbox resets daily

**Test Checklist**:
- [ ] User registration
- [ ] Email verification
- [ ] Login with email/password
- [ ] Token refresh
- [ ] Logout
- [ ] Password reset flow
- [ ] 2FA enable/verify (if applicable)
- [ ] Error handling
- [ ] Token expiration handling

**Automated Test Example**:
\`\`\`typescript
describe('Auth v2 Migration', () => {
  it('should login and parse v2 response correctly', async () => {
    const response = await login('test@example.com', 'TestPass123!');

    expect(response).toHaveProperty('tokens');
    expect(response).toHaveProperty('user');
    expect(response).toHaveProperty('session');

    expect(response.tokens.access_token).toBeTruthy();
    expect(response.user.id).toMatch(/^usr_/);
    expect(typeof response.tokens.expires_in).toBe('number');
  });

  it('should handle errors correctly', async () => {
    await expect(login('test@example.com', 'wrong')).rejects.toThrow('INVALID_CREDENTIALS');
  });
});
\`\`\`

### Step 6: Deploy to Production (30 min)

**Deployment Strategy**:
1. **Blue-Green Deployment** (Recommended):
   - Deploy v2-compatible code to "green" environment
   - Test green environment
   - Switch traffic from blue to green
   - Keep blue as rollback option

2. **Canary Deployment**:
   - Deploy to 10% of servers
   - Monitor error rates for 1 hour
   - Gradually increase to 100%

3. **Feature Flag**:
   - Deploy with v2 code behind feature flag
   - Enable for internal users first
   - Enable for all users after validation

**Monitoring During Deployment**:
\`\`\`bash
# Monitor error rates
curl https://api.sumafinance.com/v2/auth/login | jq '.error.code'

# Check response times
curl -w "@curl-format.txt" -o /dev/null -s https://api.sumafinance.com/v2/auth/login
\`\`\`

### Step 7: Monitor & Verify (Ongoing)

**Key Metrics to Monitor**:
- API error rate (should be <1%)
- Response time (should be <200ms)
- Token refresh success rate (should be >99%)
- Login success rate (should match v1 baseline)

**Monitoring Dashboard**:
```
API v2 Migration Health
├── Total Requests: 150,000/day
├── Error Rate: 0.3% ✓
├── Avg Response Time: 145ms ✓
├── P95 Response Time: 280ms ✓
└── Active Sessions: 5,000 ✓
```

---

## Code Examples

### Complete JavaScript/TypeScript Migration

**Before (v1)**:
\`\`\`typescript
// auth-service-v1.ts
class AuthService {
  async login(email: string, password: string) {
    const response = await fetch('https://api.sumafinance.com/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (data.error) {
      throw new Error(data.error);
    }

    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('user_id', data.user_id.toString());

    return data;
  }

  async refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');

    const response = await fetch('https://api.sumafinance.com/api/v1/auth/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': \`Bearer \${refreshToken}\`
      }
    });

    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);

    return data;
  }
}
\`\`\`

**After (v2)**:
\`\`\`typescript
// auth-service-v2.ts
interface LoginResponse {
  tokens: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    refresh_expires_in: number;
  };
  user: {
    id: string;
    email: string;
    name: string;
    email_verified: boolean;
    two_factor_enabled: boolean;
  };
  session: {
    session_id: string;
    created_at: string;
  };
}

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, any>;
  };
}

class AuthService {
  private baseURL = 'https://api.sumafinance.com/api/v2';
  private clientId = 'web-dashboard-v1.2.3';

  async login(email: string, password: string): Promise<LoginResponse> {
    const response = await fetch(\`\${this.baseURL}/auth/login\`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': this.clientId
      },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new AuthError(data.error.code, data.error.message);
    }

    // Store tokens with expiration
    localStorage.setItem('access_token', data.tokens.access_token);
    localStorage.setItem('refresh_token', data.tokens.refresh_token);
    localStorage.setItem('user_id', data.user.id);
    localStorage.setItem('token_expires_at',
      (Date.now() + data.tokens.expires_in * 1000).toString()
    );

    return data;
  }

  async refreshToken(): Promise<void> {
    const refreshToken = localStorage.getItem('refresh_token');

    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch(\`\${this.baseURL}/auth/refresh\`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': this.clientId
      },
      body: JSON.stringify({ refresh_token: refreshToken })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new AuthError(data.error.code, data.error.message);
    }

    localStorage.setItem('access_token', data.tokens.access_token);
    localStorage.setItem('refresh_token', data.tokens.refresh_token);
    localStorage.setItem('token_expires_at',
      (Date.now() + data.tokens.expires_in * 1000).toString()
    );
  }

  isTokenExpired(): boolean {
    const expiresAt = localStorage.getItem('token_expires_at');
    if (!expiresAt) return true;
    return Date.now() > parseInt(expiresAt) - 60000; // Refresh 1 min before expiry
  }
}

class AuthError extends Error {
  constructor(public code: string, message: string) {
    super(message);
    this.name = 'AuthError';
  }
}
\`\`\`

### Complete Go Migration

**Before (v1)**:
\`\`\`go
// auth_client_v1.go
package auth

type LoginRequest struct {
    Email    string \`json:"email"\`
    Password string \`json:"password"\`
}

type LoginResponse struct {
    AccessToken  string \`json:"access_token"\`
    RefreshToken string \`json:"refresh_token"\`
    TokenType    string \`json:"token_type"\`
    ExpiresIn    int    \`json:"expires_in"\`
    UserID       int    \`json:"user_id"\`
    Email        string \`json:"email"\`
    Name         string \`json:"name"\`
}

func (c *Client) Login(email, password string) (*LoginResponse, error) {
    req := LoginRequest{Email: email, Password: password}
    body, _ := json.Marshal(req)

    resp, err := http.Post(
        "https://api.sumafinance.com/api/v1/auth/login",
        "application/json",
        bytes.NewBuffer(body),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var loginResp LoginResponse
    json.NewDecoder(resp.Body).Decode(&loginResp)

    return &loginResp, nil
}
\`\`\`

**After (v2)**:
\`\`\`go
// auth_client_v2.go
package auth

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type LoginRequest struct {
    Email    string \`json:"email"\`
    Password string \`json:"password"\`
    DeviceID string \`json:"device_id,omitempty"\`
}

type TokenSet struct {
    AccessToken       string \`json:"access_token"\`
    RefreshToken      string \`json:"refresh_token"\`
    TokenType         string \`json:"token_type"\`
    ExpiresIn         int    \`json:"expires_in"\`
    RefreshExpiresIn  int    \`json:"refresh_expires_in"\`
}

type User struct {
    ID               string \`json:"id"\`
    Email            string \`json:"email"\`
    Name             string \`json:"name"\`
    EmailVerified    bool   \`json:"email_verified"\`
    TwoFactorEnabled bool   \`json:"two_factor_enabled"\`
}

type Session struct {
    SessionID string    \`json:"session_id"\`
    DeviceID  string    \`json:"device_id"\`
    CreatedAt time.Time \`json:"created_at"\`
}

type LoginResponse struct {
    Tokens  TokenSet \`json:"tokens"\`
    User    User     \`json:"user"\`
    Session Session  \`json:"session"\`
}

type ErrorResponse struct {
    Error struct {
        Code    string                 \`json:"code"\`
        Message string                 \`json:"message"\`
        Details map[string]interface{} \`json:"details,omitempty"\`
    } \`json:"error"\`
}

type Client struct {
    BaseURL  string
    ClientID string
    HTTPClient *http.Client
}

func NewClient(clientID string) *Client {
    return &Client{
        BaseURL:  "https://api.sumafinance.com/api/v2",
        ClientID: clientID,
        HTTPClient: &http.Client{Timeout: 10 * time.Second},
    }
}

func (c *Client) Login(email, password string) (*LoginResponse, error) {
    req := LoginRequest{Email: email, Password: password}
    body, _ := json.Marshal(req)

    httpReq, err := http.NewRequest(
        "POST",
        fmt.Sprintf("%s/auth/login", c.BaseURL),
        bytes.NewBuffer(body),
    )
    if err != nil {
        return nil, err
    }

    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("X-Client-Id", c.ClientID)

    resp, err := c.HTTPClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        var errResp ErrorResponse
        json.NewDecoder(resp.Body).Decode(&errResp)
        return nil, fmt.Errorf("%s: %s", errResp.Error.Code, errResp.Error.Message)
    }

    var loginResp LoginResponse
    if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
        return nil, err
    }

    return &loginResp, nil
}

func (c *Client) RefreshToken(refreshToken string) (*TokenSet, error) {
    body, _ := json.Marshal(map[string]string{
        "refresh_token": refreshToken,
    })

    httpReq, err := http.NewRequest(
        "POST",
        fmt.Sprintf("%s/auth/refresh", c.BaseURL),
        bytes.NewBuffer(body),
    )
    if err != nil {
        return nil, err
    }

    httpReq.Header.Set("Content-Type", "application/json")
    httpReq.Header.Set("X-Client-Id", c.ClientID)

    resp, err := c.HTTPClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        var errResp ErrorResponse
        json.NewDecoder(resp.Body).Decode(&errResp)
        return nil, fmt.Errorf("%s: %s", errResp.Error.Code, errResp.Error.Message)
    }

    var tokenResp struct {
        Tokens TokenSet \`json:"tokens"\`
    }
    if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
        return nil, err
    }

    return &tokenResp.Tokens, nil
}
\`\`\`

---

## FAQ

### Q: Can I use both v1 and v2 simultaneously during migration?
**A**: Yes, absolutely! You can gradually migrate endpoints. For example, migrate login first, then registration, etc. Both versions will work concurrently until v1 sunset.

### Q: Will my v1 API keys work with v2?
**A**: Yes, API keys are version-agnostic. The same API key works with both v1 and v2.

### Q: What happens to my existing JWT tokens after migrating to v2?
**A**: Existing v1 JWT tokens remain valid until expiration. New logins via v2 will issue v2 tokens with the enhanced payload structure.

### Q: Do I need to re-register all users?
**A**: No, user accounts are shared between versions. Only your API integration code needs updating.

### Q: How do I test the migration without affecting production users?
**A**: Use our sandbox environment at `https://sandbox.api.sumafinance.com/api/v2` with test credentials from your developer portal.

### Q: What if I can't complete migration before the sunset date?
**A**: Contact api-extensions@sumafinance.com with your business justification and estimated timeline. Extensions are granted on a case-by-case basis (maximum 30 days).

### Q: Will there be downtime during my migration?
**A**: No, both versions run concurrently. You can migrate at your own pace without downtime.

### Q: How do I handle users with active sessions during migration?
**A**: Active v1 sessions remain valid. New logins will use v2. Consider implementing a "force refresh" mechanism to gradually transition active users.

### Q: Are there any rate limit differences between v1 and v2?
**A**: No, rate limits remain the same: 1000 requests/hour for standard tier.

### Q: How do I migrate mobile apps that users haven't updated?
**A**: Plan your mobile app releases to include v2 support before v1 sunset. For critical cases, consider a forced update mechanism.

---

## Support Resources

- **Documentation**: https://docs.sumafinance.com/api/v2
- **Migration Guide**: https://docs.sumafinance.com/api/migration/v1-to-v2
- **Migration Support Email**: api-migration@sumafinance.com
- **Emergency Support**: api-emergency@sumafinance.com (for urgent issues)
- **Developer Portal**: https://developer.sumafinance.com
- **Status Page**: https://status.sumafinance.com
- **Changelog**: https://docs.sumafinance.com/api/changelog

**Community**:
- Discord: #api-migration channel
- Stack Overflow: Tag [suma-finance-api]
- GitHub Discussions: https://github.com/sumafinance/api-feedback

**Office Hours**:
- Weekly migration Q&A: Tuesdays at 10:00 AM UTC
- Join: https://meet.google.com/suma-api-migration
```

### Changelog

```markdown
# SUMA Finance API Changelog

## [2.1.0] - 2024-09-15

### Added
- **Biometric Authentication**: New endpoints for registering and verifying biometric credentials (TouchID, FaceID)
  - `POST /api/v2/auth/biometric/register`
  - `POST /api/v2/auth/biometric/verify`
- **OAuth 2.0 Social Login**: Google and Apple Sign-In integration
  - `POST /api/v2/auth/oauth/google`
  - `POST /api/v2/auth/oauth/apple`
- **Device Trust Scoring**: Optional device fingerprinting and trust score calculation (beta feature flag: `device-trust-score`)
- **Security Recommendations**: Personalized security recommendations based on user behavior (beta feature flag: `security-recommendations`)

### Changed
- Increased rate limit for premium tier: 1000 req/hr → 10000 req/hr
- Improved JWT payload with additional security claims
- Enhanced error messages with field-level validation details

### Deprecated
- None

### Fixed
- Fixed race condition in refresh token rotation
- Resolved issue with concurrent session creation
- Fixed email verification token expiration edge case

### Security
- Upgraded JWT signing algorithm to RS256 (previously HS256)
- Added device fingerprinting for fraud detection
- Implemented refresh token reuse detection

---

## [2.0.0] - 2024-06-01

### Breaking Changes
- **Response Format Changed**: Nested structure with `tokens`, `user`, and `session` objects (see migration guide)
- **User ID Type Changed**: From integer to string with `usr_` prefix
- **Error Format Standardized**: Consistent error object with `code`, `message`, and `details`
- **New Required Header**: `X-Client-Id` header mandatory for all requests

### Added
- Email verification token integrity checks with HMAC-SHA256
- Refresh token rotation with reuse detection
- Session fixation prevention (regenerate session ID after login)
- Enhanced 2FA with backup codes
- GDPR consent management endpoints
- Account lockout protection after 5 failed attempts
- Comprehensive security event logging
- Device management and trusted device tracking

### Changed
- Token expiration visibility: Added `refresh_expires_in` field
- Password complexity requirements: Minimum 12 characters (was 8)
- Session timeout: 15 minutes idle, 8 hours absolute

### Deprecated
- API v1 marked as deprecated (sunset date: 2025-06-01)

### Migration
- See comprehensive migration guide: https://docs.sumafinance.com/api/migration/v1-to-v2

---

## [1.2.0] - 2024-03-01

### Added
- Two-factor authentication (email OTP)
  - `POST /api/v1/auth/enable-2fa`
  - `POST /api/v1/auth/verify-2fa`
- Password reset functionality
  - `POST /api/v1/auth/forgot-password`
  - `POST /api/v1/auth/reset-password`

### Changed
- Improved password validation error messages
- Enhanced rate limiting for login attempts

### Fixed
- Fixed email verification link expiration handling
- Resolved session cookie SameSite attribute issue

---

## [1.1.0] - 2024-01-15

### Added
- User registration endpoint: `POST /api/v1/auth/register`
- Email verification endpoint: `GET /api/v1/auth/verify-email`
- Logout endpoint: `POST /api/v1/auth/logout`

### Changed
- Improved JWT payload structure
- Enhanced input validation for email format

### Fixed
- Fixed refresh token expiration bug
- Resolved CORS preflight issue for auth endpoints

---

## [1.0.0] - 2023-12-01

### Added
- Initial release
- Login endpoint: `POST /api/v1/auth/login`
- Token refresh endpoint: `POST /api/v1/auth/refresh`
- JWT-based authentication
- Session management with Redis
```

## Client SDK Versioning

### SDK Version Strategy

**SDK versions track API versions**:
```
@sumafinance/api-client@1.x.x → API v1
@sumafinance/api-client@2.x.x → API v2
```

**NPM Package Versions**:
```bash
# Install v2 SDK (latest)
npm install @sumafinance/api-client@2

# Install specific v2 version
npm install @sumafinance/api-client@2.1.0

# Install v1 SDK (deprecated)
npm install @sumafinance/api-client@1
```

**Go Module Versions**:
```bash
# Install v2 SDK
go get github.com/sumafinance/go-sdk/v2@latest

# Install specific v2 version
go get github.com/sumafinance/go-sdk/v2@v2.1.0

# Install v1 SDK
go get github.com/sumafinance/go-sdk@v1.2.0
```

### Version Check in SDK

**TypeScript SDK**:
```typescript
// @sumafinance/api-client v2.1.0
export class SumaFinanceClient {
  private apiVersion = 2;
  private sdkVersion = '2.1.0';
  private baseURL: string;

  constructor(config: ClientConfig) {
    this.baseURL = config.baseURL || 'https://api.sumafinance.com';
    this.apiVersion = config.apiVersion || 2;

    // Validate SDK version matches requested API version
    if (config.apiVersion && Math.floor(config.apiVersion) !== Math.floor(this.apiVersion)) {
      throw new Error(
        `SDK version ${this.sdkVersion} is for API v${this.apiVersion}. ` +
        `Please install @sumafinance/api-client@${config.apiVersion} for API v${config.apiVersion}.`
      );
    }
  }

  async login(email: string, password: string): Promise<LoginResponse> {
    const response = await fetch(`${this.baseURL}/api/v${this.apiVersion}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': `sdk-js-v${this.sdkVersion}`,
        'X-SDK-Version': this.sdkVersion
      },
      body: JSON.stringify({ email, password })
    });

    // Handle version-specific response format
    const data = await response.json();

    if (!response.ok) {
      throw new SumaFinanceError(data.error.code, data.error.message);
    }

    // v2 response format
    return {
      accessToken: data.tokens.access_token,
      refreshToken: data.tokens.refresh_token,
      expiresIn: data.tokens.expires_in,
      refreshExpiresIn: data.tokens.refresh_expires_in,
      user: data.user,
      session: data.session
    };
  }
}
```

**Go SDK**:
```go
// github.com/sumafinance/go-sdk/v2 v2.1.0
package suma

import (
    "fmt"
    "net/http"
)

const (
    APIVersion  = 2
    SDKVersion  = "2.1.0"
    DefaultBaseURL = "https://api.sumafinance.com"
)

type Client struct {
    BaseURL    string
    APIVersion int
    SDKVersion string
    HTTPClient *http.Client
    ClientID   string
}

func NewClient(config *Config) (*Client, error) {
    client := &Client{
        BaseURL:    config.BaseURL,
        APIVersion: APIVersion,
        SDKVersion: SDKVersion,
        HTTPClient: &http.Client{Timeout: 10 * time.Second},
        ClientID:   config.ClientID,
    }

    if client.BaseURL == "" {
        client.BaseURL = DefaultBaseURL
    }

    return client, nil
}

func (c *Client) Login(email, password string) (*LoginResponse, error) {
    url := fmt.Sprintf("%s/api/v%d/auth/login", c.BaseURL, c.APIVersion)

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Client-Id", fmt.Sprintf("sdk-go-v%s", c.SDKVersion))
    req.Header.Set("X-SDK-Version", c.SDKVersion)

    // ... request logic

    // Parse v2 response format
    return &LoginResponse{
        AccessToken:       data.Tokens.AccessToken,
        RefreshToken:      data.Tokens.RefreshToken,
        ExpiresIn:         data.Tokens.ExpiresIn,
        RefreshExpiresIn:  data.Tokens.RefreshExpiresIn,
        User:              data.User,
        Session:           data.Session,
    }, nil
}
```

### SDK Deprecation Warnings

**Display warnings for deprecated SDK versions**:
```typescript
// SDK v1.x.x (deprecated)
export class SumaFinanceClient {
  constructor(config: ClientConfig) {
    console.warn(
      'WARNING: @sumafinance/api-client v1.x is deprecated. ' +
      'API v1 will be sunset on 2025-06-01. ' +
      'Please migrate to v2: npm install @sumafinance/api-client@2\n' +
      'Migration guide: https://docs.sumafinance.com/sdk/migration/v1-to-v2'
    );

    this.apiVersion = 1;
    this.baseURL = 'https://api.sumafinance.com';
  }
}
```

## Testing Strategy

### Contract Testing

**Test Both Versions Simultaneously**:
```typescript
// tests/api-versioning.test.ts
describe('API Versioning Contract Tests', () => {
  describe('v1 (Deprecated)', () => {
    const v1Client = new SumaFinanceClient({ apiVersion: 1 });

    it('should return flat array response format', async () => {
      const response = await fetch('https://sandbox.api.sumafinance.com/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
      });

      const data = await response.json();

      // v1 contract: flat response
      expect(data).toHaveProperty('access_token');
      expect(data).toHaveProperty('refresh_token');
      expect(data).toHaveProperty('user_id');
      expect(data).toHaveProperty('email');
      expect(data).toHaveProperty('name');

      // v1 user ID is integer
      expect(typeof data.user_id).toBe('number');
    });

    it('should include deprecation headers', async () => {
      const response = await fetch('https://sandbox.api.sumafinance.com/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
      });

      expect(response.headers.get('X-API-Deprecated')).toBe('true');
      expect(response.headers.get('X-API-Sunset-Date')).toBeTruthy();
      expect(response.headers.get('Warning')).toContain('deprecated');
    });
  });

  describe('v2 (Current)', () => {
    const v2Client = new SumaFinanceClient({ apiVersion: 2 });

    it('should return nested response with tokens, user, session', async () => {
      const response = await fetch('https://sandbox.api.sumafinance.com/api/v2/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-Id': 'test-suite-v1.0.0'
        },
        body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
      });

      const data = await response.json();

      // v2 contract: nested response
      expect(data).toHaveProperty('tokens');
      expect(data).toHaveProperty('user');
      expect(data).toHaveProperty('session');

      // Tokens object
      expect(data.tokens).toHaveProperty('access_token');
      expect(data.tokens).toHaveProperty('refresh_token');
      expect(data.tokens).toHaveProperty('expires_in');
      expect(data.tokens).toHaveProperty('refresh_expires_in');

      // User object
      expect(data.user).toHaveProperty('id');
      expect(data.user).toHaveProperty('email');
      expect(data.user).toHaveProperty('email_verified');
      expect(data.user).toHaveProperty('two_factor_enabled');

      // v2 user ID is string with prefix
      expect(typeof data.user.id).toBe('string');
      expect(data.user.id).toMatch(/^usr_/);

      // Session object
      expect(data.session).toHaveProperty('session_id');
      expect(data.session).toHaveProperty('created_at');
    });

    it('should NOT include deprecation headers', async () => {
      const response = await fetch('https://sandbox.api.sumafinance.com/api/v2/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-Id': 'test-suite-v1.0.0'
        },
        body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
      });

      expect(response.headers.get('X-API-Deprecated')).toBe('false');
      expect(response.headers.get('X-API-Sunset-Date')).toBe('null');
    });

    it('should handle standardized error format', async () => {
      const response = await fetch('https://sandbox.api.sumafinance.com/api/v2/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-Id': 'test-suite-v1.0.0'
        },
        body: JSON.stringify({ email: 'test@example.com', password: 'WrongPassword' })
      });

      expect(response.status).toBe(401);

      const data = await response.json();

      expect(data).toHaveProperty('error');
      expect(data.error).toHaveProperty('code');
      expect(data.error).toHaveProperty('message');
      expect(data.error.code).toBe('INVALID_CREDENTIALS');
    });
  });
});
```

### Backward Compatibility Testing

```typescript
describe('Backward Compatibility', () => {
  it('v1 should continue working after v2 release', async () => {
    // v1 request
    const v1Response = await fetch('https://sandbox.api.sumafinance.com/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
    });

    expect(v1Response.status).toBe(200);

    // v2 request
    const v2Response = await fetch('https://sandbox.api.sumafinance.com/api/v2/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': 'test-suite-v1.0.0'
      },
      body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
    });

    expect(v2Response.status).toBe(200);

    // Both should succeed
    const v1Data = await v1Response.json();
    const v2Data = await v2Response.json();

    // Same user should be authenticated
    expect(v1Data.email).toBe(v2Data.user.email);
  });

  it('JWT tokens should work across versions during transition', async () => {
    // Login with v2
    const loginResponse = await fetch('https://sandbox.api.sumafinance.com/api/v2/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': 'test-suite-v1.0.0'
      },
      body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
    });

    const loginData = await loginResponse.json();
    const accessToken = loginData.tokens.access_token;

    // Use token with v1 endpoint (if applicable)
    // NOTE: This depends on whether your API supports cross-version token usage
    // Adjust test based on your specific implementation
  });

  it('should handle sunset version correctly', async () => {
    // Simulate sunset scenario
    const response = await fetch('https://sandbox.api.sumafinance.com/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Simulate-Sunset': 'true'  // Test header to simulate sunset
      },
      body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
    });

    expect(response.status).toBe(410);

    const data = await response.json();

    expect(data.error.code).toBe('VERSION_SUNSET');
    expect(data.error.migration_guide_url).toBeTruthy();
    expect(data.error.current_version.version).toBe(2);
  });
});
```

### Migration Testing

```typescript
describe('Migration Testing', () => {
  it('should handle gradual migration of endpoints', async () => {
    // Scenario: App partially migrated (login uses v2, registration still uses v1)

    // Login with v2
    const loginResp = await fetch('https://sandbox.api.sumafinance.com/api/v2/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': 'test-suite-v1.0.0'
      },
      body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
    });

    expect(loginResp.status).toBe(200);

    // Register with v1 (still supported during migration)
    const registerResp = await fetch('https://sandbox.api.sumafinance.com/api/v1/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'newuser@example.com',
        password: 'NewUserPass123!',
        name: 'New User'
      })
    });

    expect(registerResp.status).toBe(201);
  });

  it('should validate migration adapter correctness', async () => {
    // If using adapter pattern, test that v2 responses match expected format
    // even when backed by v1 business logic

    const v2Response = await fetch('https://sandbox.api.sumafinance.com/api/v2/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Client-Id': 'test-suite-v1.0.0'
      },
      body: JSON.stringify({ email: 'test@example.com', password: 'TestPass123!' })
    });

    const data = await response.json();

    // Verify adapter correctly transforms v1 data to v2 format
    expect(data.tokens.access_token).toBeTruthy();
    expect(data.user.id).toMatch(/^usr_/);
    expect(data.session.session_id).toBeTruthy();
  });
});
```

## Monitoring & Metrics

### Version Usage Metrics

**Track the following metrics**:
1. **Requests per version** (daily, weekly, monthly)
2. **Active API keys per version**
3. **Error rates per version**
4. **Response times per version**
5. **Endpoints most used per version**
6. **New vs returning clients per version**
7. **Migration progress** (% of clients on current version)

**DataDog Dashboard Configuration**:
```json
{
  "title": "API Version Usage",
  "widgets": [
    {
      "definition": {
        "title": "Requests by API Version (Last 30 Days)",
        "type": "timeseries",
        "requests": [
          {
            "q": "sum:api.request.count{*} by {api_version}",
            "display_type": "bars",
            "style": {
              "palette": "dog_classic"
            }
          }
        ]
      }
    },
    {
      "definition": {
        "title": "API Version Distribution",
        "type": "query_value",
        "requests": [
          {
            "q": "sum:api.request.count{api_version:v1}",
            "aggregator": "sum"
          },
          {
            "q": "sum:api.request.count{api_version:v2}",
            "aggregator": "sum"
          }
        ]
      }
    },
    {
      "definition": {
        "title": "Error Rate by Version",
        "type": "timeseries",
        "requests": [
          {
            "q": "sum:api.error.count{*} by {api_version} / sum:api.request.count{*} by {api_version}",
            "display_type": "line"
          }
        ]
      }
    },
    {
      "definition": {
        "title": "Active Clients Still on v1",
        "type": "query_table",
        "requests": [
          {
            "q": "top(sum:api.request.count{api_version:v1} by {api_key}, 10, 'sum', 'desc')"
          }
        ]
      }
    }
  ]
}
```

**SQL Query for Version Usage**:
```sql
-- Daily version usage summary
SELECT
  DATE(request_timestamp) as date,
  api_version,
  COUNT(*) as total_requests,
  COUNT(DISTINCT api_key) as unique_clients,
  AVG(response_time_ms) as avg_response_time,
  PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_response_time,
  SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count,
  ROUND(100.0 * SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) as error_rate
FROM api_request_logs
WHERE request_timestamp >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE(request_timestamp), api_version
ORDER BY date DESC, api_version;

-- Top clients still using deprecated v1
SELECT
  api_key,
  client_name,
  client_email,
  COUNT(*) as request_count,
  MAX(request_timestamp) as last_request,
  MIN(request_timestamp) as first_request,
  ROUND(COUNT(*)::numeric / 30.0, 0) as avg_daily_requests
FROM api_request_logs
WHERE api_version = 'v1'
  AND request_timestamp >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY api_key, client_name, client_email
HAVING COUNT(*) > 1000
ORDER BY request_count DESC
LIMIT 50;

-- Migration progress over time
WITH version_counts AS (
  SELECT
    DATE(request_timestamp) as date,
    api_version,
    COUNT(*) as request_count
  FROM api_request_logs
  WHERE request_timestamp >= CURRENT_DATE - INTERVAL '90 days'
  GROUP BY DATE(request_timestamp), api_version
)
SELECT
  date,
  SUM(CASE WHEN api_version = 'v1' THEN request_count ELSE 0 END) as v1_requests,
  SUM(CASE WHEN api_version = 'v2' THEN request_count ELSE 0 END) as v2_requests,
  ROUND(100.0 * SUM(CASE WHEN api_version = 'v2' THEN request_count ELSE 0 END) /
    SUM(request_count), 2) as v2_percentage
FROM version_counts
GROUP BY date
ORDER BY date DESC;
```

### Alerting

**Configure alerts for**:
1. **Spike in deprecated version usage**: Alert if v1 usage increases >20% day-over-day
2. **Client making requests to sunset version**: Alert immediately when 410 responses occur
3. **High error rate in new version**: Alert if v2 error rate >5%
4. **Slow migration progress**: Alert if <50% traffic on v2 within 6 months of deprecation
5. **Approaching sunset with active v1 clients**: Alert 30 days before sunset if >100 clients still on v1

**DataDog Alert Examples**:
```
Alert 1: Deprecated Version Spike
Metric: sum:api.request.count{api_version:v1}
Condition: Change > 20% (day-over-day)
Message: "🚨 v1 API usage spiked by {{value}}%. Expected decline, seeing increase. Investigate immediately."
Notify: #api-alerts, api-team@sumafinance.com

Alert 2: Sunset Version Access
Metric: sum:api.response.count{status_code:410}
Condition: > 0 (in last 5 minutes)
Message: "⚠️ Client attempting to access sunset API v1. Count: {{value}}. Client info: {{api_key}}"
Notify: #api-alerts-urgent, api-team@sumafinance.com

Alert 3: High Error Rate in New Version
Metric: sum:api.error.count{api_version:v2} / sum:api.request.count{api_version:v2}
Condition: > 0.05 (5%)
Message: "🚨 v2 API error rate {{value}}% exceeds threshold. Investigate for regression."
Notify: #api-alerts-critical, oncall@sumafinance.com

Alert 4: Slow Migration Progress
Metric: sum:api.request.count{api_version:v2} / sum:api.request.count{*}
Condition: < 0.50 (6 months after v1 deprecation)
Message: "⚠️ Only {{value}}% of traffic on v2, 6 months after v1 deprecation. Increase migration efforts."
Notify: #api-team, product@sumafinance.com

Alert 5: Approaching Sunset with Active Clients
Metric: count(distinct api_key) where api_version='v1'
Condition: > 100 (30 days before sunset)
Message: "🚨 URGENT: {{value}} clients still using v1, sunset in 30 days. Immediate outreach required."
Notify: #api-alerts-urgent, ceo@sumafinance.com, api-team@sumafinance.com
```

## Best Practices

### DO ✅
- **Communicate early and often**: Announce deprecations 12+ months in advance
- **Provide comprehensive migration guides**: Include code examples for all major languages
- **Support multiple versions concurrently**: Run N and N-1 versions simultaneously
- **Use semantic versioning**: Clear MAJOR.MINOR.PATCH scheme
- **Add deprecation headers**: Warn clients proactively via response headers
- **Test backward compatibility**: Automated contract tests for all versions
- **Monitor version usage**: Track migration progress and identify laggards
- **Offer migration support**: Dedicated support channel and office hours
- **Maintain security across versions**: Backport critical security patches to deprecated versions
- **Document breaking changes clearly**: Explicit list with before/after code examples
- **Automate migration testing**: CI/CD pipeline tests for both versions
- **Respect sunset dates**: Give clients predictable timelines
- **Keep SDK versions in sync**: SDK major version matches API major version

### DON'T ❌
- **Break APIs without warning**: Never introduce breaking changes in MINOR/PATCH versions
- **Remove versions too quickly**: Minimum 12-month deprecation period
- **Version every minor change**: Reserve major versions for breaking changes
- **Have too many active versions**: Maximum 2 active versions (current + previous)
- **Change v1 behavior in v2 unexpectedly**: Clearly document all behavioral changes
- **Ignore client migration progress**: Proactively reach out to clients lagging on migration
- **Compromise security for backward compatibility**: Security always takes priority
- **Make breaking changes without alternatives**: Provide clear migration path
- **Sunset versions during holidays**: Avoid December, summer vacation periods
- **Skip sandbox testing phase**: Always provide sandbox environment for migration testing

## Appendix

### Version Comparison Matrix

| Feature | v1 (Deprecated) | v2 (Current) | v3 (Planned) |
|---------|-----------------|--------------|--------------|
| **Status** | Deprecated | Stable | Beta (Q1 2026) |
| **Sunset Date** | 2025-06-01 | - | - |
| **Response Format** | Flat object | Nested (tokens/user/session) | Nested + metadata |
| **User ID Type** | Integer | String (usr_) | String (usr_) |
| **Authentication** | JWT (HS256) | JWT (RS256) | JWT (RS256) + Passkeys |
| **OAuth Support** | ❌ No | ✅ Google, Apple | ✅ Google, Apple, Microsoft |
| **Biometric Auth** | ❌ No | ✅ TouchID, FaceID | ✅ Enhanced biometrics |
| **2FA Methods** | Email OTP | Email OTP | Email OTP, SMS, Authenticator App |
| **Session Management** | Single session | Multiple sessions | Multiple sessions + device trust |
| **Rate Limit** | 1000/hr | 10000/hr | 100000/hr |
| **Token Expiration** | Access: 15 min | Access: 15 min, Refresh: 7 days | Configurable |
| **Error Format** | Inconsistent | Standardized (code/message/details) | Enhanced with remediation steps |
| **GDPR Compliance** | ✅ Basic | ✅ Enhanced | ✅ Full automation |
| **Device Fingerprinting** | ❌ No | ✅ Optional | ✅ Enhanced with ML |
| **Security Event Logging** | ✅ Basic | ✅ Comprehensive | ✅ Real-time analytics |
| **Refresh Token Rotation** | ❌ No | ✅ Yes | ✅ Yes with reuse detection |
| **API Documentation** | OpenAPI 3.0 | OpenAPI 3.1 | OpenAPI 3.1 + GraphQL |
| **SDK Support** | JS, Go | JS, Go, Python, Ruby | JS, Go, Python, Ruby, Swift, Kotlin |
| **Sandbox Environment** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Webhook Support** | ❌ No | ❌ No | ✅ Yes (auth events) |

### Example Migration Timeline

```
2024-01-01: v2-beta Released
            - Internal testing begins
            - Select partners invited to beta program
            - Beta documentation published
            - Migration guide draft available

2024-03-01: v2 Promoted to Stable
            - Full production release
            - SLA coverage begins
            - v1 remains stable (no deprecation yet)
            - Side-by-side operation begins

2024-06-01: v1 Marked Deprecated
            - Official deprecation announcement
            - Email sent to all API clients
            - Deprecation headers added to v1 responses
            - Migration guide finalized
            - Migration support channel opened
            - First migration webinar held

2024-07-01: Monthly Monitoring Begins
            - Track v1 vs v2 usage per client
            - Identify clients with high v1 usage
            - Send first monthly reminder emails

2024-09-01: Stop Accepting New v1 API Keys
            - New registrations default to v2
            - v1 API keys for existing clients still valid
            - Second migration webinar

2024-12-01: Mid-Point Check (6 months to sunset)
            - Send usage reports to all v1 clients
            - Offer 1:1 migration support calls
            - Third migration webinar
            - Identify clients needing extension requests

2025-03-01: Final Warning (3 months to sunset)
            - Urgent reminder emails (bi-weekly)
            - Direct outreach to high-volume clients
            - Final migration webinar
            - Emergency migration support offered

2025-05-01: Last Call (1 month to sunset)
            - Final warning emails (weekly)
            - 24/7 emergency migration support
            - Extension requests deadline
            - Simulate sunset in sandbox

2025-06-01: v1 Sunset
            - All v1 endpoints return 410 Gone
            - 72-hour emergency grace period for approved clients
            - Monitor for sunset-related issues
            - Post-sunset support available

2025-06-04: Emergency Grace Period Ends
            - All v1 access fully terminated
            - Post-mortem review
            - Documentation updated

2025-09-01: v3-beta Released (if planned)
            - Start cycle for next major version
```

### Glossary

- **API Version**: The major version number in the API URL (e.g., v1, v2)
- **Breaking Change**: A change that requires client code updates; incompatible with previous version
- **Non-Breaking Change**: A change that maintains backward compatibility; no client updates required
- **Deprecation**: Marking a version or feature for future removal with advance notice
- **Sunset**: Removing a version from service; endpoints return 410 Gone
- **Migration**: Moving from an old API version to a new version
- **Backward Compatibility**: Ensuring new changes don't break existing client integrations
- **Semantic Versioning**: Version numbering scheme (MAJOR.MINOR.PATCH) based on change impact
- **Grace Period**: Time period between deprecation announcement and sunset date
- **Adapter Pattern**: Design pattern to convert between different API version formats
- **Feature Flag**: Mechanism to enable/disable features without deploying new code
- **Contract Testing**: Testing that verifies API responses match expected format/schema
- **Rate Limiting**: Restricting number of API requests per time period
- **JWT (JSON Web Token)**: Secure token format for authentication
- **Session Management**: Tracking and managing user authentication sessions
- **OAuth 2.0**: Industry-standard protocol for authorization
- **2FA (Two-Factor Authentication)**: Additional security layer requiring two forms of verification
- **API Key**: Unique identifier for authenticating API clients
- **SDK (Software Development Kit)**: Pre-built library for interacting with the API
- **Sandbox Environment**: Testing environment for trying API changes safely
- **SLA (Service Level Agreement)**: Commitment to specific uptime and performance guarantees

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Owner**: SUMA Finance API Team
**Contact**: api-team@sumafinance.com