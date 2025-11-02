---
layout: default
title: Api Documentation
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

# API DOCUMENTATION STRATEGY

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: APIs
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

The SUMA Finance authentication API provides a comprehensive, security-first approach to user registration, login, session management, and account security. Built on REST principles with JWT-based authentication, the API enforces strict compliance with GDPR, PCI-DSS, SOC2, and OWASP Top 10 security standards. This documentation strategy leverages OpenAPI 3.0 for auto-generated interactive documentation, multi-language code examples, and a comprehensive API playground powered by Swagger UI.

The documentation follows a developer-first philosophy, prioritizing clarity, accuracy, and practical examples. All endpoints include working code snippets in JavaScript, Python, Go, Ruby, and cURL, with detailed error handling guidance. Interactive testing capabilities allow developers to authenticate and test endpoints directly in the browser, reducing integration time and support tickets.

Our approach emphasizes security transparency, providing detailed information about token lifecycles, rate limiting, GDPR compliance requirements, and security event logging. The documentation is version-controlled, auto-generated from code annotations, and maintained through CI/CD pipelines to ensure accuracy and consistency with the production API.

## Documentation Philosophy

### Principles
- **Developer-First**: Written for backend and frontend developers integrating authentication flows, with clear explanations of security requirements and implementation patterns
- **Comprehensive**: Cover all authentication endpoints (registration, login, 2FA, password reset), security headers, error codes, rate limits, and GDPR compliance mechanisms
- **Accurate**: Auto-generated OpenAPI specification from Go code annotations, validated in CI/CD, and tested against the production API
- **Practical**: Include real-world examples for common scenarios (first-time registration, login with 2FA, token refresh, password reset, session management)
- **Interactive**: Provide Swagger UI playground with pre-configured authentication, allowing developers to test endpoints with sample data
- **Searchable**: Algolia-powered search across all endpoints, error codes, and guides with contextual filtering
- **Versioned**: Document API v1 and v2 with migration guides, deprecation notices, and backward compatibility notes
- **Accessible**: Clear security terminology, GDPR compliance explanations, and step-by-step integration guides for non-security experts

### Documentation Goals
1. Reduce time-to-first-API-call from hours to minutes with quick start guide
2. Enable self-service integration with comprehensive endpoint documentation and SDKs
3. Reduce authentication-related support tickets by 80% through detailed error handling guides
4. Improve developer experience with interactive playground and multi-language examples
5. Showcase security capabilities (2FA, session management, GDPR compliance) to build trust

## Documentation Tools

### OpenAPI/Swagger (REST APIs)

**Why OpenAPI**:
- Industry standard for REST API documentation, widely adopted in fintech
- Auto-generate documentation from Go struct tags and swaggo annotations
- Interactive API explorer (Swagger UI) for testing authentication flows
- Client SDK generation for JavaScript, Python, Go, Ruby
- Contract testing to ensure API implementation matches documentation
- Security scheme definitions for JWT Bearer authentication

**OpenAPI Specification Location**:
```
/docs/openapi/v1.yaml
/docs/openapi/v2.yaml
/docs/openapi/schemas/   # Reusable schema components
/docs/openapi/examples/  # Request/response examples
```

**Specification Format**: YAML (more readable and maintainable than JSON)

**Example OpenAPI Spec**:
```yaml
openapi: 3.0.3
info:
  title: SUMA Finance Authentication API
  description: |
    Secure authentication and user management API for SUMA Finance.

    ## Getting Started
    1. [Register for an account](#tag/Authentication/operation/register)
    2. [Verify your email](#tag/Authentication/operation/verifyEmail)
    3. [Log in to receive JWT tokens](#tag/Authentication/operation/login)
    4. Include your access token in the `Authorization` header for authenticated requests

    ## Base URL
    `https://api.sumafinance.com/v1`

    ## Authentication
    Include your JWT access token in the `Authorization` header:
    ```
    Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
    ```

    ## Security Features
    - **JWT Tokens**: 15-minute access tokens, 7-day refresh tokens
    - **2FA**: Email-based OTP with 6-digit codes
    - **Rate Limiting**: 5 login attempts per minute, 10 per user per hour
    - **Session Management**: Redis-backed with automatic expiration
    - **GDPR Compliance**: Explicit consent tracking and data subject rights

    ## Support
    - **Status Page**: https://status.sumafinance.com
    - **Email**: api-support@sumafinance.com
    - **Response Time**: < 24 hours for critical issues

  version: 1.0.0
  contact:
    name: SUMA Finance API Support
    email: api-support@sumafinance.com
    url: https://docs.sumafinance.com/support
  license:
    name: Proprietary
    url: https://sumafinance.com/terms
  termsOfService: https://sumafinance.com/terms

servers:
  - url: https://api.sumafinance.com/v1
    description: Production
  - url: https://staging-api.sumafinance.com/v1
    description: Staging
  - url: http://localhost:8080/v1
    description: Local Development

security:
  - bearerAuth: []

tags:
  - name: Authentication
    description: User registration, login, logout, and email verification
  - name: Session Management
    description: JWT token refresh and session lifecycle operations
  - name: Password Management
    description: Password reset, change, and security operations
  - name: Two-Factor Authentication
    description: 2FA setup, verification, and backup codes
  - name: GDPR Compliance
    description: Consent management and data subject rights
  - name: Account Security
    description: Device management, security events, and account lockout

paths:
  /auth/register:
    post:
      summary: Register new user
      description: |
        Create a new user account with email and password. This endpoint:
        - Validates email format and uniqueness
        - Enforces password complexity (min 12 chars, uppercase, lowercase, number, special)
        - Sends verification email with signed token
        - Captures GDPR consent with timestamp and IP
        - Returns user object without password

        ## Password Requirements
        - Minimum 12 characters
        - At least one uppercase letter (A-Z)
        - At least one lowercase letter (a-z)
        - At least one number (0-9)
        - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

        ## Rate Limiting
        - 3 registration attempts per IP per hour
        - 1 registration per email per 24 hours

        ## GDPR Consent
        The `gdpr_consent` object must include explicit consent for:
        - Terms of Service acceptance
        - Privacy Policy acceptance
        - Marketing communications (optional)

        ## Email Verification
        After successful registration, a verification email is sent with a link containing a signed token valid for 24 hours.

      operationId: register
      tags:
        - Authentication
      security: []  # No authentication required
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterRequest'
            examples:
              basic:
                summary: Basic registration
                value:
                  email: "john.doe@example.com"
                  password: "SecureP@ssw0rd123!"
                  name: "John Doe"
                  gdpr_consent:
                    terms_accepted: true
                    privacy_accepted: true
                    marketing_accepted: false
      responses:
        '201':
          description: User successfully created
          headers:
            X-RateLimit-Limit:
              schema:
                type: integer
              description: Number of requests allowed per hour
            X-RateLimit-Remaining:
              schema:
                type: integer
              description: Number of requests remaining
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegisterResponse'
              examples:
                success:
                  value:
                    data:
                      id: "usr_2gXQ8jZv3mNkPqRs"
                      email: "john.doe@example.com"
                      name: "John Doe"
                      email_verified: false
                      created_at: "2025-10-29T12:34:56Z"
                      gdpr_consent:
                        terms_accepted: true
                        privacy_accepted: true
                        marketing_accepted: false
                        consent_timestamp: "2025-10-29T12:34:56Z"
                        consent_ip: "203.0.113.42"
                    message: "Registration successful. Please check your email to verify your account."
        '400':
          $ref: '#/components/responses/ValidationError'
        '409':
          $ref: '#/components/responses/EmailAlreadyExists'
        '429':
          $ref: '#/components/responses/RateLimitExceeded'
        '500':
          $ref: '#/components/responses/InternalError'

  /auth/login:
    post:
      summary: Authenticate user
      description: |
        Authenticate with email and password to receive JWT tokens.

        ## Authentication Flow
        1. Submit email and password
        2. If 2FA is enabled, receive `requires_2fa: true` with temporary token
        3. Submit 2FA code to `/auth/2fa/verify` endpoint
        4. Receive access token (15 min expiry) and refresh token (7 day expiry)

        ## Rate Limiting
        - 5 attempts per minute per IP
        - 10 attempts per hour per user
        - Account lockout after 5 failed attempts (15-minute cooldown)

        ## Security Features
        - Argon2id password hashing
        - Session fixation prevention (new session ID after login)
        - Device fingerprinting for fraud detection
        - IP address and geolocation logging
        - Security event audit trail

        ## Response Headers
        - `X-Session-ID`: Unique session identifier
        - `X-Device-ID`: Device fingerprint hash
        - `X-Requires-2FA`: Indicates if 2FA verification is required

      operationId: login
      tags:
        - Authentication
      security: []  # No authentication required
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
            examples:
              basic:
                summary: Login without 2FA
                value:
                  email: "john.doe@example.com"
                  password: "SecureP@ssw0rd123!"
                  device_fingerprint: "fp_abc123xyz789"
              with_remember:
                summary: Login with remember me (extended refresh token)
                value:
                  email: "john.doe@example.com"
                  password: "SecureP@ssw0rd123!"
                  remember_me: true
      responses:
        '200':
          description: Authentication successful
          headers:
            X-Session-ID:
              schema:
                type: string
              description: Session identifier
            X-Device-ID:
              schema:
                type: string
              description: Device fingerprint hash
          content:
            application/json:
              schema:
                oneOf:
                  - $ref: '#/components/schemas/LoginSuccessResponse'
                  - $ref: '#/components/schemas/Login2FARequiredResponse'
              examples:
                success:
                  summary: Login successful without 2FA
                  value:
                    data:
                      access_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
                      refresh_token: "rt_2gXQ8jZv3mNkPqRs"
                      token_type: "Bearer"
                      expires_in: 900
                      user:
                        id: "usr_2gXQ8jZv3mNkPqRs"
                        email: "john.doe@example.com"
                        name: "John Doe"
                        email_verified: true
                    message: "Login successful"
                requires_2fa:
                  summary: 2FA verification required
                  value:
                    data:
                      requires_2fa: true
                      temporary_token: "tmp_abc123xyz789"
                      user_id: "usr_2gXQ8jZv3mNkPqRs"
                    message: "2FA verification required. Please check your email for the OTP code."
        '401':
          $ref: '#/components/responses/InvalidCredentials'
        '403':
          $ref: '#/components/responses/AccountLocked'
        '429':
          $ref: '#/components/responses/RateLimitExceeded'
        '500':
          $ref: '#/components/responses/InternalError'

  /auth/refresh:
    post:
      summary: Refresh access token
      description: |
        Use a valid refresh token to obtain a new access token.

        ## Refresh Token Lifecycle
        - Refresh tokens are valid for 7 days (or 30 days with "remember me")
        - After each use, the refresh token is rotated (new token issued)
        - Old refresh token is invalidated to prevent reuse attacks
        - Refresh token reuse detection triggers automatic session termination

        ## Rate Limiting
        - 10 refresh requests per minute per user
        - Suspicious activity (multiple refresh attempts) triggers security alerts

      operationId: refreshToken
      tags:
        - Session Management
      security: []  # Uses refresh token instead of access token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RefreshTokenRequest'
            examples:
              basic:
                value:
                  refresh_token: "rt_2gXQ8jZv3mNkPqRs"
      responses:
        '200':
          description: Token refreshed successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RefreshTokenResponse'
              examples:
                success:
                  value:
                    data:
                      access_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
                      refresh_token: "rt_9kLMn4oPq5RsT6uV"
                      token_type: "Bearer"
                      expires_in: 900
                    message: "Token refreshed successfully"
        '401':
          $ref: '#/components/responses/InvalidRefreshToken'
        '403':
          $ref: '#/components/responses/RefreshTokenReused'
        '500':
          $ref: '#/components/responses/InternalError'

  /auth/logout:
    post:
      summary: Log out user
      description: |
        Invalidate the current access token and refresh token, ending the session.

        ## Logout Behavior
        - Access token is added to blacklist (Redis) until expiration
        - Refresh token is permanently invalidated
        - Session data is removed from Redis
        - Security event logged with timestamp and IP

        ## All Devices Logout
        Use the `all_devices` parameter to invalidate all sessions across all devices.

      operationId: logout
      tags:
        - Authentication
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LogoutRequest'
            examples:
              current_device:
                summary: Logout current device only
                value:
                  all_devices: false
              all_devices:
                summary: Logout all devices
                value:
                  all_devices: true
      responses:
        '200':
          description: Logout successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/MessageResponse'
              examples:
                success:
                  value:
                    message: "Logout successful"
        '401':
          $ref: '#/components/responses/Unauthorized'
        '500':
          $ref: '#/components/responses/InternalError'

  /auth/password/reset-request:
    post:
      summary: Request password reset
      description: |
        Request a password reset link via email.

        ## Reset Process
        1. Submit email address
        2. Receive email with signed reset token (valid 1 hour)
        3. Click link or use token to reset password at `/auth/password/reset`

        ## Security Features
        - Same response for existing/non-existing emails (enumeration prevention)
        - Signed tokens with HMAC-SHA256 to prevent tampering
        - Rate limiting: 3 requests per email per hour
        - Previous reset tokens invalidated when new one is generated

      operationId: requestPasswordReset
      tags:
        - Password Management
      security: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/PasswordResetRequestRequest'
            examples:
              basic:
                value:
                  email: "john.doe@example.com"
      responses:
        '200':
          description: Reset email sent (or will be sent if email exists)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/MessageResponse'
              examples:
                success:
                  value:
                    message: "If your email is registered, you will receive a password reset link shortly."
        '429':
          $ref: '#/components/responses/RateLimitExceeded'
        '500':
          $ref: '#/components/responses/InternalError'

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: |
        JWT access token obtained from the `/auth/login` endpoint.

        **Token Lifecycle**:
        - Access tokens expire after 15 minutes
        - Refresh tokens expire after 7 days (or 30 days with "remember me")
        - Include in `Authorization` header: `Bearer <access_token>`

        **Token Claims**:
        - `sub`: User ID
        - `email`: User email
        - `exp`: Expiration timestamp
        - `iat`: Issued at timestamp
        - `jti`: JWT ID (unique token identifier)
        - `device_id`: Device fingerprint hash

        **Token Refresh**:
        Use the `/auth/refresh` endpoint with your refresh token before the access token expires.

  parameters:
    Page:
      name: page
      in: query
      description: Page number (1-indexed)
      schema:
        type: integer
        minimum: 1
        default: 1
      example: 1

    PerPage:
      name: per_page
      in: query
      description: Number of items per page (max 100)
      schema:
        type: integer
        minimum: 1
        maximum: 100
        default: 20
      example: 20

  schemas:
    RegisterRequest:
      type: object
      required:
        - email
        - password
        - name
        - gdpr_consent
      properties:
        email:
          type: string
          format: email
          description: User's email address (must be unique)
          maxLength: 255
          example: "john.doe@example.com"
        password:
          type: string
          format: password
          description: Password meeting complexity requirements
          minLength: 12
          maxLength: 128
          example: "SecureP@ssw0rd123!"
        name:
          type: string
          description: User's full name
          minLength: 2
          maxLength: 100
          example: "John Doe"
        gdpr_consent:
          $ref: '#/components/schemas/GDPRConsent'

    GDPRConsent:
      type: object
      required:
        - terms_accepted
        - privacy_accepted
      properties:
        terms_accepted:
          type: boolean
          description: User accepted Terms of Service
          example: true
        privacy_accepted:
          type: boolean
          description: User accepted Privacy Policy
          example: true
        marketing_accepted:
          type: boolean
          description: User opted in to marketing communications
          default: false
          example: false

    RegisterResponse:
      type: object
      properties:
        data:
          type: object
          properties:
            id:
              type: string
              description: Unique user identifier
              example: "usr_2gXQ8jZv3mNkPqRs"
            email:
              type: string
              format: email
              example: "john.doe@example.com"
            name:
              type: string
              example: "John Doe"
            email_verified:
              type: boolean
              description: Email verification status
              example: false
            created_at:
              type: string
              format: date-time
              example: "2025-10-29T12:34:56Z"
            gdpr_consent:
              allOf:
                - $ref: '#/components/schemas/GDPRConsent'
                - type: object
                  properties:
                    consent_timestamp:
                      type: string
                      format: date-time
                      example: "2025-10-29T12:34:56Z"
                    consent_ip:
                      type: string
                      format: ipv4
                      example: "203.0.113.42"
        message:
          type: string
          example: "Registration successful. Please check your email to verify your account."

    LoginRequest:
      type: object
      required:
        - email
        - password
      properties:
        email:
          type: string
          format: email
          example: "john.doe@example.com"
        password:
          type: string
          format: password
          example: "SecureP@ssw0rd123!"
        device_fingerprint:
          type: string
          description: Client-generated device fingerprint for fraud detection
          example: "fp_abc123xyz789"
        remember_me:
          type: boolean
          description: Extend refresh token expiration to 30 days
          default: false

    LoginSuccessResponse:
      type: object
      properties:
        data:
          type: object
          properties:
            access_token:
              type: string
              description: JWT access token (15 min expiry)
              example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
            refresh_token:
              type: string
              description: Refresh token for obtaining new access tokens
              example: "rt_2gXQ8jZv3mNkPqRs"
            token_type:
              type: string
              enum: [Bearer]
              example: "Bearer"
            expires_in:
              type: integer
              description: Access token expiration in seconds
              example: 900
            user:
              $ref: '#/components/schemas/User'
        message:
          type: string
          example: "Login successful"

    Login2FARequiredResponse:
      type: object
      properties:
        data:
          type: object
          properties:
            requires_2fa:
              type: boolean
              example: true
            temporary_token:
              type: string
              description: Temporary token for 2FA verification (5 min expiry)
              example: "tmp_abc123xyz789"
            user_id:
              type: string
              example: "usr_2gXQ8jZv3mNkPqRs"
        message:
          type: string
          example: "2FA verification required. Please check your email for the OTP code."

    RefreshTokenRequest:
      type: object
      required:
        - refresh_token
      properties:
        refresh_token:
          type: string
          example: "rt_2gXQ8jZv3mNkPqRs"

    RefreshTokenResponse:
      type: object
      properties:
        data:
          type: object
          properties:
            access_token:
              type: string
              example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
            refresh_token:
              type: string
              description: New rotated refresh token
              example: "rt_9kLMn4oPq5RsT6uV"
            token_type:
              type: string
              enum: [Bearer]
              example: "Bearer"
            expires_in:
              type: integer
              example: 900
        message:
          type: string
          example: "Token refreshed successfully"

    LogoutRequest:
      type: object
      properties:
        all_devices:
          type: boolean
          description: Invalidate all sessions across all devices
          default: false

    PasswordResetRequestRequest:
      type: object
      required:
        - email
      properties:
        email:
          type: string
          format: email
          example: "john.doe@example.com"

    User:
      type: object
      properties:
        id:
          type: string
          example: "usr_2gXQ8jZv3mNkPqRs"
        email:
          type: string
          format: email
          example: "john.doe@example.com"
        name:
          type: string
          example: "John Doe"
        email_verified:
          type: boolean
          example: true
        two_factor_enabled:
          type: boolean
          example: false
        created_at:
          type: string
          format: date-time
          example: "2025-10-29T12:34:56Z"
        last_login_at:
          type: string
          format: date-time
          example: "2025-10-29T15:20:00Z"

    MessageResponse:
      type: object
      properties:
        message:
          type: string
          example: "Operation successful"

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
                description: Unique error identifier for support
                example: "err_550e8400-e29b-41d4-a716"
              status:
                type: string
                description: HTTP status code
                example: "400"
              code:
                type: string
                description: Machine-readable error code
                example: "VALIDATION_ERROR"
              title:
                type: string
                description: Human-readable error summary
                example: "Validation Failed"
              detail:
                type: string
                description: Specific error message
                example: "Password must be at least 12 characters long"
              source:
                type: object
                description: Location of the error
                properties:
                  pointer:
                    type: string
                    description: JSON Pointer to the field
                    example: "/data/attributes/password"
                  parameter:
                    type: string
                    description: Query parameter name
                    example: "email"

  responses:
    ValidationError:
      description: Request validation failed
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          examples:
            password_complexity:
              summary: Password complexity requirement not met
              value:
                errors:
                  - id: "err_550e8400-e29b-41d4-a716"
                    status: "400"
                    code: "PASSWORD_COMPLEXITY_ERROR"
                    title: "Password Complexity Error"
                    detail: "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
                    source:
                      pointer: "/data/attributes/password"
            email_format:
              summary: Invalid email format
              value:
                errors:
                  - id: "err_650e8400-e29b-41d4-a716"
                    status: "400"
                    code: "INVALID_EMAIL_FORMAT"
                    title: "Invalid Email"
                    detail: "Email address format is invalid"
                    source:
                      pointer: "/data/attributes/email"

    EmailAlreadyExists:
      description: Email address is already registered
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            errors:
              - id: "err_750e8400-e29b-41d4-a716"
                status: "409"
                code: "EMAIL_ALREADY_EXISTS"
                title: "Email Conflict"
                detail: "An account with this email address already exists"
                source:
                  pointer: "/data/attributes/email"

    InvalidCredentials:
      description: Invalid email or password
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            errors:
              - id: "err_850e8400-e29b-41d4-a716"
                status: "401"
                code: "INVALID_CREDENTIALS"
                title: "Authentication Failed"
                detail: "Invalid email or password"

    AccountLocked:
      description: Account is temporarily locked due to failed login attempts
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            errors:
              - id: "err_950e8400-e29b-41d4-a716"
                status: "403"
                code: "ACCOUNT_LOCKED"
                title: "Account Locked"
                detail: "Your account has been temporarily locked due to multiple failed login attempts. Please try again in 15 minutes or reset your password."

    Unauthorized:
      description: Authentication required
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            errors:
              - id: "err_a50e8400-e29b-41d4-a716"
                status: "401"
                code: "AUTHENTICATION_REQUIRED"
                title: "Authentication Required"
                detail: "Valid access token is required. Please log in."

    InvalidRefreshToken:
      description: Refresh token is invalid or expired
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            errors:
              - id: "err_b50e8400-e29b-41d4-a716"
                status: "401"
                code: "INVALID_REFRESH_TOKEN"
                title: "Invalid Refresh Token"
                detail: "The refresh token is invalid or has expired. Please log in again."

    RefreshTokenReused:
      description: Refresh token was already used (potential security breach)
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            errors:
              - id: "err_c50e8400-e29b-41d4-a716"
                status: "403"
                code: "REFRESH_TOKEN_REUSED"
                title: "Security Alert"
                detail: "This refresh token has already been used. All sessions have been terminated for security. Please log in again."

    RateLimitExceeded:
      description: Rate limit exceeded
      headers:
        X-RateLimit-Limit:
          schema:
            type: integer
          description: Number of requests allowed in the time window
        X-RateLimit-Remaining:
          schema:
            type: integer
          description: Number of requests remaining
        X-RateLimit-Reset:
          schema:
            type: integer
          description: Unix timestamp when the rate limit resets
        Retry-After:
          schema:
            type: integer
          description: Number of seconds to wait before retrying
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            errors:
              - id: "err_d50e8400-e29b-41d4-a716"
                status: "429"
                code: "RATE_LIMIT_EXCEEDED"
                title: "Rate Limit Exceeded"
                detail: "Too many requests. Please try again in 60 seconds."

    InternalError:
      description: Internal server error
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Error'
          example:
            errors:
              - id: "err_e50e8400-e29b-41d4-a716"
                status: "500"
                code: "INTERNAL_SERVER_ERROR"
                title: "Internal Server Error"
                detail: "An unexpected error occurred. Please try again later or contact support with error ID: err_e50e8400-e29b-41d4-a716"
```

### GraphQL Documentation

**Not Applicable**: SUMA Finance authentication API uses REST architecture with JWT tokens. GraphQL is not used for authentication endpoints due to:
- Better compatibility with OAuth 2.0 and JWT standards
- Simpler rate limiting and caching strategies
- Standard HTTP status codes for security errors
- Better browser and HTTP client support

If future features require GraphQL, documentation will follow these patterns:
- Schema-first design with SDL (Schema Definition Language)
- GraphQL Playground for interactive testing
- Detailed field descriptions and deprecation notices
- Query complexity analysis documentation

### Postman/Insomnia Collections

**Postman Collection Location**: `/docs/postman/SUMA-Finance-Auth-v1.json`

**Collection Features**:
- Pre-configured environment variables (base URL, tokens)
- Pre-request scripts for automatic token refresh
- Test scripts to validate responses
- Example requests for all endpoints
- Folder organization by feature (Auth, Session, Password, 2FA, GDPR)

**Postman Collection Structure**:
```json
{
  "info": {
    "name": "SUMA Finance Auth API v1",
    "description": "Complete authentication API collection with automated token management",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "auth": {
    "type": "bearer",
    "bearer": [
      {
        "key": "token",
        "value": "{{access_token}}",
        "type": "string"
      }
    ]
  },
  "event": [
    {
      "listen": "prerequest",
      "script": {
        "exec": [
          "// Auto-refresh expired access token",
          "const accessToken = pm.environment.get('access_token');",
          "const tokenExpiry = pm.environment.get('token_expiry');",
          "if (!accessToken || Date.now() > tokenExpiry) {",
          "  const refreshToken = pm.environment.get('refresh_token');",
          "  if (refreshToken) {",
          "    pm.sendRequest({",
          "      url: pm.environment.get('base_url') + '/auth/refresh',",
          "      method: 'POST',",
          "      header: { 'Content-Type': 'application/json' },",
          "      body: { mode: 'raw', raw: JSON.stringify({ refresh_token: refreshToken }) }",
          "    }, (err, res) => {",
          "      if (!err && res.code === 200) {",
          "        const data = res.json().data;",
          "        pm.environment.set('access_token', data.access_token);",
          "        pm.environment.set('refresh_token', data.refresh_token);",
          "        pm.environment.set('token_expiry', Date.now() + (data.expires_in * 1000));",
          "      }",
          "    });",
          "  }",
          "}"
        ]
      }
    }
  ],
  "item": [
    {
      "name": "Authentication",
      "item": [
        {
          "name": "Register",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"email\": \"{{$randomEmail}}\",\n  \"password\": \"SecureP@ssw0rd123!\",\n  \"name\": \"{{$randomFullName}}\",\n  \"gdpr_consent\": {\n    \"terms_accepted\": true,\n    \"privacy_accepted\": true,\n    \"marketing_accepted\": false\n  }\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/register",
              "host": ["{{base_url}}"],
              "path": ["auth", "register"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Status code is 201', () => pm.response.to.have.status(201));",
                  "pm.test('Response has user ID', () => {",
                  "  const json = pm.response.json();",
                  "  pm.expect(json.data).to.have.property('id');",
                  "  pm.environment.set('user_id', json.data.id);",
                  "});",
                  "pm.test('Email is not verified', () => {",
                  "  const json = pm.response.json();",
                  "  pm.expect(json.data.email_verified).to.be.false;",
                  "});"
                ]
              }
            }
          ]
        },
        {
          "name": "Login",
          "request": {
            "auth": { "type": "noauth" },
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"email\": \"john.doe@example.com\",\n  \"password\": \"SecureP@ssw0rd123!\",\n  \"remember_me\": false\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/login",
              "host": ["{{base_url}}"],
              "path": ["auth", "login"]
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "pm.test('Status code is 200', () => pm.response.to.have.status(200));",
                  "pm.test('Response has tokens', () => {",
                  "  const json = pm.response.json();",
                  "  pm.expect(json.data).to.have.property('access_token');",
                  "  pm.expect(json.data).to.have.property('refresh_token');",
                  "  pm.environment.set('access_token', json.data.access_token);",
                  "  pm.environment.set('refresh_token', json.data.refresh_token);",
                  "  pm.environment.set('token_expiry', Date.now() + (json.data.expires_in * 1000));",
                  "});"
                ]
              }
            }
          ]
        },
        {
          "name": "Logout",
          "request": {
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"all_devices\": false\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/logout",
              "host": ["{{base_url}}"],
              "path": ["auth", "logout"]
            }
          }
        }
      ]
    },
    {
      "name": "Session Management",
      "item": [
        {
          "name": "Refresh Token",
          "request": {
            "auth": { "type": "noauth" },
            "method": "POST",
            "header": [
              { "key": "Content-Type", "value": "application/json" }
            ],
            "body": {
              "mode": "raw",
              "raw": "{\n  \"refresh_token\": \"{{refresh_token}}\"\n}"
            },
            "url": {
              "raw": "{{base_url}}/auth/refresh",
              "host": ["{{base_url}}"],
              "path": ["auth", "refresh"]
            }
          }
        }
      ]
    }
  ]
}
```

**Environment Template**:
```json
{
  "name": "SUMA Finance - Production",
  "values": [
    { "key": "base_url", "value": "https://api.sumafinance.com/v1", "enabled": true },
    { "key": "access_token", "value": "", "enabled": true },
    { "key": "refresh_token", "value": "", "enabled": true },
    { "key": "token_expiry", "value": "", "enabled": true },
    { "key": "user_id", "value": "", "enabled": true }
  ]
}
```

## Documentation Structure

### Homepage

**Location**: `/docs/index.md`

**Content**:
```markdown
# SUMA Finance API Documentation

Secure authentication and session management for SUMA Finance.

## Quick Start

Get up and running in 5 minutes:

1. **[Register an Account](#register)**: Create a test account with email/password
2. **[Verify Email](#verify-email)**: Complete email verification (check your inbox)
3. **[Log In](#login)**: Authenticate and receive JWT tokens
4. **[Make Authenticated Requests](#using-tokens)**: Include access token in Authorization header

```bash
# Register
curl -X POST https://api.sumafinance.com/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@example.com",
    "password": "SecureP@ssw0rd123!",
    "name": "Your Name",
    "gdpr_consent": {
      "terms_accepted": true,
      "privacy_accepted": true
    }
  }'

# Login
curl -X POST https://api.sumafinance.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@example.com",
    "password": "SecureP@ssw0rd123!"
  }'
```

## Popular Endpoints

- **[Register User](/docs/api-reference/authentication#post-authregister)**: Create new account with GDPR consent
- **[Login](/docs/api-reference/authentication#post-authlogin)**: Authenticate and get JWT tokens
- **[Refresh Token](/docs/api-reference/session#post-authrefresh)**: Get new access token
- **[Request Password Reset](/docs/api-reference/password#post-authpasswordreset-request)**: Initiate password reset flow
- **[Enable 2FA](/docs/api-reference/2fa#post-auth2faenable)**: Set up two-factor authentication

## Features

### Security
- **JWT Authentication**: Short-lived access tokens (15 min) with refresh tokens (7 days)
- **Two-Factor Authentication**: Email-based OTP with 6-digit codes
- **Rate Limiting**: Automatic protection against brute force attacks
- **Account Lockout**: Temporary lockout after failed login attempts
- **Session Management**: Redis-backed sessions with automatic expiration

### Compliance
- **GDPR**: Explicit consent tracking, data subject rights, breach notification
- **PCI-DSS**: Secure credential storage and transmission
- **SOC 2**: Comprehensive audit logging and access controls
- **OWASP Top 10**: Protection against common security vulnerabilities

### Developer Experience
- **[API Playground](/api-playground)**: Test endpoints directly in your browser
- **[SDKs](/docs/sdks)**: Official libraries for JavaScript, Python, Go, Ruby
- **[Postman Collection](/docs/postman)**: Pre-configured requests with auto-refresh
- **[Code Examples](/docs/examples)**: Working examples in 5+ languages

## SDKs & Libraries

Official SDKs available:
- [JavaScript/TypeScript](/docs/sdks/javascript) - `npm install @sumafinance/auth-client`
- [Python](/docs/sdks/python) - `pip install sumafinance-auth`
- [Go](/docs/sdks/go) - `go get github.com/sumafinance/auth-go`
- [Ruby](/docs/sdks/ruby) - `gem install sumafinance-auth`

## Documentation Sections

- **[Getting Started](/docs/getting-started)**: Step-by-step integration guide
- **[API Reference](/docs/api-reference)**: Complete endpoint documentation
- **[Authentication Guide](/docs/guides/authentication)**: JWT tokens and session lifecycle
- **[Security Guide](/docs/guides/security)**: Best practices and threat model
- **[GDPR Compliance](/docs/guides/gdpr)**: Data protection and user rights
- **[Error Handling](/docs/guides/errors)**: Error codes and troubleshooting
- **[Rate Limiting](/docs/guides/rate-limiting)**: Request limits and backoff strategies

## Support

- **[API Status](https://status.sumafinance.com)**: Real-time API health monitoring
- **[Contact Support](mailto:api-support@sumafinance.com)**: Email support (< 24h response)
- **[GitHub Issues](https://github.com/sumafinance/api-issues)**: Report bugs and feature requests
- **[Changelog](/docs/changelog)**: API updates and deprecations
```

### Getting Started Guide

**Location**: `/docs/getting-started.md`

**Content**:
```markdown
# Getting Started with SUMA Finance Auth API

This guide will walk you through integrating SUMA Finance authentication into your application.

## Prerequisites

- **Account**: Create a developer account at [sumafinance.com/developers](https://sumafinance.com/developers)
- **Base URL**: `https://api.sumafinance.com/v1`
- **Content Type**: All requests and responses use `application/json`

## Step 1: Register a User

Create a new user account with email, password, and GDPR consent.

### Request

```bash
curl -X POST https://api.sumafinance.com/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecureP@ssw0rd123!",
    "name": "John Doe",
    "gdpr_consent": {
      "terms_accepted": true,
      "privacy_accepted": true,
      "marketing_accepted": false
    }
  }'
```

### Response (201 Created)

```json
{
  "data": {
    "id": "usr_2gXQ8jZv3mNkPqRs",
    "email": "john.doe@example.com",
    "name": "John Doe",
    "email_verified": false,
    "created_at": "2025-10-29T12:34:56Z",
    "gdpr_consent": {
      "terms_accepted": true,
      "privacy_accepted": true,
      "marketing_accepted": false,
      "consent_timestamp": "2025-10-29T12:34:56Z",
      "consent_ip": "203.0.113.42"
    }
  },
  "message": "Registration successful. Please check your email to verify your account."
}
```

### Password Requirements

Your password must meet these complexity requirements:
- Minimum 12 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

### GDPR Consent

You must capture explicit consent for:
- **terms_accepted**: User accepts Terms of Service (required)
- **privacy_accepted**: User accepts Privacy Policy (required)
- **marketing_accepted**: User opts in to marketing emails (optional)

The API automatically logs the consent timestamp and IP address for compliance.

## Step 2: Verify Email

After registration, the user receives a verification email with a link:

```
https://sumafinance.com/verify-email?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Your application should extract the token and call the verification endpoint.

### Request

```bash
curl -X POST https://api.sumafinance.com/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

### Response (200 OK)

```json
{
  "data": {
    "email_verified": true,
    "verified_at": "2025-10-29T12:40:00Z"
  },
  "message": "Email verified successfully"
}
```

### Token Expiration

Email verification tokens are valid for **24 hours**. If expired, the user can request a new verification email:

```bash
curl -X POST https://api.sumafinance.com/v1/auth/resend-verification \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com"
  }'
```

## Step 3: Log In

Authenticate the user with email and password to receive JWT tokens.

### Request

```bash
curl -X POST https://api.sumafinance.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecureP@ssw0rd123!"
  }'
```

### Response (200 OK)

```json
{
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfMmdYUThqWnYzbU5rUHFScyIsImVtYWlsIjoiam9obi5kb2VAZXhhbXBsZS5jb20iLCJleHAiOjE3MzAwODQ3MDAsImlhdCI6MTczMDA4MzkwMCwianRpIjoianRpXzEyMzQ1Njc4OTAifQ...",
    "refresh_token": "rt_2gXQ8jZv3mNkPqRs",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": {
      "id": "usr_2gXQ8jZv3mNkPqRs",
      "email": "john.doe@example.com",
      "name": "John Doe",
      "email_verified": true,
      "two_factor_enabled": false,
      "created_at": "2025-10-29T12:34:56Z",
      "last_login_at": "2025-10-29T13:15:00Z"
    }
  },
  "message": "Login successful"
}
```

### Token Lifecycle

- **Access Token**: Valid for **15 minutes** (`expires_in: 900`)
- **Refresh Token**: Valid for **7 days** (or **30 days** with "remember me")

Store both tokens securely:
- **Browser**: Use `httpOnly` cookies or `sessionStorage` (never `localStorage`)
- **Mobile**: Use platform secure storage (iOS Keychain, Android KeyStore)
- **Server**: Store in memory or Redis session

### Login with 2FA

If the user has 2FA enabled, the login response will indicate additional verification is required:

```json
{
  "data": {
    "requires_2fa": true,
    "temporary_token": "tmp_abc123xyz789",
    "user_id": "usr_2gXQ8jZv3mNkPqRs"
  },
  "message": "2FA verification required. Please check your email for the OTP code."
}
```

The user must verify the OTP code (see [2FA Guide](/docs/guides/2fa)).

## Step 4: Make Authenticated Requests

Include the access token in the `Authorization` header for all authenticated requests.

### Request

```bash
curl -X GET https://api.sumafinance.com/v1/users/me \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json"
```

### Response (200 OK)

```json
{
  "data": {
    "id": "usr_2gXQ8jZv3mNkPqRs",
    "email": "john.doe@example.com",
    "name": "John Doe",
    "email_verified": true
  }
}
```

### Handling Expired Tokens

If the access token expires (after 15 minutes), you'll receive a `401 Unauthorized` error:

```json
{
  "errors": [
    {
      "status": "401",
      "code": "TOKEN_EXPIRED",
      "title": "Token Expired",
      "detail": "Access token has expired. Please refresh your token."
    }
  ]
}
```

Use the refresh token to obtain a new access token (next step).

## Step 5: Refresh Access Token

Before the access token expires, use the refresh token to obtain a new one.

### Request

```bash
curl -X POST https://api.sumafinance.com/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "rt_2gXQ8jZv3mNkPqRs"
  }'
```

### Response (200 OK)

```json
{
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "rt_9kLMn4oPq5RsT6uV",
    "token_type": "Bearer",
    "expires_in": 900
  },
  "message": "Token refreshed successfully"
}
```

### Token Rotation

**Important**: The API uses **refresh token rotation** for security. Each time you refresh:
1. A new access token is issued
2. A **new refresh token** is issued
3. The old refresh token is **invalidated**

Always update both tokens after each refresh.

### Refresh Token Reuse Detection

If you attempt to use an old (already-used) refresh token, the API will:
1. Detect the reuse attempt (potential security breach)
2. Invalidate **all** sessions for that user
3. Return a `403 Forbidden` error

The user must log in again with email/password.

## Step 6: Log Out

Invalidate the current session and tokens.

### Request

```bash
curl -X POST https://api.sumafinance.com/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "all_devices": false
  }'
```

### Response (200 OK)

```json
{
  "message": "Logout successful"
}
```

### Logout Options

- **Current Device Only** (`all_devices: false`): Invalidates only the current session
- **All Devices** (`all_devices: true`): Invalidates all sessions across all devices

## Next Steps

Now that you've completed the basic authentication flow, explore:

- **[Two-Factor Authentication](/docs/guides/2fa)**: Add an extra layer of security
- **[Password Management](/docs/guides/password)**: Password reset and change flows
- **[Session Management](/docs/guides/session)**: Best practices for token storage and refresh
- **[Error Handling](/docs/guides/errors)**: Comprehensive error code reference
- **[Rate Limiting](/docs/guides/rate-limiting)**: Understand rate limits and backoff strategies
- **[GDPR Compliance](/docs/guides/gdpr)**: Implement data subject rights
- **[Security Best Practices](/docs/guides/security)**: Threat model and mitigation strategies

## Code Examples

Browse working examples in multiple languages:
- [JavaScript/TypeScript](/docs/examples/javascript)
- [Python](/docs/examples/python)
- [Go](/docs/examples/go)
- [Ruby](/docs/examples/ruby)

## SDKs

Use official SDKs for faster integration:
- [JavaScript SDK](/docs/sdks/javascript)
- [Python SDK](/docs/sdks/python)
- [Go SDK](/docs/sdks/go)
- [Ruby SDK](/docs/sdks/ruby)
```

### API Reference

**Location**: `/docs/api-reference/` (auto-generated from OpenAPI spec)

The API Reference is generated from the OpenAPI specification using **Redoc** for static documentation and **Swagger UI** for interactive testing.

**Structure**:
```
/docs/api-reference/
  index.html                    # API overview with all endpoints
  authentication/               # Authentication endpoints
    register.html
    login.html
    logout.html
    verify-email.html
  session/                      # Session management
    refresh-token.html
    list-sessions.html
    revoke-session.html
  password/                     # Password management
    reset-request.html
    reset-confirm.html
    change-password.html
  2fa/                          # Two-factor authentication
    enable.html
    verify.html
    disable.html
  gdpr/                         # GDPR compliance
    get-user-data.html
    delete-account.html
    withdraw-consent.html
```

**Generation Command**:
```bash
# Generate static documentation with Redoc
npx @redocly/cli build-docs docs/openapi/v1.yaml \
  --output docs/api-reference/index.html \
  --title "SUMA Finance API Reference" \
  --theme.colors.primary.main "#2563eb"

# Validate OpenAPI spec
npx @redocly/cli lint docs/openapi/v1.yaml
```

### Guides & Tutorials

**Topics**:
```markdown
# API Guides

## Authentication
- [Getting Started with Authentication](/docs/guides/authentication)
- [JWT Token Lifecycle](/docs/guides/jwt-lifecycle)
- [Session Management Best Practices](/docs/guides/session-management)
- [OAuth 2.0 Integration](/docs/guides/oauth2) (future)

## Security
- [Two-Factor Authentication Setup](/docs/guides/2fa)
- [Password Security Best Practices](/docs/guides/password-security)
- [Account Lockout Protection](/docs/guides/account-lockout)
- [Device Management](/docs/guides/device-management)
- [Security Event Logging](/docs/guides/security-logging)

## Core Concepts
- [Rate Limiting](/docs/guides/rate-limiting)
- [Error Handling](/docs/guides/error-handling)
- [Pagination](/docs/guides/pagination)
- [API Versioning](/docs/guides/versioning)
- [Idempotency](/docs/guides/idempotency)

## Compliance
- [GDPR Compliance Guide](/docs/guides/gdpr)
- [PCI-DSS Requirements](/docs/guides/pci-dss)
- [SOC 2 Audit Trail](/docs/guides/soc2)
- [Data Subject Rights Implementation](/docs/guides/data-rights)
- [Consent Management](/docs/guides/consent-management)

## Integration Patterns
- [Single-Page Application (SPA) Integration](/docs/guides/spa-integration)
- [Mobile App Integration](/docs/guides/mobile-integration)
- [Backend-to-Backend Authentication](/docs/guides/b2b-auth)
- [Webhook Security](/docs/guides/webhook-security)

## Advanced Topics
- [Token Refresh Strategies](/docs/guides/token-refresh-strategies)
- [Concurrent Session Management](/docs/guides/concurrent-sessions)
- [Cross-Device Authentication](/docs/guides/cross-device-auth)
- [Passwordless Authentication](/docs/guides/passwordless) (future)
- [Biometric Authentication](/docs/guides/biometric) (future)

## Testing
- [Testing Authentication Flows](/docs/guides/testing)
- [Mocking API Responses](/docs/guides/mocking)
- [Integration Test Setup](/docs/guides/integration-tests)
```

### Code Examples

**Multi-language Examples**:
```markdown
# Complete Authentication Flow Examples

## JavaScript/TypeScript

### Registration

``javascript
import axios from 'axios';

const API_BASE_URL = 'https://api.sumafinance.com/v1';

async function register(email, password, name) {
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/register`, {
      email,
      password,
      name,
      gdpr_consent: {
        terms_accepted: true,
        privacy_accepted: true,
        marketing_accepted: false
      }
    });

    console.log('Registration successful:', response.data);
    return response.data;
  } catch (error) {
    if (error.response?.status === 409) {
      console.error('Email already exists');
    } else if (error.response?.status === 400) {
      const errors = error.response.data.errors;
      errors.forEach(err => console.error(`${err.title}: ${err.detail}`));
    }
    throw error;
  }
}

// Usage
await register('john.doe@example.com', 'SecureP@ssw0rd123!', 'John Doe');
``

### Login with Token Storage

``javascript
class AuthService {
  constructor() {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiry = null;
  }

  async login(email, password) {
    const response = await axios.post(`${API_BASE_URL}/auth/login`, {
      email,
      password
    });

    const { access_token, refresh_token, expires_in } = response.data.data;

    this.accessToken = access_token;
    this.refreshToken = refresh_token;
    this.tokenExpiry = Date.now() + (expires_in * 1000);

    // Store in sessionStorage (or httpOnly cookies for better security)
    sessionStorage.setItem('access_token', access_token);
    sessionStorage.setItem('refresh_token', refresh_token);
    sessionStorage.setItem('token_expiry', this.tokenExpiry.toString());

    return response.data;
  }

  async refreshTokenIfNeeded() {
    if (Date.now() >= this.tokenExpiry - 60000) { // Refresh 1 min before expiry
      await this.refreshAccessToken();
    }
  }

  async refreshAccessToken() {
    const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
      refresh_token: this.refreshToken
    });

    const { access_token, refresh_token, expires_in } = response.data.data;

    this.accessToken = access_token;
    this.refreshToken = refresh_token;
    this.tokenExpiry = Date.now() + (expires_in * 1000);

    sessionStorage.setItem('access_token', access_token);
    sessionStorage.setItem('refresh_token', refresh_token);
    sessionStorage.setItem('token_expiry', this.tokenExpiry.toString());
  }

  async makeAuthenticatedRequest(url, options = {}) {
    await this.refreshTokenIfNeeded();

    return axios({
      url,
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.accessToken}`
      }
    });
  }
}

// Usage
const auth = new AuthService();
await auth.login('john.doe@example.com', 'SecureP@ssw0rd123!');

// Make authenticated request
const user = await auth.makeAuthenticatedRequest(`${API_BASE_URL}/users/me`);
``

## Python

### Registration

``python
import requests
from typing import Dict, Any

API_BASE_URL = 'https://api.sumafinance.com/v1'

def register(email: str, password: str, name: str) -> Dict[str, Any]:
    """Register a new user account."""
    try:
        response = requests.post(
            f'{API_BASE_URL}/auth/register',
            json={
                'email': email,
                'password': password,
                'name': name,
                'gdpr_consent': {
                    'terms_accepted': True,
                    'privacy_accepted': True,
                    'marketing_accepted': False
                }
            },
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 409:
            print('Email already exists')
        elif e.response.status_code == 400:
            errors = e.response.json().get('errors', [])
            for error in errors:
                print(f"{error['title']}: {error['detail']}")
        raise

# Usage
result = register('john.doe@example.com', 'SecureP@ssw0rd123!', 'John Doe')
print(f"User created: {result['data']['id']}")
``

### Login with Token Management

``python
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class AuthClient:
    def __init__(self, base_url: str = 'https://api.sumafinance.com/v1'):
        self.base_url = base_url
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None

    def login(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate user and store tokens."""
        response = requests.post(
            f'{self.base_url}/auth/login',
            json={'email': email, 'password': password}
        )
        response.raise_for_status()

        data = response.json()['data']
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        self.token_expiry = datetime.now() + timedelta(seconds=data['expires_in'])

        return data

    def refresh_token_if_needed(self):
        """Refresh access token if it's about to expire."""
        if self.token_expiry and datetime.now() >= self.token_expiry - timedelta(minutes=1):
            self.refresh_access_token()

    def refresh_access_token(self):
        """Refresh the access token using refresh token."""
        response = requests.post(
            f'{self.base_url}/auth/refresh',
            json={'refresh_token': self.refresh_token}
        )
        response.raise_for_status()

        data = response.json()['data']
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        self.token_expiry = datetime.now() + timedelta(seconds=data['expires_in'])

    def make_authenticated_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make an authenticated API request with automatic token refresh."""
        self.refresh_token_if_needed()

        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {self.access_token}'

        response = requests.request(
            method,
            f'{self.base_url}{endpoint}',
            headers=headers,
            **kwargs
        )
        response.raise_for_status()
        return response

# Usage
client = AuthClient()
client.login('john.doe@example.com', 'SecureP@ssw0rd123!')

# Make authenticated request
response = client.make_authenticated_request('GET', '/users/me')
user = response.json()
print(f"Logged in as: {user['data']['name']}")
``

## Go

### Registration

``go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

const APIBaseURL = "https://api.sumafinance.com/v1"

type GDPRConsent struct {
    TermsAccepted     bool `json:"terms_accepted"`
    PrivacyAccepted   bool `json:"privacy_accepted"`
    MarketingAccepted bool `json:"marketing_accepted"`
}

type RegisterRequest struct {
    Email       string      `json:"email"`
    Password    string      `json:"password"`
    Name        string      `json:"name"`
    GDPRConsent GDPRConsent `json:"gdpr_consent"`
}

type User struct {
    ID            string `json:"id"`
    Email         string `json:"email"`
    Name          string `json:"name"`
    EmailVerified bool   `json:"email_verified"`
}

type RegisterResponse struct {
    Data struct {
        User
    } `json:"data"`
    Message string `json:"message"`
}

func Register(email, password, name string) (*User, error) {
    reqBody := RegisterRequest{
        Email:    email,
        Password: password,
        Name:     name,
        GDPRConsent: GDPRConsent{
            TermsAccepted:     true,
            PrivacyAccepted:   true,
            MarketingAccepted: false,
        },
    }

    jsonData, err := json.Marshal(reqBody)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    resp, err := http.Post(
        fmt.Sprintf("%s/auth/register", APIBaseURL),
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusCreated {
        return nil, fmt.Errorf("registration failed with status: %d", resp.StatusCode)
    }

    var result RegisterResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return &result.Data.User, nil
}

func main() {
    user, err := Register("john.doe@example.com", "SecureP@ssw0rd123!", "John Doe")
    if err != nil {
        panic(err)
    }
    fmt.Printf("User created: %s (%s)\n", user.Name, user.ID)
}
``

### Login with Token Management

``go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type AuthClient struct {
    BaseURL      string
    AccessToken  string
    RefreshToken string
    TokenExpiry  time.Time
    HTTPClient   *http.Client
}

type LoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

type LoginResponse struct {
    Data struct {
        AccessToken  string `json:"access_token"`
        RefreshToken string `json:"refresh_token"`
        ExpiresIn    int    `json:"expires_in"`
    } `json:"data"`
}

func NewAuthClient(baseURL string) *AuthClient {
    return &AuthClient{
        BaseURL:    baseURL,
        HTTPClient: &http.Client{Timeout: 10 * time.Second},
    }
}

func (c *AuthClient) Login(email, password string) error {
    reqBody := LoginRequest{Email: email, Password: password}
    jsonData, _ := json.Marshal(reqBody)

    resp, err := c.HTTPClient.Post(
        fmt.Sprintf("%s/auth/login", c.BaseURL),
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("login failed: %d", resp.StatusCode)
    }

    var result LoginResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return err
    }

    c.AccessToken = result.Data.AccessToken
    c.RefreshToken = result.Data.RefreshToken
    c.TokenExpiry = time.Now().Add(time.Duration(result.Data.ExpiresIn) * time.Second)

    return nil
}

func (c *AuthClient) RefreshTokenIfNeeded() error {
    if time.Now().After(c.TokenExpiry.Add(-1 * time.Minute)) {
        return c.RefreshAccessToken()
    }
    return nil
}

func (c *AuthClient) RefreshAccessToken() error {
    reqBody := map[string]string{"refresh_token": c.RefreshToken}
    jsonData, _ := json.Marshal(reqBody)

    resp, err := c.HTTPClient.Post(
        fmt.Sprintf("%s/auth/refresh", c.BaseURL),
        "application/json",
        bytes.NewBuffer(jsonData),
    )
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    var result LoginResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return err
    }

    c.AccessToken = result.Data.AccessToken
    c.RefreshToken = result.Data.RefreshToken
    c.TokenExpiry = time.Now().Add(time.Duration(result.Data.ExpiresIn) * time.Second)

    return nil
}

func (c *AuthClient) MakeAuthenticatedRequest(method, endpoint string) (*http.Response, error) {
    if err := c.RefreshTokenIfNeeded(); err != nil {
        return nil, err
    }

    req, err := http.NewRequest(method, fmt.Sprintf("%s%s", c.BaseURL, endpoint), nil)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.AccessToken))
    req.Header.Set("Content-Type", "application/json")

    return c.HTTPClient.Do(req)
}

func main() {
    client := NewAuthClient("https://api.sumafinance.com/v1")

    if err := client.Login("john.doe@example.com", "SecureP@ssw0rd123!"); err != nil {
        panic(err)
    }

    resp, err := client.MakeAuthenticatedRequest("GET", "/users/me")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("User: %+v\n", result["data"])
}
``

## Ruby

### Registration

``ruby
require 'net/http'
require 'json'
require 'uri'

API_BASE_URL = 'https://api.sumafinance.com/v1'

def register(email, password, name)
  uri = URI("#{API_BASE_URL}/auth/register")

  request = Net::HTTP::Post.new(uri)
  request['Content-Type'] = 'application/json'
  request.body = {
    email: email,
    password: password,
    name: name,
    gdpr_consent: {
      terms_accepted: true,
      privacy_accepted: true,
      marketing_accepted: false
    }
  }.to_json

  response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
    http.request(request)
  end

  if response.code == '201'
    JSON.parse(response.body)
  else
    raise "Registration failed: #{response.code} - #{response.body}"
  end
end

# Usage
result = register('john.doe@example.com', 'SecureP@ssw0rd123!', 'John Doe')
puts "User created: #{result['data']['id']}"
``

### Login with Token Management

``ruby
require 'net/http'
require 'json'
require 'uri'
require 'time'

class AuthClient
  attr_reader :base_url, :access_token, :refresh_token, :token_expiry

  def initialize(base_url = 'https://api.sumafinance.com/v1')
    @base_url = base_url
    @access_token = nil
    @refresh_token = nil
    @token_expiry = nil
  end

  def login(email, password)
    uri = URI("#{@base_url}/auth/login")
    request = Net::HTTP::Post.new(uri)
    request['Content-Type'] = 'application/json'
    request.body = { email: email, password: password }.to_json

    response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
      http.request(request)
    end

    raise "Login failed: #{response.code}" unless response.code == '200'

    data = JSON.parse(response.body)['data']
    @access_token = data['access_token']
    @refresh_token = data['refresh_token']
    @token_expiry = Time.now + data['expires_in']

    data
  end

  def refresh_token_if_needed
    refresh_access_token if Time.now >= @token_expiry - 60
  end

  def refresh_access_token
    uri = URI("#{@base_url}/auth/refresh")
    request = Net::HTTP::Post.new(uri)
    request['Content-Type'] = 'application/json'
    request.body = { refresh_token: @refresh_token }.to_json

    response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
      http.request(request)
    end

    data = JSON.parse(response.body)['data']
    @access_token = data['access_token']
    @refresh_token = data['refresh_token']
    @token_expiry = Time.now + data['expires_in']
  end

  def make_authenticated_request(method, endpoint)
    refresh_token_if_needed

    uri = URI("#{@base_url}#{endpoint}")
    request = Net::HTTP.const_get(method.capitalize).new(uri)
    request['Authorization'] = "Bearer #{@access_token}"
    request['Content-Type'] = 'application/json'

    Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
      http.request(request)
    end
  end
end

# Usage
client = AuthClient.new
client.login('john.doe@example.com', 'SecureP@ssw0rd123!')

response = client.make_authenticated_request(:get, '/users/me')
user = JSON.parse(response.body)
puts "Logged in as: #{user['data']['name']}"
``

## cURL

### Complete Authentication Flow

``bash
#!/bin/bash

API_BASE_URL="https://api.sumafinance.com/v1"

# 1. Register
echo "Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE_URL/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecureP@ssw0rd123!",
    "name": "John Doe",
    "gdpr_consent": {
      "terms_accepted": true,
      "privacy_accepted": true,
      "marketing_accepted": false
    }
  }')

USER_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.data.id')
echo "User created: $USER_ID"

# 2. Login
echo "Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecureP@ssw0rd123!"
  }')

ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.access_token')
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.refresh_token')
echo "Login successful"

# 3. Get user profile
echo "Fetching user profile..."
USER_RESPONSE=$(curl -s -X GET "$API_BASE_URL/users/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json")

echo "User: $(echo "$USER_RESPONSE" | jq -r '.data.name')"

# 4. Refresh token
echo "Refreshing token..."
REFRESH_RESPONSE=$(curl -s -X POST "$API_BASE_URL/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")

ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.data.access_token')
REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.data.refresh_token')
echo "Token refreshed"

# 5. Logout
echo "Logging out..."
curl -s -X POST "$API_BASE_URL/auth/logout" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"all_devices": false}'

echo "Logout successful"
``
```

### Error Reference

**Location**: `/docs/guides/error-handling.md`

**Content** (excerpt):
```markdown
# Error Reference

## Error Response Format

All error responses follow the JSON:API error format:

``json
{
  "errors": [
    {
      "id": "error-uuid",              // Unique error ID for support
      "status": "400",                  // HTTP status code
      "code": "VALIDATION_ERROR",       // Machine-readable error code
      "title": "Validation Failed",     // Human-readable error summary
      "detail": "Specific error message", // Detailed explanation
      "source": {
        "pointer": "/data/attributes/email" // JSON Pointer to error location
      }
    }
  ]
}
``

## Authentication Errors (401)

### AUTHENTICATION_REQUIRED

**Meaning**: No authentication token provided or token is missing.

**HTTP Status**: 401 Unauthorized

**Solution**: Include a valid JWT access token in the `Authorization` header:
``
Authorization: Bearer <access_token>
``

**Example**:
``json
{
  "errors": [{
    "status": "401",
    "code": "AUTHENTICATION_REQUIRED",
    "title": "Authentication Required",
    "detail": "Valid access token is required. Please log in."
  }]
}
``

### TOKEN_EXPIRED

**Meaning**: Access token has expired (after 15 minutes).

**HTTP Status**: 401 Unauthorized

**Solution**: Use your refresh token to obtain a new access token via `POST /auth/refresh`.

**Example**:
``json
{
  "errors": [{
    "status": "401",
    "code": "TOKEN_EXPIRED",
    "title": "Token Expired",
    "detail": "Access token has expired. Please refresh your token."
  }]
}
``

### INVALID_TOKEN

**Meaning**: Token is malformed, tampered with, or signature is invalid.

**HTTP Status**: 401 Unauthorized

**Solution**: Log in again to obtain a new token. If this persists, check that you're using the correct token format.

**Example**:
``json
{
  "errors": [{
    "status": "401",
    "code": "INVALID_TOKEN",
    "title": "Invalid Token",
    "detail": "The provided token is invalid or malformed."
  }]
}
``

### INVALID_CREDENTIALS

**Meaning**: Email or password is incorrect during login.

**HTTP Status**: 401 Unauthorized

**Solution**: Verify the email and password are correct. Check for:
- Typos in email or password
- Correct account (user may have multiple accounts)
- Password was not changed recently

After 5 failed attempts, the account will be temporarily locked.

**Example**:
``json
{
  "errors": [{
    "status": "401",
    "code": "INVALID_CREDENTIALS",
    "title": "Authentication Failed",
    "detail": "Invalid email or password"
  }]
}
``

## Authorization Errors (403)

### ACCOUNT_LOCKED

**Meaning**: Account is temporarily locked due to 5 failed login attempts.

**HTTP Status**: 403 Forbidden

**Lockout Duration**: 15 minutes

**Solution**: 
1. Wait 15 minutes for automatic unlock
2. Use password reset flow if password is forgotten
3. Contact support if account remains locked

**Example**:
``json
{
  "errors": [{
    "status": "403",
    "code": "ACCOUNT_LOCKED",
    "title": "Account Locked",
    "detail": "Your account has been temporarily locked due to multiple failed login attempts. Please try again in 15 minutes or reset your password."
  }]
}
``

### REFRESH_TOKEN_REUSED

**Meaning**: Attempted to use a refresh token that was already used (potential security breach).

**HTTP Status**: 403 Forbidden

**Security Action**: All user sessions have been terminated.

**Solution**: Log in again with email and password. This may indicate:
- Multiple clients trying to refresh simultaneously (race condition)
- Token theft or session hijacking attempt

**Example**:
``json
{
  "errors": [{
    "status": "403",
    "code": "REFRESH_TOKEN_REUSED",
    "title": "Security Alert",
    "detail": "This refresh token has already been used. All sessions have been terminated for security. Please log in again."
  }]
}
``

## Validation Errors (422)

### PASSWORD_COMPLEXITY_ERROR

**Meaning**: Password does not meet complexity requirements.

**HTTP Status**: 422 Unprocessable Entity

**Password Requirements**:
- Minimum 12 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

**Example**:
``json
{
  "errors": [{
    "status": "422",
    "code": "PASSWORD_COMPLEXITY_ERROR",
    "title": "Password Complexity Error",
    "detail": "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
    "source": {
      "pointer": "/data/attributes/password"
    }
  }]
}
``

### INVALID_EMAIL_FORMAT

**Meaning**: Email address format is invalid.

**HTTP Status**: 422 Unprocessable Entity

**Solution**: Ensure email follows the format: `local-part@domain.tld`

**Example**:
``json
{
  "errors": [{
    "status": "422",
    "code": "INVALID_EMAIL_FORMAT",
    "title": "Invalid Email",
    "detail": "Email address format is invalid",
    "source": {
      "pointer": "/data/attributes/email"
    }
  }]
}
``

## Rate Limit Errors (429)

### RATE_LIMIT_EXCEEDED

**Meaning**: Too many requests to this endpoint in the rate limit window.

**HTTP Status**: 429 Too Many Requests

**Rate Limits**:
- **Login**: 5 attempts per minute per IP, 10 per hour per user
- **Registration**: 3 attempts per hour per IP
- **Password Reset**: 3 requests per hour per email
- **Refresh Token**: 10 requests per minute per user

**Solution**: 
1. Check `Retry-After` header for wait time
2. Implement exponential backoff
3. Cache tokens appropriately to reduce refresh calls

**Response Headers**:
- `X-RateLimit-Limit`: Total requests allowed
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Unix timestamp when limit resets
- `Retry-After`: Seconds to wait before retrying

**Example**:
``json
{
  "errors": [{
    "status": "429",
    "code": "RATE_LIMIT_EXCEEDED",
    "title": "Rate Limit Exceeded",
    "detail": "Too many requests. Please try again in 60 seconds."
  }]
}
``

**Backoff Strategy** (JavaScript):
``javascript
async function loginWithRetry(email, password, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await login(email, password);
    } catch (error) {
      if (error.response?.status === 429) {
        const retryAfter = parseInt(error.response.headers['retry-after'] || '60');
        console.log(`Rate limited. Retrying after ${retryAfter} seconds...`);
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
      } else {
        throw error;
      }
    }
  }
  throw new Error('Max retries exceeded');
}
``

## Complete Error Code Reference

| Code | HTTP Status | Category | Description |
|------|-------------|----------|-------------|
| AUTHENTICATION_REQUIRED | 401 | Auth | No token provided |
| TOKEN_EXPIRED | 401 | Auth | Access token expired |
| INVALID_TOKEN | 401 | Auth | Token is malformed or invalid |
| INVALID_CREDENTIALS | 401 | Auth | Wrong email or password |
| INVALID_REFRESH_TOKEN | 401 | Auth | Refresh token invalid or expired |
| ACCOUNT_LOCKED | 403 | Security | Account locked after failed attempts |
| REFRESH_TOKEN_REUSED | 403 | Security | Refresh token reuse detected |
| FORBIDDEN | 403 | Auth | Insufficient permissions |
| PASSWORD_COMPLEXITY_ERROR | 422 | Validation | Password doesn't meet requirements |
| INVALID_EMAIL_FORMAT | 422 | Validation | Email format is invalid |
| EMAIL_ALREADY_EXISTS | 409 | Conflict | Email is already registered |
| RATE_LIMIT_EXCEEDED | 429 | Rate Limit | Too many requests |
| INTERNAL_SERVER_ERROR | 500 | Server | Unexpected server error |
```

## Interactive Documentation

### API Playground

**Tool**: Swagger UI

**Location**: `/api-playground`

**Features**:
- Try all authentication endpoints in browser
- Pre-configured Bearer authentication
- Auto-populate request bodies with examples
- View real-time request/response
- Copy code snippets (cURL, JavaScript, Python, etc.)
- Test with production or staging environment

**Swagger UI Configuration**:
```javascript
// server.js (Express)
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./docs/openapi/v1.yaml');

app.use('/api-playground', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
  customCss: `
    .swagger-ui .topbar { display: none }
    .swagger-ui .info { margin: 20px 0 }
  `,
  customSiteTitle: "SUMA Finance API Playground",
  customfavIcon: "/favicon.ico",
  swaggerOptions: {
    persistAuthorization: true,  // Remember auth token between page reloads
    displayRequestDuration: true, // Show request timing
    filter: true,                 // Enable endpoint search
    tryItOutEnabled: true,        // Enable "Try it out" by default
    requestSnippetsEnabled: true  // Show code snippets
  }
}));
```

**Pre-configured Authentication**:
1. User logs in via `/auth/login` endpoint in playground
2. Clicks "Authorize" button at top
3. Pastes access token into Bearer auth field
4. All subsequent requests automatically include token

### Live Examples

Not applicable for authentication API (requires secure token handling). Users should use:
- Postman Collection (pre-configured)
- Official SDKs (handles tokens securely)
- Code examples in documentation

## SDK Documentation

### Official SDKs

**Languages**:
- **JavaScript/TypeScript**: `@sumafinance/auth-client`
- **Python**: `sumafinance-auth`
- **Go**: `github.com/sumafinance/auth-go`
- **Ruby**: `sumafinance-auth`

### JavaScript SDK Documentation

**Location**: `/docs/sdks/javascript.md`

**Content** (excerpt):
```markdown
# JavaScript SDK

## Installation

``bash
npm install @sumafinance/auth-client
``

## Quick Start

``javascript
import { AuthClient } from '@sumafinance/auth-client';

const auth = new AuthClient({
  baseURL: 'https://api.sumafinance.com/v1',
  onTokenRefresh: (tokens) => {
    // Save new tokens to storage
    sessionStorage.setItem('access_token', tokens.accessToken);
    sessionStorage.setItem('refresh_token', tokens.refreshToken);
  }
});

// Register
const user = await auth.register({
  email: 'john.doe@example.com',
  password: 'SecureP@ssw0rd123!',
  name: 'John Doe',
  gdprConsent: {
    termsAccepted: true,
    privacyAccepted: true
  }
});

// Login
const session = await auth.login({
  email: 'john.doe@example.com',
  password: 'SecureP@ssw0rd123!'
});

// Make authenticated request
const currentUser = await auth.users.me();
``

## API Reference

### `new AuthClient(options)`

Create a new authentication client.

**Parameters**:
- `options.baseURL` (string): API base URL (default: `https://api.sumafinance.com/v1`)
- `options.onTokenRefresh` (function): Callback when tokens are refreshed
- `options.autoRefresh` (boolean): Automatically refresh tokens (default: `true`)

### `auth.register(data)`

Register a new user account.

**Parameters**:
- `data.email` (string, required): User's email address
- `data.password` (string, required): Password (min 12 chars, complexity requirements)
- `data.name` (string, required): User's full name
- `data.gdprConsent` (object, required): GDPR consent object

**Returns**: `Promise<User>`

**Throws**: 
- `ValidationError`: Invalid input
- `ConflictError`: Email already exists

**Example**:
``javascript
try {
  const user = await auth.register({
    email: 'john.doe@example.com',
    password: 'SecureP@ssw0rd123!',
    name: 'John Doe',
    gdprConsent: {
      termsAccepted: true,
      privacyAccepted: true,
      marketingAccepted: false
    }
  });
  console.log(`User created: ${user.id}`);
} catch (error) {
  if (error instanceof ValidationError) {
    console.error('Validation errors:', error.errors);
  }
}
``
```

## Documentation Maintenance

### Auto-generation

**Generate OpenAPI from Go Code**:

Using swaggo annotations:
```go
// @Summary Register new user
// @Description Create a new user account with email and password
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration data"
// @Success 201 {object} RegisterResponse
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
    // Implementation
}
```

**Generate Command**:
```bash
# Install swag
go install github.com/swaggo/swag/cmd/swag@latest

# Generate OpenAPI spec
swag init -g server.go -o docs/openapi --parseDependency --parseInternal

# Convert JSON to YAML
yq eval -P docs/openapi/swagger.json > docs/openapi/v1.yaml
```

### CI/CD Integration

**Automated Documentation Pipeline**:
```yaml
# .github/workflows/docs.yml
name: Generate and Deploy API Docs

on:
  push:
    branches: [main, develop]
    paths:
      - 'src/**/*.go'
      - 'docs/**'

jobs:
  generate-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'

      - name: Install swag
        run: go install github.com/swaggo/swag/cmd/swag@latest

      - name: Generate OpenAPI Spec
        run: swag init -g src/server.go -o docs/openapi

      - name: Convert to YAML
        run: |
          npm install -g js-yaml
          js-yaml docs/openapi/swagger.json > docs/openapi/v1.yaml

      - name: Validate OpenAPI Spec
        run: |
          npm install -g @redocly/cli
          npx @redocly/cli lint docs/openapi/v1.yaml

      - name: Generate Static Documentation
        run: |
          npx @redocly/cli build-docs docs/openapi/v1.yaml \
            --output docs/api-reference/index.html \
            --title "SUMA Finance API Reference"

      - name: Deploy to GitHub Pages
        if: github.ref == 'refs/heads/main'
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./docs
          cname: docs.sumafinance.com
```

### Version Control

**Documentation Versioning Structure**:
```
/docs
  /v1
    /openapi.yaml
    /getting-started.md
    /guides/
    /examples/
  /v2
    /openapi.yaml
    /getting-started.md
    /guides/
    /migration/
      /v1-to-v2.md
```

**Version Switcher** (Docusaurus config):
```javascript
module.exports = {
  themeConfig: {
    navbar: {
      items: [
        {
          type: 'docsVersionDropdown',
          position: 'right',
          dropdownActiveClassDisabled: true,
        }
      ]
    }
  },
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          versions: {
            current: {
              label: 'v2 (Current)',
              path: 'v2',
            },
            '1.0.0': {
              label: 'v1 (Legacy)',
              path: 'v1',
              banner: 'warning',
              message: 'This version is deprecated. Please migrate to v2.'
            }
          }
        }
      }
    ]
  ]
};
```

### Review Process

**Documentation PR Checklist**:
```markdown
## Documentation Review Checklist

### Code Examples
- [ ] All code examples tested and working
- [ ] Examples provided in JavaScript, Python, Go, Ruby, cURL
- [ ] Error handling demonstrated
- [ ] Token refresh logic included

### API Documentation
- [ ] All endpoints documented with descriptions
- [ ] Request/response schemas defined
- [ ] Success response examples provided
- [ ] Error response examples for all error codes
- [ ] Rate limiting information included
- [ ] Authentication requirements specified

### OpenAPI Specification
- [ ] OpenAPI spec validates without errors
- [ ] All schemas have descriptions and examples
- [ ] Security schemes properly configured
- [ ] Response status codes documented
- [ ] Tags used for logical grouping

### Content Quality
- [ ] Links tested and working
- [ ] Spelling and grammar checked
- [ ] Screenshots updated (if UI changes)
- [ ] Code formatting consistent
- [ ] Markdown formatting correct

### Security
- [ ] No API keys or secrets in examples
- [ ] Security best practices documented
- [ ] GDPR compliance information accurate
- [ ] Rate limits clearly specified

### Completeness
- [ ] Getting Started guide updated
- [ ] SDK documentation updated
- [ ] Error reference updated
- [ ] Changelog updated
- [ ] Migration guide (if breaking changes)
```

## Documentation Hosting

### Static Site Generator

**Tool**: Docusaurus

**Why Docusaurus**:
- React-based, fast and modern
- Built-in versioning support
- Excellent search (Algolia integration)
- MDX support (interactive components)
- OpenAPI plugin available
- Active community and maintenance

**Docusaurus Configuration**:
```javascript
// docusaurus.config.js
module.exports = {
  title: 'SUMA Finance API Documentation',
  tagline: 'Secure authentication for fintech applications',
  url: 'https://docs.sumafinance.com',
  baseUrl: '/',
  favicon: 'img/favicon.ico',

  organizationName: 'sumafinance',
  projectName: 'api-docs',

  themeConfig: {
    navbar: {
      title: 'SUMA Finance',
      logo: {
        alt: 'SUMA Finance Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          to: 'docs/getting-started',
          label: 'Docs',
          position: 'left'
        },
        {
          to: 'docs/api-reference',
          label: 'API Reference',
          position: 'left'
        },
        {
          to: 'docs/guides',
          label: 'Guides',
          position: 'left'
        },
        {
          href: '/api-playground',
          label: 'API Playground',
          position: 'right'
        },
        {
          href: 'https://github.com/sumafinance',
          label: 'GitHub',
          position: 'right'
        }
      ]
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            { label: 'Getting Started', to: 'docs/getting-started' },
            { label: 'API Reference', to: 'docs/api-reference' },
            { label: 'Guides', to: 'docs/guides' }
          ]
        },
        {
          title: 'SDKs',
          items: [
            { label: 'JavaScript', to: 'docs/sdks/javascript' },
            { label: 'Python', to: 'docs/sdks/python' },
            { label: 'Go', to: 'docs/sdks/go' },
            { label: 'Ruby', to: 'docs/sdks/ruby' }
          ]
        },
        {
          title: 'Support',
          items: [
            { label: 'API Status', href: 'https://status.sumafinance.com' },
            { label: 'Contact Support', href: 'mailto:api-support@sumafinance.com' },
            { label: 'GitHub', href: 'https://github.com/sumafinance/api-issues' }
          ]
        }
      ],
      copyright: `Copyright © ${new Date().getFullYear()} SUMA Finance. Built with Docusaurus.`
    },
    algolia: {
      apiKey: 'YOUR_ALGOLIA_API_KEY',
      indexName: 'sumafinance',
      contextualSearch: true,
      searchParameters: {},
    },
    prism: {
      theme: require('prism-react-renderer/themes/github'),
      darkTheme: require('prism-react-renderer/themes/dracula'),
      additionalLanguages: ['bash', 'ruby', 'go']
    }
  },

  plugins: [
    [
      'docusaurus-plugin-openapi-docs',
      {
        id: 'openapi',
        docsPluginId: 'classic',
        config: {
          auth: {
            specPath: 'docs/openapi/v1.yaml',
            outputDir: 'docs/api-reference',
            sidebarOptions: {
              groupPathsBy: 'tag'
            }
          }
        }
      }
    ]
  ],

  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/sumafinance/api-docs/edit/main/',
          remarkPlugins: [require('remark-code-import')],
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css')
        }
      }
    ]
  ]
};
```

### Search

**Algolia DocSearch Configuration**:
```json
{
  "index_name": "sumafinance",
  "start_urls": [
    {
      "url": "https://docs.sumafinance.com/docs/",
      "tags": ["docs"],
      "selectors_key": "docs"
    },
    {
      "url": "https://docs.sumafinance.com/docs/api-reference/",
      "tags": ["api"],
      "selectors_key": "api"
    }
  ],
  "selectors": {
    "docs": {
      "lvl0": ".menu__link--sublist.menu__link--active",
      "lvl1": "article h1",
      "lvl2": "article h2",
      "lvl3": "article h3",
      "text": "article p, article li"
    },
    "api": {
      "lvl0": {
        "selector": ".openapi-tabs__heading",
        "global": true
      },
      "lvl1": "article h1",
      "lvl2": "article h2",
      "text": "article p, article li, article code"
    }
  }
}
```

## Analytics & Feedback

### Track Documentation Usage

**Metrics to Track**:
- **Page Views**: Most/least visited endpoints
- **Search Queries**: What users are looking for
- **Time on Page**: Which pages need improvement
- **Exit Pages**: Where users get stuck
- **External Link Clicks**: SDK downloads, support contacts
- **Playground Usage**: Most-tested endpoints

**Google Analytics 4 Configuration**:
```javascript
// docusaurus.config.js
module.exports = {
  themeConfig: {
    gtag: {
      trackingID: 'G-XXXXXXXXXX',
      anonymizeIP: true
    }
  },
  plugins: [
    [
      '@docusaurus/plugin-google-gtag',
      {
        trackingID: 'G-XXXXXXXXXX',
        anonymizeIP: true
      }
    ]
  ]
};
```

**Custom Events**:
```javascript
// Track API playground usage
gtag('event', 'api_playground_test', {
  endpoint: '/auth/login',
  method: 'POST',
  status_code: 200
});

// Track SDK download
gtag('event', 'sdk_download', {
  language: 'javascript',
  version: '1.0.0'
});

// Track search queries
gtag('event', 'search', {
  search_term: 'refresh token'
});
```

### Feedback Mechanism

**Feedback Widget**:
```html
<!-- docs/src/components/FeedbackWidget.jsx -->
<div className="feedback-widget">
  <p>Was this page helpful?</p>
  <div className="feedback-buttons">
    <button onClick={() => sendFeedback('yes')} className="btn-yes">
      👍 Yes
    </button>
    <button onClick={() => sendFeedback('no')} className="btn-no">
      👎 No
    </button>
  </div>
  {showFollowUp && (
    <textarea
      placeholder="Tell us more (optional)"
      onChange={(e) => setComment(e.target.value)}
    />
  )}
</div>

<script>
function sendFeedback(helpful) {
  gtag('event', 'feedback', {
    page: window.location.pathname,
    helpful: helpful
  });
  
  fetch('https://api.sumafinance.com/internal/feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      page: window.location.pathname,
      helpful: helpful,
      comment: comment,
      user_agent: navigator.userAgent
    })
  });
  
  setShowFollowUp(true);
}
</script>
```

## Best Practices

### Writing Style

**DO**:
- ✅ Use active voice ("Send a POST request" not "A POST request should be sent")
- ✅ Write short, scannable sentences (max 20-25 words)
- ✅ Include code examples for every concept
- ✅ Explain "why" behind security decisions (builds trust)
- ✅ Document common pitfalls ("⚠️ Warning: Refresh tokens must be rotated")
- ✅ Test all examples before publishing
- ✅ Use real-world data in examples (not "foo@bar.com")

**DON'T**:
- ❌ Use jargon without explanation ("JWT", "PKCE", "Argon2id" need context)
- ❌ Assume prior security knowledge (explain concepts)
- ❌ Write long paragraphs (break into lists and headings)
- ❌ Skip error scenarios (show what can go wrong)
- ❌ Use broken links (validate in CI)
- ❌ Show secrets in examples (use placeholders)

### Code Examples

**Requirements**:
- ✅ Tested and working (run in CI)
- ✅ Include error handling (try/catch, status checks)
- ✅ Show both request and response
- ✅ Use realistic data (actual email formats, proper passwords)
- ✅ Comment complex parts (token refresh logic)
- ✅ Follow language best practices (async/await in JS, context in Go)
- ✅ Include security notes (where to store tokens)

### Maintenance

**Quarterly Documentation Audit**:
```markdown
## Q1 2025 Documentation Audit

### Review Checklist
- [ ] Test all code examples (automated in CI)
- [ ] Update deprecated endpoints (mark as deprecated in OpenAPI)
- [ ] Fix broken links (automated link checker)
- [ ] Update screenshots (automation flow changed)
- [ ] Review user feedback (10+ requests for WebAuthn docs)
- [ ] Update SDK versions (new JavaScript SDK v2.0.0)
- [ ] Check error codes (new ACCOUNT_SUSPENDED code added)
- [ ] Review rate limits (login limit increased to 10/min)
- [ ] Update compliance information (new GDPR requirements)

### Action Items
- Add WebAuthn/Passkey documentation (high demand)
- Update JavaScript SDK examples to v2.0.0
- Add troubleshooting guide for mobile apps
- Improve 2FA setup guide with screenshots
- Add video tutorial for quick start
```

## Appendix

### Documentation Checklist

**For Each Endpoint**:
- [ ] Clear description (what it does, when to use)
- [ ] Authentication requirements (Bearer token, OAuth, none)
- [ ] Request parameters (path, query, headers)
- [ ] Request body schema (with examples)
- [ ] Response schema (success case)
- [ ] Success response example (realistic data)
- [ ] Error response examples (401, 403, 422, 429, 500)
- [ ] Code examples (JavaScript, Python, Go, Ruby, cURL)
- [ ] Rate limit information (requests per minute/hour)
- [ ] Related endpoints (links to similar operations)
- [ ] Security notes (GDPR implications, PII handling)
- [ ] Versioning notes (deprecated, new in v2)

### Tools Comparison

| Tool | Type | Best For | Hosting | Cost | Pros | Cons |
|------|------|----------|---------|------|------|------|
| **Swagger UI** | Interactive | API testing | Self-hosted | Free | Standard, interactive | Basic design |
| **Redoc** | Static | Beautiful docs | Self-hosted | Free | Beautiful, responsive | No try-it-out |
| **Postman** | Collection | API testing | Cloud | Free/Paid | Powerful testing | Not web-friendly |
| **Docusaurus** | Static site | Complete docs | Self-hosted | Free | Modern, fast, versioning | React knowledge needed |
| **GitBook** | Hosted | Quick setup | Cloud | Paid | Easy, beautiful | Limited customization |
| **ReadMe** | Hosted | All-in-one | Cloud | Paid | Interactive, analytics | Expensive |
| **Stoplight** | Hosted | API design-first | Cloud | Paid | Collaborative | Learning curve |

### Resources

**OpenAPI & Documentation**:
- [OpenAPI 3.0 Specification](https://swagger.io/specification/)
- [OpenAPI Best Practices](https://swagger.io/blog/api-documentation/)
- [JSON:API Error Format](https://jsonapi.org/format/#errors)

**Writing & Style**:
- [Write the Docs Community](https://www.writethedocs.org/)
- [Google Developer Documentation Style Guide](https://developers.google.com/style)
- [Microsoft Writing Style Guide](https://learn.microsoft.com/en-us/style-guide/)

**Tools**:
- [Swagger Editor](https://editor.swagger.io/) - Online OpenAPI editor
- [Redocly CLI](https://redocly.com/docs/cli/) - OpenAPI linting and docs generation
- [Stoplight Studio](https://stoplight.io/studio) - Visual OpenAPI editor
- [Docusaurus](https://docusaurus.io/) - Static site generator
- [Algolia DocSearch](https://docsearch.algolia.com/) - Free search for docs

**Security Documentation**:
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [JWT Best Practices](https://curity.io/resources/learn/jwt-best-practices/)
- [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749)

**Compliance**:
- [GDPR Documentation Requirements](https://gdpr.eu/documentation/)
- [PCI DSS Documentation Guide](https://www.pcisecuritystandards.org/)