---
layout: default
title: Graphql Schema
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

# GRAPHQL SCHEMA DESIGN

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: APIs
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

The SUMA Finance Authentication API provides a comprehensive GraphQL interface for user registration, authentication, session management, and security features. This schema implements enterprise-grade security controls including JWT-based authentication with refresh token rotation, email-based two-factor authentication, GDPR-compliant consent management, and extensive audit logging. The API is designed to meet OWASP Top 10 requirements, GDPR, PCI-DSS, SOC 2, and ISO 27001 compliance standards for fintech applications.

The schema follows a schema-first approach with strong typing, comprehensive error handling, and mutation payload patterns that provide detailed success/failure information. All authentication operations are instrumented with security event logging, rate limiting, and account lockout protections. The design supports both web and mobile clients with biometric authentication capabilities, device management, and session tracking across multiple devices.

Key operations include user registration with email verification, secure login with JWT tokens, refresh token rotation with reuse detection, password reset flows with signed tokens, email-based OTP for 2FA, GDPR consent tracking, device fingerprinting, security event auditing, and social login integration. The schema is optimized for performance with DataLoader implementations to prevent N+1 queries and Redis-backed caching for session lookups.

## GraphQL Design Principles

### Why GraphQL
- **Flexible Queries**: Clients request exactly what they need (minimize data exposure)
- **Single Endpoint**: All operations through one URL (simplified security boundary)
- **Strong Typing**: Schema-first development with type safety (prevent data leaks)
- **Real-time**: Built-in subscriptions for security alerts and session updates
- **Efficient**: Reduce over-fetching and under-fetching (performance optimization)
- **Introspection**: Self-documenting API (developer experience)

### Schema-First Approach
1. Define schema (types, queries, mutations, subscriptions)
2. Generate TypeScript types for type safety
3. Implement resolvers with security middleware
4. Write comprehensive unit and integration tests
5. Generate API documentation from schema

### Design Philosophy
- Intuitive type naming (User, Session, SecurityEvent)
- Consistent field naming (camelCase)
- Nullable by default, non-null where critical (id, email, tokens)
- Pagination for all lists (security events, sessions, devices)
- Rich error messages with codes and field-level errors
- Versioning through field deprecation (maintain backwards compatibility)
- Security-first design (authentication required by default)

## GraphQL Endpoint

### URL
- **Production**: `https://api.suma.finance/graphql`
- **Staging**: `https://staging-api.suma.finance/graphql`
- **Development**: `https://dev-api.suma.finance/graphql`

### Protocol
- **Method**: POST
- **Content-Type**: application/json
- **Accept**: application/json
- **TLS**: TLS 1.3 only (enforced)

### GraphQL Playground
- **Development**: `https://dev-api.suma.finance/graphql` (interactive IDE with authentication)
- **Staging**: `https://staging-api.suma.finance/graphql` (require API key)
- **Production**: Disabled (use external GraphiQL with authentication)

### CORS Configuration
```
Access-Control-Allow-Origin: https://suma.finance, https://app.suma.finance
Access-Control-Allow-Methods: POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, X-Request-ID, X-Device-ID
Access-Control-Max-Age: 86400
```

## Authentication & Authorization

### Authentication
**Method**: Bearer Token (JWT) in Authorization header

**HTTP Headers**:
```http
POST /graphql
Authorization: Bearer {jwt_access_token}
Content-Type: application/json
X-Request-ID: {uuid}
X-Device-ID: {device_fingerprint}
X-Client-Version: {app_version}
```

**JWT Structure (Access Token)**:
```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "roles": ["user"],
  "permissions": ["auth:read", "auth:write"],
  "session_id": "session-uuid",
  "device_id": "device-fingerprint",
  "iat": 1234567890,
  "exp": 1234568790,
  "iss": "suma.finance",
  "aud": "suma.finance"
}
```

**JWT Expiration**:
- Access Token: 15 minutes
- Refresh Token: 7 days
- Email Verification Token: 24 hours
- Password Reset Token: 1 hour
- OTP: 5 minutes

**GraphQL Context**:
```typescript
interface Context {
  user?: {
    id: UUID;
    email: Email;
    emailVerified: boolean;
    roles: UserRole[];
    permissions: Permission[];
    sessionId: UUID;
    deviceId: string;
    mfaVerified: boolean;
  };
  requestId: UUID;
  deviceId?: string;
  clientVersion?: string;
  ipAddress: string;
  userAgent: string;
  cache: KeyValueCache;
  loaders: {
    userLoader: DataLoader<UUID, User>;
    sessionLoader: DataLoader<UUID, Session>;
    deviceLoader: DataLoader<UUID, Device>;
    consentLoader: DataLoader<UUID, Consent[]>;
  };
}
```

### Authorization Directives

**Schema Directives**:
```graphql
directive @auth(requires: [Permission!]) on FIELD_DEFINITION | OBJECT
directive @rateLimit(limit: Int!, window: Int!) on FIELD_DEFINITION
directive @mfaRequired on FIELD_DEFINITION

enum Permission {
  # Authentication permissions
  AUTH_READ
  AUTH_WRITE
  AUTH_DELETE
  
  # User management permissions
  USER_READ
  USER_WRITE
  USER_DELETE
  
  # Security permissions
  SECURITY_ADMIN
  AUDIT_READ
  
  # Admin permissions
  ADMIN_ACCESS
}

enum UserRole {
  USER
  ADMIN
  SECURITY_OFFICER
  COMPLIANCE_OFFICER
  SUPPORT
}
```

**Usage Example**:
```graphql
type Query {
  """Get current authenticated user"""
  me: User! @auth(requires: [AUTH_READ])
  
  """Get user by ID (admin only)"""
  user(id: UUID!): User @auth(requires: [USER_READ, ADMIN_ACCESS])
  
  """List all users (admin only)"""
  users(
    first: Int = 20
    after: String
    filter: UserFilterInput
  ): UserConnection! @auth(requires: [USER_READ, ADMIN_ACCESS])
  
  """Get security audit log"""
  securityEvents(
    first: Int = 50
    after: String
    filter: SecurityEventFilterInput
  ): SecurityEventConnection! @auth(requires: [AUDIT_READ]) @rateLimit(limit: 10, window: 60)
}

type Mutation {
  """Update user profile"""
  updateProfile(input: UpdateProfileInput!): UpdateProfilePayload! 
    @auth(requires: [AUTH_WRITE])
  
  """Change password (requires current password)"""
  changePassword(input: ChangePasswordInput!): ChangePasswordPayload! 
    @auth(requires: [AUTH_WRITE]) @mfaRequired
  
  """Delete user account (requires password confirmation)"""
  deleteAccount(password: String!): DeleteAccountPayload! 
    @auth(requires: [AUTH_DELETE]) @mfaRequired
}
```

## Schema Definition

### Scalar Types

**Custom Scalars**:
```graphql
"""ISO 8601 date-time string (2025-01-15T10:30:00Z)"""
scalar DateTime

"""Email address (RFC 5322 compliant)"""
scalar Email

"""UUID v4 identifier"""
scalar UUID

"""URL string (https only in production)"""
scalar URL

"""JSON object"""
scalar JSON

"""Positive integer (> 0)"""
scalar PositiveInt

"""Non-negative integer (>= 0)"""
scalar NonNegativeInt

"""Phone number in E.164 format (+351912345678)"""
scalar PhoneNumber

"""IP address (IPv4 or IPv6)"""
scalar IPAddress

"""JWT token string"""
scalar JWT

"""Base64 encoded string"""
scalar Base64

"""6-digit OTP code"""
scalar OTP
```

**Scalar Implementation** (TypeScript):
```typescript
import { GraphQLScalarType, Kind, GraphQLError } from 'graphql';
import validator from 'validator';

export const EmailScalar = new GraphQLScalarType({
  name: 'Email',
  description: 'Email address (RFC 5322 compliant)',
  serialize(value: string): string {
    if (!validator.isEmail(value)) {
      throw new GraphQLError('Invalid email format');
    }
    return value.toLowerCase();
  },
  parseValue(value: string): string {
    if (!validator.isEmail(value)) {
      throw new GraphQLError('Invalid email format');
    }
    return value.toLowerCase();
  },
  parseLiteral(ast): string | null {
    if (ast.kind === Kind.STRING) {
      if (!validator.isEmail(ast.value)) {
        throw new GraphQLError('Invalid email format');
      }
      return ast.value.toLowerCase();
    }
    return null;
  }
});

export const UUIDScalar = new GraphQLScalarType({
  name: 'UUID',
  description: 'UUID v4 identifier',
  serialize(value: string): string {
    if (!validator.isUUID(value, 4)) {
      throw new GraphQLError('Invalid UUID format');
    }
    return value;
  },
  parseValue(value: string): string {
    if (!validator.isUUID(value, 4)) {
      throw new GraphQLError('Invalid UUID format');
    }
    return value;
  },
  parseLiteral(ast): string | null {
    if (ast.kind === Kind.STRING && validator.isUUID(ast.value, 4)) {
      return ast.value;
    }
    return null;
  }
});

export const OTPScalar = new GraphQLScalarType({
  name: 'OTP',
  description: '6-digit OTP code',
  serialize(value: string): string {
    return value;
  },
  parseValue(value: string): string {
    if (!/^\d{6}$/.test(value)) {
      throw new GraphQLError('OTP must be a 6-digit number');
    }
    return value;
  },
  parseLiteral(ast): string | null {
    if (ast.kind === Kind.STRING && /^\d{6}$/.test(ast.value)) {
      return ast.value;
    }
    return null;
  }
});
```

### Enums

```graphql
"""User account status"""
enum UserStatus {
  """Account is active and verified"""
  ACTIVE
  
  """Account pending email verification"""
  PENDING_VERIFICATION
  
  """Account temporarily suspended"""
  SUSPENDED
  
  """Account locked due to security reasons"""
  LOCKED
  
  """Account closed by user"""
  CLOSED
  
  """Account banned by admin"""
  BANNED
}

"""Two-factor authentication method"""
enum MFAMethod {
  """Email-based OTP"""
  EMAIL_OTP
  
  """SMS-based OTP"""
  SMS_OTP
  
  """Authenticator app (TOTP)"""
  TOTP
  
  """Backup recovery codes"""
  RECOVERY_CODE
}

"""Session status"""
enum SessionStatus {
  """Session is active"""
  ACTIVE
  
  """Session expired"""
  EXPIRED
  
  """Session revoked by user"""
  REVOKED
  
  """Session terminated by system"""
  TERMINATED
}

"""Device trust level"""
enum DeviceTrustLevel {
  """Device is trusted"""
  TRUSTED
  
  """Device is known but not trusted"""
  KNOWN
  
  """Device is unknown"""
  UNKNOWN
  
  """Device is blocked"""
  BLOCKED
}

"""Security event type"""
enum SecurityEventType {
  # Authentication events
  LOGIN_SUCCESS
  LOGIN_FAILED
  LOGOUT
  
  # Registration events
  REGISTRATION_STARTED
  REGISTRATION_COMPLETED
  EMAIL_VERIFIED
  
  # Password events
  PASSWORD_CHANGED
  PASSWORD_RESET_REQUESTED
  PASSWORD_RESET_COMPLETED
  
  # MFA events
  MFA_ENABLED
  MFA_DISABLED
  MFA_VERIFIED
  MFA_FAILED
  
  # Session events
  SESSION_CREATED
  SESSION_REFRESHED
  SESSION_REVOKED
  REFRESH_TOKEN_ROTATED
  REFRESH_TOKEN_REUSE_DETECTED
  
  # Security events
  ACCOUNT_LOCKED
  ACCOUNT_UNLOCKED
  SUSPICIOUS_ACTIVITY
  DEVICE_TRUSTED
  DEVICE_BLOCKED
  
  # Profile events
  PROFILE_UPDATED
  EMAIL_CHANGED
  PHONE_CHANGED
  
  # Account events
  ACCOUNT_DELETED
  ACCOUNT_SUSPENDED
  ACCOUNT_REACTIVATED
}

"""Security event severity"""
enum SecurityEventSeverity {
  INFO
  WARNING
  ERROR
  CRITICAL
}

"""GDPR consent type"""
enum ConsentType {
  """Terms of Service"""
  TERMS_OF_SERVICE
  
  """Privacy Policy"""
  PRIVACY_POLICY
  
  """Marketing communications"""
  MARKETING
  
  """Data processing"""
  DATA_PROCESSING
  
  """Third-party data sharing"""
  THIRD_PARTY_SHARING
  
  """Cookies"""
  COOKIES
}

"""Sort order"""
enum SortOrder {
  ASC
  DESC
}

"""OAuth provider"""
enum OAuthProvider {
  GOOGLE
  APPLE
  FACEBOOK
}
```

### Object Types

#### User Type
```graphql
"""Represents a user in SUMA Finance"""
type User {
  """Unique user identifier"""
  id: UUID!
  
  """Email address (unique)"""
  email: Email!
  
  """Full name"""
  name: String!
  
  """Phone number in E.164 format"""
  phone: PhoneNumber
  
  """Account status"""
  status: UserStatus!
  
  """User roles"""
  roles: [UserRole!]!
  
  """Email verification status"""
  emailVerified: Boolean!
  
  """Phone verification status"""
  phoneVerified: Boolean!
  
  """Profile avatar URL"""
  avatar: URL
  
  """Two-factor authentication enabled"""
  mfaEnabled: Boolean!
  
  """Configured MFA methods"""
  mfaMethods: [MFAMethod!]!
  
  """Last login timestamp"""
  lastLoginAt: DateTime
  
  """Last login IP address"""
  lastLoginIp: IPAddress
  
  """Account creation timestamp"""
  createdAt: DateTime!
  
  """Last update timestamp"""
  updatedAt: DateTime!
  
  """Account locked until (null if not locked)"""
  lockedUntil: DateTime
  
  """Failed login attempts counter"""
  failedLoginAttempts: NonNegativeInt!
  
  """Password last changed timestamp"""
  passwordChangedAt: DateTime
  
  """User's active sessions"""
  sessions(
    first: Int = 10
    after: String
    status: SessionStatus
  ): SessionConnection! @auth(requires: [AUTH_READ])
  
  """User's registered devices"""
  devices(
    first: Int = 20
    after: String
    trustLevel: DeviceTrustLevel
  ): DeviceConnection! @auth(requires: [AUTH_READ])
  
  """User's security events"""
  securityEvents(
    first: Int = 50
    after: String
    filter: SecurityEventFilterInput
  ): SecurityEventConnection! @auth(requires: [AUTH_READ])
  
  """User's GDPR consents"""
  consents: [Consent!]! @auth(requires: [AUTH_READ])
  
  """OAuth linked accounts"""
  linkedAccounts: [LinkedAccount!]! @auth(requires: [AUTH_READ])
}
```

#### Session Type
```graphql
"""Represents an active user session"""
type Session {
  """Unique session identifier"""
  id: UUID!
  
  """User associated with session"""
  user: User!
  
  """Session status"""
  status: SessionStatus!
  
  """Device fingerprint"""
  deviceId: String!
  
  """Device information"""
  device: Device
  
  """IP address at session creation"""
  ipAddress: IPAddress!
  
  """User agent string"""
  userAgent: String!
  
  """Client application version"""
  clientVersion: String
  
  """Session creation timestamp"""
  createdAt: DateTime!
  
  """Last activity timestamp"""
  lastActivityAt: DateTime!
  
  """Session expiration timestamp"""
  expiresAt: DateTime!
  
  """Refresh token expiration"""
  refreshExpiresAt: DateTime!
  
  """MFA verification status"""
  mfaVerified: Boolean!
  
  """Session revoked timestamp"""
  revokedAt: DateTime
  
  """Reason for revocation"""
  revokedReason: String
}
```

#### Device Type
```graphql
"""Represents a registered device"""
type Device {
  """Unique device identifier"""
  id: UUID!
  
  """Device fingerprint"""
  fingerprint: String!
  
  """User owning the device"""
  user: User!
  
  """Device name (user-defined)"""
  name: String
  
  """Device type"""
  deviceType: String
  
  """Operating system"""
  os: String
  
  """Browser/app name"""
  browser: String
  
  """Trust level"""
  trustLevel: DeviceTrustLevel!
  
  """First seen timestamp"""
  firstSeenAt: DateTime!
  
  """Last seen timestamp"""
  lastSeenAt: DateTime!
  
  """Last seen IP address"""
  lastSeenIp: IPAddress
  
  """Biometric authentication enabled"""
  biometricEnabled: Boolean!
  
  """Push notification token"""
  pushToken: String
  
  """Device blocked status"""
  isBlocked: Boolean!
  
  """Blocked reason"""
  blockedReason: String
  
  """Sessions from this device"""
  sessions(first: Int = 10, after: String): SessionConnection!
}
```

#### SecurityEvent Type
```graphql
"""Represents a security audit event"""
type SecurityEvent {
  """Unique event identifier"""
  id: UUID!
  
  """User associated with event"""
  user: User
  
  """Event type"""
  eventType: SecurityEventType!
  
  """Event severity"""
  severity: SecurityEventSeverity!
  
  """Event description"""
  description: String!
  
  """IP address"""
  ipAddress: IPAddress
  
  """User agent"""
  userAgent: String
  
  """Device fingerprint"""
  deviceId: String
  
  """Session ID"""
  sessionId: UUID
  
  """Event timestamp"""
  timestamp: DateTime!
  
  """Request ID for correlation"""
  requestId: UUID
  
  """Additional event metadata"""
  metadata: JSON
  
  """Geolocation data"""
  geolocation: Geolocation
}
```

#### Consent Type
```graphql
"""Represents GDPR consent record"""
type Consent {
  """Unique consent identifier"""
  id: UUID!
  
  """User who gave consent"""
  user: User!
  
  """Consent type"""
  consentType: ConsentType!
  
  """Consent granted"""
  granted: Boolean!
  
  """Consent version"""
  version: String!
  
  """Consent timestamp"""
  consentedAt: DateTime!
  
  """IP address at consent"""
  ipAddress: IPAddress!
  
  """Withdrawal timestamp"""
  withdrawnAt: DateTime
  
  """Consent text (localized)"""
  consentText: String!
  
  """Consent locale"""
  locale: String!
}
```

#### LinkedAccount Type
```graphql
"""Represents OAuth linked account"""
type LinkedAccount {
  """Unique link identifier"""
  id: UUID!
  
  """User account"""
  user: User!
  
  """OAuth provider"""
  provider: OAuthProvider!
  
  """Provider user ID"""
  providerUserId: String!
  
  """Provider email"""
  providerEmail: Email
  
  """Link creation timestamp"""
  linkedAt: DateTime!
  
  """Last used timestamp"""
  lastUsedAt: DateTime
}
```

#### Geolocation Type
```graphql
"""Geolocation information"""
type Geolocation {
  """Country code (ISO 3166-1)"""
  countryCode: String
  
  """Country name"""
  country: String
  
  """Region/state"""
  region: String
  
  """City"""
  city: String
  
  """Latitude"""
  latitude: Float
  
  """Longitude"""
  longitude: Float
  
  """Timezone"""
  timezone: String
}
```

### Input Types

```graphql
"""Input for user registration"""
input RegisterInput {
  """Email address"""
  email: Email!
  
  """Full name"""
  name: String!
  
  """Password (min 12 chars, complexity requirements)"""
  password: String!
  
  """Phone number (optional)"""
  phone: PhoneNumber
  
  """GDPR consents"""
  consents: [ConsentInput!]!
  
  """Device fingerprint"""
  deviceId: String
  
  """Referral code (optional)"""
  referralCode: String
}

"""Input for GDPR consent"""
input ConsentInput {
  """Consent type"""
  consentType: ConsentType!
  
  """Consent granted"""
  granted: Boolean!
  
  """Consent version"""
  version: String!
  
  """Locale"""
  locale: String = "en"
}

"""Input for user login"""
input LoginInput {
  """Email address"""
  email: Email!
  
  """Password"""
  password: String!
  
  """Device fingerprint"""
  deviceId: String
  
  """Remember device (extend refresh token)"""
  rememberDevice: Boolean = false
}

"""Input for MFA verification"""
input VerifyMFAInput {
  """Session ID requiring MFA"""
  sessionId: UUID!
  
  """MFA method used"""
  method: MFAMethod!
  
  """OTP code or recovery code"""
  code: String!
}

"""Input for password reset request"""
input RequestPasswordResetInput {
  """Email address"""
  email: Email!
  
  """Device fingerprint"""
  deviceId: String
}

"""Input for password reset"""
input ResetPasswordInput {
  """Reset token from email"""
  token: String!
  
  """New password"""
  newPassword: String!
  
  """Device fingerprint"""
  deviceId: String
}

"""Input for password change"""
input ChangePasswordInput {
  """Current password"""
  currentPassword: String!
  
  """New password"""
  newPassword: String!
}

"""Input for profile update"""
input UpdateProfileInput {
  """Full name"""
  name: String
  
  """Phone number"""
  phone: PhoneNumber
  
  """Avatar URL"""
  avatar: URL
}

"""Input for email verification"""
input VerifyEmailInput {
  """Verification token from email"""
  token: String!
}

"""Input for resend verification email"""
input ResendVerificationEmailInput {
  """Email address"""
  email: Email!
}

"""Input for enabling MFA"""
input EnableMFAInput {
  """MFA method to enable"""
  method: MFAMethod!
  
  """Phone number (for SMS OTP)"""
  phone: PhoneNumber
  
  """Current password confirmation"""
  password: String!
}

"""Input for disabling MFA"""
input DisableMFAInput {
  """Current password confirmation"""
  password: String!
  
  """MFA verification code"""
  code: String!
}

"""Input for trusting a device"""
input TrustDeviceInput {
  """Device ID to trust"""
  deviceId: UUID!
  
  """Device name"""
  name: String
}

"""Input for OAuth login"""
input OAuthLoginInput {
  """OAuth provider"""
  provider: OAuthProvider!
  
  """Authorization code from provider"""
  code: String!
  
  """Redirect URI used"""
  redirectUri: URL!
  
  """Device fingerprint"""
  deviceId: String
}

"""Filter input for security events"""
input SecurityEventFilterInput {
  """Filter by event types"""
  eventTypes: [SecurityEventType!]
  
  """Filter by severity"""
  severities: [SecurityEventSeverity!]
  
  """Filter by date range (start)"""
  startDate: DateTime
  
  """Filter by date range (end)"""
  endDate: DateTime
  
  """Filter by IP address"""
  ipAddress: IPAddress
  
  """Filter by device"""
  deviceId: String
}

"""Filter input for users"""
input UserFilterInput {
  """Filter by status"""
  status: UserStatus
  
  """Filter by role"""
  role: UserRole
  
  """Filter by email verified"""
  emailVerified: Boolean
  
  """Filter by MFA enabled"""
  mfaEnabled: Boolean
  
  """Search term (name, email)"""
  searchTerm: String
}
```

### Interface Types

```graphql
"""Common fields for all entities"""
interface Node {
  """Unique identifier"""
  id: UUID!
}

"""Timestamped entities"""
interface Timestamped {
  """Creation timestamp"""
  createdAt: DateTime!
  
  """Last update timestamp"""
  updatedAt: DateTime!
}

"""User implementing interfaces"""
type User implements Node & Timestamped {
  id: UUID!
  createdAt: DateTime!
  updatedAt: DateTime!
  # ... other User fields
}
```

### Pagination (Connection Pattern)

```graphql
"""Page information for cursor-based pagination"""
type PageInfo {
  """Whether more results exist after current page"""
  hasNextPage: Boolean!
  
  """Whether results exist before current page"""
  hasPreviousPage: Boolean!
  
  """Cursor pointing to start of page"""
  startCursor: String
  
  """Cursor pointing to end of page"""
  endCursor: String
}

"""Edge in a session connection"""
type SessionEdge {
  """Cursor for this session"""
  cursor: String!
  
  """The session node"""
  node: Session!
}

"""Connection for paginated sessions"""
type SessionConnection {
  """Total count of sessions"""
  totalCount: Int!
  
  """Page information"""
  pageInfo: PageInfo!
  
  """List of edges"""
  edges: [SessionEdge!]!
  
  """List of nodes (convenience)"""
  nodes: [Session!]!
}

"""Edge in a device connection"""
type DeviceEdge {
  cursor: String!
  node: Device!
}

"""Connection for paginated devices"""
type DeviceConnection {
  totalCount: Int!
  pageInfo: PageInfo!
  edges: [DeviceEdge!]!
  nodes: [Device!]!
}

"""Edge in a security event connection"""
type SecurityEventEdge {
  cursor: String!
  node: SecurityEvent!
}

"""Connection for paginated security events"""
type SecurityEventConnection {
  totalCount: Int!
  pageInfo: PageInfo!
  edges: [SecurityEventEdge!]!
  nodes: [SecurityEvent!]!
}

"""Edge in a user connection"""
type UserEdge {
  cursor: String!
  node: User!
}

"""Connection for paginated users"""
type UserConnection {
  totalCount: Int!
  pageInfo: PageInfo!
  edges: [UserEdge!]!
  nodes: [User!]!
}
```

## Root Query Type

```graphql
type Query {
  """Get current authenticated user"""
  me: User! @auth(requires: [AUTH_READ])
  
  """Get user by ID (admin only)"""
  user(id: UUID!): User @auth(requires: [USER_READ, ADMIN_ACCESS])
  
  """List all users (admin only)"""
  users(
    first: Int = 20
    after: String
    filter: UserFilterInput
    sortBy: UserSortField = CREATED_AT
    sortOrder: SortOrder = DESC
  ): UserConnection! @auth(requires: [USER_READ, ADMIN_ACCESS])
  
  """Get session by ID"""
  session(id: UUID!): Session @auth(requires: [AUTH_READ])
  
  """List current user's sessions"""
  mySessions(
    first: Int = 10
    after: String
    status: SessionStatus
  ): SessionConnection! @auth(requires: [AUTH_READ])
  
  """Get device by ID"""
  device(id: UUID!): Device @auth(requires: [AUTH_READ])
  
  """List current user's devices"""
  myDevices(
    first: Int = 20
    after: String
    trustLevel: DeviceTrustLevel
  ): DeviceConnection! @auth(requires: [AUTH_READ])
  
  """Get security event by ID"""
  securityEvent(id: UUID!): SecurityEvent @auth(requires: [AUDIT_READ])
  
  """List security events for current user"""
  mySecurityEvents(
    first: Int = 50
    after: String
    filter: SecurityEventFilterInput
  ): SecurityEventConnection! @auth(requires: [AUTH_READ])
  
  """List all security events (admin)"""
  securityEvents(
    first: Int = 50
    after: String
    filter: SecurityEventFilterInput
  ): SecurityEventConnection! @auth(requires: [AUDIT_READ, ADMIN_ACCESS])
  
  """Get current user's GDPR consents"""
  myConsents: [Consent!]! @auth(requires: [AUTH_READ])
  
  """Check if email is available"""
  checkEmailAvailability(email: Email!): EmailAvailability! @rateLimit(limit: 5, window: 60)
  
  """Validate password strength"""
  validatePasswordStrength(password: String!): PasswordStrength!
  
  """Get MFA setup information"""
  mfaSetup(method: MFAMethod!): MFASetupInfo! @auth(requires: [AUTH_WRITE])
}

"""Email availability check result"""
type EmailAvailability {
  """Whether email is available"""
  available: Boolean!
  
  """Suggested alternatives if not available"""
  suggestions: [Email!]
}

"""Password strength validation result"""
type PasswordStrength {
  """Strength score (0-4)"""
  score: Int!
  
  """Strength label"""
  strength: String!
  
  """Whether password meets requirements"""
  meetsRequirements: Boolean!
  
  """Specific requirement checks"""
  checks: PasswordChecks!
  
  """Suggestions for improvement"""
  suggestions: [String!]!
  
  """Estimated crack time"""
  crackTime: String
}

"""Password requirement checks"""
type PasswordChecks {
  minLength: Boolean!
  hasUppercase: Boolean!
  hasLowercase: Boolean!
  hasNumber: Boolean!
  hasSpecialChar: Boolean!
  notCommon: Boolean!
  notBreached: Boolean!
}

"""MFA setup information"""
type MFASetupInfo {
  """MFA method"""
  method: MFAMethod!
  
  """QR code URL (for TOTP)"""
  qrCodeUrl: URL
  
  """Secret key (for TOTP)"""
  secretKey: String
  
  """Backup codes"""
  backupCodes: [String!]
}

"""User sort field"""
enum UserSortField {
  CREATED_AT
  UPDATED_AT
  LAST_LOGIN_AT
  NAME
  EMAIL
}
```

## Root Mutation Type

```graphql
type Mutation {
  # Registration & verification
  """Register a new user account"""
  register(input: RegisterInput!): RegisterPayload! @rateLimit(limit: 3, window: 300)
  
  """Verify email address"""
  verifyEmail(input: VerifyEmailInput!): VerifyEmailPayload!
  
  """Resend verification email"""
  resendVerificationEmail(input: ResendVerificationEmailInput!): ResendVerificationEmailPayload! 
    @rateLimit(limit: 3, window: 300)
  
  # Authentication
  """Login with email and password"""
  login(input: LoginInput!): LoginPayload! @rateLimit(limit: 5, window: 300)
  
  """Logout current session"""
  logout: LogoutPayload! @auth(requires: [AUTH_READ])
  
  """Logout from all sessions"""
  logoutAll: LogoutAllPayload! @auth(requires: [AUTH_WRITE])
  
  """Refresh access token"""
  refreshToken(refreshToken: JWT!): RefreshTokenPayload! @rateLimit(limit: 10, window: 60)
  
  """Login with OAuth provider"""
  oauthLogin(input: OAuthLoginInput!): OAuthLoginPayload! @rateLimit(limit: 5, window: 300)
  
  # MFA
  """Verify MFA code"""
  verifyMFA(input: VerifyMFAInput!): VerifyMFAPayload! @rateLimit(limit: 5, window: 300)
  
  """Request MFA code (OTP)"""
  requestMFACode(sessionId: UUID!, method: MFAMethod!): RequestMFACodePayload! 
    @rateLimit(limit: 3, window: 300)
  
  """Enable MFA for account"""
  enableMFA(input: EnableMFAInput!): EnableMFAPayload! 
    @auth(requires: [AUTH_WRITE]) @rateLimit(limit: 3, window: 300)
  
  """Disable MFA for account"""
  disableMFA(input: DisableMFAInput!): DisableMFAPayload! 
    @auth(requires: [AUTH_WRITE]) @mfaRequired
  
  """Regenerate MFA backup codes"""
  regenerateBackupCodes(password: String!): RegenerateBackupCodesPayload! 
    @auth(requires: [AUTH_WRITE]) @mfaRequired
  
  # Password management
  """Request password reset email"""
  requestPasswordReset(input: RequestPasswordResetInput!): RequestPasswordResetPayload! 
    @rateLimit(limit: 3, window: 300)
  
  """Reset password with token"""
  resetPassword(input: ResetPasswordInput!): ResetPasswordPayload! 
    @rateLimit(limit: 3, window: 300)
  
  """Change password (authenticated)"""
  changePassword(input: ChangePasswordInput!): ChangePasswordPayload! 
    @auth(requires: [AUTH_WRITE]) @mfaRequired
  
  # Profile management
  """Update user profile"""
  updateProfile(input: UpdateProfileInput!): UpdateProfilePayload! 
    @auth(requires: [AUTH_WRITE])
  
  """Change email address"""
  changeEmail(newEmail: Email!, password: String!): ChangeEmailPayload! 
    @auth(requires: [AUTH_WRITE]) @mfaRequired
  
  """Change phone number"""
  changePhone(newPhone: PhoneNumber!, password: String!): ChangePhonePayload! 
    @auth(requires: [AUTH_WRITE]) @mfaRequired
  
  # Session management
  """Revoke specific session"""
  revokeSession(sessionId: UUID!): RevokeSessionPayload! 
    @auth(requires: [AUTH_WRITE])
  
  """Revoke all sessions except current"""
  revokeOtherSessions: RevokeOtherSessionsPayload! 
    @auth(requires: [AUTH_WRITE])
  
  # Device management
  """Trust a device"""
  trustDevice(input: TrustDeviceInput!): TrustDevicePayload! 
    @auth(requires: [AUTH_WRITE])
  
  """Untrust a device"""
  untrustDevice(deviceId: UUID!): UntrustDevicePayload! 
    @auth(requires: [AUTH_WRITE])
  
  """Block a device"""
  blockDevice(deviceId: UUID!): BlockDevicePayload! 
    @auth(requires: [AUTH_WRITE])
  
  """Remove device"""
  removeDevice(deviceId: UUID!): RemoveDevicePayload! 
    @auth(requires: [AUTH_WRITE])
  
  # GDPR & consent
  """Update GDPR consent"""
  updateConsent(consentType: ConsentType!, granted: Boolean!): UpdateConsentPayload! 
    @auth(requires: [AUTH_WRITE])
  
  """Request data export (GDPR)"""
  requestDataExport: RequestDataExportPayload! 
    @auth(requires: [AUTH_READ])
  
  """Delete account (GDPR right to erasure)"""
  deleteAccount(password: String!, reason: String): DeleteAccountPayload! 
    @auth(requires: [AUTH_DELETE]) @mfaRequired
  
  # Admin operations
  """Unlock user account (admin)"""
  unlockAccount(userId: UUID!): UnlockAccountPayload! 
    @auth(requires: [ADMIN_ACCESS, SECURITY_ADMIN])
  
  """Suspend user account (admin)"""
  suspendAccount(userId: UUID!, reason: String!): SuspendAccountPayload! 
    @auth(requires: [ADMIN_ACCESS, SECURITY_ADMIN])
  
  """Reactivate suspended account (admin)"""
  reactivateAccount(userId: UUID!): ReactivateAccountPayload! 
    @auth(requires: [ADMIN_ACCESS, SECURITY_ADMIN])
}
```

## Mutation Payloads

### Standard Payload Pattern

```graphql
"""Standard mutation response interface"""
interface MutationPayload {
  """Whether the mutation succeeded"""
  success: Boolean!
  
  """Human-readable message"""
  message: String
  
  """List of errors if any"""
  errors: [UserError!]
}

"""User-facing error"""
type UserError {
  """Error code"""
  code: String!
  
  """Error message"""
  message: String!
  
  """Field that caused the error"""
  field: String
  
  """Additional error metadata"""
  meta: JSON
}

"""Authentication token pair"""
type AuthTokens {
  """JWT access token (15 min)"""
  accessToken: JWT!
  
  """JWT refresh token (7 days)"""
  refreshToken: JWT!
  
  """Access token expiration timestamp"""
  accessTokenExpiresAt: DateTime!
  
  """Refresh token expiration timestamp"""
  refreshTokenExpiresAt: DateTime!
  
  """Token type (always "Bearer")"""
  tokenType: String!
}

"""Register user response"""
type RegisterPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Created user (partial data until verified)"""
  user: User
  
  """Verification email sent"""
  verificationEmailSent: Boolean!
}

"""Verify email response"""
type VerifyEmailPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated user"""
  user: User
}

"""Resend verification email response"""
type ResendVerificationEmailPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Email sent timestamp"""
  sentAt: DateTime
}

"""Login response"""
type LoginPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """User data"""
  user: User
  
  """Authentication tokens"""
  tokens: AuthTokens
  
  """Session information"""
  session: Session
  
  """Whether MFA is required"""
  mfaRequired: Boolean!
  
  """Available MFA methods"""
  mfaMethods: [MFAMethod!]
}

"""Logout response"""
type LogoutPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
}

"""Logout all sessions response"""
type LogoutAllPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Number of sessions revoked"""
  sessionsRevoked: Int!
}

"""Refresh token response"""
type RefreshTokenPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """New authentication tokens"""
  tokens: AuthTokens
  
  """Updated session"""
  session: Session
}

"""OAuth login response"""
type OAuthLoginPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """User data"""
  user: User
  
  """Authentication tokens"""
  tokens: AuthTokens
  
  """Session information"""
  session: Session
  
  """Whether this was a new registration"""
  isNewUser: Boolean!
}

"""Verify MFA response"""
type VerifyMFAPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated session with MFA verified"""
  session: Session
  
  """User data"""
  user: User
}

"""Request MFA code response"""
type RequestMFACodePayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Code sent timestamp"""
  sentAt: DateTime
  
  """Code expiration timestamp"""
  expiresAt: DateTime
}

"""Enable MFA response"""
type EnableMFAPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated user"""
  user: User
  
  """Backup recovery codes"""
  backupCodes: [String!]
}

"""Disable MFA response"""
type DisableMFAPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated user"""
  user: User
}

"""Regenerate backup codes response"""
type RegenerateBackupCodesPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """New backup codes"""
  backupCodes: [String!]!
}

"""Request password reset response"""
type RequestPasswordResetPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Reset email sent"""
  emailSent: Boolean!
}

"""Reset password response"""
type ResetPasswordPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """User data"""
  user: User
}

"""Change password response"""
type ChangePasswordPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Password changed timestamp"""
  changedAt: DateTime
}

"""Update profile response"""
type UpdateProfilePayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated user"""
  user: User
}

"""Change email response"""
type ChangeEmailPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Verification email sent to new address"""
  verificationEmailSent: Boolean!
}

"""Change phone response"""
type ChangePhonePayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Verification SMS sent"""
  verificationSmsSent: Boolean!
}

"""Revoke session response"""
type RevokeSessionPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
}

"""Revoke other sessions response"""
type RevokeOtherSessionsPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Number of sessions revoked"""
  sessionsRevoked: Int!
}

"""Trust device response"""
type TrustDevicePayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated device"""
  device: Device
}

"""Untrust device response"""
type UntrustDevicePayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated device"""
  device: Device
}

"""Block device response"""
type BlockDevicePayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
}

"""Remove device response"""
type RemoveDevicePayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
}

"""Update consent response"""
type UpdateConsentPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated consent"""
  consent: Consent
}

"""Request data export response"""
type RequestDataExportPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Export request ID"""
  exportId: UUID
  
  """Estimated completion time"""
  estimatedCompletionAt: DateTime
}

"""Delete account response"""
type DeleteAccountPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Deletion scheduled timestamp"""
  scheduledAt: DateTime
}

"""Unlock account response"""
type UnlockAccountPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated user"""
  user: User
}

"""Suspend account response"""
type SuspendAccountPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated user"""
  user: User
}

"""Reactivate account response"""
type ReactivateAccountPayload implements MutationPayload {
  success: Boolean!
  message: String
  errors: [UserError!]
  
  """Updated user"""
  user: User
}
```

## Root Subscription Type

```graphql
type Subscription {
  """Subscribe to session updates for current user"""
  sessionUpdated: Session! @auth(requires: [AUTH_READ])
  
  """Subscribe to security events for current user"""
  securityEventCreated: SecurityEvent! @auth(requires: [AUTH_READ])
  
  """Subscribe to account status changes"""
  accountStatusChanged: User! @auth(requires: [AUTH_READ])
  
  """Subscribe to device changes"""
  deviceUpdated: Device! @auth(requires: [AUTH_READ])
  
  """Subscribe to all security events (admin)"""
  allSecurityEvents: SecurityEvent! @auth(requires: [AUDIT_READ, ADMIN_ACCESS])
}
```

### Subscription Implementation

**WebSocket Protocol**: GraphQL over WebSocket (graphql-ws)

**Client Setup** (TypeScript):
```typescript
import { createClient } from 'graphql-ws';

const client = createClient({
  url: 'wss://api.suma.finance/graphql',
  connectionParams: {
    authorization: `Bearer ${accessToken}`,
    deviceId: deviceFingerprint
  },
  retryAttempts: 5,
  keepAlive: 30000
});

const subscription = client.subscribe(
  {
    query: `
      subscription OnSecurityEvent {
        securityEventCreated {
          id
          eventType
          severity
          description
          timestamp
        }
      }
    `
  },
  {
    next: (data) => {
      console.log('Security event:', data);
      // Show notification to user
    },
    error: (error) => {
      console.error('Subscription error:', error);
    },
    complete: () => {
      console.log('Subscription completed');
    }
  }
);

// Unsubscribe
subscription();
```

## Resolver Implementation

### Query Resolver Example

```typescript
import { AuthenticationError, ForbiddenError } from 'apollo-server-express';
import { Context } from '../types';
import { checkPermission } from '../auth/permissions';
import { encodeCursor, decodeCursor } from '../utils/cursor';

const queryResolvers = {
  Query: {
    me: async (parent: any, args: any, context: Context) => {
      if (!context.user) {
        throw new AuthenticationError('Not authenticated');
      }
      
      // Load from DataLoader
      return await context.loaders.userLoader.load(context.user.id);
    },

    user: async (parent: any, { id }: { id: string }, context: Context) => {
      checkPermission(context, ['USER_READ', 'ADMIN_ACCESS']);
      
      const user = await context.loaders.userLoader.load(id);
      
      if (!user) {
        throw new UserInputError('User not found');
      }
      
      // Log security event
      await logSecurityEvent(context, {
        eventType: 'USER_ACCESSED',
        userId: context.user.id,
        targetUserId: id,
        severity: 'INFO'
      });
      
      return user;
    },

    mySessions: async (
      parent: any,
      args: { first: number; after?: string; status?: SessionStatus },
      context: Context
    ) => {
      if (!context.user) {
        throw new AuthenticationError('Not authenticated');
      }

      const { first, after, status } = args;
      const cursor = after ? decodeCursor(after) : null;

      const result = await sessionService.findByUserId(context.user.id, {
        limit: first + 1, // Fetch one extra to determine hasNextPage
        cursor,
        status
      });

      const hasNextPage = result.length > first;
      const nodes = hasNextPage ? result.slice(0, -1) : result;

      return {
        totalCount: await sessionService.countByUserId(context.user.id, { status }),
        pageInfo: {
          hasNextPage,
          hasPreviousPage: cursor !== null,
          startCursor: nodes.length > 0 ? encodeCursor(nodes[0].id) : null,
          endCursor: nodes.length > 0 ? encodeCursor(nodes[nodes.length - 1].id) : null
        },
        edges: nodes.map(session => ({
          cursor: encodeCursor(session.id),
          node: session
        })),
        nodes
      };
    },

    checkEmailAvailability: async (
      parent: any,
      { email }: { email: string },
      context: Context
    ) => {
      // Rate limit check handled by directive
      
      const exists = await userService.emailExists(email.toLowerCase());
      
      return {
        available: !exists,
        suggestions: exists ? await userService.suggestAlternativeEmails(email) : []
      };
    },

    validatePasswordStrength: async (
      parent: any,
      { password }: { password: string },
      context: Context
    ) => {
      const result = await passwordService.validateStrength(password);
      
      return {
        score: result.score,
        strength: result.strengthLabel,
        meetsRequirements: result.meetsRequirements,
        checks: {
          minLength: password.length >= 12,
          hasUppercase: /[A-Z]/.test(password),
          hasLowercase: /[a-z]/.test(password),
          hasNumber: /\d/.test(password),
          hasSpecialChar: /[^A-Za-z0-9]/.test(password),
          notCommon: !result.isCommon,
          notBreached: !result.isBreached
        },
        suggestions: result.suggestions,
        crackTime: result.crackTimeDisplay
      };
    }
  }
};
```

### Mutation Resolver Example

```typescript
import { hash, verify } from 'argon2';
import { v4 as uuidv4 } from 'uuid';
import { ValidationError } from '../errors';

const mutationResolvers = {
  Mutation: {
    register: async (
      parent: any,
      { input }: { input: RegisterInput },
      context: Context
    ) => {
      try {
        // Validate input
        const validationErrors = await validateRegisterInput(input);
        if (validationErrors.length > 0) {
          return {
            success: false,
            message: 'Validation failed',
            errors: validationErrors,
            user: null,
            verificationEmailSent: false
          };
        }

        // Check email availability
        if (await userService.emailExists(input.email.toLowerCase())) {
          return {
            success: false,
            message: 'Email already registered',
            errors: [
              {
                code: 'EMAIL_EXISTS',
                message: 'This email is already registered',
                field: 'email'
              }
            ],
            user: null,
            verificationEmailSent: false
          };
        }

        // Check password strength
        const passwordCheck = await passwordService.validateStrength(input.password);
        if (!passwordCheck.meetsRequirements) {
          return {
            success: false,
            message: 'Password does not meet requirements',
            errors: [
              {
                code: 'WEAK_PASSWORD',
                message: passwordCheck.suggestions.join('. '),
                field: 'password'
              }
            ],
            user: null,
            verificationEmailSent: false
          };
        }

        // Hash password with Argon2id
        const passwordHash = await hash(input.password, {
          type: 2, // Argon2id
          memoryCost: 65536, // 64 MB
          timeCost: 3,
          parallelism: 4
        });

        // Create user
        const user = await userService.create({
          id: uuidv4(),
          email: input.email.toLowerCase(),
          name: input.name,
          phone: input.phone,
          passwordHash,
          status: 'PENDING_VERIFICATION',
          roles: ['USER'],
          emailVerified: false,
          phoneVerified: false,
          mfaEnabled: false,
          mfaMethods: [],
          failedLoginAttempts: 0,
          createdAt: new Date(),
          updatedAt: new Date()
        });

        // Store GDPR consents
        await Promise.all(
          input.consents.map(consent =>
            consentService.create({
              userId: user.id,
              consentType: consent.consentType,
              granted: consent.granted,
              version: consent.version,
              ipAddress: context.ipAddress,
              locale: consent.locale,
              consentedAt: new Date()
            })
          )
        );

        // Generate verification token
        const verificationToken = await tokenService.generateEmailVerificationToken(user.id);

        // Send verification email
        await emailService.sendVerificationEmail(user.email, user.name, verificationToken);

        // Log security event
        await logSecurityEvent(context, {
          eventType: 'REGISTRATION_COMPLETED',
          userId: user.id,
          severity: 'INFO',
          description: `User registered: ${user.email}`
        });

        return {
          success: true,
          message: 'Registration successful. Please verify your email.',
          errors: [],
          user,
          verificationEmailSent: true
        };
      } catch (error) {
        logger.error('Registration failed', { error, input });
        
        return {
          success: false,
          message: 'Registration failed',
          errors: [
            {
              code: 'REGISTRATION_FAILED',
              message: 'An unexpected error occurred'
            }
          ],
          user: null,
          verificationEmailSent: false
        };
      }
    },

    login: async (
      parent: any,
      { input }: { input: LoginInput },
      context: Context
    ) => {
      try {
        // Find user
        const user = await userService.findByEmail(input.email.toLowerCase());

        if (!user) {
          // Log failed attempt (email enumeration prevention)
          await logSecurityEvent(context, {
            eventType: 'LOGIN_FAILED',
            severity: 'WARNING',
            description: `Login attempt for non-existent email: ${input.email}`,
            metadata: { email: input.email }
          });

          // Same response as wrong password (prevent enumeration)
          return {
            success: false,
            message: 'Invalid email or password',
            errors: [
              {
                code: 'INVALID_CREDENTIALS',
                message: 'Invalid email or password'
              }
            ],
            user: null,
            tokens: null,
            session: null,
            mfaRequired: false,
            mfaMethods: []
          };
        }

        // Check account status
        if (user.status === 'LOCKED') {
          if (user.lockedUntil && user.lockedUntil > new Date()) {
            return {
              success: false,
              message: 'Account is locked',
              errors: [
                {
                  code: 'ACCOUNT_LOCKED',
                  message: `Account locked until ${user.lockedUntil.toISOString()}`,
                  meta: { lockedUntil: user.lockedUntil }
                }
              ],
              user: null,
              tokens: null,
              session: null,
              mfaRequired: false,
              mfaMethods: []
            };
          } else {
            // Auto-unlock
            await userService.update(user.id, {
              status: 'ACTIVE',
              lockedUntil: null,
              failedLoginAttempts: 0
            });
          }
        }

        if (user.status === 'SUSPENDED' || user.status === 'BANNED') {
          return {
            success: false,
            message: 'Account is suspended',
            errors: [
              {
                code: 'ACCOUNT_SUSPENDED',
                message: 'Your account has been suspended. Contact support.'
              }
            ],
            user: null,
            tokens: null,
            session: null,
            mfaRequired: false,
            mfaMethods: []
          };
        }

        // Verify password
        const passwordValid = await verify(user.passwordHash, input.password);

        if (!passwordValid) {
          // Increment failed attempts
          const failedAttempts = user.failedLoginAttempts + 1;
          const updates: any = { failedLoginAttempts: failedAttempts };

          // Lock account after 5 failed attempts
          if (failedAttempts >= 5) {
            updates.status = 'LOCKED';
            updates.lockedUntil = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
          }

          await userService.update(user.id, updates);

          // Log failed attempt
          await logSecurityEvent(context, {
            eventType: 'LOGIN_FAILED',
            userId: user.id,
            severity: failedAttempts >= 5 ? 'CRITICAL' : 'WARNING',
            description: `Failed login attempt (${failedAttempts}/5)`
          });

          return {
            success: false,
            message: 'Invalid email or password',
            errors: [
              {
                code: 'INVALID_CREDENTIALS',
                message: failedAttempts >= 5
                  ? 'Account locked due to too many failed attempts'
                  : 'Invalid email or password',
                meta: { remainingAttempts: Math.max(0, 5 - failedAttempts) }
              }
            ],
            user: null,
            tokens: null,
            session: null,
            mfaRequired: false,
            mfaMethods: []
          };
        }

        // Reset failed attempts on successful password verification
        await userService.update(user.id, { failedLoginAttempts: 0 });

        // Check if MFA is required
        if (user.mfaEnabled) {
          // Create temporary session (not fully authenticated)
          const tempSession = await sessionService.create({
            userId: user.id,
            deviceId: input.deviceId || 'unknown',
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
            clientVersion: context.clientVersion,
            status: 'ACTIVE',
            mfaVerified: false,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes to complete MFA
          });

          // Send MFA code
          await mfaService.sendOTP(user.id, user.mfaMethods[0]);

          // Log MFA required
          await logSecurityEvent(context, {
            eventType: 'LOGIN_SUCCESS',
            userId: user.id,
            sessionId: tempSession.id,
            severity: 'INFO',
            description: 'Login successful, MFA required'
          });

          return {
            success: true,
            message: 'MFA verification required',
            errors: [],
            user,
            tokens: null,
            session: tempSession,
            mfaRequired: true,
            mfaMethods: user.mfaMethods
          };
        }

        // Create session
        const session = await sessionService.create({
          userId: user.id,
          deviceId: input.deviceId || 'unknown',
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
          clientVersion: context.clientVersion,
          status: 'ACTIVE',
          mfaVerified: !user.mfaEnabled,
          expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000), // 8 hours
          refreshExpiresAt: new Date(
            Date.now() + (input.rememberDevice ? 30 : 7) * 24 * 60 * 60 * 1000
          ) // 7 or 30 days
        });

        // Generate JWT tokens
        const tokens = await tokenService.generateAuthTokens(user, session);

        // Update last login
        await userService.update(user.id, {
          lastLoginAt: new Date(),
          lastLoginIp: context.ipAddress
        });

        // Log successful login
        await logSecurityEvent(context, {
          eventType: 'LOGIN_SUCCESS',
          userId: user.id,
          sessionId: session.id,
          severity: 'INFO',
          description: 'Login successful'
        });

        // Publish subscription event
        await pubsub.publish(`SESSION_UPDATED_${user.id}`, {
          sessionUpdated: session
        });

        return {
          success: true,
          message: 'Login successful',
          errors: [],
          user,
          tokens,
          session,
          mfaRequired: false,
          mfaMethods: []
        };
      } catch (error) {
        logger.error('Login failed', { error, input });
        
        return {
          success: false,
          message: 'Login failed',
          errors: [
            {
              code: 'LOGIN_FAILED',
              message: 'An unexpected error occurred'
            }
          ],
          user: null,
          tokens: null,
          session: null,
          mfaRequired: false,
          mfaMethods: []
        };
      }
    },

    refreshToken: async (
      parent: any,
      { refreshToken }: { refreshToken: string },
      context: Context
    ) => {
      try {
        // Verify refresh token
        const payload = await tokenService.verifyRefreshToken(refreshToken);

        // Check for token reuse (security)
        const isReused = await tokenService.isRefreshTokenReused(payload.jti);
        if (isReused) {
          // Revoke all sessions for user (possible token theft)
          await sessionService.revokeAllByUserId(payload.sub);

          await logSecurityEvent(context, {
            eventType: 'REFRESH_TOKEN_REUSE_DETECTED',
            userId: payload.sub,
            severity: 'CRITICAL',
            description: 'Refresh token reuse detected - all sessions revoked'
          });

          throw new ForbiddenError('Refresh token reuse detected');
        }

        // Mark token as used
        await tokenService.markRefreshTokenUsed(payload.jti);

        // Load session
        const session = await sessionService.findById(payload.sessionId);

        if (!session || session.status !== 'ACTIVE') {
          throw new ForbiddenError('Invalid session');
        }

        // Load user
        const user = await context.loaders.userLoader.load(payload.sub);

        if (!user || user.status !== 'ACTIVE') {
          throw new ForbiddenError('User account not active');
        }

        // Rotate refresh token
        const newTokens = await tokenService.rotateRefreshToken(user, session);

        // Update session last activity
        await sessionService.update(session.id, {
          lastActivityAt: new Date()
        });

        // Log token refresh
        await logSecurityEvent(context, {
          eventType: 'SESSION_REFRESHED',
          userId: user.id,
          sessionId: session.id,
          severity: 'INFO',
          description: 'Access token refreshed'
        });

        return {
          success: true,
          message: 'Token refreshed',
          errors: [],
          tokens: newTokens,
          session
        };
      } catch (error) {
        logger.error('Token refresh failed', { error });
        
        return {
          success: false,
          message: 'Token refresh failed',
          errors: [
            {
              code: 'INVALID_REFRESH_TOKEN',
              message: error.message
            }
          ],
          tokens: null,
          session: null
        };
      }
    }
  }
};
```

### Field Resolver Example

```typescript
const userResolvers = {
  User: {
    // Lazy load sessions
    sessions: async (
      user: User,
      args: { first: number; after?: string; status?: SessionStatus },
      context: Context
    ) => {
      // Check authorization
      if (context.user?.id !== user.id && !hasPermission(context, ['ADMIN_ACCESS'])) {
        throw new ForbiddenError('Cannot access other user sessions');
      }

      const { first, after, status } = args;
      const cursor = after ? decodeCursor(after) : null;

      const result = await sessionService.findByUserId(user.id, {
        limit: first + 1,
        cursor,
        status
      });

      const hasNextPage = result.length > first;
      const nodes = hasNextPage ? result.slice(0, -1) : result;

      return {
        totalCount: await sessionService.countByUserId(user.id, { status }),
        pageInfo: {
          hasNextPage,
          hasPreviousPage: cursor !== null,
          startCursor: nodes.length > 0 ? encodeCursor(nodes[0].id) : null,
          endCursor: nodes.length > 0 ? encodeCursor(nodes[nodes.length - 1].id) : null
        },
        edges: nodes.map(session => ({
          cursor: encodeCursor(session.id),
          node: session
        })),
        nodes
      };
    },

    // Lazy load devices
    devices: async (
      user: User,
      args: { first: number; after?: string; trustLevel?: DeviceTrustLevel },
      context: Context
    ) => {
      // Check authorization
      if (context.user?.id !== user.id && !hasPermission(context, ['ADMIN_ACCESS'])) {
        throw new ForbiddenError('Cannot access other user devices');
      }

      // Use DataLoader to batch load devices
      const devices = await deviceService.findByUserId(user.id, args);

      return devices;
    },

    // Lazy load consents
    consents: async (user: User, args: any, context: Context) => {
      // Check authorization
      if (context.user?.id !== user.id && !hasPermission(context, ['ADMIN_ACCESS'])) {
        throw new ForbiddenError('Cannot access other user consents');
      }

      // Use DataLoader
      return await context.loaders.consentLoader.load(user.id);
    }
  },

  Session: {
    // Resolve user from session
    user: async (session: Session, args: any, context: Context) => {
      return await context.loaders.userLoader.load(session.userId);
    },

    // Resolve device from session
    device: async (session: Session, args: any, context: Context) => {
      if (!session.deviceId) return null;
      
      const device = await deviceService.findByFingerprint(session.deviceId);
      return device;
    }
  },

  SecurityEvent: {
    // Resolve user from security event
    user: async (event: SecurityEvent, args: any, context: Context) => {
      if (!event.userId) return null;
      return await context.loaders.userLoader.load(event.userId);
    }
  }
};
```

### Subscription Resolver Example

```typescript
import { PubSub } from 'graphql-subscriptions';
import { withFilter } from 'graphql-subscriptions';

const pubsub = new PubSub();

const subscriptionResolvers = {
  Subscription: {
    sessionUpdated: {
      subscribe: withFilter(
        (parent, args, context: Context) => {
          if (!context.user) {
            throw new AuthenticationError('Not authenticated');
          }
          
          return pubsub.asyncIterator([`SESSION_UPDATED_${context.user.id}`]);
        },
        (payload, variables, context: Context) => {
          // Additional filtering
          return payload.sessionUpdated.userId === context.user.id;
        }
      )
    },

    securityEventCreated: {
      subscribe: withFilter(
        (parent, args, context: Context) => {
          if (!context.user) {
            throw new AuthenticationError('Not authenticated');
          }
          
          return pubsub.asyncIterator([`SECURITY_EVENT_${context.user.id}`]);
        },
        (payload, variables, context: Context) => {
          return payload.securityEventCreated.userId === context.user.id;
        }
      )
    },

    accountStatusChanged: {
      subscribe: withFilter(
        (parent, args, context: Context) => {
          if (!context.user) {
            throw new AuthenticationError('Not authenticated');
          }
          
          return pubsub.asyncIterator([`ACCOUNT_STATUS_${context.user.id}`]);
        },
        (payload, variables, context: Context) => {
          return payload.accountStatusChanged.id === context.user.id;
        }
      )
    },

    allSecurityEvents: {
      subscribe: (parent, args, context: Context) => {
        checkPermission(context, ['AUDIT_READ', 'ADMIN_ACCESS']);
        
        return pubsub.asyncIterator(['SECURITY_EVENT_ALL']);
      }
    }
  }
};

// Publish events
export async function publishSessionUpdate(session: Session) {
  await pubsub.publish(`SESSION_UPDATED_${session.userId}`, {
    sessionUpdated: session
  });
}

export async function publishSecurityEvent(event: SecurityEvent) {
  if (event.userId) {
    await pubsub.publish(`SECURITY_EVENT_${event.userId}`, {
      securityEventCreated: event
    });
  }
  
  await pubsub.publish('SECURITY_EVENT_ALL', {
    allSecurityEvents: event
  });
}

export async function publishAccountStatusChange(user: User) {
  await pubsub.publish(`ACCOUNT_STATUS_${user.id}`, {
    accountStatusChanged: user
  });
}
```

## DataLoader (N+1 Problem Solution)

### DataLoader Implementation

```typescript
import DataLoader from 'dataloader';
import { User, Session, Device, Consent } from '../models';

export function createLoaders() {
  return {
    userLoader: new DataLoader<string, User>(async (userIds: string[]) => {
      const users = await userService.findByIds(userIds);
      
      // Return in same order as requested
      return userIds.map(id => users.find(u => u.id === id) || null);
    }),

    sessionLoader: new DataLoader<string, Session>(async (sessionIds: string[]) => {
      const sessions = await sessionService.findByIds(sessionIds);
      return sessionIds.map(id => sessions.find(s => s.id === id) || null);
    }),

    deviceLoader: new DataLoader<string, Device>(async (deviceIds: string[]) => {
      const devices = await deviceService.findByIds(deviceIds);
      return deviceIds.map(id => devices.find(d => d.id === id) || null);
    }),

    consentLoader: new DataLoader<string, Consent[]>(async (userIds: string[]) => {
      const consents = await consentService.findByUserIds(userIds);
      
      // Group by user ID
      const consentsByUser = consents.reduce((acc, consent) => {
        if (!acc[consent.userId]) {
          acc[consent.userId] = [];
        }
        acc[consent.userId].push(consent);
        return acc;
      }, {} as Record<string, Consent[]>);
      
      return userIds.map(id => consentsByUser[id] || []);
    })
  };
}

// Usage in context
export function createContext({ req }: { req: Request }): Context {
  const token = extractTokenFromHeader(req.headers.authorization);
  const user = token ? verifyAccessToken(token) : null;

  return {
    user,
    requestId: req.headers['x-request-id'] || uuidv4(),
    deviceId: req.headers['x-device-id'],
    clientVersion: req.headers['x-client-version'],
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    loaders: createLoaders(),
    cache: new InMemoryLRUCache()
  };
}
```

## Error Handling

### Error Types

```typescript
import { ApolloError } from 'apollo-server-express';

export class AuthenticationError extends ApolloError {
  constructor(message: string) {
    super(message, 'UNAUTHENTICATED');
  }
}

export class AuthorizationError extends ApolloError {
  constructor(message: string) {
    super(message, 'FORBIDDEN');
  }
}

export class ValidationError extends ApolloError {
  constructor(message: string, public fields: Record<string, string>) {
    super(message, 'BAD_USER_INPUT');
  }
}

export class AccountLockedError extends ApolloError {
  constructor(message: string, public lockedUntil: Date) {
    super(message, 'ACCOUNT_LOCKED');
    this.extensions = { lockedUntil: lockedUntil.toISOString() };
  }
}

export class MFARequiredError extends ApolloError {
  constructor(message: string, public methods: string[]) {
    super(message, 'MFA_REQUIRED');
    this.extensions = { mfaMethods: methods };
  }
}

export class RateLimitError extends ApolloError {
  constructor(message: string, public retryAfter: number) {
    super(message, 'RATE_LIMIT_EXCEEDED');
    this.extensions = { retryAfter };
  }
}
```

### Error Formatting

```typescript
import { GraphQLError, GraphQLFormattedError } from 'graphql';

export const formatError = (error: GraphQLError): GraphQLFormattedError => {
  // Log error for monitoring
  logger.error('GraphQL Error', {
    message: error.message,
    code: error.extensions?.code,
    path: error.path,
    locations: error.locations,
    userId: error.extensions?.userId,
    requestId: error.extensions?.requestId
  });

  // Don't expose internal errors to client
  if (error.originalError && !error.extensions?.code) {
    return {
      message: 'Internal server error',
      extensions: {
        code: 'INTERNAL_SERVER_ERROR',
        requestId: error.extensions?.requestId
      }
    };
  }

  // Return formatted error
  return {
    message: error.message,
    locations: error.locations,
    path: error.path,
    extensions: {
      code: error.extensions?.code || 'INTERNAL_SERVER_ERROR',
      ...error.extensions
    }
  };
};
```

## Validation

### Input Validation

```typescript
import Joi from 'joi';

export const registerSchema = Joi.object({
  email: Joi.string()
    .email()
    .lowercase()
    .max(255)
    .required()
    .messages({
      'string.email': 'Invalid email format',
      'any.required': 'Email is required'
    }),
  
  name: Joi.string()
    .min(2)
    .max(100)
    .trim()
    .required()
    .messages({
      'string.min': 'Name must be at least 2 characters',
      'string.max': 'Name must not exceed 100 characters',
      'any.required': 'Name is required'
    }),
  
  password: Joi.string()
    .min(12)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.min': 'Password must be at least 12 characters',
      'string.pattern.base': 'Password must contain uppercase, lowercase, number, and special character',
      'any.required': 'Password is required'
    }),
  
  phone: Joi.string()
    .pattern(/^\+[1-9]\d{1,14}$/)
    .optional()
    .messages({
      'string.pattern.base': 'Phone must be in E.164 format (e.g., +351912345678)'
    }),
  
  consents: Joi.array()
    .items(
      Joi.object({
        consentType: Joi.string().valid(...Object.values(ConsentType)).required(),
        granted: Joi.boolean().required(),
        version: Joi.string().required(),
        locale: Joi.string().default('en')
      })
    )
    .min(1)
    .required()
    .messages({
      'array.min': 'At least one consent is required'
    })
});

export function validateRegisterInput(input: RegisterInput): UserError[] {
  const { error } = registerSchema.validate(input, { abortEarly: false });

  if (!error) return [];

  return error.details.map(detail => ({
    code: 'VALIDATION_ERROR',
    message: detail.message,
    field: detail.path.join('.')
  }));
}
```

## Performance Optimization

### Query Complexity Analysis

```typescript
import { createComplexityLimitRule } from 'graphql-validation-complexity';

const complexityLimit = createComplexityLimitRule(1000, {
  scalarCost: 1,
  objectCost: 5,
  listFactor: 10,
  introspectionListFactor: 10,
  createError: (cost, max) => {
    return new GraphQLError(
      `Query is too complex: ${cost}. Maximum allowed complexity: ${max}`,
      {
        extensions: {
          code: 'QUERY_TOO_COMPLEX',
          cost,
          max
        }
      }
    );
  }
});
```

### Query Depth Limiting

```typescript
import depthLimit from 'graphql-depth-limit';

const server = new ApolloServer({
  schema,
  validationRules: [depthLimit(7)],
  formatError
});
```

### Caching Strategy

```typescript
import { InMemoryLRUCache } from '@apollo/utils.keyvaluecache';
import Redis from 'ioredis';
import { RedisCache } from 'apollo-server-cache-redis';

// Redis cache for production
const redisCache = new RedisCache({
  client: new Redis({
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT),
    password: process.env.REDIS_PASSWORD,
    db: 0
  })
});

// In-memory cache for development
const memoryCache = new InMemoryLRUCache({
  maxSize: Math.pow(2, 20) * 100, // 100 MB
  ttl: 300000 // 5 minutes
});

const cache = process.env.NODE_ENV === 'production' ? redisCache : memoryCache;

// Cache resolver results
const userResolvers = {
  Query: {
    user: async (parent, { id }, context: Context) => {
      const cacheKey = `user:${id}`;

      // Check cache
      const cached = await context.cache.get(cacheKey);
      if (cached) {
        return JSON.parse(cached);
      }

      // Fetch from database
      const user = await userService.findById(id);

      if (user) {
        // Store in cache (5 minutes)
        await context.cache.set(
          cacheKey,
          JSON.stringify(user),
          { ttl: 300 }
        );
      }

      return user;
    }
  }
};

// Invalidate cache on mutations
const userMutations = {
  Mutation: {
    updateProfile: async (parent, { input }, context: Context) => {
      const user = await userService.update(context.user.id, input);

      // Invalidate cache
      await context.cache.delete(`user:${context.user.id}`);

      return { success: true, user };
    }
  }
};
```

## Rate Limiting

### GraphQL-Specific Rate Limiting

```typescript
import { shield, rule, and } from 'graphql-shield';
import { RateLimiterMemory, RateLimiterRedis } from 'rate-limiter-flexible';
import Redis from 'ioredis';

const redis = new Redis({
  host: process.env.REDIS_HOST,
  enableOfflineQueue: false
});

// Rate limiters
const authRateLimiter = new RateLimiterRedis({
  storeClient: redis,
  keyPrefix: 'rl:auth',
  points: 5, // 5 attempts
  duration: 300 // per 5 minutes
});

const apiRateLimiter = new RateLimiterRedis({