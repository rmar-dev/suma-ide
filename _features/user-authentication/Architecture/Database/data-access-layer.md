---
layout: default
title: Data Access Layer
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

# DATA ACCESS LAYER

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Database
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

The SUMA Finance authentication system requires a robust, secure, and scalable data access layer to handle user credentials, sessions, audit logs, and GDPR compliance data. This document defines a comprehensive data access architecture using the Repository Pattern with PostgreSQL and Redis, optimized for high-performance authentication operations with stringent security requirements.

The data access layer implements multi-tier caching, connection pooling, and transaction management to achieve sub-100ms response times for token operations and sub-200ms for authentication flows. All sensitive data (passwords, tokens, PII) is encrypted at rest using AES-256-GCM, with secure key management and rotation policies. The architecture supports horizontal scalability, comprehensive audit logging, and GDPR-compliant data handling with built-in support for data subject rights (access, erasure, portability).

Critical focus areas include: preventing SQL injection through parameterized queries, optimizing N+1 query problems in session/device lookups, implementing Redis-backed session storage with automatic expiration, and maintaining comprehensive audit trails for all authentication events. The repository pattern abstracts data access complexity while providing type-safe interfaces for business logic layers.

## Architecture Pattern

### Repository Pattern (Recommended)
**Why**: Provides clean separation between business logic and data access, enables comprehensive testing through interface mocking, ensures consistent query patterns, and supports multiple data sources (PostgreSQL for persistence, Redis for sessions/cache).

**Structure**:
```
src/repositories/
├── interfaces/              # Repository contracts
│   ├── IUserRepository.go
│   ├── ISessionRepository.go
│   ├── IAuditLogRepository.go
│   ├── IConsentRepository.go
│   ├── IDeviceRepository.go
│   └── IOTPRepository.go
├── postgres/                # PostgreSQL implementations
│   ├── UserRepository.go
│   ├── AuditLogRepository.go
│   ├── ConsentRepository.go
│   └── DeviceRepository.go
├── redis/                   # Redis implementations
│   ├── SessionRepository.go
│   ├── OTPRepository.go
│   └── LockoutRepository.go
├── specifications/          # Query specifications
│   ├── UserSpecs.go
│   └── AuditSpecs.go
└── base/                    # Base repository utilities
    ├── BaseRepository.go
    └── Transaction.go
```

**Benefits**:
- Decouples business logic from database implementation details
- Easy to mock for unit testing authentication flows
- Consistent error handling and retry logic
- Supports database migration without affecting business logic
- Enables query optimization at repository level
- Facilitates compliance auditing through centralized data access

### Alternative: Active Record
**When to Use**: Not recommended for this project due to complex security requirements, need for multi-database coordination (PostgreSQL + Redis), and strict separation of concerns for audit compliance.
**Trade-off**: Would couple domain models to database, making security testing and compliance validation more difficult.

## Technology Stack

### Primary Database: PostgreSQL 15+
**Rationale**: 
- ACID compliance critical for financial authentication data
- Row-level security for multi-tenant isolation
- Native JSON support for flexible consent/device metadata
- Excellent performance for complex audit queries
- pgcrypto extension for at-rest encryption

### Cache/Session Store: Redis 7+
**Rationale**:
- Sub-millisecond session lookups (target: <10ms)
- Automatic TTL expiration for tokens/OTP
- Atomic operations for lockout counters
- Pub/sub for session invalidation events
- Cluster mode for high availability

### ORM Selection
**Primary**: pgx (PostgreSQL driver) + sqlx (query extensions)
**Rationale**: 
- Zero-reflection performance overhead
- Native PostgreSQL type support
- Prepared statement caching
- Connection pooling with health checks
- Direct control over query execution

**Configuration Example**:
```go
package database

import (
    "context"
    "fmt"
    "time"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/redis/go-redis/v9"
)

type Config struct {
    PostgresURL      string
    RedisURL         string
    MaxConnections   int
    MinConnections   int
    MaxConnLifetime  time.Duration
    MaxConnIdleTime  time.Duration
    HealthCheckPeriod time.Duration
}

type DataSource struct {
    PgPool      *pgxpool.Pool
    RedisClient *redis.ClusterClient
}

func NewDataSource(cfg Config) (*DataSource, error) {
    // PostgreSQL connection pool
    pgConfig, err := pgxpool.ParseConfig(cfg.PostgresURL)
    if err != nil {
        return nil, fmt.Errorf("invalid postgres URL: %w", err)
    }
    
    pgConfig.MaxConns = int32(cfg.MaxConnections)
    pgConfig.MinConns = int32(cfg.MinConnections)
    pgConfig.MaxConnLifetime = cfg.MaxConnLifetime
    pgConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
    pgConfig.HealthCheckPeriod = cfg.HealthCheckPeriod
    
    // Enable prepared statement caching
    pgConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
    
    pgPool, err := pgxpool.NewWithConfig(context.Background(), pgConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to create pool: %w", err)
    }
    
    // Redis cluster client
    redisClient := redis.NewClusterClient(&redis.ClusterOptions{
        Addrs:              []string{cfg.RedisURL},
        MaxRetries:         3,
        PoolSize:           50,
        MinIdleConns:       10,
        MaxConnAge:         time.Hour,
        PoolTimeout:        4 * time.Second,
        IdleTimeout:        5 * time.Minute,
        IdleCheckFrequency: time.Minute,
    })
    
    // Test connections
    if err := pgPool.Ping(context.Background()); err != nil {
        return nil, fmt.Errorf("postgres ping failed: %w", err)
    }
    
    if err := redisClient.Ping(context.Background()).Err(); err != nil {
        return nil, fmt.Errorf("redis ping failed: %w", err)
    }
    
    return &DataSource{
        PgPool:      pgPool,
        RedisClient: redisClient,
    }, nil
}

func (ds *DataSource) Close() {
    ds.PgPool.Close()
    ds.RedisClient.Close()
}
```

## Domain Models

### User Entity

```go
package models

import (
    "time"
    "github.com/google/uuid"
)

// User represents a registered user in the system
type User struct {
    // Identity
    ID           uuid.UUID  `db:"id"`
    Email        string     `db:"email"`
    PasswordHash string     `db:"password_hash"`
    
    // Profile
    FirstName    *string    `db:"first_name"`
    LastName     *string    `db:"last_name"`
    PhoneNumber  *string    `db:"phone_number"`
    
    // Status
    Status           UserStatus  `db:"status"`
    EmailVerified    bool        `db:"email_verified"`
    EmailVerifiedAt  *time.Time  `db:"email_verified_at"`
    PhoneVerified    bool        `db:"phone_verified"`
    TwoFactorEnabled bool        `db:"two_factor_enabled"`
    
    // Security
    FailedLoginAttempts int        `db:"failed_login_attempts"`
    LockedUntil         *time.Time `db:"locked_until"`
    LastLoginAt         *time.Time `db:"last_login_at"`
    LastLoginIP         *string    `db:"last_login_ip"`
    PasswordChangedAt   time.Time  `db:"password_changed_at"`
    
    // GDPR
    ConsentGiven       bool       `db:"consent_given"`
    ConsentGivenAt     *time.Time `db:"consent_given_at"`
    ConsentWithdrawnAt *time.Time `db:"consent_withdrawn_at"`
    
    // Timestamps
    CreatedAt time.Time  `db:"created_at"`
    UpdatedAt time.Time  `db:"updated_at"`
    DeletedAt *time.Time `db:"deleted_at"`
}

type UserStatus string

const (
    UserStatusActive    UserStatus = "active"
    UserStatusInactive  UserStatus = "inactive"
    UserStatusSuspended UserStatus = "suspended"
    UserStatusPending   UserStatus = "pending_verification"
)

// IsActive checks if user can authenticate
func (u *User) IsActive() bool {
    return u.Status == UserStatusActive && 
           u.DeletedAt == nil && 
           u.EmailVerified &&
           (u.LockedUntil == nil || u.LockedUntil.Before(time.Now()))
}

// IsLocked checks if account is temporarily locked
func (u *User) IsLocked() bool {
    return u.LockedUntil != nil && u.LockedUntil.After(time.Now())
}

// FullName returns concatenated name
func (u *User) FullName() string {
    if u.FirstName == nil && u.LastName == nil {
        return ""
    }
    first := ""
    if u.FirstName != nil {
        first = *u.FirstName
    }
    last := ""
    if u.LastName != nil {
        last = *u.LastName
    }
    return fmt.Sprintf("%s %s", first, last).Trim()
}
```

### Session Entity

```go
package models

// Session represents an active user session stored in Redis
type Session struct {
    SessionID      string    `json:"session_id"`
    UserID         uuid.UUID `json:"user_id"`
    RefreshToken   string    `json:"refresh_token"`
    DeviceID       string    `json:"device_id"`
    IPAddress      string    `json:"ip_address"`
    UserAgent      string    `json:"user_agent"`
    CreatedAt      time.Time `json:"created_at"`
    LastActivityAt time.Time `json:"last_activity_at"`
    ExpiresAt      time.Time `json:"expires_at"`
}

// IsExpired checks if session has expired
func (s *Session) IsExpired() bool {
    return time.Now().After(s.ExpiresAt)
}

// IsIdle checks if session exceeded idle timeout
func (s *Session) IsIdle(idleTimeout time.Duration) bool {
    return time.Since(s.LastActivityAt) > idleTimeout
}
```

### Audit Log Entity

```go
package models

// AuditLog represents a security event for compliance tracking
type AuditLog struct {
    ID          uuid.UUID       `db:"id"`
    UserID      *uuid.UUID      `db:"user_id"`
    EventType   AuditEventType  `db:"event_type"`
    EventStatus AuditStatus     `db:"event_status"`
    IPAddress   string          `db:"ip_address"`
    UserAgent   string          `db:"user_agent"`
    DeviceID    *string         `db:"device_id"`
    Metadata    map[string]any  `db:"metadata"`
    CreatedAt   time.Time       `db:"created_at"`
}

type AuditEventType string

const (
    EventLogin              AuditEventType = "login"
    EventLoginFailed        AuditEventType = "login_failed"
    EventLogout             AuditEventType = "logout"
    EventPasswordChanged    AuditEventType = "password_changed"
    EventPasswordResetReq   AuditEventType = "password_reset_requested"
    EventPasswordReset      AuditEventType = "password_reset"
    Event2FAEnabled         AuditEventType = "2fa_enabled"
    Event2FADisabled        AuditEventType = "2fa_disabled"
    Event2FAVerified        AuditEventType = "2fa_verified"
    EventEmailVerified      AuditEventType = "email_verified"
    EventAccountLocked      AuditEventType = "account_locked"
    EventAccountUnlocked    AuditEventType = "account_unlocked"
    EventConsentGiven       AuditEventType = "consent_given"
    EventConsentWithdrawn   AuditEventType = "consent_withdrawn"
    EventDataExported       AuditEventType = "data_exported"
    EventDataDeleted        AuditEventType = "data_deleted"
)

type AuditStatus string

const (
    AuditStatusSuccess AuditStatus = "success"
    AuditStatusFailure AuditStatus = "failure"
)
```

### Consent Entity

```go
package models

// Consent represents GDPR consent tracking
type Consent struct {
    ID             uuid.UUID      `db:"id"`
    UserID         uuid.UUID      `db:"user_id"`
    ConsentType    ConsentType    `db:"consent_type"`
    ConsentVersion string         `db:"consent_version"`
    Granted        bool           `db:"granted"`
    GrantedAt      *time.Time     `db:"granted_at"`
    WithdrawnAt    *time.Time     `db:"withdrawn_at"`
    IPAddress      string         `db:"ip_address"`
    UserAgent      string         `db:"user_agent"`
    CreatedAt      time.Time      `db:"created_at"`
    UpdatedAt      time.Time      `db:"updated_at"`
}

type ConsentType string

const (
    ConsentTypeTermsOfService ConsentType = "terms_of_service"
    ConsentTypePrivacyPolicy  ConsentType = "privacy_policy"
    ConsentTypeMarketing      ConsentType = "marketing"
    ConsentTypeDataProcessing ConsentType = "data_processing"
)
```

### Device Entity

```go
package models

// Device represents a trusted device for device management
type Device struct {
    ID            uuid.UUID         `db:"id"`
    UserID        uuid.UUID         `db:"user_id"`
    DeviceID      string            `db:"device_id"`
    DeviceName    string            `db:"device_name"`
    DeviceType    DeviceType        `db:"device_type"`
    Fingerprint   string            `db:"fingerprint"`
    Trusted       bool              `db:"trusted"`
    LastUsedAt    time.Time         `db:"last_used_at"`
    LastIPAddress string            `db:"last_ip_address"`
    Metadata      map[string]string `db:"metadata"`
    CreatedAt     time.Time         `db:"created_at"`
    UpdatedAt     time.Time         `db:"updated_at"`
}

type DeviceType string

const (
    DeviceTypeWeb     DeviceType = "web"
    DeviceTypeMobile  DeviceType = "mobile"
    DeviceTypeTablet  DeviceType = "tablet"
    DeviceTypeDesktop DeviceType = "desktop"
)
```

## Repository Interface

### Base Repository Interface

```go
package interfaces

import (
    "context"
    "github.com/google/uuid"
)

type BaseRepository[T any] interface {
    FindByID(ctx context.Context, id uuid.UUID) (*T, error)
    Create(ctx context.Context, entity *T) error
    Update(ctx context.Context, entity *T) error
    Delete(ctx context.Context, id uuid.UUID) error
    Exists(ctx context.Context, id uuid.UUID) (bool, error)
}
```

### User Repository Interface

```go
package interfaces

import (
    "context"
    "github.com/google/uuid"
    "suma-finance/internal/models"
)

type IUserRepository interface {
    BaseRepository[models.User]
    
    // Query methods
    FindByEmail(ctx context.Context, email string) (*models.User, error)
    FindByEmailWithLock(ctx context.Context, email string) (*models.User, error)
    FindActiveUsers(ctx context.Context, limit, offset int) ([]*models.User, error)
    FindByStatus(ctx context.Context, status models.UserStatus) ([]*models.User, error)
    
    // Security methods
    IncrementFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error
    ResetFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error
    LockAccount(ctx context.Context, userID uuid.UUID, lockDuration time.Duration) error
    UnlockAccount(ctx context.Context, userID uuid.UUID) error
    UpdateLastLogin(ctx context.Context, userID uuid.UUID, ipAddress string) error
    
    // Verification methods
    MarkEmailVerified(ctx context.Context, userID uuid.UUID) error
    Enable2FA(ctx context.Context, userID uuid.UUID) error
    Disable2FA(ctx context.Context, userID uuid.UUID) error
    
    // GDPR methods
    GrantConsent(ctx context.Context, userID uuid.UUID) error
    WithdrawConsent(ctx context.Context, userID uuid.UUID) error
    SoftDelete(ctx context.Context, userID uuid.UUID) error
    HardDelete(ctx context.Context, userID uuid.UUID) error
    ExportUserData(ctx context.Context, userID uuid.UUID) (map[string]interface{}, error)
    
    // Password management
    UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error
    CheckPasswordHistory(ctx context.Context, userID uuid.UUID, passwordHash string, historyCount int) (bool, error)
    
    // Pagination
    FindPaginated(ctx context.Context, opts PaginationOptions) (*PaginatedResult[models.User], error)
    
    // Analytics
    CountByStatus(ctx context.Context) (map[models.UserStatus]int, error)
    CountTotal(ctx context.Context) (int64, error)
}

type PaginationOptions struct {
    Page       int
    PerPage    int
    SortBy     string
    SortOrder  string // "ASC" or "DESC"
    Filters    map[string]interface{}
}

type PaginatedResult[T any] struct {
    Data       []*T
    Total      int64
    Page       int
    PerPage    int
    TotalPages int
}
```

### Session Repository Interface

```go
package interfaces

import (
    "context"
    "time"
    "github.com/google/uuid"
    "suma-finance/internal/models"
)

type ISessionRepository interface {
    // Session CRUD
    Create(ctx context.Context, session *models.Session, ttl time.Duration) error
    Get(ctx context.Context, sessionID string) (*models.Session, error)
    Update(ctx context.Context, session *models.Session) error
    Delete(ctx context.Context, sessionID string) error
    
    // User session management
    FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
    DeleteByUserID(ctx context.Context, userID uuid.UUID) error
    DeleteByDeviceID(ctx context.Context, userID uuid.UUID, deviceID string) error
    
    // Activity tracking
    UpdateLastActivity(ctx context.Context, sessionID string) error
    
    // Refresh token management
    GetByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error)
    InvalidateRefreshToken(ctx context.Context, refreshToken string) error
    
    // Session limits
    CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error)
    EnforceConcurrentSessionLimit(ctx context.Context, userID uuid.UUID, maxSessions int) error
    
    // Cleanup
    DeleteExpiredSessions(ctx context.Context) (int, error)
}
```

### Audit Log Repository Interface

```go
package interfaces

import (
    "context"
    "time"
    "github.com/google/uuid"
    "suma-finance/internal/models"
)

type IAuditLogRepository interface {
    // Logging
    Log(ctx context.Context, log *models.AuditLog) error
    LogBatch(ctx context.Context, logs []*models.AuditLog) error
    
    // Query methods
    FindByUserID(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*models.AuditLog, error)
    FindByEventType(ctx context.Context, eventType models.AuditEventType, limit, offset int) ([]*models.AuditLog, error)
    FindByDateRange(ctx context.Context, startDate, endDate time.Time) ([]*models.AuditLog, error)
    FindFailedLoginAttempts(ctx context.Context, userID uuid.UUID, since time.Time) ([]*models.AuditLog, error)
    
    // Security analytics
    DetectSuspiciousActivity(ctx context.Context, userID uuid.UUID, timeWindow time.Duration) (bool, error)
    CountFailedLogins(ctx context.Context, userID uuid.UUID, since time.Time) (int, error)
    FindLoginsByIP(ctx context.Context, ipAddress string, limit int) ([]*models.AuditLog, error)
    
    // GDPR compliance
    ExportUserAuditLog(ctx context.Context, userID uuid.UUID) ([]*models.AuditLog, error)
    DeleteUserAuditLog(ctx context.Context, userID uuid.UUID) error
    
    // Cleanup
    DeleteOldLogs(ctx context.Context, olderThan time.Time) (int64, error)
}
```

### OTP Repository Interface

```go
package interfaces

import (
    "context"
    "time"
    "github.com/google/uuid"
)

type IOTPRepository interface {
    // OTP management
    Store(ctx context.Context, userID uuid.UUID, otp string, ttl time.Duration) error
    Verify(ctx context.Context, userID uuid.UUID, otp string) (bool, error)
    Delete(ctx context.Context, userID uuid.UUID) error
    
    // Rate limiting
    IncrementAttempts(ctx context.Context, userID uuid.UUID) (int, error)
    GetAttempts(ctx context.Context, userID uuid.UUID) (int, error)
    ResetAttempts(ctx context.Context, userID uuid.UUID) error
    
    // Resend control
    SetResendCooldown(ctx context.Context, userID uuid.UUID, cooldown time.Duration) error
    CanResend(ctx context.Context, userID uuid.UUID) (bool, error)
}
```

## Repository Implementation

### User Repository Implementation

```go
package postgres

import (
    "context"
    "database/sql"
    "fmt"
    "time"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
    "suma-finance/internal/models"
    "suma-finance/internal/repositories/interfaces"
)

type UserRepository struct {
    pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) interfaces.IUserRepository {
    return &UserRepository{pool: pool}
}

func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
    query := `
        SELECT id, email, password_hash, first_name, last_name, phone_number,
               status, email_verified, email_verified_at, phone_verified, 
               two_factor_enabled, failed_login_attempts, locked_until,
               last_login_at, last_login_ip, password_changed_at,
               consent_given, consent_given_at, consent_withdrawn_at,
               created_at, updated_at, deleted_at
        FROM users
        WHERE id = $1 AND deleted_at IS NULL
    `
    
    var user models.User
    err := r.pool.QueryRow(ctx, query, id).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
        &user.PhoneNumber, &user.Status, &user.EmailVerified, &user.EmailVerifiedAt,
        &user.PhoneVerified, &user.TwoFactorEnabled, &user.FailedLoginAttempts,
        &user.LockedUntil, &user.LastLoginAt, &user.LastLoginIP, &user.PasswordChangedAt,
        &user.ConsentGiven, &user.ConsentGivenAt, &user.ConsentWithdrawnAt,
        &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
    )
    
    if err != nil {
        if err == pgx.ErrNoRows {
            return nil, fmt.Errorf("user not found: %w", err)
        }
        return nil, fmt.Errorf("failed to find user: %w", err)
    }
    
    return &user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
    query := `
        SELECT id, email, password_hash, first_name, last_name, phone_number,
               status, email_verified, email_verified_at, phone_verified, 
               two_factor_enabled, failed_login_attempts, locked_until,
               last_login_at, last_login_ip, password_changed_at,
               consent_given, consent_given_at, consent_withdrawn_at,
               created_at, updated_at, deleted_at
        FROM users
        WHERE email = $1 AND deleted_at IS NULL
    `
    
    var user models.User
    err := r.pool.QueryRow(ctx, query, email).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
        &user.PhoneNumber, &user.Status, &user.EmailVerified, &user.EmailVerifiedAt,
        &user.PhoneVerified, &user.TwoFactorEnabled, &user.FailedLoginAttempts,
        &user.LockedUntil, &user.LastLoginAt, &user.LastLoginIP, &user.PasswordChangedAt,
        &user.ConsentGiven, &user.ConsentGivenAt, &user.ConsentWithdrawnAt,
        &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
    )
    
    if err != nil {
        if err == pgx.ErrNoRows {
            return nil, fmt.Errorf("user not found: %w", err)
        }
        return nil, fmt.Errorf("failed to find user by email: %w", err)
    }
    
    return &user, nil
}

func (r *UserRepository) FindByEmailWithLock(ctx context.Context, email string) (*models.User, error) {
    query := `
        SELECT id, email, password_hash, first_name, last_name, phone_number,
               status, email_verified, email_verified_at, phone_verified, 
               two_factor_enabled, failed_login_attempts, locked_until,
               last_login_at, last_login_ip, password_changed_at,
               consent_given, consent_given_at, consent_withdrawn_at,
               created_at, updated_at, deleted_at
        FROM users
        WHERE email = $1 AND deleted_at IS NULL
        FOR UPDATE
    `
    
    var user models.User
    err := r.pool.QueryRow(ctx, query, email).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
        &user.PhoneNumber, &user.Status, &user.EmailVerified, &user.EmailVerifiedAt,
        &user.PhoneVerified, &user.TwoFactorEnabled, &user.FailedLoginAttempts,
        &user.LockedUntil, &user.LastLoginAt, &user.LastLoginIP, &user.PasswordChangedAt,
        &user.ConsentGiven, &user.ConsentGivenAt, &user.ConsentWithdrawnAt,
        &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
    )
    
    if err != nil {
        if err == pgx.ErrNoRows {
            return nil, fmt.Errorf("user not found: %w", err)
        }
        return nil, fmt.Errorf("failed to find user with lock: %w", err)
    }
    
    return &user, nil
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
    query := `
        INSERT INTO users (
            id, email, password_hash, first_name, last_name, phone_number,
            status, email_verified, password_changed_at, consent_given,
            created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
        )
    `
    
    now := time.Now()
    user.ID = uuid.New()
    user.CreatedAt = now
    user.UpdatedAt = now
    user.PasswordChangedAt = now
    
    _, err := r.pool.Exec(ctx, query,
        user.ID, user.Email, user.PasswordHash, user.FirstName, user.LastName,
        user.PhoneNumber, user.Status, user.EmailVerified, user.PasswordChangedAt,
        user.ConsentGiven, user.CreatedAt, user.UpdatedAt,
    )
    
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    
    return nil
}

func (r *UserRepository) IncrementFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error {
    query := `
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1,
            updated_at = $2
        WHERE id = $1
    `
    
    _, err := r.pool.Exec(ctx, query, userID, time.Now())
    if err != nil {
        return fmt.Errorf("failed to increment failed login attempts: %w", err)
    }
    
    return nil
}

func (r *UserRepository) ResetFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error {
    query := `
        UPDATE users
        SET failed_login_attempts = 0,
            locked_until = NULL,
            updated_at = $2
        WHERE id = $1
    `
    
    _, err := r.pool.Exec(ctx, query, userID, time.Now())
    if err != nil {
        return fmt.Errorf("failed to reset failed login attempts: %w", err)
    }
    
    return nil
}

func (r *UserRepository) LockAccount(ctx context.Context, userID uuid.UUID, lockDuration time.Duration) error {
    query := `
        UPDATE users
        SET locked_until = $2,
            updated_at = $3
        WHERE id = $1
    `
    
    lockUntil := time.Now().Add(lockDuration)
    _, err := r.pool.Exec(ctx, query, userID, lockUntil, time.Now())
    if err != nil {
        return fmt.Errorf("failed to lock account: %w", err)
    }
    
    return nil
}

func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID, ipAddress string) error {
    query := `
        UPDATE users
        SET last_login_at = $2,
            last_login_ip = $3,
            updated_at = $2
        WHERE id = $1
    `
    
    now := time.Now()
    _, err := r.pool.Exec(ctx, query, userID, now, ipAddress)
    if err != nil {
        return fmt.Errorf("failed to update last login: %w", err)
    }
    
    return nil
}

func (r *UserRepository) FindPaginated(ctx context.Context, opts interfaces.PaginationOptions) (*interfaces.PaginatedResult[models.User], error) {
    // Count total
    countQuery := `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`
    var total int64
    err := r.pool.QueryRow(ctx, countQuery).Scan(&total)
    if err != nil {
        return nil, fmt.Errorf("failed to count users: %w", err)
    }
    
    // Build query with filters
    query := `
        SELECT id, email, password_hash, first_name, last_name, phone_number,
               status, email_verified, email_verified_at, phone_verified, 
               two_factor_enabled, failed_login_attempts, locked_until,
               last_login_at, last_login_ip, password_changed_at,
               consent_given, consent_given_at, consent_withdrawn_at,
               created_at, updated_at, deleted_at
        FROM users
        WHERE deleted_at IS NULL
    `
    
    args := []interface{}{}
    argCount := 1
    
    // Apply filters
    if status, ok := opts.Filters["status"].(string); ok {
        query += fmt.Sprintf(" AND status = $%d", argCount)
        args = append(args, status)
        argCount++
    }
    
    if search, ok := opts.Filters["search"].(string); ok {
        query += fmt.Sprintf(" AND (email ILIKE $%d OR first_name ILIKE $%d OR last_name ILIKE $%d)", argCount, argCount, argCount)
        args = append(args, "%"+search+"%")
        argCount++
    }
    
    // Sort
    query += fmt.Sprintf(" ORDER BY %s %s", opts.SortBy, opts.SortOrder)
    
    // Pagination
    offset := (opts.Page - 1) * opts.PerPage
    query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argCount, argCount+1)
    args = append(args, opts.PerPage, offset)
    
    rows, err := r.pool.Query(ctx, query, args...)
    if err != nil {
        return nil, fmt.Errorf("failed to query users: %w", err)
    }
    defer rows.Close()
    
    users := make([]*models.User, 0)
    for rows.Next() {
        var user models.User
        err := rows.Scan(
            &user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName,
            &user.PhoneNumber, &user.Status, &user.EmailVerified, &user.EmailVerifiedAt,
            &user.PhoneVerified, &user.TwoFactorEnabled, &user.FailedLoginAttempts,
            &user.LockedUntil, &user.LastLoginAt, &user.LastLoginIP, &user.PasswordChangedAt,
            &user.ConsentGiven, &user.ConsentGivenAt, &user.ConsentWithdrawnAt,
            &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to scan user: %w", err)
        }
        users = append(users, &user)
    }
    
    totalPages := int(total) / opts.PerPage
    if int(total)%opts.PerPage > 0 {
        totalPages++
    }
    
    return &interfaces.PaginatedResult[models.User]{
        Data:       users,
        Total:      total,
        Page:       opts.Page,
        PerPage:    opts.PerPage,
        TotalPages: totalPages,
    }, nil
}

func (r *UserRepository) SoftDelete(ctx context.Context, userID uuid.UUID) error {
    query := `
        UPDATE users
        SET deleted_at = $2,
            updated_at = $2
        WHERE id = $1
    `
    
    now := time.Now()
    _, err := r.pool.Exec(ctx, query, userID, now)
    if err != nil {
        return fmt.Errorf("failed to soft delete user: %w", err)
    }
    
    return nil
}
```

### Session Repository Implementation (Redis)

```go
package redis

import (
    "context"
    "encoding/json"
    "fmt"
    "time"
    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "suma-finance/internal/models"
    "suma-finance/internal/repositories/interfaces"
)

type SessionRepository struct {
    client *redis.ClusterClient
}

func NewSessionRepository(client *redis.ClusterClient) interfaces.ISessionRepository {
    return &SessionRepository{client: client}
}

func (r *SessionRepository) Create(ctx context.Context, session *models.Session, ttl time.Duration) error {
    // Store session by session ID
    sessionKey := fmt.Sprintf("session:%s", session.SessionID)
    sessionData, err := json.Marshal(session)
    if err != nil {
        return fmt.Errorf("failed to marshal session: %w", err)
    }
    
    pipe := r.client.Pipeline()
    
    // Set session data with TTL
    pipe.Set(ctx, sessionKey, sessionData, ttl)
    
    // Add to user's session set
    userSessionsKey := fmt.Sprintf("user:sessions:%s", session.UserID.String())
    pipe.SAdd(ctx, userSessionsKey, session.SessionID)
    pipe.Expire(ctx, userSessionsKey, ttl)
    
    // Index by refresh token
    refreshTokenKey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)
    pipe.Set(ctx, refreshTokenKey, session.SessionID, ttl)
    
    _, err = pipe.Exec(ctx)
    if err != nil {
        return fmt.Errorf("failed to create session: %w", err)
    }
    
    return nil
}

func (r *SessionRepository) Get(ctx context.Context, sessionID string) (*models.Session, error) {
    sessionKey := fmt.Sprintf("session:%s", sessionID)
    
    data, err := r.client.Get(ctx, sessionKey).Bytes()
    if err != nil {
        if err == redis.Nil {
            return nil, fmt.Errorf("session not found")
        }
        return nil, fmt.Errorf("failed to get session: %w", err)
    }
    
    var session models.Session
    if err := json.Unmarshal(data, &session); err != nil {
        return nil, fmt.Errorf("failed to unmarshal session: %w", err)
    }
    
    return &session, nil
}

func (r *SessionRepository) UpdateLastActivity(ctx context.Context, sessionID string) error {
    session, err := r.Get(ctx, sessionID)
    if err != nil {
        return err
    }
    
    session.LastActivityAt = time.Now()
    
    sessionKey := fmt.Sprintf("session:%s", sessionID)
    sessionData, err := json.Marshal(session)
    if err != nil {
        return fmt.Errorf("failed to marshal session: %w", err)
    }
    
    // Get current TTL and preserve it
    ttl, err := r.client.TTL(ctx, sessionKey).Result()
    if err != nil {
        return fmt.Errorf("failed to get session TTL: %w", err)
    }
    
    if err := r.client.Set(ctx, sessionKey, sessionData, ttl).Err(); err != nil {
        return fmt.Errorf("failed to update session: %w", err)
    }
    
    return nil
}

func (r *SessionRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error) {
    refreshTokenKey := fmt.Sprintf("refresh_token:%s", refreshToken)
    
    sessionID, err := r.client.Get(ctx, refreshTokenKey).Result()
    if err != nil {
        if err == redis.Nil {
            return nil, fmt.Errorf("refresh token not found")
        }
        return nil, fmt.Errorf("failed to get session by refresh token: %w", err)
    }
    
    return r.Get(ctx, sessionID)
}

func (r *SessionRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
    userSessionsKey := fmt.Sprintf("user:sessions:%s", userID.String())
    
    sessionIDs, err := r.client.SMembers(ctx, userSessionsKey).Result()
    if err != nil {
        return nil, fmt.Errorf("failed to get user sessions: %w", err)
    }
    
    sessions := make([]*models.Session, 0, len(sessionIDs))
    for _, sessionID := range sessionIDs {
        session, err := r.Get(ctx, sessionID)
        if err != nil {
            // Session might have expired, skip
            continue
        }
        sessions = append(sessions, session)
    }
    
    return sessions, nil
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
    sessions, err := r.FindByUserID(ctx, userID)
    if err != nil {
        return err
    }
    
    pipe := r.client.Pipeline()
    
    for _, session := range sessions {
        sessionKey := fmt.Sprintf("session:%s", session.SessionID)
        refreshTokenKey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)
        
        pipe.Del(ctx, sessionKey)
        pipe.Del(ctx, refreshTokenKey)
    }
    
    userSessionsKey := fmt.Sprintf("user:sessions:%s", userID.String())
    pipe.Del(ctx, userSessionsKey)
    
    _, err = pipe.Exec(ctx)
    if err != nil {
        return fmt.Errorf("failed to delete user sessions: %w", err)
    }
    
    return nil
}

func (r *SessionRepository) CountActiveSessions(ctx context.Context, userID uuid.UUID) (int, error) {
    userSessionsKey := fmt.Sprintf("user:sessions:%s", userID.String())
    
    count, err := r.client.SCard(ctx, userSessionsKey).Result()
    if err != nil {
        return 0, fmt.Errorf("failed to count sessions: %w", err)
    }
    
    return int(count), nil
}

func (r *SessionRepository) EnforceConcurrentSessionLimit(ctx context.Context, userID uuid.UUID, maxSessions int) error {
    sessions, err := r.FindByUserID(ctx, userID)
    if err != nil {
        return err
    }
    
    if len(sessions) <= maxSessions {
        return nil
    }
    
    // Sort by last activity, delete oldest
    // (Implementation would sort sessions by LastActivityAt)
    
    sessionsToDelete := len(sessions) - maxSessions
    for i := 0; i < sessionsToDelete; i++ {
        if err := r.Delete(ctx, sessions[i].SessionID); err != nil {
            return fmt.Errorf("failed to delete old session: %w", err)
        }
    }
    
    return nil
}
```

### OTP Repository Implementation (Redis)

```go
package redis

import (
    "context"
    "fmt"
    "time"
    "github.com/google/uuid"
    "github.com/redis/go-redis/v9"
    "suma-finance/internal/repositories/interfaces"
)

type OTPRepository struct {
    client *redis.ClusterClient
}

func NewOTPRepository(client *redis.ClusterClient) interfaces.IOTPRepository {
    return &OTPRepository{client: client}
}

func (r *OTPRepository) Store(ctx context.Context, userID uuid.UUID, otp string, ttl time.Duration) error {
    otpKey := fmt.Sprintf("otp:%s", userID.String())
    
    if err := r.client.Set(ctx, otpKey, otp, ttl).Err(); err != nil {
        return fmt.Errorf("failed to store OTP: %w", err)
    }
    
    return nil
}

func (r *OTPRepository) Verify(ctx context.Context, userID uuid.UUID, otp string) (bool, error) {
    otpKey := fmt.Sprintf("otp:%s", userID.String())
    
    storedOTP, err := r.client.Get(ctx, otpKey).Result()
    if err != nil {
        if err == redis.Nil {
            return false, nil
        }
        return false, fmt.Errorf("failed to verify OTP: %w", err)
    }
    
    if storedOTP != otp {
        return false, nil
    }
    
    // Delete OTP after successful verification (one-time use)
    if err := r.client.Del(ctx, otpKey).Err(); err != nil {
        return true, fmt.Errorf("failed to delete OTP after verification: %w", err)
    }
    
    return true, nil
}

func (r *OTPRepository) IncrementAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
    attemptsKey := fmt.Sprintf("otp:attempts:%s", userID.String())
    
    count, err := r.client.Incr(ctx, attemptsKey).Result()
    if err != nil {
        return 0, fmt.Errorf("failed to increment OTP attempts: %w", err)
    }
    
    // Set expiry on first attempt (5 minutes)
    if count == 1 {
        r.client.Expire(ctx, attemptsKey, 5*time.Minute)
    }
    
    return int(count), nil
}

func (r *OTPRepository) GetAttempts(ctx context.Context, userID uuid.UUID) (int, error) {
    attemptsKey := fmt.Sprintf("otp:attempts:%s", userID.String())
    
    count, err := r.client.Get(ctx, attemptsKey).Int()
    if err != nil {
        if err == redis.Nil {
            return 0, nil
        }
        return 0, fmt.Errorf("failed to get OTP attempts: %w", err)
    }
    
    return count, nil
}

func (r *OTPRepository) SetResendCooldown(ctx context.Context, userID uuid.UUID, cooldown time.Duration) error {
    cooldownKey := fmt.Sprintf("otp:resend:%s", userID.String())
    
    if err := r.client.Set(ctx, cooldownKey, "1", cooldown).Err(); err != nil {
        return fmt.Errorf("failed to set resend cooldown: %w", err)
    }
    
    return nil
}

func (r *OTPRepository) CanResend(ctx context.Context, userID uuid.UUID) (bool, error) {
    cooldownKey := fmt.Sprintf("otp:resend:%s", userID.String())
    
    exists, err := r.client.Exists(ctx, cooldownKey).Result()
    if err != nil {
        return false, fmt.Errorf("failed to check resend cooldown: %w", err)
    }
    
    return exists == 0, nil
}
```

## Query Optimization

### N+1 Problem Prevention

**Problem**: Loading user with all devices and sessions
```go
// Bad: N+1 queries
users, _ := userRepo.FindAll(ctx)
for _, user := range users {
    devices, _ := deviceRepo.FindByUserID(ctx, user.ID) // N queries!
    sessions, _ := sessionRepo.FindByUserID(ctx, user.ID) // N queries!
}
```

**Solution: Batch Loading**
```go
func (r *UserRepository) FindWithDevices(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID][]*models.Device, error) {
    query := `
        SELECT user_id, id, device_id, device_name, device_type, 
               fingerprint, trusted, last_used_at, last_ip_address,
               created_at, updated_at
        FROM devices
        WHERE user_id = ANY($1)
        ORDER BY last_used_at DESC
    `
    
    rows, err := r.pool.Query(ctx, query, userIDs)
    if err != nil {
        return nil, fmt.Errorf("failed to batch load devices: %w", err)
    }
    defer rows.Close()
    
    devicesByUser := make(map[uuid.UUID][]*models.Device)
    for rows.Next() {
        var userID uuid.UUID
        var device models.Device
        
        err := rows.Scan(
            &userID, &device.ID, &device.DeviceID, &device.DeviceName,
            &device.DeviceType, &device.Fingerprint, &device.Trusted,
            &device.LastUsedAt, &device.LastIPAddress,
            &device.CreatedAt, &device.UpdatedAt,
        )
        if err != nil {
            return nil, fmt.Errorf("failed to scan device: %w", err)
        }
        
        devicesByUser[userID] = append(devicesByUser[userID], &device)
    }
    
    return devicesByUser, nil
}
```

### Projection (Select Specific Fields)

```go
// Instead of selecting all fields
func (r *UserRepository) FindEmailsForMarketing(ctx context.Context) ([]string, error) {
    query := `
        SELECT email
        FROM users
        WHERE deleted_at IS NULL
          AND consent_given = true
          AND status = 'active'
    `
    
    rows, err := r.pool.Query(ctx, query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    emails := make([]string, 0)
    for rows.Next() {
        var email string
        if err := rows.Scan(&email); err != nil {
            return nil, err
        }
        emails = append(emails, email)
    }
    
    return emails, nil
}
```

### Index Usage

```sql
-- Critical indexes for authentication queries
CREATE INDEX CONCURRENTLY idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY idx_users_status ON users(status) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;

-- Audit log indexes
CREATE INDEX CONCURRENTLY idx_audit_logs_user_id ON audit_logs(user_id, created_at DESC);
CREATE INDEX CONCURRENTLY idx_audit_logs_event_type ON audit_logs(event_type, created_at DESC);
CREATE INDEX CONCURRENTLY idx_audit_logs_ip_address ON audit_logs(ip_address, created_at DESC);

-- Device indexes
CREATE INDEX CONCURRENTLY idx_devices_user_id ON devices(user_id, last_used_at DESC);
CREATE INDEX CONCURRENTLY idx_devices_fingerprint ON devices(fingerprint);
```

## Caching Strategy

### Application-Level Caching for User Lookups

```go
type CachedUserRepository struct {
    baseRepo    interfaces.IUserRepository
    redisClient *redis.ClusterClient
    cacheTTL    time.Duration
}

func NewCachedUserRepository(baseRepo interfaces.IUserRepository, redisClient *redis.ClusterClient) *CachedUserRepository {
    return &CachedUserRepository{
        baseRepo:    baseRepo,
        redisClient: redisClient,
        cacheTTL:    5 * time.Minute,
    }
}

func (r *CachedUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
    cacheKey := fmt.Sprintf("user:id:%s", id.String())
    
    // Try cache first
    cached, err := r.redisClient.Get(ctx, cacheKey).Bytes()
    if err == nil {
        var user models.User
        if err := json.Unmarshal(cached, &user); err == nil {
            return &user, nil
        }
    }
    
    // Cache miss - fetch from database
    user, err := r.baseRepo.FindByID(ctx, id)
    if err != nil {
        return nil, err
    }
    
    // Store in cache
    userData, _ := json.Marshal(user)
    r.redisClient.Set(ctx, cacheKey, userData, r.cacheTTL)
    
    return user, nil
}

func (r *CachedUserRepository) Update(ctx context.Context, user *models.User) error {
    if err := r.baseRepo.Update(ctx, user); err != nil {
        return err
    }
    
    // Invalidate cache
    cacheKey := fmt.Sprintf("user:id:%s", user.ID.String())
    r.redisClient.Del(ctx, cacheKey)
    
    emailCacheKey := fmt.Sprintf("user:email:%s", user.Email)
    r.redisClient.Del(ctx, emailCacheKey)
    
    return nil
}
```

## Transaction Management

### Basic Transaction for Registration

```go
func (r *UserRepository) CreateWithConsent(ctx context.Context, user *models.User, consents []*models.Consent) error {
    tx, err := r.pool.Begin(ctx)
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    defer tx.Rollback(ctx)
    
    // Create user
    userQuery := `
        INSERT INTO users (
            id, email, password_hash, first_name, last_name,
            status, email_verified, password_changed_at,
            consent_given, consent_given_at, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    `
    
    now := time.Now()
    user.ID = uuid.New()
    user.CreatedAt = now
    user.UpdatedAt = now
    user.PasswordChangedAt = now
    user.ConsentGivenAt = &now
    
    _, err = tx.Exec(ctx, userQuery,
        user.ID, user.Email, user.PasswordHash, user.FirstName, user.LastName,
        user.Status, user.EmailVerified, user.PasswordChangedAt,
        user.ConsentGiven, user.ConsentGivenAt, user.CreatedAt, user.UpdatedAt,
    )
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    
    // Create consent records
    consentQuery := `
        INSERT INTO consents (
            id, user_id, consent_type, consent_version, granted,
            granted_at, ip_address, user_agent, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `
    
    for _, consent := range consents {
        consent.ID = uuid.New()
        consent.UserID = user.ID
        consent.CreatedAt = now
        consent.UpdatedAt = now
        
        _, err = tx.Exec(ctx, consentQuery,
            consent.ID, consent.UserID, consent.ConsentType, consent.ConsentVersion,
            consent.Granted, consent.GrantedAt, consent.IPAddress, consent.UserAgent,
            consent.CreatedAt, consent.UpdatedAt,
        )
        if err != nil {
            return fmt.Errorf("failed to create consent: %w", err)
        }
    }
    
    // Commit transaction
    if err := tx.Commit(ctx); err != nil {
        return fmt.Errorf("failed to commit transaction: %w", err)
    }
    
    return nil
}
```

## Error Handling

```go
package errors

import "errors"

var (
    ErrUserNotFound          = errors.New("user not found")
    ErrUserAlreadyExists     = errors.New("user already exists")
    ErrInvalidCredentials    = errors.New("invalid credentials")
    ErrAccountLocked         = errors.New("account is locked")
    ErrAccountNotVerified    = errors.New("email not verified")
    ErrSessionNotFound       = errors.New("session not found")
    ErrSessionExpired        = errors.New("session expired")
    ErrInvalidRefreshToken   = errors.New("invalid refresh token")
    ErrOTPExpired            = errors.New("OTP expired")
    ErrOTPInvalid            = errors.New("OTP invalid")
    ErrTooManyAttempts       = errors.New("too many attempts")
    ErrDatabaseConnection    = errors.New("database connection failed")
    ErrTransactionFailed     = errors.New("transaction failed")
)

func WrapRepositoryError(err error) error {
    if err == nil {
        return nil
    }
    
    // Map pgx errors to domain errors
    if errors.Is(err, pgx.ErrNoRows) {
        return ErrUserNotFound
    }
    
    // Check for unique constraint violations
    if strings.Contains(err.Error(), "unique constraint") {
        return ErrUserAlreadyExists
    }
    
    return fmt.Errorf("repository error: %w", err)
}
```

## Testing

### Repository Testing with Test Database

```go
package postgres_test

import (
    "context"
    "testing"
    "time"
    "github.com/google/uuid"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "suma-finance/internal/models"
    "suma-finance/internal/repositories/postgres"
    "suma-finance/test/testutil"
)

func TestUserRepository_Create(t *testing.T) {
    // Setup test database
    pool := testutil.SetupTestDB(t)
    defer testutil.TeardownTestDB(t, pool)
    
    repo := postgres.NewUserRepository(pool)
    ctx := context.Background()
    
    // Test user creation
    user := &models.User{
        Email:        "test@example.com",
        PasswordHash: "hashed_password",
        FirstName:    stringPtr("John"),
        LastName:     stringPtr("Doe"),
        Status:       models.UserStatusPending,
        ConsentGiven: true,
    }
    
    err := repo.Create(ctx, user)
    require.NoError(t, err)
    assert.NotEqual(t, uuid.Nil, user.ID)
    assert.False(t, user.CreatedAt.IsZero())
    
    // Verify user was created
    found, err := repo.FindByEmail(ctx, "test@example.com")
    require.NoError(t, err)
    assert.Equal(t, user.Email, found.Email)
    assert.Equal(t, user.PasswordHash, found.PasswordHash)
}

func TestUserRepository_IncrementFailedLoginAttempts(t *testing.T) {
    pool := testutil.SetupTestDB(t)
    defer testutil.TeardownTestDB(t, pool)
    
    repo := postgres.NewUserRepository(pool)
    ctx := context.Background()
    
    // Create test user
    user := testutil.CreateTestUser(t, repo)
    
    // Increment attempts
    err := repo.IncrementFailedLoginAttempts(ctx, user.ID)
    require.NoError(t, err)
    
    // Verify increment
    found, err := repo.FindByID(ctx, user.ID)
    require.NoError(t, err)
    assert.Equal(t, 1, found.FailedLoginAttempts)
    
    // Increment again
    err = repo.IncrementFailedLoginAttempts(ctx, user.ID)
    require.NoError(t, err)
    
    found, err = repo.FindByID(ctx, user.ID)
    require.NoError(t, err)
    assert.Equal(t, 2, found.FailedLoginAttempts)
}

func TestUserRepository_LockAccount(t *testing.T) {
    pool := testutil.SetupTestDB(t)
    defer testutil.TeardownTestDB(t, pool)
    
    repo := postgres.NewUserRepository(pool)
    ctx := context.Background()
    
    user := testutil.CreateTestUser(t, repo)
    
    // Lock account for 15 minutes
    lockDuration := 15 * time.Minute
    err := repo.LockAccount(ctx, user.ID, lockDuration)
    require.NoError(t, err)
    
    // Verify lock
    found, err := repo.FindByID(ctx, user.ID)
    require.NoError(t, err)
    require.NotNil(t, found.LockedUntil)
    assert.True(t, found.LockedUntil.After(time.Now()))
    assert.True(t, found.IsLocked())
}
```

### Mocking Repositories

```go
package mocks

import (
    "context"
    "github.com/google/uuid"
    "github.com/stretchr/testify/mock"
    "suma-finance/internal/models"
    "suma-finance/internal/repositories/interfaces"
)

type MockUserRepository struct {
    mock.Mock
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
    args := m.Called(ctx, email)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}

// Usage in service tests
func TestAuthService_Login(t *testing.T) {
    mockRepo := new(mocks.MockUserRepository)
    authService := services.NewAuthService(mockRepo)
    
    testUser := &models.User{
        ID:           uuid.New(),
        Email:        "test@example.com",
        PasswordHash: "$argon2id$...",
        Status:       models.UserStatusActive,
        EmailVerified: true,
    }
    
    mockRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(testUser, nil)
    mockRepo.On("UpdateLastLogin", mock.Anything, testUser.ID, mock.Anything).Return(nil)
    
    result, err := authService.Login(context.Background(), "test@example.com", "password123")
    
    assert.NoError(t, err)
    assert.NotNil(t, result)
    mockRepo.AssertExpectations(t)
}
```

## Best Practices

### DO
- ✅ Use repository pattern for clean abstraction
- ✅ Implement pagination for all list queries
- ✅ Use parameterized queries to prevent SQL injection
- ✅ Cache frequently accessed data (user profiles, sessions)
- ✅ Use transactions for related operations (user creation + consent)
- ✅ Handle errors gracefully with domain-specific errors
- ✅ Write comprehensive repository tests
- ✅ Use connection pooling with health checks
- ✅ Implement row-level locking for concurrent updates
- ✅ Use indexes on frequently queried columns
- ✅ Batch load related data to prevent N+1 problems
- ✅ Set appropriate TTLs for Redis data
- ✅ Log slow queries for optimization

### DON'T
- ❌ Put business logic in repositories (authentication logic belongs in services)
- ❌ Use `SELECT *` in queries (select only needed fields)
- ❌ Forget to handle N+1 query problems
- ❌ Expose raw SQL in business/API layers
- ❌ Skip error handling or return generic errors
- ❌ Store sensitive data unencrypted
- ❌ Forget to release database connections
- ❌ Hardcode database credentials (use environment variables)
- ❌ Use ORM auto-migrations in production
- ❌ Skip prepared statement caching
- ❌ Ignore connection pool exhaustion
- ❌ Cache data without considering invalidation strategy

## Appendix

### Repository Method Naming Conventions

| Operation | Method Name | Example |
|-----------|-------------|---------|
| Get one | `FindByX`, `GetX` | `FindByEmail`, `GetByID` |
| Get many | `Find`, `FindAll`, `List` | `FindActiveUsers`, `ListByStatus` |
| Create | `Create`, `Insert` | `Create`, `CreateWithConsent` |
| Update | `Update`, `Save` | `Update`, `UpdateLastLogin` |
| Delete | `Delete`, `Remove`, `SoftDelete` | `SoftDelete`, `HardDelete` |
| Count | `Count` | `CountByStatus`, `CountTotal` |
| Exists | `Exists` | `ExistsByEmail` |
| Increment | `Increment` | `IncrementFailedLoginAttempts` |

### Performance Checklist

- [x] Use indexes on: `email`, `status`, `locked_until`, `user_id` (foreign keys)
- [x] Implement pagination for user lists, audit logs
- [x] Prevent N+1 queries with batch loading for devices/sessions
- [x] Use Redis for session/OTP caching (sub-10ms lookups)
- [x] Select only needed fields (projection queries)
- [x] Use connection pooling (min: 10, max: 50 connections)
- [x] Monitor slow queries (threshold: >100ms)
- [x] Optimize audit log queries with time-based indexes
- [x] Use prepared statements for all queries
- [x] Implement query timeouts (5s max)
- [x] Cache user lookups with 5-minute TTL
- [x] Use Redis pub/sub for session invalidation

### Database Schema

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone_number VARCHAR(20),
    status VARCHAR(20) NOT NULL DEFAULT 'pending_verification',
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP,
    phone_verified BOOLEAN DEFAULT FALSE,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    password_changed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    consent_given BOOLEAN DEFAULT FALSE,
    consent_given_at TIMESTAMP,
    consent_withdrawn_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

-- Audit logs table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50) NOT NULL,
    event_status VARCHAR(20) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    device_id VARCHAR(255),
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Consents table
CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_type VARCHAR(50) NOT NULL,
    consent_version VARCHAR(20) NOT NULL,
    granted BOOLEAN NOT NULL,
    granted_at TIMESTAMP,
    withdrawn_at TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Devices table
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255) NOT NULL,
    device_type VARCHAR(20) NOT NULL,
    fingerprint VARCHAR(255) NOT NULL,
    trusted BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_ip_address VARCHAR(45),
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, device_id)
);

-- Indexes
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type, created_at DESC);
CREATE INDEX idx_audit_logs_ip_address ON audit_logs(ip_address, created_at DESC);
CREATE INDEX idx_consents_user_id ON consents(user_id);
CREATE INDEX idx_devices_user_id ON devices(user_id, last_used_at DESC);
CREATE INDEX idx_devices_fingerprint ON devices(fingerprint);
```

### Glossary

- **Repository Pattern**: Design pattern that abstracts data access logic behind interfaces, providing a collection-like API for domain entities
- **N+1 Problem**: Performance anti-pattern where one query retrieves parent records followed by N additional queries for each child record
- **Connection Pooling**: Technique of maintaining a cache of database connections for reuse, reducing connection overhead
- **Prepared Statement**: Pre-compiled SQL statement with parameter placeholders, improving performance and preventing SQL injection
- **Row-Level Locking**: Database locking mechanism that locks individual rows during transactions to prevent concurrent modification conflicts
- **Soft Delete**: Marking records as deleted without physical removal from database (using `deleted_at` timestamp)
- **Hard Delete**: Permanent physical removal of records from database
- **TTL (Time To Live)**: Expiration time for cached data, after which it's automatically removed
- **ACID**: Atomicity, Consistency, Isolation, Durability - properties ensuring reliable database transactions
- **Projection Query**: Query that retrieves only specific columns rather than all columns (`SELECT *`)
- **Batch Loading**: Technique of loading multiple related records in a single query to avoid N+1 problems
- **Query Builder**: API for constructing SQL queries programmatically in a type-safe manner
- **ORM (Object-Relational Mapping)**: Framework that maps database tables to programming language objects