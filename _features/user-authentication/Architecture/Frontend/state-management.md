---
layout: default
title: State Management
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

# arch-state-management-generator

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Identity & Access Management
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Executive Summary

This document defines the state management architecture for the SUMA Finance authentication system, covering user registration, login, session management, 2FA, password reset, and GDPR consent workflows. The architecture prioritizes security, compliance, and scalability for a fintech application handling sensitive financial data.

### Key Decisions
- **Backend State**: Redis-backed session storage with PostgreSQL persistence
- **Frontend State**: React Context + Redux Toolkit for authentication state
- **Mobile State**: React Native with Redux + Secure Storage
- **Token Strategy**: JWT access tokens (15 min) + refresh tokens (7 days) with rotation
- **Session Strategy**: Redis clusters for high-performance session lookups (<10ms)

---

## 2. State Management Requirements

### 2.1 Functional Requirements

#### Authentication State
- **User Identity**: User ID, email, roles, permissions
- **Session State**: Active sessions, device fingerprints, IP addresses
- **Token State**: Access token, refresh token, expiration timestamps
- **2FA State**: 2FA enabled/disabled, OTP verification status, backup codes
- **Device State**: Trusted devices, device fingerprints, last access times

#### Registration State
- **Form State**: Email, password, consent checkboxes, validation errors
- **Verification State**: Email verification status, token validity, resend cooldown
- **Consent State**: GDPR consent timestamps, IP addresses, consent versions

#### Security State
- **Lockout State**: Failed login attempts, lockout timestamp, unlock mechanism
- **Rate Limiting**: Request counts per IP/user, cooldown periods
- **Audit Logs**: Login attempts, password changes, 2FA events with timestamps

### 2.2 Non-Functional Requirements

#### Performance
- **Session Lookup**: <10ms (Redis)
- **Token Validation**: <50ms
- **State Hydration**: <200ms (initial page load)
- **State Persistence**: <100ms (write operations)

#### Scalability
- **Concurrent Sessions**: Support 100,000+ active sessions
- **Session Writes**: 10,000 writes/second (Redis cluster)
- **State Replication**: Multi-region session replication

#### Security
- **Encryption at Rest**: AES-256-GCM for sensitive state (PII, credentials)
- **Encryption in Transit**: TLS 1.3 for all state synchronization
- **State Isolation**: User state isolated by session tokens
- **Token Rotation**: Refresh token rotation on every use

#### Availability
- **Session Availability**: 99.95% (Redis cluster with failover)
- **State Recovery**: Automatic session recovery on Redis failover
- **Backup Strategy**: PostgreSQL as persistent state backup

---

## 3. State Architecture

### 3.1 State Layers

```
┌─────────────────────────────────────────────────┐
│          Client-Side State (Ephemeral)          │
│  React Context, Redux, Local Storage (tokens)   │
└───────────────────┬─────────────────────────────┘
                    │ HTTPS/TLS 1.3
┌───────────────────▼─────────────────────────────┐
│           API Gateway + JWT Validation          │
│        Token verification, rate limiting        │
└───────────────────┬─────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────┐
│         Session State (Redis Cluster)           │
│  Active sessions, OTP cache, rate limit state   │
│  TTL-based expiration, sub-10ms lookups          │
└───────────────────┬─────────────────────────────┘
                    │
┌───────────────────▼─────────────────────────────┐
│      Persistent State (PostgreSQL)              │
│  Users, credentials, audit logs, consent        │
│  ACID transactions, referential integrity       │
└─────────────────────────────────────────────────┘
```

### 3.2 State Components

#### 3.2.1 Client-Side State (React/React Native)

**Technology**: React Context API + Redux Toolkit

**State Structure**:
```typescript
interface AuthState {
  user: {
    id: string;
    email: string;
    emailVerified: boolean;
    roles: string[];
    permissions: string[];
    mfaEnabled: boolean;
    createdAt: string;
  } | null;
  
  tokens: {
    accessToken: string;
    refreshToken: string;
    accessTokenExpiry: number;
    refreshTokenExpiry: number;
  } | null;
  
  session: {
    sessionId: string;
    deviceId: string;
    lastActivity: number;
    expiresAt: number;
  } | null;
  
  ui: {
    isLoading: boolean;
    isAuthenticated: boolean;
    requiresMFA: boolean;
    lockoutUntil: number | null;
    errors: Record<string, string>;
  };
  
  consent: {
    privacyPolicy: boolean;
    termsOfService: boolean;
    marketing: boolean;
    acceptedAt: string | null;
  };
}
```

**State Management Pattern**:
```typescript
// Redux Toolkit Slice
import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

export const loginUser = createAsyncThunk(
  'auth/login',
  async (credentials: LoginCredentials, { rejectWithValue }) => {
    try {
      const response = await authAPI.login(credentials);
      // Store tokens in secure storage
      await secureStorage.setTokens(response.tokens);
      return response;
    } catch (error) {
      return rejectWithValue(error.response.data);
    }
  }
);

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    logout: (state) => {
      state.user = null;
      state.tokens = null;
      state.session = null;
      secureStorage.clearTokens();
    },
    updateLastActivity: (state) => {
      if (state.session) {
        state.session.lastActivity = Date.now();
      }
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(loginUser.pending, (state) => {
        state.ui.isLoading = true;
        state.ui.errors = {};
      })
      .addCase(loginUser.fulfilled, (state, action) => {
        state.user = action.payload.user;
        state.tokens = action.payload.tokens;
        state.session = action.payload.session;
        state.ui.isAuthenticated = true;
        state.ui.isLoading = false;
      })
      .addCase(loginUser.rejected, (state, action) => {
        state.ui.isLoading = false;
        state.ui.errors = action.payload as Record<string, string>;
      });
  },
});
```

**Storage Strategy**:
- **Access Tokens**: Memory only (Redux state)
- **Refresh Tokens**: Secure storage (HttpOnly cookies on web, KeyChain/KeyStore on mobile)
- **User Profile**: LocalStorage (non-sensitive data only)
- **Consent State**: LocalStorage with server synchronization

**Mobile-Specific Considerations**:
```typescript
// React Native Secure Storage
import * as SecureStore from 'expo-secure-store';

class TokenManager {
  async saveTokens(tokens: Tokens): Promise<void> {
    await SecureStore.setItemAsync('accessToken', tokens.accessToken);
    await SecureStore.setItemAsync('refreshToken', tokens.refreshToken);
  }
  
  async getAccessToken(): Promise<string | null> {
    return await SecureStore.getItemAsync('accessToken');
  }
  
  async clearTokens(): Promise<void> {
    await SecureStore.deleteItemAsync('accessToken');
    await SecureStore.deleteItemAsync('refreshToken');
  }
}
```

#### 3.2.2 Session State (Redis)

**Technology**: Redis Cluster (AWS ElastiCache)

**State Structure**:
```redis
# Session Data (Hash)
HSET session:{sessionId}
  userId: "uuid"
  email: "user@example.com"
  deviceId: "fingerprint"
  ipAddress: "192.168.1.1"
  userAgent: "Mozilla/5.0..."
  createdAt: "2025-10-29T10:00:00Z"
  lastActivity: "2025-10-29T10:15:00Z"
  expiresAt: "2025-10-29T18:00:00Z"
  mfaVerified: "true"
  
# TTL: 8 hours (absolute timeout)
EXPIRE session:{sessionId} 28800

# Refresh Token Mapping (String)
SET refresh_token:{tokenHash} {sessionId}
EXPIRE refresh_token:{tokenHash} 604800  # 7 days

# OTP Cache (String)
SET otp:{userId} "123456"
EXPIRE otp:{userId} 300  # 5 minutes

# Rate Limiting (Counter)
INCR rate_limit:login:{ipAddress}
EXPIRE rate_limit:login:{ipAddress} 60  # 1 minute

# Account Lockout (String)
SET lockout:{userId} "2025-10-29T10:30:00Z"
EXPIRE lockout:{userId} 900  # 15 minutes

# User Active Sessions (Set)
SADD user_sessions:{userId} {sessionId1} {sessionId2}
EXPIRE user_sessions:{userId} 604800
```

**Redis Operations**:
```go
// Session Service (Go)
type SessionService struct {
    redis *redis.ClusterClient
}

func (s *SessionService) CreateSession(ctx context.Context, session *Session) error {
    pipe := s.redis.Pipeline()
    
    sessionKey := fmt.Sprintf("session:%s", session.ID)
    pipe.HSet(ctx, sessionKey, map[string]interface{}{
        "userId":       session.UserID,
        "email":        session.Email,
        "deviceId":     session.DeviceID,
        "ipAddress":    session.IPAddress,
        "userAgent":    session.UserAgent,
        "createdAt":    session.CreatedAt,
        "lastActivity": session.LastActivity,
        "expiresAt":    session.ExpiresAt,
        "mfaVerified":  session.MFAVerified,
    })
    pipe.Expire(ctx, sessionKey, 8*time.Hour)
    
    // Add to user's active sessions
    userSessionsKey := fmt.Sprintf("user_sessions:%s", session.UserID)
    pipe.SAdd(ctx, userSessionsKey, session.ID)
    pipe.Expire(ctx, userSessionsKey, 7*24*time.Hour)
    
    _, err := pipe.Exec(ctx)
    return err
}

func (s *SessionService) GetSession(ctx context.Context, sessionID string) (*Session, error) {
    sessionKey := fmt.Sprintf("session:%s", sessionID)
    result, err := s.redis.HGetAll(ctx, sessionKey).Result()
    if err != nil {
        return nil, err
    }
    
    if len(result) == 0 {
        return nil, ErrSessionNotFound
    }
    
    // Update last activity with idle timeout check
    lastActivity, _ := time.Parse(time.RFC3339, result["lastActivity"])
    if time.Since(lastActivity) > 15*time.Minute {
        s.DeleteSession(ctx, sessionID)
        return nil, ErrSessionExpired
    }
    
    // Refresh session activity
    s.redis.HSet(ctx, sessionKey, "lastActivity", time.Now().Format(time.RFC3339))
    
    return mapToSession(result), nil
}

func (s *SessionService) DeleteSession(ctx context.Context, sessionID string) error {
    pipe := s.redis.Pipeline()
    
    // Get userId before deletion
    sessionKey := fmt.Sprintf("session:%s", sessionID)
    userId, _ := s.redis.HGet(ctx, sessionKey, "userId").Result()
    
    pipe.Del(ctx, sessionKey)
    
    if userId != "" {
        userSessionsKey := fmt.Sprintf("user_sessions:%s", userId)
        pipe.SRem(ctx, userSessionsKey, sessionID)
    }
    
    _, err := pipe.Exec(ctx)
    return err
}
```

**Session Cleanup Strategy**:
- **Automatic TTL Expiration**: Redis handles automatic cleanup
- **Idle Timeout Check**: Application-level check on session retrieval
- **Manual Cleanup**: Background job removes orphaned sessions every 1 hour
- **Concurrent Session Limit**: Enforce max 5 sessions per user

#### 3.2.3 Persistent State (PostgreSQL)

**Technology**: PostgreSQL 15+ with encryption at rest

**Schema Design**:
```sql
-- Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash TEXT NOT NULL,  -- Argon2id hash
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,  -- Soft delete for GDPR
    
    -- Security
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,  -- Encrypted TOTP secret
    backup_codes TEXT[],  -- Encrypted backup codes
    
    -- Account Security
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE,
    
    -- GDPR
    consent_version INT NOT NULL DEFAULT 1,
    data_processing_consent BOOLEAN DEFAULT FALSE,
    marketing_consent BOOLEAN DEFAULT FALSE,
    consent_timestamp TIMESTAMP WITH TIME ZONE,
    consent_ip_address INET,
    
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NULL;

-- Sessions Table (Backup persistence)
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_active ON sessions(user_id, revoked) WHERE revoked = FALSE;

-- Refresh Tokens Table
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,  -- SHA256 hash
    parent_token_hash TEXT,  -- For rotation detection
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT refresh_tokens_session_id_fkey FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Email Verification Tokens
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,  -- HMAC-SHA256
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT email_verification_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_email_verification_tokens_token_hash ON email_verification_tokens(token_hash);
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at);

-- Password Reset Tokens
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,  -- HMAC-SHA256
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT password_reset_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

-- Audit Logs (Append-only)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,  -- login, logout, password_change, etc.
    event_status VARCHAR(20) NOT NULL,  -- success, failure
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_id VARCHAR(255),
    metadata JSONB,  -- Additional event-specific data
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_event_status ON audit_logs(event_status);

-- Trusted Devices
CREATE TABLE trusted_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50),  -- mobile, desktop, tablet
    fingerprint JSONB,  -- Browser/device fingerprint data
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    trusted_at TIMESTAMP WITH TIME ZONE,
    ip_addresses INET[],
    
    CONSTRAINT trusted_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT trusted_devices_unique_device UNIQUE (user_id, device_id)
);

CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_device_id ON trusted_devices(device_id);

-- Consent Audit Trail
CREATE TABLE consent_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_version INT NOT NULL,
    data_processing_consent BOOLEAN NOT NULL,
    marketing_consent BOOLEAN NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    action VARCHAR(20) NOT NULL,  -- granted, withdrawn, updated
    
    CONSTRAINT consent_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_consent_history_user_id ON consent_history(user_id);
CREATE INDEX idx_consent_history_timestamp ON consent_history(timestamp DESC);
```

**Repository Pattern (Go)**:
```go
type UserRepository struct {
    db *sql.DB
}

func (r *UserRepository) CreateUser(ctx context.Context, user *User) error {
    query := `
        INSERT INTO users (
            email, password_hash, mfa_enabled,
            data_processing_consent, marketing_consent,
            consent_timestamp, consent_ip_address, consent_version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, created_at
    `
    
    err := r.db.QueryRowContext(
        ctx, query,
        user.Email,
        user.PasswordHash,
        user.MFAEnabled,
        user.DataProcessingConsent,
        user.MarketingConsent,
        time.Now(),
        user.ConsentIPAddress,
        1,  // Initial consent version
    ).Scan(&user.ID, &user.CreatedAt)
    
    if err != nil {
        return fmt.Errorf("failed to create user: %w", err)
    }
    
    // Log consent in audit trail
    r.logConsentEvent(ctx, user.ID, "granted")
    
    return nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
    query := `
        SELECT id, email, email_verified, password_hash, created_at,
               mfa_enabled, failed_login_attempts, locked_until,
               data_processing_consent, marketing_consent
        FROM users
        WHERE email = $1 AND deleted_at IS NULL
    `
    
    var user User
    err := r.db.QueryRowContext(ctx, query, email).Scan(
        &user.ID,
        &user.Email,
        &user.EmailVerified,
        &user.PasswordHash,
        &user.CreatedAt,
        &user.MFAEnabled,
        &user.FailedLoginAttempts,
        &user.LockedUntil,
        &user.DataProcessingConsent,
        &user.MarketingConsent,
    )
    
    if err == sql.ErrNoRows {
        return nil, ErrUserNotFound
    }
    
    return &user, err
}

func (r *UserRepository) IncrementFailedAttempts(ctx context.Context, userID string) error {
    query := `
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_until = CASE
                WHEN failed_login_attempts + 1 >= 5
                THEN NOW() + INTERVAL '15 minutes'
                ELSE locked_until
            END
        WHERE id = $1
    `
    
    _, err := r.db.ExecContext(ctx, query, userID)
    return err
}

func (r *UserRepository) ResetFailedAttempts(ctx context.Context, userID string) error {
    query := `
        UPDATE users
        SET failed_login_attempts = 0,
            locked_until = NULL
        WHERE id = $1
    `
    
    _, err := r.db.ExecContext(ctx, query, userID)
    return err
}
```

---

## 4. State Synchronization

### 4.1 Client-Server Synchronization

**Token Refresh Flow**:
```typescript
// Automatic Token Refresh (React)
import { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';

const useTokenRefresh = () => {
  const dispatch = useDispatch();
  const tokens = useSelector(state => state.auth.tokens);
  
  useEffect(() => {
    if (!tokens) return;
    
    const timeUntilExpiry = tokens.accessTokenExpiry - Date.now();
    const refreshThreshold = 60 * 1000; // Refresh 1 minute before expiry
    
    if (timeUntilExpiry < refreshThreshold) {
      dispatch(refreshAccessToken());
    }
    
    // Set up automatic refresh
    const timer = setTimeout(() => {
      dispatch(refreshAccessToken());
    }, timeUntilExpiry - refreshThreshold);
    
    return () => clearTimeout(timer);
  }, [tokens, dispatch]);
};

// Axios Interceptor for Token Refresh
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const newTokens = await authAPI.refreshToken();
        store.dispatch(setTokens(newTokens));
        
        // Retry original request with new token
        originalRequest.headers.Authorization = `Bearer ${newTokens.accessToken}`;
        return axios(originalRequest);
      } catch (refreshError) {
        // Refresh failed, logout user
        store.dispatch(logout());
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);
```

**Backend Token Refresh Handler**:
```go
func (h *AuthHandler) RefreshToken(c *gin.Context) {
    // Extract refresh token from HttpOnly cookie
    refreshToken, err := c.Cookie("refresh_token")
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "No refresh token"})
        return
    }
    
    // Validate refresh token
    tokenHash := hashToken(refreshToken)
    session, err := h.sessionService.GetSessionByRefreshToken(c.Request.Context(), tokenHash)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
        return
    }
    
    // Check for token reuse (rotation detection)
    if session.RefreshTokenUsed {
        // Potential attack - revoke all user sessions
        h.sessionService.RevokeAllUserSessions(c.Request.Context(), session.UserID)
        h.auditLogger.LogSecurityEvent(c.Request.Context(), AuditEvent{
            UserID:    session.UserID,
            EventType: "token_reuse_detected",
            IPAddress: c.ClientIP(),
            Severity:  "critical",
        })
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Token reuse detected"})
        return
    }
    
    // Generate new token pair
    newAccessToken, err := h.tokenService.GenerateAccessToken(session.UserID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
        return
    }
    
    newRefreshToken, err := h.tokenService.GenerateRefreshToken(session.UserID, session.ID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
        return
    }
    
    // Mark old refresh token as used
    h.sessionService.MarkRefreshTokenUsed(c.Request.Context(), tokenHash)
    
    // Store new refresh token in Redis + PostgreSQL
    newTokenHash := hashToken(newRefreshToken)
    h.sessionService.StoreRefreshToken(c.Request.Context(), RefreshTokenData{
        UserID:          session.UserID,
        SessionID:       session.ID,
        TokenHash:       newTokenHash,
        ParentTokenHash: tokenHash,
        ExpiresAt:       time.Now().Add(7 * 24 * time.Hour),
    })
    
    // Set new refresh token in HttpOnly cookie
    c.SetCookie(
        "refresh_token",
        newRefreshToken,
        7*24*60*60, // 7 days
        "/",
        "",
        true,  // Secure
        true,  // HttpOnly
    )
    
    c.JSON(http.StatusOK, gin.H{
        "accessToken": newAccessToken,
        "expiresIn":   900, // 15 minutes
    })
}
```

### 4.2 Redis-PostgreSQL Synchronization

**Write-Through Cache Pattern**:
```go
func (s *SessionService) CreateSessionWithPersistence(ctx context.Context, session *Session) error {
    // 1. Write to PostgreSQL first (source of truth)
    err := s.db.CreateSession(ctx, session)
    if err != nil {
        return fmt.Errorf("failed to persist session: %w", err)
    }
    
    // 2. Write to Redis cache
    err = s.redis.CreateSession(ctx, session)
    if err != nil {
        // Log error but don't fail - cache miss will trigger DB lookup
        s.logger.Warn("failed to cache session", "sessionId", session.ID, "error", err)
    }
    
    return nil
}

func (s *SessionService) GetSessionWithFallback(ctx context.Context, sessionID string) (*Session, error) {
    // 1. Try Redis first (fast path)
    session, err := s.redis.GetSession(ctx, sessionID)
    if err == nil {
        return session, nil
    }
    
    // 2. Redis miss - query PostgreSQL
    session, err = s.db.GetSession(ctx, sessionID)
    if err != nil {
        return nil, err
    }
    
    // 3. Populate Redis cache for next request
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        
        err := s.redis.CreateSession(ctx, session)
        if err != nil {
            s.logger.Warn("failed to populate cache", "sessionId", sessionID, "error", err)
        }
    }()
    
    return session, nil
}
```

**Background Synchronization Job**:
```go
// Periodic sync job to ensure Redis-PostgreSQL consistency
func (s *SessionService) StartSyncJob(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            s.syncExpiredSessions(ctx)
            s.syncOrphanedSessions(ctx)
        case <-ctx.Done():
            return
        }
    }
}

func (s *SessionService) syncExpiredSessions(ctx context.Context) {
    // Delete expired sessions from PostgreSQL
    result, err := s.db.Exec(ctx, `
        DELETE FROM sessions
        WHERE expires_at < NOW() OR revoked = TRUE
    `)
    if err != nil {
        s.logger.Error("failed to sync expired sessions", "error", err)
        return
    }
    
    rowsAffected, _ := result.RowsAffected()
    s.logger.Info("synced expired sessions", "deleted", rowsAffected)
}

func (s *SessionService) syncOrphanedSessions(ctx context.Context) {
    // Find sessions in PostgreSQL but not in Redis
    sessions, err := s.db.GetActiveSessions(ctx)
    if err != nil {
        s.logger.Error("failed to query active sessions", "error", err)
        return
    }
    
    for _, session := range sessions {
        exists, _ := s.redis.Exists(ctx, fmt.Sprintf("session:%s", session.ID)).Result()
        if exists == 0 {
            // Repopulate Redis cache
            s.redis.CreateSession(ctx, &session)
        }
    }
}
```

---

## 5. State Validation & Integrity

### 5.1 JWT Validation

**Token Structure**:
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "key-2025-10"
  },
  "payload": {
    "sub": "user-uuid",
    "email": "user@example.com",
    "roles": ["user"],
    "permissions": ["read:profile", "write:profile"],
    "session_id": "session-uuid",
    "mfa_verified": true,
    "iat": 1730188800,
    "exp": 1730189700,
    "nbf": 1730188800,
    "iss": "https://api.sumafinance.com",
    "aud": ["https://api.sumafinance.com", "https://app.sumafinance.com"]
  },
  "signature": "..."
}
```

**Validation Middleware**:
```go
func (m *AuthMiddleware) ValidateJWT() gin.HandlerFunc {
    return func(c *gin.Context) {
        // 1. Extract token from Authorization header
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization header"})
            return
        }
        
        tokenString := strings.TrimPrefix(authHeader, "Bearer ")
        
        // 2. Parse and validate token
        token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
            // Validate signing algorithm
            if token.Method.Alg() != "RS256" {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            
            // Get public key by kid
            kid, ok := token.Header["kid"].(string)
            if !ok {
                return nil, fmt.Errorf("missing kid in token header")
            }
            
            return m.keyManager.GetPublicKey(kid)
        })
        
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            return
        }
        
        // 3. Validate claims
        claims, ok := token.Claims.(*JWTClaims)
        if !ok || !token.Valid {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
            return
        }
        
        // 4. Validate expiration
        if time.Now().Unix() > claims.ExpiresAt {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
            return
        }
        
        // 5. Validate not-before
        if time.Now().Unix() < claims.NotBefore {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token not yet valid"})
            return
        }
        
        // 6. Validate issuer and audience
        if claims.Issuer != "https://api.sumafinance.com" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid issuer"})
            return
        }
        
        // 7. Verify session still exists in Redis
        session, err := m.sessionService.GetSession(c.Request.Context(), claims.SessionID)
        if err != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session not found or expired"})
            return
        }
        
        // 8. Verify user still active in database
        user, err := m.userService.GetUserByID(c.Request.Context(), claims.Subject)
        if err != nil || user.DeletedAt != nil {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
            return
        }
        
        // 9. Check account lockout status
        if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
                "error": "Account locked",
                "locked_until": user.LockedUntil,
            })
            return
        }
        
        // 10. Attach user context to request
        c.Set("user_id", claims.Subject)
        c.Set("session_id", claims.SessionID)
        c.Set("user_email", claims.Email)
        c.Set("user_roles", claims.Roles)
        c.Set("user_permissions", claims.Permissions)
        
        c.Next()
    }
}
```

### 5.2 Session Integrity Checks

**Redis Session Validation**:
```go
func (s *SessionService) ValidateSessionIntegrity(ctx context.Context, sessionID string) error {
    // 1. Check session exists
    sessionKey := fmt.Sprintf("session:%s", sessionID)
    exists, err := s.redis.Exists(ctx, sessionKey).Result()
    if err != nil || exists == 0 {
        return ErrSessionNotFound
    }
    
    // 2. Get session data
    session, err := s.GetSession(ctx, sessionID)
    if err != nil {
        return err
    }
    
    // 3. Validate expiration
    if time.Now().After(session.ExpiresAt) {
        s.DeleteSession(ctx, sessionID)
        return ErrSessionExpired
    }
    
    // 4. Validate idle timeout
    if time.Since(session.LastActivity) > 15*time.Minute {
        s.DeleteSession(ctx, sessionID)
        return ErrSessionIdleTimeout
    }
    
    // 5. Cross-check with PostgreSQL
    dbSession, err := s.db.GetSession(ctx, sessionID)
    if err != nil {
        return ErrSessionNotFound
    }
    
    if dbSession.Revoked {
        // Session revoked in DB but still in Redis - clean up
        s.DeleteSession(ctx, sessionID)
        return ErrSessionRevoked
    }
    
    // 6. Validate user ID consistency
    if session.UserID != dbSession.UserID {
        s.logger.Error("session integrity violation", "sessionId", sessionID)
        s.DeleteSession(ctx, sessionID)
        return ErrSessionIntegrityViolation
    }
    
    return nil
}
```

### 5.3 Consent State Validation

**GDPR Consent Checks**:
```go
func (s *ConsentService) ValidateUserConsent(ctx context.Context, userID string) error {
    user, err := s.userRepo.GetUserByID(ctx, userID)
    if err != nil {
        return err
    }
    
    // 1. Check data processing consent (mandatory)
    if !user.DataProcessingConsent {
        return ErrMissingDataProcessingConsent
    }
    
    // 2. Check consent version
    currentVersion := s.getCurrentConsentVersion()
    if user.ConsentVersion < currentVersion {
        return ErrOutdatedConsent
    }
    
    // 3. Validate consent timestamp
    if user.ConsentTimestamp.IsZero() {
        return ErrMissingConsentTimestamp
    }
    
    // 4. Check if consent has expired (optional - depends on GDPR interpretation)
    if time.Since(user.ConsentTimestamp) > 2*365*24*time.Hour {
        return ErrExpiredConsent
    }
    
    return nil
}
```

---

## 6. State Migration & Versioning

### 6.1 Database Schema Migrations

**Migration Tool**: golang-migrate

**Example Migration**:
```sql
-- 001_initial_schema.up.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 001_initial_schema.down.sql
DROP TABLE users;

-- 002_add_mfa_support.up.sql
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN backup_codes TEXT[];

-- 002_add_mfa_support.down.sql
ALTER TABLE users DROP COLUMN mfa_enabled;
ALTER TABLE users DROP COLUMN mfa_secret;
ALTER TABLE users DROP COLUMN backup_codes;

-- 003_add_consent_tracking.up.sql
ALTER TABLE users ADD COLUMN consent_version INT NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN data_processing_consent BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN marketing_consent BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN consent_timestamp TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN consent_ip_address INET;

CREATE TABLE consent_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_version INT NOT NULL,
    data_processing_consent BOOLEAN NOT NULL,
    marketing_consent BOOLEAN NOT NULL,
    ip_address INET NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    action VARCHAR(20) NOT NULL
);

-- 003_add_consent_tracking.down.sql
DROP TABLE consent_history;
ALTER TABLE users DROP COLUMN consent_version;
ALTER TABLE users DROP COLUMN data_processing_consent;
ALTER TABLE users DROP COLUMN marketing_consent;
ALTER TABLE users DROP COLUMN consent_timestamp;
ALTER TABLE users DROP COLUMN consent_ip_address;
```

**Migration Execution**:
```bash
# Apply all pending migrations
migrate -database "postgres://user:pass@localhost:5432/db?sslmode=disable" \
        -path ./migrations \
        up

# Rollback last migration
migrate -database "postgres://user:pass@localhost:5432/db?sslmode=disable" \
        -path ./migrations \
        down 1
```

### 6.2 State Version Management

**Client State Versioning**:
```typescript
// State migration system
interface StateMigration {
  version: number;
  migrate: (oldState: any) => any;
}

const migrations: StateMigration[] = [
  {
    version: 1,
    migrate: (state) => state, // Initial version
  },
  {
    version: 2,
    migrate: (state) => ({
      ...state,
      consent: {
        privacyPolicy: state.gdprConsent || false,
        termsOfService: state.termsAccepted || false,
        marketing: false,
        acceptedAt: state.consentTimestamp || null,
      },
    }),
  },
  {
    version: 3,
    migrate: (state) => ({
      ...state,
      session: {
        ...state.session,
        deviceId: generateDeviceFingerprint(),
      },
    }),
  },
];

function migrateState(storedState: any, currentVersion: number): any {
  let state = storedState;
  const storedVersion = state._version || 1;
  
  if (storedVersion === currentVersion) {
    return state;
  }
  
  for (let i = storedVersion; i < currentVersion; i++) {
    const migration = migrations.find(m => m.version === i + 1);
    if (migration) {
      state = migration.migrate(state);
      state._version = i + 1;
    }
  }
  
  return state;
}

// Load state with migration
function loadPersistedState(): AuthState | undefined {
  const storedState = localStorage.getItem('auth_state');
  if (!storedState) return undefined;
  
  try {
    const parsed = JSON.parse(storedState);
    const currentVersion = 3; // Increment when adding migrations
    return migrateState(parsed, currentVersion);
  } catch (error) {
    console.error('Failed to migrate state:', error);
    localStorage.removeItem('auth_state');
    return undefined;
  }
}
```

---

## 7. Performance Optimization

### 7.1 Redis Optimization

**Connection Pooling**:
```go
func NewRedisClient() *redis.ClusterClient {
    return redis.NewClusterClient(&redis.ClusterOptions{
        Addrs: []string{
            "redis-node-1:6379",
            "redis-node-2:6379",
            "redis-node-3:6379",
        },
        
        // Connection pool settings
        PoolSize:        100,  // Max connections per node
        MinIdleConns:    10,   // Keep minimum idle connections
        MaxRetries:      3,
        DialTimeout:     5 * time.Second,
        ReadTimeout:     3 * time.Second,
        WriteTimeout:    3 * time.Second,
        PoolTimeout:     4 * time.Second,
        IdleTimeout:     5 * time.Minute,
        
        // Retry strategy
        MaxRetryBackoff: 512 * time.Millisecond,
    })
}
```

**Pipeline Operations**:
```go
// Batch session updates for performance
func (s *SessionService) UpdateMultipleSessionActivities(ctx context.Context, sessionIDs []string) error {
    pipe := s.redis.Pipeline()
    now := time.Now().Format(time.RFC3339)
    
    for _, sessionID := range sessionIDs {
        sessionKey := fmt.Sprintf("session:%s", sessionID)
        pipe.HSet(ctx, sessionKey, "lastActivity", now)
    }
    
    _, err := pipe.Exec(ctx)
    return err
}
```

### 7.2 Database Query Optimization

**Prepared Statements**:
```go
type SessionRepository struct {
    db                *sql.DB
    getSessionStmt    *sql.Stmt
    createSessionStmt *sql.Stmt
    updateActivityStmt *sql.Stmt
}

func NewSessionRepository(db *sql.DB) (*SessionRepository, error) {
    repo := &SessionRepository{db: db}
    
    var err error
    
    // Prepare frequently-used queries
    repo.getSessionStmt, err = db.Prepare(`
        SELECT id, user_id, device_id, ip_address, created_at, last_activity, expires_at
        FROM sessions
        WHERE id = $1 AND revoked = FALSE
    `)
    if err != nil {
        return nil, err
    }
    
    repo.createSessionStmt, err = db.Prepare(`
        INSERT INTO sessions (id, user_id, device_id, ip_address, expires_at)
        VALUES ($1, $2, $3, $4, $5)
    `)
    if err != nil {
        return nil, err
    }
    
    return repo, nil
}
```

**Index Strategy**:
```sql
-- Composite index for common query patterns
CREATE INDEX idx_sessions_user_active ON sessions(user_id, revoked, expires_at)
    WHERE revoked = FALSE;

-- Partial index for active sessions only
CREATE INDEX idx_active_sessions ON sessions(expires_at)
    WHERE revoked = FALSE AND expires_at > NOW();

-- Index for audit log queries
CREATE INDEX idx_audit_logs_user_timestamp ON audit_logs(user_id, timestamp DESC);
```

### 7.3 Client-Side Optimization

**State Persistence Throttling**:
```typescript
import { debounce } from 'lodash';

// Debounce state persistence to avoid excessive writes
const persistState = debounce((state: AuthState) => {
  try {
    localStorage.setItem('auth_state', JSON.stringify(state));
  } catch (error) {
    console.error('Failed to persist state:', error);
  }
}, 1000);

// Redux middleware
const persistenceMiddleware = (store: any) => (next: any) => (action: any) => {
  const result = next(action);
  const state = store.getState().auth;
  persistState(state);
  return result;
};
```

**Selective State Updates**:
```typescript
// Only update what's necessary
const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    updateLastActivity: (state) => {
      // Update only timestamp, don't trigger full re-render
      if (state.session) {
        state.session.lastActivity = Date.now();
      }
    },
  },
});

// Use React.memo to prevent unnecessary re-renders
export const UserProfile = React.memo(({ user }: { user: User }) => {
  return <div>{user.email}</div>;
}, (prevProps, nextProps) => {
  return prevProps.user.id === nextProps.user.id;
});
```

---

## 8. Monitoring & Observability

### 8.1 State Metrics

**Redis Metrics**:
```go
func (s *SessionService) RecordMetrics(ctx context.Context) {
    // Session count
    count, _ := s.redis.DBSize(ctx).Result()
    metrics.Gauge("redis.sessions.total", float64(count))
    
    // Memory usage
    info, _ := s.redis.Info(ctx, "memory").Result()
    metrics.Gauge("redis.memory.used", parseMemoryUsage(info))
    
    // Hit rate
    stats, _ := s.redis.Info(ctx, "stats").Result()
    hits := parseStats(stats, "keyspace_hits")
    misses := parseStats(stats, "keyspace_misses")
    hitRate := float64(hits) / float64(hits + misses)
    metrics.Gauge("redis.hit_rate", hitRate)
}
```

**PostgreSQL Metrics**:
```go
func (r *UserRepository) RecordQueryMetrics(ctx context.Context, queryName string, duration time.Duration, err error) {
    metrics.Histogram("postgres.query.duration", duration.Milliseconds(), map[string]string{
        "query": queryName,
        "status": statusFromError(err),
    })
    
    if err != nil {
        metrics.Counter("postgres.query.errors", 1, map[string]string{
            "query": queryName,
        })
    }
}
```

### 8.2 Audit Logging

**Structured Audit Logs**:
```go
type AuditLogger struct {
    db *sql.DB
}

func (l *AuditLogger) LogAuthEvent(ctx context.Context, event AuthEvent) error {
    query := `
        INSERT INTO audit_logs (
            user_id, event_type, event_status, ip_address,
            user_agent, device_id, metadata, timestamp
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `
    
    metadata, _ := json.Marshal(event.Metadata)
    
    _, err := l.db.ExecContext(
        ctx, query,
        event.UserID,
        event.EventType,
        event.Status,
        event.IPAddress,
        event.UserAgent,
        event.DeviceID,
        metadata,
        time.Now(),
    )
    
    // Also send to external logging service
    l.sendToDatadog(event)
    
    return err
}

func (l *AuditLogger) sendToDatadog(event AuthEvent) {
    log := map[string]interface{}{
        "service":    "auth",
        "event_type": event.EventType,
        "status":     event.Status,
        "user_id":    event.UserID,
        "ip":         event.IPAddress,
        "timestamp":  time.Now().Unix(),
    }
    
    // Send to Datadog Logs API
    // Implementation depends on Datadog client
}
```

---

## 9. Security Considerations

### 9.1 Token Security

**Secure Token Generation**:
```go
import (
    "crypto/rand"
    "encoding/base64"
    "golang.org/x/crypto/sha3"
)

func generateSecureToken(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

func hashToken(token string) string {
    hash := sha3.Sum256([]byte(token))
    return base64.URLEncoding.EncodeToString(hash[:])
}
```

### 9.2 State Encryption

**Sensitive Data Encryption**:
```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "io"
)

func encryptSensitiveData(plaintext string, key []byte) (string, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}
```

---

## 10. Testing Strategy

### 10.1 State Testing

**Redux State Testing**:
```typescript
import { configureStore } from '@reduxjs/toolkit';
import authReducer, { loginUser, logout } from './authSlice';

describe('Auth State', () => {
  let store: ReturnType<typeof configureStore>;
  
  beforeEach(() => {
    store = configureStore({ reducer: { auth: authReducer } });
  });
  
  it('should handle successful login', async () => {
    const credentials = { email: 'test@example.com', password: 'password123' };
    
    await store.dispatch(loginUser(credentials));
    
    const state = store.getState().auth;
    expect(state.user).not.toBeNull();
    expect(state.ui.isAuthenticated).toBe(true);
    expect(state.tokens).not.toBeNull();
  });
  
  it('should handle logout', () => {
    store.dispatch(logout());
    
    const state = store.getState().auth;
    expect(state.user).toBeNull();
    expect(state.tokens).toBeNull();
    expect(state.ui.isAuthenticated).toBe(false);
  });
});
```

**Session Service Testing**:
```go
func TestSessionService_CreateSession(t *testing.T) {
    ctx := context.Background()
    
    // Setup test dependencies
    redisClient := setupTestRedis(t)
    db := setupTestDB(t)
    service := NewSessionService(redisClient, db)
    
    // Test session creation
    session := &Session{
        ID:       uuid.New().String(),
        UserID:   "test-user-id",
        DeviceID: "test-device",
        IPAddress: "127.0.0.1",
        ExpiresAt: time.Now().Add(8 * time.Hour),
    }
    
    err := service.CreateSession(ctx, session)
    assert.NoError(t, err)
    
    // Verify session in Redis
    retrieved, err := service.GetSession(ctx, session.ID)
    assert.NoError(t, err)
    assert.Equal(t, session.UserID, retrieved.UserID)
    
    // Verify session in PostgreSQL
    dbSession, err := db.GetSession(ctx, session.ID)
    assert.NoError(t, err)
    assert.Equal(t, session.UserID, dbSession.UserID)
}
```

---

## 11. Implementation Checklist

- [ ] **Backend State (Go)**
  - [ ] Redis cluster setup with ElastiCache
  - [ ] PostgreSQL schema with migrations
  - [ ] Session service with write-through cache
  - [ ] Token service with RS256 JWT
  - [ ] Refresh token rotation logic
  - [ ] Audit logging implementation
  
- [ ] **Frontend State (React)**
  - [ ] Redux Toolkit setup with persistence
  - [ ] Authentication slice with async thunks
  - [ ] Token refresh interceptor
  - [ ] Secure storage for mobile
  - [ ] State migration system
  
- [ ] **Synchronization**
  - [ ] Redis-PostgreSQL sync job
  - [ ] Client-server token refresh flow
  - [ ] Session cleanup background jobs
  
- [ ] **Security**
  - [ ] JWT validation middleware
  - [ ] Token rotation with reuse detection
  - [ ] Session integrity checks
  - [ ] GDPR consent validation
  - [ ] Encryption at rest (AES-256-GCM)
  
- [ ] **Monitoring**
  - [ ] Redis metrics (hit rate, memory)
  - [ ] PostgreSQL query performance
  - [ ] Datadog integration
  - [ ] Audit log retention policy
  
- [ ] **Testing**
  - [ ] Redux state unit tests
  - [ ] Session service integration tests
  - [ ] Token validation tests
  - [ ] Load testing (1000 req/s)

---

**Document Version**: 1.0  
**Last Updated**: 2025-10-29  
**Review Cycle**: Quarterly