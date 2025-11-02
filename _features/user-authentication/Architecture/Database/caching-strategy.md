---
layout: default
title: Caching Strategy
nav_exclude: true
---



# CACHING STRATEGY

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Database
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

This caching strategy defines a comprehensive multi-layer caching approach for the SUMA Finance authentication and user registration system. The strategy employs a three-tier caching architecture: L1 (Application Memory), L2 (Redis Distributed Cache), and L3 (CDN) to achieve the aggressive performance targets of < 200ms for login/registration and < 100ms for token refresh operations.

The caching strategy prioritizes security, compliance (GDPR, PCI-DSS, SOC2), and performance, with particular attention to session management, token validation, and user data access patterns. Redis serves as the primary distributed cache layer for session storage, OTP codes, rate limiting counters, and frequently accessed user profiles. The strategy implements cache-aside patterns for user data, write-through for session updates, and specialized invalidation strategies for security events.

Key design principles include: short TTLs for security-sensitive data (30-60 seconds for in-memory, 5-15 minutes for Redis), tag-based invalidation for related data cleanup, encryption of cached sensitive data, and comprehensive monitoring to maintain > 90% cache hit rates for authentication flows.

## Caching Layers

### L1: Application Memory Cache
- **Technology**: In-memory LRU Cache (Go: golang-lru, Node.js: lru-cache)
- **Scope**: Per application instance (not shared across instances)
- **TTL**: 30-60 seconds
- **Size Limit**: 100MB per instance
- **Use Cases**: 
  - JWT public keys for signature verification
  - User permission sets (after initial load)
  - Rate limiting counters (local + distributed hybrid)
  - Configuration values (feature flags, security settings)
  - Hot user profiles (active within last 30 seconds)
- **Eviction Policy**: LRU (Least Recently Used)
- **Notes**: Must be invalidated on security events (password change, logout, permissions update)

### L2: Distributed Cache (Redis)
- **Technology**: Redis Cluster (AWS ElastiCache)
- **Scope**: Across all application instances globally
- **TTL**: 5 seconds - 60 minutes (varies by data type)
- **Size Limit**: 4GB primary memory (expandable based on load)
- **Use Cases**:
  - Session storage (JWT refresh tokens, device fingerprints)
  - Email verification tokens (1-hour expiry)
  - Password reset tokens (1-hour expiry)
  - OTP codes (5-minute expiry)
  - Account lockout state (15-minute duration)
  - Rate limiting counters (sliding window)
  - User profiles (5-minute TTL)
  - Device trust status (7-day TTL)
  - Failed login attempt counters (1-hour TTL)
  - Recently used password hashes (password history validation)
- **Eviction Policy**: allkeys-lru (evict any key when memory limit reached)
- **Persistence**: RDB snapshots every 5 minutes + AOF for critical data
- **Notes**: Primary cache layer for authentication system, requires encryption at rest for PII

### L3: CDN Cache
- **Technology**: AWS CloudFront with AWS WAF integration
- **Scope**: Edge locations globally (50+ locations)
- **TTL**: 1 hour - 24 hours
- **Use Cases**:
  - Public static assets (login page, registration forms, UI bundles)
  - Public API responses (JWKS endpoint for token verification)
  - Password policy documentation
  - Terms of service and privacy policy documents
- **Cache-Control Headers**: `public, max-age=3600, s-maxage=86400`
- **Notes**: No sensitive user data cached at CDN layer, WAF rules applied before caching

## Cache Technologies

### Redis Configuration

```yaml
redis:
  cluster_mode: enabled
  nodes:
    - redis-node-1.use1.cache.amazonaws.com:6379
    - redis-node-2.use1.cache.amazonaws.com:6379
    - redis-node-3.use1.cache.amazonaws.com:6379
  replication:
    primary_nodes: 3
    replicas_per_node: 2
  max_memory: 4GB
  eviction_policy: allkeys-lru
  persistence:
    rdb_snapshots: every 300 seconds if 100 writes
    aof_enabled: true
    aof_fsync: everysec
  encryption:
    at_rest: true
    in_transit: true
    tls_version: "1.3"
  timeouts:
    connect_timeout: 5s
    read_timeout: 3s
    write_timeout: 3s
  connection_pool:
    min_idle: 5
    max_active: 100
    max_idle: 20
  monitoring:
    cloudwatch_enabled: true
    metrics_interval: 60s
```

### Go Redis Client Configuration

```go
package cache

import (
    "context"
    "time"
    "github.com/go-redis/redis/v8"
    "github.com/go-redis/redis_rate/v9"
)

var (
    RedisClient *redis.ClusterClient
    RateLimiter *redis_rate.Limiter
)

func InitRedis() error {
    RedisClient = redis.NewClusterClient(&redis.ClusterOptions{
        Addrs: []string{
            "redis-node-1.use1.cache.amazonaws.com:6379",
            "redis-node-2.use1.cache.amazonaws.com:6379",
            "redis-node-3.use1.cache.amazonaws.com:6379",
        },
        Password:     getEnv("REDIS_PASSWORD"),
        PoolSize:     100,
        MinIdleConns: 5,
        MaxRetries:   3,
        DialTimeout:  5 * time.Second,
        ReadTimeout:  3 * time.Second,
        WriteTimeout: 3 * time.Second,
        TLSConfig: &tls.Config{
            MinVersion: tls.VersionTLS13,
        },
    })

    // Test connection
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := RedisClient.Ping(ctx).Err(); err != nil {
        return fmt.Errorf("redis connection failed: %w", err)
    }

    RateLimiter = redis_rate.NewLimiter(RedisClient)
    return nil
}
```

## Cache Patterns

### Cache-Aside (Lazy Loading) - User Profile

```go
// Cache-Aside pattern for user profile retrieval
func GetUserProfile(ctx context.Context, userID string) (*User, error) {
    cacheKey := CacheKeys.User(userID)
    
    // 1. Check L2 cache (Redis)
    cached, err := RedisClient.Get(ctx, cacheKey).Result()
    if err == nil {
        var user User
        if err := json.Unmarshal([]byte(cached), &user); err == nil {
            metrics.CacheHit("user_profile", "redis")
            return &user, nil
        }
    }
    
    metrics.CacheMiss("user_profile", "redis")
    
    // 2. Cache miss: fetch from database
    user, err := db.Users.FindByID(ctx, userID)
    if err != nil {
        return nil, fmt.Errorf("database query failed: %w", err)
    }
    
    // 3. Store in cache with 5-minute TTL
    userJSON, _ := json.Marshal(user)
    if err := RedisClient.Set(ctx, cacheKey, userJSON, 5*time.Minute).Err(); err != nil {
        log.Error("cache set failed", "key", cacheKey, "error", err)
        // Continue without caching (non-blocking failure)
    }
    
    return user, nil
}
```

### Write-Through - Session Update

```go
// Write-Through pattern for session updates
func UpdateSession(ctx context.Context, sessionID string, updates SessionUpdates) error {
    session, err := db.Sessions.FindByID(ctx, sessionID)
    if err != nil {
        return err
    }
    
    // Apply updates
    session.LastActivity = time.Now()
    session.IPAddress = updates.IPAddress
    session.UserAgent = updates.UserAgent
    
    // 1. Update database first
    if err := db.Sessions.Update(ctx, session); err != nil {
        return fmt.Errorf("database update failed: %w", err)
    }
    
    // 2. Update cache immediately (synchronously)
    cacheKey := CacheKeys.Session(sessionID)
    sessionJSON, _ := json.Marshal(session)
    
    ttl := time.Until(session.ExpiresAt)
    if ttl < 0 {
        ttl = 15 * time.Minute // Default session timeout
    }
    
    if err := RedisClient.Set(ctx, cacheKey, sessionJSON, ttl).Err(); err != nil {
        log.Error("cache update failed", "session_id", sessionID, "error", err)
        // Continue even if cache update fails
    }
    
    return nil
}
```

### Write-Behind (Async) - Security Event Logging

```go
// Write-Behind pattern for high-frequency security events
func LogLoginAttempt(ctx context.Context, event LoginAttemptEvent) error {
    eventKey := fmt.Sprintf("login_attempt:%s:%d", event.UserID, event.Timestamp.Unix())
    
    // 1. Write to cache immediately (fast response)
    eventJSON, _ := json.Marshal(event)
    if err := RedisClient.Set(ctx, eventKey, eventJSON, 1*time.Hour).Err(); err != nil {
        log.Error("cache write failed", "event", event, "error", err)
    }
    
    // 2. Queue for async database write (non-blocking)
    if err := eventQueue.Publish("security.login_attempt", event); err != nil {
        log.Error("queue publish failed", "event", event, "error", err)
        // Fallback: write to database synchronously
        return db.SecurityEvents.Insert(ctx, event)
    }
    
    return nil
}

// Background worker processes queued events
func processSecurityEventQueue() {
    eventQueue.Subscribe("security.login_attempt", func(msg *Message) error {
        var event LoginAttemptEvent
        json.Unmarshal(msg.Data, &event)
        
        // Batch insert for efficiency
        return db.SecurityEvents.InsertBatch(context.Background(), []SecurityEvent{event})
    })
}
```

### Token Validation with Public Key Caching

```go
// JWT public key caching with L1 + L2 layers
func GetJWTPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
    cacheKey := CacheKeys.JWTPublicKey(keyID)
    
    // L1: Check in-memory cache (fastest)
    if key, found := memoryCache.Get(cacheKey); found {
        metrics.CacheHit("jwt_public_key", "memory")
        return key.(*rsa.PublicKey), nil
    }
    
    // L2: Check Redis cache
    keyPEM, err := RedisClient.Get(ctx, cacheKey).Result()
    if err == nil {
        key, err := parseRSAPublicKey(keyPEM)
        if err == nil {
            memoryCache.Set(cacheKey, key, 60*time.Second) // Cache in L1
            metrics.CacheHit("jwt_public_key", "redis")
            return key, nil
        }
    }
    
    metrics.CacheMiss("jwt_public_key", "all")
    
    // Fetch from JWKS endpoint
    key, keyPEM, err := fetchPublicKeyFromJWKS(keyID)
    if err != nil {
        return nil, err
    }
    
    // Store in both cache layers
    memoryCache.Set(cacheKey, key, 60*time.Second)
    RedisClient.Set(ctx, cacheKey, keyPEM, 15*time.Minute)
    
    return key, nil
}
```

## Cache Keys Design

### Naming Convention

```
{namespace}:{resource}:{identifier}:{qualifier}

Namespace: "suma" (project prefix)
Resource: "user", "session", "token", "otp", "lockout", "rate_limit"
Identifier: User ID, Session ID, Token ID, etc.
Qualifier: Optional sub-resource or attribute

Examples:
suma:user:uuid-123
suma:user:uuid-123:profile
suma:user:uuid-123:permissions
suma:user:email:john@example.com
suma:session:sess-456
suma:session:user:uuid-123:active (list of active sessions)
suma:token:refresh:token-789
suma:otp:email:john@example.com
suma:otp:user:uuid-123:code
suma:lockout:user:uuid-123
suma:rate_limit:login:ip:192.168.1.1
suma:rate_limit:api:user:uuid-123
suma:password_reset:token-abc
suma:email_verify:token-def
```

### Key Generation Service

```go
package cache

import "fmt"

const namespace = "suma"

type CacheKeyGenerator struct{}

var CacheKeys = &CacheKeyGenerator{}

// User keys
func (c *CacheKeyGenerator) User(userID string) string {
    return fmt.Sprintf("%s:user:%s", namespace, userID)
}

func (c *CacheKeyGenerator) UserByEmail(email string) string {
    return fmt.Sprintf("%s:user:email:%s", namespace, email)
}

func (c *CacheKeyGenerator) UserPermissions(userID string) string {
    return fmt.Sprintf("%s:user:%s:permissions", namespace, userID)
}

func (c *CacheKeyGenerator) UserActiveSessions(userID string) string {
    return fmt.Sprintf("%s:session:user:%s:active", namespace, userID)
}

// Session keys
func (c *CacheKeyGenerator) Session(sessionID string) string {
    return fmt.Sprintf("%s:session:%s", namespace, sessionID)
}

func (c *CacheKeyGenerator) RefreshToken(tokenID string) string {
    return fmt.Sprintf("%s:token:refresh:%s", namespace, tokenID)
}

// Security keys
func (c *CacheKeyGenerator) OTPByEmail(email string) string {
    return fmt.Sprintf("%s:otp:email:%s", namespace, email)
}

func (c *CacheKeyGenerator) OTPByUser(userID string) string {
    return fmt.Sprintf("%s:otp:user:%s:code", namespace, userID)
}

func (c *CacheKeyGenerator) AccountLockout(userID string) string {
    return fmt.Sprintf("%s:lockout:user:%s", namespace, userID)
}

func (c *CacheKeyGenerator) FailedLoginAttempts(userID string) string {
    return fmt.Sprintf("%s:failed_login:user:%s", namespace, userID)
}

// Rate limiting keys
func (c *CacheKeyGenerator) RateLimitLoginByIP(ipAddress string) string {
    return fmt.Sprintf("%s:rate_limit:login:ip:%s", namespace, ipAddress)
}

func (c *CacheKeyGenerator) RateLimitLoginByUser(userID string) string {
    return fmt.Sprintf("%s:rate_limit:login:user:%s", namespace, userID)
}

func (c *CacheKeyGenerator) RateLimitAPI(userID string, endpoint string) string {
    return fmt.Sprintf("%s:rate_limit:api:%s:%s", namespace, userID, endpoint)
}

// Token keys
func (c *CacheKeyGenerator) PasswordResetToken(token string) string {
    return fmt.Sprintf("%s:password_reset:%s", namespace, token)
}

func (c *CacheKeyGenerator) EmailVerificationToken(token string) string {
    return fmt.Sprintf("%s:email_verify:%s", namespace, token)
}

func (c *CacheKeyGenerator) JWTPublicKey(keyID string) string {
    return fmt.Sprintf("%s:jwt:pubkey:%s", namespace, keyID)
}

// Device keys
func (c *CacheKeyGenerator) TrustedDevice(deviceID string) string {
    return fmt.Sprintf("%s:device:trusted:%s", namespace, deviceID)
}

func (c *CacheKeyGenerator) UserDevices(userID string) string {
    return fmt.Sprintf("%s:device:user:%s:list", namespace, userID)
}
```

## Invalidation Strategies

### Time-Based (TTL)

Time-based expiration provides automatic cleanup without manual intervention. Critical for security-sensitive data.

```go
// OTP codes: 5-minute expiry (security requirement)
RedisClient.Set(ctx, CacheKeys.OTPByUser(userID), otpCode, 5*time.Minute)

// Password reset tokens: 1-hour expiry
RedisClient.Set(ctx, CacheKeys.PasswordResetToken(token), userData, 1*time.Hour)

// Email verification tokens: 1-hour expiry
RedisClient.Set(ctx, CacheKeys.EmailVerificationToken(token), userData, 1*time.Hour)

// User profiles: 5-minute expiry
RedisClient.Set(ctx, CacheKeys.User(userID), userJSON, 5*time.Minute)

// Sessions: Dynamic expiry based on absolute timeout (8 hours)
sessionTTL := time.Until(session.ExpiresAt)
RedisClient.Set(ctx, CacheKeys.Session(sessionID), sessionJSON, sessionTTL)

// Account lockout: 15-minute expiry (cooldown period)
RedisClient.Set(ctx, CacheKeys.AccountLockout(userID), "locked", 15*time.Minute)

// Failed login attempts: 1-hour sliding window
RedisClient.Incr(ctx, CacheKeys.FailedLoginAttempts(userID))
RedisClient.Expire(ctx, CacheKeys.FailedLoginAttempts(userID), 1*time.Hour)
```

### Event-Based Invalidation

Invalidate cache immediately when underlying data changes (security events, profile updates, permission changes).

```go
// Password change: invalidate all user-related caches
func InvalidateOnPasswordChange(ctx context.Context, userID string) error {
    keys := []string{
        CacheKeys.User(userID),
        CacheKeys.UserPermissions(userID),
        CacheKeys.UserByEmail(user.Email),
    }
    
    // Delete user caches
    if err := RedisClient.Del(ctx, keys...).Err(); err != nil {
        log.Error("cache invalidation failed", "user_id", userID, "error", err)
    }
    
    // Invalidate all active sessions (security requirement)
    sessionKeys, _ := RedisClient.SMembers(ctx, CacheKeys.UserActiveSessions(userID)).Result()
    if len(sessionKeys) > 0 {
        RedisClient.Del(ctx, sessionKeys...)
        RedisClient.Del(ctx, CacheKeys.UserActiveSessions(userID))
    }
    
    // Publish invalidation event for L1 caches across all instances
    eventBus.Publish("cache.invalidate.user", map[string]string{
        "user_id": userID,
        "reason":  "password_change",
    })
    
    return nil
}

// User update: selective invalidation
func InvalidateOnUserUpdate(ctx context.Context, userID string, updatedFields []string) error {
    keys := []string{CacheKeys.User(userID)}
    
    // Invalidate email lookup if email changed
    if contains(updatedFields, "email") {
        oldEmail := getOldEmail(userID) // Fetch from change log
        keys = append(keys, CacheKeys.UserByEmail(oldEmail))
    }
    
    // Invalidate permissions if role changed
    if contains(updatedFields, "role") {
        keys = append(keys, CacheKeys.UserPermissions(userID))
    }
    
    return RedisClient.Del(ctx, keys...).Err()
}

// Logout: invalidate specific session
func InvalidateOnLogout(ctx context.Context, sessionID string, userID string) error {
    // Remove session from cache
    RedisClient.Del(ctx, CacheKeys.Session(sessionID))
    
    // Remove from user's active sessions set
    RedisClient.SRem(ctx, CacheKeys.UserActiveSessions(userID), sessionID)
    
    return nil
}
```

### Tag-Based Invalidation

Group related cache entries with tags for bulk invalidation (useful for cascading deletes).

```go
// Tag management for related cache entries
func AddCacheTag(ctx context.Context, tag string, keys ...string) error {
    tagKey := fmt.Sprintf("%s:tag:%s", namespace, tag)
    return RedisClient.SAdd(ctx, tagKey, keys).Err()
}

func InvalidateByTag(ctx context.Context, tag string) error {
    tagKey := fmt.Sprintf("%s:tag:%s", namespace, tag)
    
    // Get all keys associated with tag
    keys, err := RedisClient.SMembers(ctx, tagKey).Result()
    if err != nil {
        return err
    }
    
    if len(keys) == 0 {
        return nil
    }
    
    // Delete all tagged keys
    if err := RedisClient.Del(ctx, keys...).Err(); err != nil {
        return err
    }
    
    // Delete tag set itself
    return RedisClient.Del(ctx, tagKey).Err()
}

// Usage example: Tag all user-related caches
func CacheUserProfile(ctx context.Context, userID string, user *User) error {
    userJSON, _ := json.Marshal(user)
    cacheKey := CacheKeys.User(userID)
    
    // Cache user data
    RedisClient.Set(ctx, cacheKey, userJSON, 5*time.Minute)
    
    // Tag for bulk invalidation
    tagKey := fmt.Sprintf("user:%s", userID)
    AddCacheTag(ctx, tagKey, cacheKey)
    
    // Also tag by email for alternative lookup
    emailKey := CacheKeys.UserByEmail(user.Email)
    RedisClient.Set(ctx, emailKey, userID, 5*time.Minute)
    AddCacheTag(ctx, tagKey, emailKey)
    
    return nil
}

// Invalidate all user-related caches at once
func InvalidateUserCaches(ctx context.Context, userID string) error {
    return InvalidateByTag(ctx, fmt.Sprintf("user:%s", userID))
}
```

### Refresh Token Rotation Invalidation

Special invalidation strategy for refresh token rotation (OWASP A07 requirement).

```go
// Refresh token rotation with automatic old token invalidation
func RotateRefreshToken(ctx context.Context, oldTokenID string, userID string) (newToken string, err error) {
    // Verify old token exists and is valid
    oldTokenKey := CacheKeys.RefreshToken(oldTokenID)
    exists, err := RedisClient.Exists(ctx, oldTokenKey).Result()
    if err != nil || exists == 0 {
        return "", ErrInvalidRefreshToken
    }
    
    // Check for reuse detection (security)
    reuseKey := fmt.Sprintf("%s:reuse:%s", oldTokenKey, oldTokenID)
    reused, _ := RedisClient.Exists(ctx, reuseKey).Result()
    if reused > 0 {
        // Token reuse detected: invalidate all user sessions (security breach)
        log.Warn("refresh token reuse detected", "user_id", userID, "token_id", oldTokenID)
        InvalidateAllUserSessions(ctx, userID)
        return "", ErrTokenReuseDetected
    }
    
    // Generate new refresh token
    newTokenID := generateTokenID()
    newToken = generateJWT(userID, newTokenID, 7*24*time.Hour)
    newTokenKey := CacheKeys.RefreshToken(newTokenID)
    
    // Store new token
    tokenData := map[string]interface{}{
        "user_id":    userID,
        "created_at": time.Now().Unix(),
    }
    tokenJSON, _ := json.Marshal(tokenData)
    RedisClient.Set(ctx, newTokenKey, tokenJSON, 7*24*time.Hour)
    
    // Mark old token as used (reuse detection window)
    RedisClient.Set(ctx, reuseKey, "used", 1*time.Hour)
    
    // Delete old token (immediate invalidation)
    RedisClient.Del(ctx, oldTokenKey)
    
    return newToken, nil
}
```

## Cache Warming

### On Application Startup

```go
// Warm critical caches on application startup
func WarmCachesOnStartup(ctx context.Context) error {
    log.Info("warming caches on startup")
    
    // 1. Load JWT public keys
    if err := warmJWTPublicKeys(ctx); err != nil {
        log.Error("jwt public key warming failed", "error", err)
    }
    
    // 2. Load system configuration
    if err := warmSystemConfig(ctx); err != nil {
        log.Error("system config warming failed", "error", err)
    }
    
    // 3. Load active user sessions (last 15 minutes)
    if err := warmActiveSessions(ctx); err != nil {
        log.Error("session warming failed", "error", err)
    }
    
    log.Info("cache warming completed")
    return nil
}

func warmJWTPublicKeys(ctx context.Context) error {
    keys, err := fetchAllPublicKeysFromJWKS()
    if err != nil {
        return err
    }
    
    for keyID, keyPEM := range keys {
        cacheKey := CacheKeys.JWTPublicKey(keyID)
        RedisClient.Set(ctx, cacheKey, keyPEM, 15*time.Minute)
    }
    
    return nil
}

func warmActiveSessions(ctx context.Context) error {
    // Query database for active sessions
    cutoff := time.Now().Add(-15 * time.Minute)
    sessions, err := db.Sessions.FindActive(ctx, cutoff)
    if err != nil {
        return err
    }
    
    log.Info("warming active sessions", "count", len(sessions))
    
    // Cache sessions
    for _, session := range sessions {
        sessionJSON, _ := json.Marshal(session)
        cacheKey := CacheKeys.Session(session.ID)
        ttl := time.Until(session.ExpiresAt)
        
        if ttl > 0 {
            RedisClient.Set(ctx, cacheKey, sessionJSON, ttl)
        }
    }
    
    return nil
}
```

### Scheduled Cache Refresh

```go
// Periodic cache refresh for semi-static data
func StartScheduledCacheRefresh() {
    // Refresh JWT public keys every 10 minutes
    ticker := time.NewTicker(10 * time.Minute)
    go func() {
        for range ticker.C {
            ctx := context.Background()
            if err := warmJWTPublicKeys(ctx); err != nil {
                log.Error("scheduled jwt key refresh failed", "error", err)
            }
        }
    }()
    
    // Cleanup expired lockout entries every 5 minutes
    lockoutTicker := time.NewTicker(5 * time.Minute)
    go func() {
        for range lockoutTicker.C {
            cleanupExpiredLockouts()
        }
    }()
}
```

### Predictive Cache Warming (User Activity)

```go
// Warm cache when user activity is detected
func OnUserActivity(ctx context.Context, userID string) {
    // Check if user data is cached
    cacheKey := CacheKeys.User(userID)
    exists, _ := RedisClient.Exists(ctx, cacheKey).Result()
    
    if exists == 0 {
        // User data not cached: warm cache asynchronously
        go func() {
            user, err := db.Users.FindByID(context.Background(), userID)
            if err != nil {
                return
            }
            
            userJSON, _ := json.Marshal(user)
            RedisClient.Set(context.Background(), cacheKey, userJSON, 5*time.Minute)
        }()
    }
}
```

## Cache Monitoring

### Metrics to Track

```go
type CacheMetrics struct {
    // Hit rate metrics
    TotalRequests    int64
    CacheHits        int64
    CacheMisses      int64
    HitRate          float64 // Target: > 90%
    
    // Performance metrics
    AvgCacheLatency  time.Duration // Target: < 10ms
    AvgDBLatency     time.Duration
    LatencySavings   time.Duration
    
    // Resource metrics
    MemoryUsed       int64
    MemoryLimit      int64
    MemoryUsageRate  float64 // Target: < 80%
    KeyCount         int64
    
    // Eviction metrics
    EvictedKeys      int64
    EvictionRate     float64 // Target: < 5%
    
    // Error metrics
    ConnectionErrors int64
    TimeoutErrors    int64
}

func CollectCacheMetrics(ctx context.Context) (*CacheMetrics, error) {
    metrics := &CacheMetrics{}
    
    // Get Redis INFO stats
    info, err := RedisClient.Info(ctx, "stats", "memory").Result()
    if err != nil {
        return nil, err
    }
    
    // Parse INFO output
    stats := parseRedisInfo(info)
    
    hits := stats["keyspace_hits"].(int64)
    misses := stats["keyspace_misses"].(int64)
    
    metrics.CacheHits = hits
    metrics.CacheMisses = misses
    metrics.TotalRequests = hits + misses
    
    if metrics.TotalRequests > 0 {
        metrics.HitRate = float64(hits) / float64(metrics.TotalRequests) * 100
    }
    
    metrics.EvictedKeys = stats["evicted_keys"].(int64)
    metrics.MemoryUsed = stats["used_memory"].(int64)
    metrics.MemoryLimit = stats["maxmemory"].(int64)
    
    if metrics.MemoryLimit > 0 {
        metrics.MemoryUsageRate = float64(metrics.MemoryUsed) / float64(metrics.MemoryLimit) * 100
    }
    
    metrics.KeyCount, _ = RedisClient.DBSize(ctx).Result()
    
    return metrics, nil
}
```

### Datadog Integration

```go
import "github.com/DataDog/datadog-go/statsd"

var ddClient *statsd.Client

func InitDatadogMetrics() error {
    var err error
    ddClient, err = statsd.New("127.0.0.1:8125")
    if err != nil {
        return err
    }
    
    // Tag all metrics with service name
    ddClient.Namespace = "suma."
    ddClient.Tags = []string{"service:auth", "env:production"}
    
    return nil
}

func RecordCacheOperation(operation string, layer string, hit bool, duration time.Duration) {
    // Record hit/miss
    status := "miss"
    if hit {
        status = "hit"
    }
    
    tags := []string{
        fmt.Sprintf("operation:%s", operation),
        fmt.Sprintf("layer:%s", layer),
        fmt.Sprintf("status:%s", status),
    }
    
    ddClient.Incr("cache.requests", tags, 1)
    ddClient.Timing("cache.latency", duration, tags, 1)
    
    // Record separate hit rate metric
    if hit {
        ddClient.Incr("cache.hits", tags, 1)
    } else {
        ddClient.Incr("cache.misses", tags, 1)
    }
}

// Usage
func GetUserWithMetrics(ctx context.Context, userID string) (*User, error) {
    start := time.Now()
    
    user, hit, err := getUserFromCache(ctx, userID)
    duration := time.Since(start)
    
    RecordCacheOperation("get_user", "redis", hit, duration)
    
    return user, err
}
```

### Alerting Rules

```go
// Alert when cache hit rate drops below 90%
func MonitorCacheHitRate() {
    ticker := time.NewTicker(1 * time.Minute)
    
    for range ticker.C {
        metrics, err := CollectCacheMetrics(context.Background())
        if err != nil {
            continue
        }
        
        if metrics.HitRate < 90.0 {
            alert := Alert{
                Severity: "warning",
                Title:    "Low Cache Hit Rate",
                Message:  fmt.Sprintf("Cache hit rate is %.2f%% (target: > 90%%)", metrics.HitRate),
                Tags:     []string{"service:auth", "component:cache"},
            }
            sendAlert(alert)
        }
        
        if metrics.MemoryUsageRate > 80.0 {
            alert := Alert{
                Severity: "critical",
                Title:    "High Cache Memory Usage",
                Message:  fmt.Sprintf("Cache memory usage is %.2f%% (limit: 80%%)", metrics.MemoryUsageRate),
                Tags:     []string{"service:auth", "component:cache"},
            }
            sendAlert(alert)
        }
    }
}
```

## Best Practices

### DO

✅ **Always set TTL for cache entries**
```go
// Good: Explicit TTL
RedisClient.Set(ctx, key, value, 5*time.Minute)

// Bad: No TTL (infinite)
RedisClient.Set(ctx, key, value, 0)
```

✅ **Monitor cache hit rates continuously**
```go
// Track metrics for every cache operation
RecordCacheOperation("get_user", "redis", hit, duration)
```

✅ **Invalidate on security-critical updates**
```go
// Always invalidate cache on password change, logout, permission change
InvalidateOnPasswordChange(ctx, userID)
```

✅ **Use consistent key naming conventions**
```go
// Use centralized key generator
cacheKey := CacheKeys.User(userID)
```

✅ **Set memory limits and eviction policies**
```yaml
max_memory: 4GB
eviction_policy: allkeys-lru
```

✅ **Handle cache failures gracefully (non-blocking)**
```go
user, err := getFromCache(ctx, userID)
if err != nil {
    log.Error("cache failed, falling back to database", "error", err)
    user, err = getFromDatabase(ctx, userID)
}
```

✅ **Encrypt sensitive data in cache**
```go
// Encrypt PII before caching
encrypted := encrypt(userJSON, encryptionKey)
RedisClient.Set(ctx, key, encrypted, ttl)
```

✅ **Use connection pooling**
```go
PoolSize: 100,
MinIdleConns: 5,
```

### DON'T

❌ **Don't cache everything blindly**
```go
// Bad: Caching data that changes frequently
RedisClient.Set(ctx, "balance:"+userID, balance, 1*time.Hour) // Balance changes every transaction

// Good: Use short TTL or don't cache at all
RedisClient.Set(ctx, "balance:"+userID, balance, 10*time.Second)
```

❌ **Don't use infinite TTLs**
```go
// Bad: No expiration (memory leak risk)
RedisClient.Set(ctx, key, value, 0)

// Good: Always set TTL
RedisClient.Set(ctx, key, value, 5*time.Minute)
```

❌ **Don't forget to invalidate on updates**
```go
// Bad: Update database but not cache
db.Users.Update(ctx, user)

// Good: Invalidate cache after update
db.Users.Update(ctx, user)
RedisClient.Del(ctx, CacheKeys.User(user.ID))
```

❌ **Don't store unencrypted sensitive data**
```go
// Bad: Plain PII in cache
RedisClient.Set(ctx, key, user.SSN, ttl)

// Good: Encrypt sensitive data
encrypted := encrypt(user.SSN, key)
RedisClient.Set(ctx, key, encrypted, ttl)
```

❌ **Don't ignore cache warming**
```go
// Bad: Cold start causes latency spikes

// Good: Warm critical data on startup
WarmCachesOnStartup(ctx)
```

❌ **Don't skip error handling**
```go
// Bad: Panic on cache failure
value := RedisClient.Get(ctx, key).Val() // Panics if key not found

// Good: Handle errors gracefully
value, err := RedisClient.Get(ctx, key).Result()
if err == redis.Nil {
    // Key not found, fetch from database
}
```

❌ **Don't cache without size limits**
```go
// Bad: No memory limit (risk of OOM)
redis:
  max_memory: 0

// Good: Set memory limit
redis:
  max_memory: 4GB
  eviction_policy: allkeys-lru
```

## Appendix

### Cache Decision Matrix

| Data Type | Access Frequency | Mutability | Size | Cache Layer | TTL | Invalidation Strategy |
|-----------|------------------|------------|------|-------------|-----|----------------------|
| User Profile | High | Low | 1-5 KB | L2 (Redis) | 5 min | Event-based (on update) |
| Session Data | Very High | Medium | 500 B | L2 (Redis) | Dynamic (session lifetime) | Event-based (on logout) |
| Refresh Token | Very High | None (immutable) | 200 B | L2 (Redis) | 7 days | Event-based (on rotation) |
| OTP Code | High | None (single-use) | 10 B | L2 (Redis) | 5 min | TTL only |
| Password Reset Token | Medium | None (single-use) | 100 B | L2 (Redis) | 1 hour | TTL + event (on use) |
| Email Verification Token | Medium | None (single-use) | 100 B | L2 (Redis) | 1 hour | TTL + event (on verify) |
| Failed Login Attempts | High | High | 10 B | L2 (Redis) | 1 hour | TTL (sliding window) |
| Account Lockout Status | Medium | Medium | 10 B | L2 (Redis) | 15 min | TTL (cooldown period) |
| Rate Limit Counter | Very High | Very High | 10 B | L1 + L2 | 1 min - 1 hour | TTL (sliding window) |
| JWT Public Key | Very High | Very Low | 2 KB | L1 + L2 | 15 min | Event-based (on key rotation) |
| User Permissions | Very High | Low | 500 B | L1 + L2 | 5 min | Event-based (on role change) |
| Trusted Device | Medium | Low | 200 B | L2 (Redis) | 7 days | Event-based (on revoke) |
| Security Event Log | Medium | None (append-only) | 500 B | Write-behind | 1 hour | None (async DB write) |
| Static Assets (CSS/JS) | Very High | Very Low | 100 KB | L3 (CDN) | 24 hours | Version-based |
| JWKS Endpoint Response | High | Very Low | 5 KB | L3 (CDN) | 1 hour | Event-based (key rotation) |

### Performance Benchmarks

**Target Performance**:
- L1 (Memory) lookup: < 1ms
- L2 (Redis) lookup: < 10ms
- Database query: < 50ms
- Cache hit rate: > 90%
- Session validation: < 100ms
- Login flow: < 200ms

**Expected Cache Hit Rates**:
- User profile: 95% (high reuse within session)
- Session data: 99% (active sessions always cached)
- JWT public keys: 99.9% (rarely changes)
- OTP validation: 80% (single-use, but cached during entry)
- Rate limiting: 99% (always cached)

### Glossary

**TTL (Time To Live)**: Expiration time for cache entries. After TTL expires, the entry is automatically deleted.

**Cache Hit**: When requested data is found in cache, avoiding database query.

**Cache Miss**: When requested data is not in cache, requiring database query.

**Hit Rate**: Percentage of requests served from cache (hits / total requests).

**Eviction**: Automatic removal of cache entries when memory limit is reached, based on eviction policy (LRU, LFU, etc.).

**Cache-Aside (Lazy Loading)**: Application checks cache first, loads from database on miss, then stores in cache.

**Write-Through**: Application writes to database and cache simultaneously.

**Write-Behind (Write-Back)**: Application writes to cache immediately, queues database write for later.

**Cache Warming**: Pre-loading frequently accessed data into cache to avoid cold-start latency.

**Invalidation**: Explicit removal of cache entries when underlying data changes.

**LRU (Least Recently Used)**: Eviction policy that removes least recently accessed items first.

**Redis Cluster**: Distributed Redis deployment with automatic sharding across multiple nodes.

**Session Fixation**: Security vulnerability where attacker forces known session ID on victim. Prevented by regenerating session ID after login.

**Token Rotation**: Security practice of generating new token and invalidating old token on each use (refresh tokens).

**Reuse Detection**: Security mechanism to detect when an already-used refresh token is presented again (indicates token theft).

**JWKS (JSON Web Key Set)**: Endpoint providing public keys for JWT signature verification.

**PKCE (Proof Key for Code Exchange)**: OAuth 2.0 extension that protects authorization code flow from interception.
