

# Database Indexing Strategy - SUMA Finance: User Registration & Authentication

## 1. Indexing Strategy Overview

### Index Types Available
- **B-tree**: Default index type, optimal for equality and range queries
- **Hash**: Equality comparisons only, faster than B-tree for exact matches
- **GIN (Generalized Inverted Index)**: Full-text search, JSONB, arrays
- **GiST (Generalized Search Tree)**: Geometric data, full-text search alternative
- **BRIN (Block Range Index)**: Large tables with natural ordering

### Indexing Philosophy
- **Read-Heavy Optimization**: Authentication queries are frequent and performance-critical
- **Strategic Indexing**: Focus on login paths, session validation, and user lookups
- **Write Awareness**: Registration is less frequent; acceptable write overhead
- **Covering Indexes**: Minimize table access for hot paths

### Trade-offs
- **Read Performance**: +40-80% improvement on indexed queries
- **Write Performance**: -5-15% overhead on INSERT/UPDATE operations
- **Storage Cost**: Indexes consume 15-30% additional disk space
- **Maintenance**: Automatic with autovacuum; manual REINDEX quarterly

### Index Maintenance Strategy
- Autovacuum enabled with aggressive settings for auth tables
- Weekly ANALYZE on authentication tables
- Quarterly REINDEX during maintenance windows
- Continuous monitoring of index bloat and usage statistics

---

## 2. Primary Indexes

### Users Table Primary Key
```sql
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- columns
);

-- Automatic B-tree index: users_pkey ON users(user_id)
```

**Rationale**:
- **UUID over BIGSERIAL**: Distributed system compatibility, no sequence contention
- **Clustered**: Primary key is clustered by default in PostgreSQL
- **Performance**: O(log n) lookup time
- **Security**: Non-sequential IDs prevent enumeration attacks

### Sessions Table Primary Key
```sql
CREATE TABLE user_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- columns
);

-- Automatic B-tree index: user_sessions_pkey ON user_sessions(session_id)
```

### Password Reset Tokens Primary Key
```sql
CREATE TABLE password_reset_tokens (
    token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- columns
);
```

---

## 3. Foreign Key Indexes

### Session → User Foreign Key
```sql
-- Foreign key definition
ALTER TABLE user_sessions
ADD CONSTRAINT fk_user_sessions_user_id
FOREIGN KEY (user_id) REFERENCES users(user_id)
ON DELETE CASCADE;

-- Required index for foreign key performance
CREATE INDEX idx_user_sessions_user_id 
ON user_sessions(user_id);
```

**Impact**:
- **JOIN Performance**: 60-80% faster joins between sessions and users
- **DELETE Performance**: CASCADE deletes use index for efficient cleanup
- **Type**: B-tree for range and equality queries
- **Selectivity**: High (each user has 1-5 sessions on average)

### Password Reset Token → User Foreign Key
```sql
-- Foreign key definition
ALTER TABLE password_reset_tokens
ADD CONSTRAINT fk_password_reset_tokens_user_id
FOREIGN KEY (user_id) REFERENCES users(user_id)
ON DELETE CASCADE;

-- Required index
CREATE INDEX idx_password_reset_tokens_user_id 
ON password_reset_tokens(user_id);
```

---

## 4. Query-Driven Indexes

### Q1: Login by Email
**Query Description**: Authenticate user by email and password

```sql
SELECT user_id, email, password_hash, is_active, email_verified_at, failed_login_attempts
FROM users
WHERE email = $1
  AND is_active = true
  AND deleted_at IS NULL;
```

**Analysis**:
- **WHERE Clause**: email (equality), is_active (equality), deleted_at (IS NULL)
- **JOIN Analysis**: None
- **ORDER BY**: None
- **Selectivity**: Email is unique; high selectivity

**Recommended Index**: Composite partial index
```sql
CREATE UNIQUE INDEX idx_users_email_active 
ON users(email) 
WHERE is_active = true AND deleted_at IS NULL;
```

**Performance Improvement**: 
- **Before**: Sequential scan (~50ms for 100k users)
- **After**: Index scan (~0.5ms)
- **Improvement**: 99% faster

---

### Q2: Session Validation
**Query Description**: Validate active session token

```sql
SELECT s.session_id, s.user_id, s.expires_at, u.is_active, u.email_verified_at
FROM user_sessions s
INNER JOIN users u ON s.user_id = u.user_id
WHERE s.session_token = $1
  AND s.expires_at > NOW()
  AND u.is_active = true
  AND u.deleted_at IS NULL;
```

**Analysis**:
- **WHERE Clause**: session_token (equality), expires_at (range), is_active (equality)
- **JOIN**: user_id foreign key (already indexed)
- **Frequency**: High (every authenticated request)

**Recommended Index**: Composite covering index
```sql
CREATE INDEX idx_user_sessions_token_expiry 
ON user_sessions(session_token, expires_at)
INCLUDE (user_id, session_id);
```

**Performance Improvement**:
- **Before**: Index scan + table lookup (~2ms)
- **After**: Index-only scan (~0.3ms)
- **Improvement**: 85% faster

---

### Q3: User Lookup by ID
**Query Description**: Fetch user profile by ID

```sql
SELECT user_id, email, first_name, last_name, is_active, email_verified_at, created_at
FROM users
WHERE user_id = $1
  AND deleted_at IS NULL;
```

**Analysis**:
- **WHERE Clause**: user_id (equality, primary key), deleted_at (IS NULL)
- **Selectivity**: Primary key = unique

**Recommended Index**: Primary key sufficient, add partial index for soft deletes
```sql
CREATE INDEX idx_users_not_deleted 
ON users(user_id) 
WHERE deleted_at IS NULL;
```

**Note**: This may be redundant if soft deletes are rare. Monitor usage.

---

### Q4: Active Sessions by User
**Query Description**: List all active sessions for a user

```sql
SELECT session_id, session_token, created_at, expires_at, ip_address, user_agent
FROM user_sessions
WHERE user_id = $1
  AND expires_at > NOW()
ORDER BY created_at DESC;
```

**Analysis**:
- **WHERE Clause**: user_id (equality), expires_at (range)
- **ORDER BY**: created_at (descending)
- **Use Case**: User session management, multi-device tracking

**Recommended Index**: Composite index
```sql
CREATE INDEX idx_user_sessions_user_expiry_created 
ON user_sessions(user_id, expires_at, created_at DESC);
```

**Performance Improvement**:
- Eliminates sort operation
- Uses index for filtering and ordering
- ~70% faster than separate indexes

---

### Q5: Password Reset Token Lookup
**Query Description**: Validate password reset token

```sql
SELECT token_id, user_id, token_hash, expires_at, used_at
FROM password_reset_tokens
WHERE token_hash = $1
  AND expires_at > NOW()
  AND used_at IS NULL;
```

**Analysis**:
- **WHERE Clause**: token_hash (equality), expires_at (range), used_at (IS NULL)
- **Frequency**: Low (password resets only)
- **Security**: Token must be unique and indexed

**Recommended Index**: Unique partial index
```sql
CREATE UNIQUE INDEX idx_password_reset_tokens_hash 
ON password_reset_tokens(token_hash) 
WHERE used_at IS NULL AND expires_at > NOW();
```

**Performance Improvement**:
- Ensures token uniqueness
- Fast validation (~0.5ms)
- Automatic cleanup excluded from index

---

### Q6: Expired Session Cleanup
**Query Description**: Delete expired sessions (background job)

```sql
DELETE FROM user_sessions
WHERE expires_at < NOW();
```

**Analysis**:
- **WHERE Clause**: expires_at (range)
- **Frequency**: Hourly background job
- **Volume**: Potentially large batch deletes

**Recommended Index**: B-tree index on expires_at
```sql
CREATE INDEX idx_user_sessions_expires_at 
ON user_sessions(expires_at);
```

**Performance Improvement**:
- Faster identification of expired sessions
- Reduces vacuum overhead
- ~50% faster cleanup

---

### Q7: Account Lockout Check
**Query Description**: Check failed login attempts for rate limiting

```sql
SELECT user_id, failed_login_attempts, last_failed_login_at
FROM users
WHERE email = $1;
```

**Analysis**:
- **WHERE Clause**: email (equality)
- **Covered by**: idx_users_email_active

**Recommended Index**: Extend existing index to covering index
```sql
DROP INDEX idx_users_email_active;

CREATE UNIQUE INDEX idx_users_email_active 
ON users(email) 
INCLUDE (user_id, failed_login_attempts, last_failed_login_at, is_active)
WHERE is_active = true AND deleted_at IS NULL;
```

---

## 5. Composite Indexes

### Column Order Selection Rules
1. **Equality before Range**: `WHERE user_id = ? AND created_at > ?` → Index (user_id, created_at)
2. **High Selectivity First**: Unique or near-unique columns lead
3. **ORDER BY Alignment**: Match ORDER BY clause column order
4. **LEFT-PREFIX Rule**: Index (a, b, c) can serve queries on (a), (a, b), (a, b, c)

### Leading Column Strategy
```sql
-- Good: Can serve WHERE email = ? OR WHERE email = ? AND is_active = ?
CREATE INDEX idx_users_email_active ON users(email, is_active);

-- Bad: Can only serve WHERE is_active = ? AND email = ?
CREATE INDEX idx_users_active_email ON users(is_active, email);
```

### Index Prefix Usage
```sql
-- Multi-purpose index
CREATE INDEX idx_user_sessions_user_expiry_created 
ON user_sessions(user_id, expires_at, created_at DESC);

-- Serves:
-- WHERE user_id = ?
-- WHERE user_id = ? AND expires_at > ?
-- WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC
```

---

## 6. Covering Indexes

### Session Validation Covering Index
```sql
CREATE INDEX idx_user_sessions_token_covering 
ON user_sessions(session_token)
INCLUDE (user_id, session_id, expires_at);
```

**Benefit**: Index-only scan eliminates heap access
**Storage**: +20% index size
**Performance**: +85% query speed

### User Email Lookup Covering Index
```sql
CREATE UNIQUE INDEX idx_users_email_covering 
ON users(email)
INCLUDE (user_id, password_hash, is_active, email_verified_at, failed_login_attempts);
```

**Benefit**: Login query becomes index-only scan
**Storage**: +30% index size
**Performance**: +70% login speed

---

## 7. Partial/Filtered Indexes

### Active Users Only
```sql
CREATE UNIQUE INDEX idx_users_email_active 
ON users(email) 
WHERE is_active = true AND deleted_at IS NULL;
```

**Benefits**:
- **Storage Savings**: 40-60% smaller than full index if many deleted users
- **Write Performance**: Inactive users don't update index
- **Query Speed**: Smaller index = better cache utilization

### Unused Password Reset Tokens
```sql
CREATE UNIQUE INDEX idx_password_reset_tokens_hash_unused 
ON password_reset_tokens(token_hash) 
WHERE used_at IS NULL;
```

**Benefits**:
- Enforces uniqueness only for active tokens
- Excludes historical data from index
- ~70% storage reduction

### Active Sessions Only
```sql
CREATE INDEX idx_user_sessions_active 
ON user_sessions(user_id, expires_at) 
WHERE expires_at > NOW();
```

**Benefits**:
- Background cleanup doesn't require this index
- Smaller index for hot queries
- Automatic "archival" as sessions expire

---

## 8. Full-Text Search Indexes

### User Search by Name or Email
```sql
-- Add tsvector column
ALTER TABLE users 
ADD COLUMN search_vector tsvector 
GENERATED ALWAYS AS (
    to_tsvector('english', 
        coalesce(first_name, '') || ' ' || 
        coalesce(last_name, '') || ' ' || 
        coalesce(email, '')
    )
) STORED;

-- GIN index for full-text search
CREATE INDEX idx_users_search_vector 
ON users USING GIN(search_vector);
```

**Query Example**:
```sql
SELECT user_id, email, first_name, last_name
FROM users
WHERE search_vector @@ to_tsquery('english', 'john & doe')
  AND is_active = true
ORDER BY ts_rank(search_vector, to_tsquery('english', 'john & doe')) DESC;
```

**Performance**:
- Full-text search: ~10ms for 100k users
- Sequential LIKE scan: ~200ms
- Improvement: 95% faster

---

## 9. JSONB Indexes

### User Preferences/Settings
```sql
-- If user preferences stored as JSONB
ALTER TABLE users ADD COLUMN preferences JSONB DEFAULT '{}';

-- GIN index for JSONB queries
CREATE INDEX idx_users_preferences 
ON users USING GIN(preferences);
```

**Query Examples**:
```sql
-- Contains key
SELECT * FROM users WHERE preferences ? 'theme';

-- JSON path query
SELECT * FROM users WHERE preferences @> '{"notifications": {"email": true}}';

-- Specific key value
SELECT * FROM users WHERE preferences->>'language' = 'en';
```

### Performance Comparison
- **jsonb_path_ops**: Faster, less storage, but only supports @> operator
- **Default GIN**: More flexible, supports ?, ?&, ?|, @>, @@

```sql
-- For contains queries only (recommended)
CREATE INDEX idx_users_preferences_ops 
ON users USING GIN(preferences jsonb_path_ops);
```

---

## 10. Index Maintenance

### REINDEX Strategy
```sql
-- Quarterly maintenance window
REINDEX INDEX CONCURRENTLY idx_users_email_active;
REINDEX INDEX CONCURRENTLY idx_user_sessions_token_expiry;
REINDEX INDEX CONCURRENTLY idx_user_sessions_user_expiry_created;
```

**Schedule**: 
- **Frequency**: Quarterly or when bloat > 30%
- **Method**: CONCURRENTLY to avoid blocking reads
- **Timing**: Off-peak hours (2-4 AM)

### VACUUM and ANALYZE
```sql
-- Aggressive autovacuum for authentication tables
ALTER TABLE users SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02
);

ALTER TABLE user_sessions SET (
    autovacuum_vacuum_scale_factor = 0.10,
    autovacuum_analyze_scale_factor = 0.05
);
```

**Manual Execution**:
```sql
-- Weekly ANALYZE
ANALYZE users;
ANALYZE user_sessions;
ANALYZE password_reset_tokens;

-- Monthly VACUUM ANALYZE
VACUUM ANALYZE users;
VACUUM ANALYZE user_sessions;
```

### Index Bloat Monitoring
```sql
-- Check index bloat percentage
SELECT
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,
    idx_scan AS index_scans,
    idx_tup_read AS tuples_read,
    idx_tup_fetch AS tuples_fetched,
    ROUND(100.0 * idx_scan / NULLIF(idx_scan + seq_scan, 0), 2) AS index_usage_percent
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY pg_relation_size(indexrelid) DESC;
```

**Action Threshold**: REINDEX when bloat > 30% or size growth without usage increase

### Statistics Updates
```sql
-- Ensure statistics are current
ALTER TABLE users SET (statistics_target = 1000);
ALTER TABLE user_sessions SET (statistics_target = 500);

-- Force statistics update after bulk operations
ANALYZE users;
```

---

## 11. Performance Monitoring

### Query Execution Plan Analysis
```sql
-- Enable query plan logging
ALTER DATABASE suma_finance SET log_min_duration_statement = 100; -- Log queries > 100ms

-- Analyze specific query
EXPLAIN (ANALYZE, BUFFERS, VERBOSE) 
SELECT user_id, email 
FROM users 
WHERE email = 'test@example.com';
```

**Expected Output**:
```
Index Scan using idx_users_email_active on users  (cost=0.29..8.30 rows=1 width=45) (actual time=0.015..0.016 rows=1 loops=1)
  Index Cond: (email = 'test@example.com'::text)
  Filter: (is_active AND (deleted_at IS NULL))
  Buffers: shared hit=4
Planning Time: 0.082 ms
Execution Time: 0.032 ms
```

### Index Hit Ratio Tracking
```sql
-- Overall cache hit ratio (should be > 99%)
SELECT 
    sum(heap_blks_read) AS heap_read,
    sum(heap_blks_hit) AS heap_hit,
    ROUND(100.0 * sum(heap_blks_hit) / NULLIF(sum(heap_blks_hit) + sum(heap_blks_read), 0), 2) AS cache_hit_ratio
FROM pg_statio_user_tables;

-- Index cache hit ratio
SELECT 
    sum(idx_blks_read) AS idx_read,
    sum(idx_blks_hit) AS idx_hit,
    ROUND(100.0 * sum(idx_blks_hit) / NULLIF(sum(idx_blks_hit) + sum(idx_blks_read), 0), 2) AS index_cache_hit_ratio
FROM pg_statio_user_tables;
```

### Slow Query Identification
```sql
-- Install pg_stat_statements extension
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Top 10 slowest queries
SELECT 
    calls,
    ROUND(total_exec_time::numeric, 2) AS total_time_ms,
    ROUND(mean_exec_time::numeric, 2) AS mean_time_ms,
    ROUND(max_exec_time::numeric, 2) AS max_time_ms,
    LEFT(query, 100) AS query_preview
FROM pg_stat_statements
WHERE query NOT LIKE '%pg_stat_statements%'
ORDER BY mean_exec_time DESC
LIMIT 10;
```

### Index Usage Statistics
```sql
-- Index usage report
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan AS scans,
    pg_size_pretty(pg_relation_size(indexrelid)) AS size,
    CASE 
        WHEN idx_scan = 0 THEN 'UNUSED'
        WHEN idx_scan < 100 THEN 'RARELY USED'
        ELSE 'ACTIVE'
    END AS status
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan ASC;
```

### Missing Index Detection
```sql
-- Queries with sequential scans (potential missing indexes)
SELECT 
    schemaname,
    tablename,
    seq_scan AS sequential_scans,
    seq_tup_read AS rows_read_seq,
    idx_scan AS index_scans,
    idx_tup_fetch AS rows_fetched_idx,
    ROUND(100.0 * seq_scan / NULLIF(seq_scan + idx_scan, 0), 2) AS seq_scan_percent
FROM pg_stat_user_tables
WHERE seq_scan > 1000
  AND seq_scan > idx_scan
ORDER BY seq_tup_read DESC;
```

---

## 12. Index Anti-Patterns

### Over-Indexing Warnings
**Problem**: Too many indexes on a single table
```sql
-- Check index count per table
SELECT 
    tablename,
    COUNT(*) AS index_count
FROM pg_indexes
WHERE schemaname = 'public'
GROUP BY tablename
HAVING COUNT(*) > 7
ORDER BY index_count DESC;
```

**Guideline**: 
- Users table: 5-7 indexes maximum
- Sessions table: 4-6 indexes maximum
- Each index adds 5-15% write overhead

### Duplicate Indexes Detection
```sql
-- Find duplicate or redundant indexes
SELECT 
    idx1.tablename,
    idx1.indexname AS index1,
    idx2.indexname AS index2,
    idx1.indexdef AS definition1,
    idx2.indexdef AS definition2
FROM pg_indexes idx1
JOIN pg_indexes idx2 
    ON idx1.tablename = idx2.tablename
    AND idx1.indexname < idx2.indexname
WHERE idx1.schemaname = 'public'
  AND idx1.indexdef = idx2.indexdef;
```

**Action**: Remove duplicate indexes immediately

### Rarely Used Indexes
```sql
-- Indexes with < 100 scans in production
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan AS scans,
    pg_size_pretty(pg_relation_size(indexrelid)) AS size,
    'CONSIDER DROPPING' AS recommendation
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
  AND idx_scan < 100
  AND indexrelid IN (
      SELECT indexrelid 
      FROM pg_stat_user_indexes 
      WHERE schemaname = 'public'
  )
ORDER BY pg_relation_size(indexrelid) DESC;
```

**Action**: Monitor for 1 month; drop if still unused

### Low-Selectivity Indexes
**Problem**: Index on columns with few distinct values

```sql
-- Check column cardinality
SELECT 
    attname AS column_name,
    n_distinct,
    CASE 
        WHEN n_distinct < 10 THEN 'LOW SELECTIVITY - BAD INDEX CANDIDATE'
        WHEN n_distinct < 100 THEN 'MEDIUM SELECTIVITY - COMPOSITE INDEX ONLY'
        ELSE 'HIGH SELECTIVITY - GOOD INDEX CANDIDATE'
    END AS selectivity
FROM pg_stats
WHERE tablename = 'users'
  AND schemaname = 'public'
ORDER BY n_distinct DESC;
```

**Example**: 
- ❌ `is_active` (2 distinct values: true/false)
- ✅ `email` (n distinct values ≈ n rows)

**Guideline**: Avoid standalone indexes on boolean columns; use in composite or partial indexes only

### Index on Highly-Volatile Columns
**Problem**: Frequent updates cause index churn

```sql
-- Identify frequently updated columns
SELECT 
    schemaname,
    tablename,
    n_tup_upd AS updates,
    n_tup_hot_upd AS hot_updates,
    ROUND(100.0 * n_tup_hot_upd / NULLIF(n_tup_upd, 0), 2) AS hot_update_percent
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY n_tup_upd DESC;
```

**Anti-Pattern Examples**:
- ❌ Index on `last_login_at` (updated every login)
- ❌ Index on `failed_login_attempts` (updated frequently)
- ✅ Use partial index or composite index only when necessary

---

## Summary: Recommended Index Set

### Users Table
```sql
-- Primary key (automatic)
CREATE UNIQUE INDEX users_pkey ON users(user_id);

-- Email login (covering)
CREATE UNIQUE INDEX idx_users_email_active 
ON users(email) 
INCLUDE (user_id, password_hash, is_active, email_verified_at, failed_login_attempts)
WHERE is_active = true AND deleted_at IS NULL;

-- Full-text search
CREATE INDEX idx_users_search_vector ON users USING GIN(search_vector);
```

### User Sessions Table
```sql
-- Primary key (automatic)
CREATE UNIQUE INDEX user_sessions_pkey ON user_sessions(session_id);

-- Foreign key
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);

-- Session validation (covering)
CREATE INDEX idx_user_sessions_token_expiry 
ON user_sessions(session_token, expires_at)
INCLUDE (user_id, session_id);

-- User's active sessions
CREATE INDEX idx_user_sessions_user_expiry_created 
ON user_sessions(user_id, expires_at, created_at DESC);

-- Cleanup job
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);
```

### Password Reset Tokens Table
```sql
-- Primary key (automatic)
CREATE UNIQUE INDEX password_reset_tokens_pkey ON password_reset_tokens(token_id);

-- Foreign key
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);

-- Token validation (partial)
CREATE UNIQUE INDEX idx_password_reset_tokens_hash 
ON password_reset_tokens(token_hash) 
WHERE used_at IS NULL AND expires_at > NOW();
```

**Total Indexes**: 11
**Estimated Storage Overhead**: ~25% of table data
**Expected Performance Improvement**: 60-95% on authentication queries
