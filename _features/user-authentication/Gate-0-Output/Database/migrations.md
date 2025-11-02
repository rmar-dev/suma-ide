---
layout: default
title: Migrations
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

Claude configuration file at C:\Users\ricma\.claude.json is corrupted: Unterminated string in JSON at position 8192 (line 44 column 7063)

Claude configuration file at C:\Users\ricma\.claude.json is corrupted
The corrupted file has been backed up to: C:\Users\ricma\.claude.json.corrupted.1762037208710
A backup file exists at: C:\Users\ricma\.claude.json.backup
You can manually restore it by running: cp "C:\Users\ricma\.claude.json.backup" "C:\Users\ricma\.claude.json"

# Database Migrations: User Registration & Authentication

## 1. Migration Strategy Overview

### Migration Tool Selection
- **Tool**: Flyway (Java-based, database-agnostic, industry standard)
- **Rationale**: 
  - SQL-first approach with support for Java-based migrations
  - Strong version control integration
  - Excellent rollback and repair capabilities
  - Enterprise-grade reliability

### Version Numbering Scheme
```
V{MAJOR}.{MINOR}.{PATCH}__{DESCRIPTION}.sql

Examples:
V1.0.0__create_users_table.sql
V1.1.0__add_email_verification.sql
V1.1.1__fix_password_hash_length.sql
```

### Migration File Naming Conventions
- **Versioned**: `V{VERSION}__{DESCRIPTION}.sql` - Applied once, immutable
- **Repeatable**: `R__{DESCRIPTION}.sql` - Applied on checksum change
- **Undo**: `U{VERSION}__{DESCRIPTION}.sql` - Rollback scripts

### Rollback Strategy
- Every migration includes corresponding undo script
- Pre-migration database snapshot for critical changes
- Rollback testing mandatory in staging environment
- Maximum rollback window: 24 hours for production

---

## 2. Initial Schema Setup

### Initial Migration File Structure
```
migrations/
├── V1.0.0__create_users_table.sql
├── U1.0.0__create_users_table.sql
├── V1.1.0__create_authentication_tokens_table.sql
├── U1.1.0__create_authentication_tokens_table.sql
├── V1.2.0__create_password_reset_tokens_table.sql
├── U1.2.0__create_password_reset_tokens_table.sql
├── V1.3.0__create_audit_logs_table.sql
├── U1.3.0__create_audit_logs_table.sql
├── V1.4.0__add_indexes.sql
├── U1.4.0__add_indexes.sql
└── R__seed_initial_data.sql
```

### Base Tables Creation Order
1. `users` (no dependencies)
2. `authentication_tokens` (depends on users)
3. `password_reset_tokens` (depends on users)
4. `audit_logs` (depends on users)
5. Indexes (after all tables)

### Initial Indexes Creation
- Primary keys (auto-created with tables)
- Foreign key indexes
- Query performance indexes (email, token lookups)
- Audit trail indexes (timestamp-based queries)

### Initial Data Seeding Requirements
- System admin user (if required)
- Default roles/permissions
- Configuration parameters
- Application constants

---

## 3. Migration Files Structure

### V1.0.0: Create Users Table

**Migration ID**: V1.0.0  
**Description**: Create core users table with authentication fields  
**Dependencies**: None

**Up Migration** (`V1.0.0__create_users_table.sql`):
```sql
-- Users table for authentication and user management
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20),
    phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
    account_status VARCHAR(20) NOT NULL DEFAULT 'active',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT valid_account_status CHECK (account_status IN ('active', 'suspended', 'locked', 'deleted')),
    CONSTRAINT valid_phone CHECK (phone_number IS NULL OR phone_number ~* '^\+?[1-9]\d{1,14}$')
);

-- Indexes
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_account_status ON users(account_status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users(created_at);

-- Comments
COMMENT ON TABLE users IS 'Core user accounts for authentication and profile management';
COMMENT ON COLUMN users.password_hash IS 'Bcrypt hash with cost factor 12';
COMMENT ON COLUMN users.failed_login_attempts IS 'Counter for account lockout mechanism';
COMMENT ON COLUMN users.locked_until IS 'Account locked until this timestamp if failed attempts exceeded';
```

**Down Migration** (`U1.0.0__create_users_table.sql`):
```sql
DROP TABLE IF EXISTS users CASCADE;
```

---

### V1.1.0: Create Authentication Tokens Table

**Migration ID**: V1.1.0  
**Description**: Create table for JWT refresh tokens and session management  
**Dependencies**: V1.0.0

**Up Migration** (`V1.1.0__create_authentication_tokens_table.sql`):
```sql
-- Authentication tokens for session management
CREATE TABLE authentication_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    token_type VARCHAR(20) NOT NULL DEFAULT 'refresh',
    device_info JSONB,
    ip_address INET NOT NULL,
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_token_type CHECK (token_type IN ('refresh', 'access', 'api_key')),
    CONSTRAINT valid_revoked_reason CHECK (
        revoked_at IS NULL OR 
        revoked_reason IN ('user_logout', 'admin_revoke', 'security_breach', 'token_rotation', 'expired')
    )
);

-- Indexes
CREATE INDEX idx_auth_tokens_user_id ON authentication_tokens(user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_tokens_token_hash ON authentication_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_tokens_expires_at ON authentication_tokens(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_tokens_created_at ON authentication_tokens(created_at);

-- Comments
COMMENT ON TABLE authentication_tokens IS 'Manages refresh tokens and active sessions';
COMMENT ON COLUMN authentication_tokens.token_hash IS 'SHA-256 hash of the actual token';
COMMENT ON COLUMN authentication_tokens.device_info IS 'JSON containing device fingerprint data';
```

**Down Migration** (`U1.1.0__create_authentication_tokens_table.sql`):
```sql
DROP TABLE IF EXISTS authentication_tokens CASCADE;
```

---

### V1.2.0: Create Password Reset Tokens Table

**Migration ID**: V1.2.0  
**Description**: Create table for password reset token management  
**Dependencies**: V1.0.0

**Up Migration** (`V1.2.0__create_password_reset_tokens_table.sql`):
```sql
-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT expires_in_future CHECK (expires_at > created_at)
);

-- Indexes
CREATE INDEX idx_password_reset_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_token_hash ON password_reset_tokens(token_hash) WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_expires_at ON password_reset_tokens(expires_at) WHERE used_at IS NULL;

-- Comments
COMMENT ON TABLE password_reset_tokens IS 'One-time tokens for password reset flow';
COMMENT ON COLUMN password_reset_tokens.token_hash IS 'SHA-256 hash of the reset token';
```

**Down Migration** (`U1.2.0__create_password_reset_tokens_table.sql`):
```sql
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
```

---

### V1.3.0: Create Audit Logs Table

**Migration ID**: V1.3.0  
**Description**: Create audit trail for authentication events  
**Dependencies**: V1.0.0

**Up Migration** (`V1.3.0__create_audit_logs_table.sql`):
```sql
-- Audit logs for security and compliance
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    event_category VARCHAR(20) NOT NULL,
    event_data JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT valid_event_category CHECK (
        event_category IN ('authentication', 'authorization', 'user_management', 'security', 'system')
    )
);

-- Indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_event_category ON audit_logs(event_category);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_success ON audit_logs(success) WHERE success = FALSE;

-- Partitioning setup (optional for high volume)
-- CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
--     FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

-- Comments
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail for security and compliance';
COMMENT ON COLUMN audit_logs.event_type IS 'Specific event: login_success, login_failed, password_changed, etc.';
COMMENT ON COLUMN audit_logs.event_data IS 'Additional context stored as JSON';
```

**Down Migration** (`U1.3.0__create_audit_logs_table.sql`):
```sql
DROP TABLE IF EXISTS audit_logs CASCADE;
```

---

### V1.4.0: Add Performance Indexes

**Migration ID**: V1.4.0  
**Description**: Add additional indexes for query optimization  
**Dependencies**: V1.0.0, V1.1.0, V1.2.0, V1.3.0

**Up Migration** (`V1.4.0__add_indexes.sql`):
```sql
-- Composite indexes for common queries
CREATE INDEX idx_users_status_created ON users(account_status, created_at DESC) 
    WHERE deleted_at IS NULL;

CREATE INDEX idx_auth_tokens_user_expires ON authentication_tokens(user_id, expires_at) 
    WHERE revoked_at IS NULL;

-- Partial indexes for active sessions
CREATE INDEX idx_auth_tokens_active ON authentication_tokens(user_id, last_used_at) 
    WHERE revoked_at IS NULL AND expires_at > NOW();

-- GIN index for JSONB queries (if needed)
CREATE INDEX idx_auth_tokens_device_info ON authentication_tokens USING GIN (device_info) 
    WHERE device_info IS NOT NULL;

CREATE INDEX idx_audit_logs_event_data ON audit_logs USING GIN (event_data) 
    WHERE event_data IS NOT NULL;
```

**Down Migration** (`U1.4.0__add_indexes.sql`):
```sql
DROP INDEX IF EXISTS idx_users_status_created;
DROP INDEX IF EXISTS idx_auth_tokens_user_expires;
DROP INDEX IF EXISTS idx_auth_tokens_active;
DROP INDEX IF EXISTS idx_auth_tokens_device_info;
DROP INDEX IF EXISTS idx_audit_logs_event_data;
```

---

## 4. Schema Change Types

### Adding Tables
```sql
-- Template for new table
CREATE TABLE new_table (
    id BIGSERIAL PRIMARY KEY,
    -- columns
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Always include rollback
-- U{VERSION}: DROP TABLE IF EXISTS new_table CASCADE;
```

### Altering Tables

**Add Column** (`V1.5.0__add_mfa_columns.sql`):
```sql
-- Add MFA support columns
ALTER TABLE users 
    ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN mfa_secret VARCHAR(255),
    ADD COLUMN mfa_backup_codes JSONB;

-- Backfill existing users
UPDATE users SET mfa_enabled = FALSE WHERE mfa_enabled IS NULL;

-- Add check constraint
ALTER TABLE users 
    ADD CONSTRAINT valid_mfa CHECK (
        (mfa_enabled = FALSE AND mfa_secret IS NULL) OR
        (mfa_enabled = TRUE AND mfa_secret IS NOT NULL)
    );
```

**Rollback**:
```sql
ALTER TABLE users 
    DROP CONSTRAINT IF EXISTS valid_mfa,
    DROP COLUMN IF EXISTS mfa_enabled,
    DROP COLUMN IF EXISTS mfa_secret,
    DROP COLUMN IF EXISTS mfa_backup_codes;
```

**Modify Column** (`V1.6.0__extend_password_hash_length.sql`):
```sql
-- Extend password hash length for future algorithm upgrades
ALTER TABLE users 
    ALTER COLUMN password_hash TYPE VARCHAR(512);
```

**Rollback**:
```sql
-- Safe if all hashes are <= 255 chars
ALTER TABLE users 
    ALTER COLUMN password_hash TYPE VARCHAR(255);
```

### Dropping Tables
```sql
-- Always use soft delete first, then hard delete after grace period
-- V1.7.0: Mark table as deprecated
ALTER TABLE deprecated_table RENAME TO deprecated_table_old;

-- V1.8.0: After 30 days, drop
DROP TABLE IF EXISTS deprecated_table_old CASCADE;
```

### Adding Constraints

**Foreign Keys**:
```sql
-- Add with validation (locks table)
ALTER TABLE authentication_tokens 
    ADD CONSTRAINT fk_auth_tokens_user_id 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Zero-downtime approach: Add NOT VALID, then VALIDATE
ALTER TABLE authentication_tokens 
    ADD CONSTRAINT fk_auth_tokens_user_id 
    FOREIGN KEY (user_id) REFERENCES users(id) 
    NOT VALID;

-- In separate transaction
ALTER TABLE authentication_tokens 
    VALIDATE CONSTRAINT fk_auth_tokens_user_id;
```

**Unique Constraints**:
```sql
-- Add unique constraint with zero downtime
CREATE UNIQUE INDEX CONCURRENTLY idx_users_email_unique 
    ON users(LOWER(email)) WHERE deleted_at IS NULL;

ALTER TABLE users 
    ADD CONSTRAINT users_email_unique 
    UNIQUE USING INDEX idx_users_email_unique;
```

### Removing Constraints
```sql
-- Drop constraint
ALTER TABLE users DROP CONSTRAINT IF EXISTS old_constraint;

-- Drop index
DROP INDEX CONCURRENTLY IF EXISTS idx_old_index;
```

### Renaming Objects
```sql
-- Rename table (quick operation, but breaks code)
ALTER TABLE old_table_name RENAME TO new_table_name;

-- Rename column
ALTER TABLE users RENAME COLUMN old_column TO new_column;

-- Zero-downtime approach: Create view with old name
CREATE VIEW old_table_name AS SELECT * FROM new_table_name;
```

---

## 5. Data Migrations

### Data Transformation Scripts

**V2.0.0: Normalize Email Addresses**:
```sql
-- Normalize all email addresses to lowercase
UPDATE users 
SET email = LOWER(email),
    updated_at = NOW()
WHERE email != LOWER(email);

-- Audit the change
INSERT INTO audit_logs (user_id, event_type, event_category, event_data, success, created_at)
SELECT 
    id,
    'email_normalized',
    'user_management',
    jsonb_build_object('old_email', email, 'new_email', LOWER(email)),
    TRUE,
    NOW()
FROM users
WHERE email != LOWER(email);
```

### Data Backfill Requirements

**V2.1.0: Backfill Missing Account Status**:
```sql
-- Backfill account_status for old records
UPDATE users 
SET account_status = CASE
    WHEN deleted_at IS NOT NULL THEN 'deleted'
    WHEN locked_until IS NOT NULL AND locked_until > NOW() THEN 'locked'
    ELSE 'active'
END,
updated_at = NOW()
WHERE account_status IS NULL;
```

### Bulk Data Updates

**V2.2.0: Reset Failed Login Attempts**:
```sql
-- Reset stale failed login attempts (older than 24 hours)
UPDATE users 
SET failed_login_attempts = 0,
    locked_until = NULL,
    updated_at = NOW()
WHERE failed_login_attempts > 0 
  AND last_login_at < NOW() - INTERVAL '24 hours';
```

### Data Cleanup Operations

**V2.3.0: Archive Old Audit Logs**:
```sql
-- Move audit logs older than 1 year to archive table
CREATE TABLE IF NOT EXISTS audit_logs_archive (LIKE audit_logs INCLUDING ALL);

INSERT INTO audit_logs_archive 
SELECT * FROM audit_logs 
WHERE created_at < NOW() - INTERVAL '1 year';

DELETE FROM audit_logs 
WHERE created_at < NOW() - INTERVAL '1 year';

-- Vacuum to reclaim space
VACUUM ANALYZE audit_logs;
```

### ETL Processes

**V2.4.0: Consolidate User Data**:
```sql
-- Create materialized view for user summary
CREATE MATERIALIZED VIEW user_summary AS
SELECT 
    u.id,
    u.email,
    u.first_name,
    u.last_name,
    u.account_status,
    u.created_at,
    u.last_login_at,
    COUNT(DISTINCT at.id) as active_sessions,
    COUNT(DISTINCT al.id) FILTER (WHERE al.created_at > NOW() - INTERVAL '30 days') as recent_activities
FROM users u
LEFT JOIN authentication_tokens at ON u.id = at.user_id AND at.revoked_at IS NULL
LEFT JOIN audit_logs al ON u.id = al.user_id
WHERE u.deleted_at IS NULL
GROUP BY u.id;

CREATE UNIQUE INDEX ON user_summary(id);

-- Refresh schedule (run via cron)
-- REFRESH MATERIALIZED VIEW CONCURRENTLY user_summary;
```

---

## 6. Index Management

### Creating New Indexes

**Standard Index**:
```sql
-- Simple B-tree index
CREATE INDEX idx_users_last_login ON users(last_login_at DESC);
```

**Concurrent Index** (Zero Downtime):
```sql
-- Create index without locking table
CREATE INDEX CONCURRENTLY idx_users_phone_number 
ON users(phone_number) 
WHERE phone_number IS NOT NULL AND deleted_at IS NULL;
```

**Partial Index**:
```sql
-- Index only active users
CREATE INDEX idx_users_active_email 
ON users(email) 
WHERE account_status = 'active' AND deleted_at IS NULL;
```

**Expression Index**:
```sql
-- Index on computed value
CREATE INDEX idx_users_email_lower 
ON users(LOWER(email)) 
WHERE deleted_at IS NULL;
```

**Multi-Column Index**:
```sql
-- Composite index for common query
CREATE INDEX idx_users_status_created 
ON users(account_status, created_at DESC) 
WHERE deleted_at IS NULL;
```

### Dropping Obsolete Indexes

**Safe Drop**:
```sql
-- Drop with CONCURRENTLY to avoid locks
DROP INDEX CONCURRENTLY IF EXISTS idx_obsolete_index;
```

### Rebuilding Indexes

**REINDEX**:
```sql
-- Rebuild single index (locks table)
REINDEX INDEX idx_users_email;

-- Rebuild all indexes on table (locks table)
REINDEX TABLE users;

-- Zero-downtime rebuild: Create new, drop old
CREATE INDEX CONCURRENTLY idx_users_email_new ON users(email);
DROP INDEX CONCURRENTLY idx_users_email;
ALTER INDEX idx_users_email_new RENAME TO idx_users_email;
```

### Concurrent Index Creation Strategy

**V3.0.0: Add Complex Indexes**:
```sql
-- Step 1: Create indexes concurrently (no locks)
CREATE INDEX CONCURRENTLY idx_auth_tokens_composite 
ON authentication_tokens(user_id, expires_at, revoked_at);

CREATE INDEX CONCURRENTLY idx_audit_logs_user_created 
ON audit_logs(user_id, created_at DESC);

-- Step 2: Analyze tables
ANALYZE authentication_tokens;
ANALYZE audit_logs;

-- Step 3: Verify index usage
-- SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
-- FROM pg_stat_user_indexes
-- WHERE indexname IN ('idx_auth_tokens_composite', 'idx_audit_logs_user_created');
```

---

## 7. Migration Testing

### Pre-Migration Validation Checks

**Checklist Script** (`pre_migration_checks.sql`):
```sql
-- 1. Check database version compatibility
SELECT version();

-- 2. Verify sufficient disk space (at least 20% free)
SELECT 
    pg_size_pretty(pg_database_size(current_database())) as db_size,
    pg_size_pretty(pg_tablespace_size('pg_default')) as tablespace_size;

-- 3. Check for blocking queries
SELECT pid, usename, application_name, state, query 
FROM pg_stat_activity 
WHERE state != 'idle' AND query NOT LIKE '%pg_stat_activity%';

-- 4. Verify no pending migrations
SELECT * FROM flyway_schema_history 
WHERE success = FALSE OR installed_rank IS NULL;

-- 5. Check table row counts (baseline)
SELECT 
    schemaname,
    tablename,
    n_live_tup as row_count
FROM pg_stat_user_tables
WHERE tablename IN ('users', 'authentication_tokens', 'password_reset_tokens', 'audit_logs')
ORDER BY tablename;

-- 6. Verify foreign key integrity
SELECT conname, conrelid::regclass, confrelid::regclass
FROM pg_constraint
WHERE contype = 'f' AND connamespace = 'public'::regnamespace;

-- 7. Check for duplicate emails (if adding unique constraint)
SELECT email, COUNT(*) 
FROM users 
WHERE deleted_at IS NULL
GROUP BY email 
HAVING COUNT(*) > 1;
```

### Post-Migration Validation Checks

**Validation Script** (`post_migration_checks.sql`):
```sql
-- 1. Verify migration success
SELECT * FROM flyway_schema_history 
ORDER BY installed_rank DESC 
LIMIT 5;

-- 2. Check table structures
SELECT 
    table_name,
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_name IN ('users', 'authentication_tokens', 'password_reset_tokens', 'audit_logs')
ORDER BY table_name, ordinal_position;

-- 3. Verify constraints
SELECT 
    tc.constraint_name,
    tc.table_name,
    tc.constraint_type,
    cc.check_clause
FROM information_schema.table_constraints tc
LEFT JOIN information_schema.check_constraints cc 
    ON tc.constraint_name = cc.constraint_name
WHERE tc.table_schema = 'public'
ORDER BY tc.table_name, tc.constraint_type;

-- 4. Verify indexes
SELECT 
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY tablename, indexname;

-- 5. Check row counts (compare with baseline)
SELECT 
    schemaname,
    tablename,
    n_live_tup as row_count,
    n_dead_tup as dead_tuples
FROM pg_stat_user_tables
WHERE tablename IN ('users', 'authentication_tokens', 'password_reset_tokens', 'audit_logs')
ORDER BY tablename;

-- 6. Verify foreign key relationships
SELECT 
    COUNT(*) as orphaned_records
FROM authentication_tokens at
LEFT JOIN users u ON at.user_id = u.id
WHERE u.id IS NULL;

-- 7. Test sample queries
SELECT COUNT(*) FROM users WHERE deleted_at IS NULL;
SELECT COUNT(*) FROM authentication_tokens WHERE revoked_at IS NULL;
SELECT COUNT(*) FROM audit_logs WHERE created_at > NOW() - INTERVAL '1 day';
```

### Data Integrity Verification

**Integrity Checks** (`data_integrity_checks.sql`):
```sql
-- 1. Verify no NULL violations
SELECT 'users' as table_name, COUNT(*) as null_emails
FROM users WHERE email IS NULL
UNION ALL
SELECT 'users', COUNT(*) FROM users WHERE password_hash IS NULL
UNION ALL
SELECT 'authentication_tokens', COUNT(*) FROM authentication_tokens WHERE user_id IS NULL;

-- 2. Check email format validity
SELECT COUNT(*) as invalid_emails
FROM users 
WHERE email !~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$';

-- 3. Verify password hash length
SELECT COUNT(*) as short_hashes
FROM users 
WHERE LENGTH(password_hash) < 60; -- bcrypt should be 60 chars

-- 4. Check for expired tokens not revoked
SELECT COUNT(*) as expired_not_revoked
FROM authentication_tokens 
WHERE expires_at < NOW() AND revoked_at IS NULL;

-- 5. Verify timestamp consistency
SELECT COUNT(*) as inconsistent_timestamps
FROM users 
WHERE created_at > updated_at;

-- 6. Check for orphaned records
SELECT 'authentication_tokens' as table_name, COUNT(*) as orphaned
FROM authentication_tokens at
LEFT JOIN users u ON at.user_id = u.id
WHERE u.id IS NULL
UNION ALL
SELECT 'password_reset_tokens', COUNT(*)
FROM password_reset_tokens prt
LEFT JOIN users u ON prt.user_id = u.id
WHERE u.id IS NULL;
```

### Performance Testing After Migration

**Performance Benchmarks**:
```sql
-- 1. Explain analyze common queries
EXPLAIN (ANALYZE, BUFFERS) 
SELECT * FROM users 
WHERE email = 'test@example.com' AND deleted_at IS NULL;

EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM authentication_tokens 
WHERE user_id = 12345 AND revoked_at IS NULL 
ORDER BY created_at DESC;

EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM audit_logs 
WHERE user_id = 12345 AND created_at > NOW() - INTERVAL '30 days'
ORDER BY created_at DESC;

-- 2. Check index usage statistics
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC;

-- 3. Check table statistics
SELECT 
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch,
    n_tup_ins,
    n_tup_upd,
    n_tup_del
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY tablename;
```

### Rollback Testing

**Rollback Test Procedure**:
```bash
#!/bin/bash
# rollback_test.sh

# 1. Backup current state
pg_dump -h localhost -U financeuser financeapp > backup_before_rollback.sql

# 2. Execute rollback migration
flyway -configFiles=flyway.conf undo

# 3. Verify rollback success
psql -h localhost -U financeuser -d financeapp -f post_migration_checks.sql

# 4. Re-apply migration
flyway -configFiles=flyway.conf migrate

# 5. Verify migration success
psql -h localhost -U financeuser -d financeapp -f post_migration_checks.sql

echo "Rollback test completed successfully"
```

---

## 8. Zero-Downtime Migrations

### Multi-Phase Migration Strategy

**Phase 1: Add New Column (Nullable)**
```sql
-- V4.0.0: Add new column without constraints
ALTER TABLE users ADD COLUMN new_field VARCHAR(255);
CREATE INDEX CONCURRENTLY idx_users_new_field ON users(new_field);
```

**Phase 2: Backfill Data**
```sql
-- V4.1.0: Backfill new column in batches
DO $$
DECLARE
    batch_size INTEGER := 1000;
    total_rows INTEGER;
    processed INTEGER := 0;
BEGIN
    SELECT COUNT(*) INTO total_rows FROM users WHERE new_field IS NULL;
    
    WHILE processed < total_rows LOOP
        UPDATE users 
        SET new_field = compute_new_value(old_field),
            updated_at = NOW()
        WHERE id IN (
            SELECT id FROM users 
            WHERE new_field IS NULL 
            LIMIT batch_size
        );
        
        processed := processed + batch_size;
        COMMIT; -- Commit in batches
        PERFORM pg_sleep(0.1); -- Throttle to avoid blocking
    END LOOP;
END $$;
```

**Phase 3: Add Constraints**
```sql
-- V4.2.0: Add NOT NULL constraint after backfill
ALTER TABLE users ALTER COLUMN new_field SET NOT NULL;
```

**Phase 4: Remove Old Column**
```sql
-- V4.3.0: Drop old column (after verification period)
ALTER TABLE users DROP COLUMN old_field;
```

### Backward-Compatible Schema Changes

**Additive Changes Only**:
```sql
-- ✅ SAFE: Add new column (nullable)
ALTER TABLE users ADD COLUMN middle_name VARCHAR(100);

-- ✅ SAFE: Add new table
CREATE TABLE user_preferences (
    user_id BIGINT PRIMARY KEY REFERENCES users(id),
    preferences JSONB
);

-- ✅ SAFE: Add new index
CREATE INDEX CONCURRENTLY idx_users_last_name ON users(last_name);

-- ❌ UNSAFE: Drop column (old code will break)
-- ALTER TABLE users DROP COLUMN old_field;

-- ❌ UNSAFE: Rename column (old code will break)
-- ALTER TABLE users RENAME COLUMN email TO email_address;

-- ❌ UNSAFE: Add NOT NULL constraint (will fail for nulls)
-- ALTER TABLE users ALTER COLUMN new_field SET NOT NULL;
```

**Dual-Write Pattern**:
```sql
-- Maintain both old and new columns during transition
-- Application writes to both columns
-- V5.0.0: Add new column
ALTER TABLE users ADD COLUMN email_normalized VARCHAR(255);

-- V5.1.0: Backfill
UPDATE users SET email_normalized = LOWER(email);

-- V5.2.0: Add index
CREATE INDEX CONCURRENTLY idx_users_email_normalized ON users(email_normalized);

-- After all services updated to use new column:
-- V5.3.0: Drop old column
ALTER TABLE users DROP COLUMN email;
ALTER TABLE users RENAME COLUMN email_normalized TO email;
```

### Feature Flags for Gradual Rollout

**Schema Support for Feature Flags**:
```sql
-- V6.0.0: Add feature flag table
CREATE TABLE feature_flags (
    id SERIAL PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    rollout_percentage INTEGER NOT NULL DEFAULT 0,
    target_users JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    CONSTRAINT valid_rollout CHECK (rollout_percentage BETWEEN 0 AND 100)
);

-- Seed feature flags
INSERT INTO feature_flags (feature_name, enabled, rollout_percentage) VALUES
('mfa_enforcement', FALSE, 0),
('email_verification_required', TRUE, 100),
('password_complexity_rules', TRUE, 50);
```

### Blue-Green Deployment Considerations

**Database Compatibility Requirements**:
- **Blue (Old Version)**: Must work with schema version N and N+1
- **Green (New Version)**: Must work with schema version N+1

**Migration Timing**:
```
1. Deploy Green application (supports schema N+1)
2. Run migration (schema N → N+1)
3. Verify Green application works
4. Switch traffic to Green
5. Keep Blue running for rollback (supports schema N+1)
6. After stability period, decommission Blue
```

**Example: Add Column with Default**:
```sql
-- ✅ Compatible with both versions
ALTER TABLE users ADD COLUMN notification_preference VARCHAR(20) DEFAULT 'email';

-- Old code: Ignores new column (works)
-- New code: Reads new column (works)
```

---

## 9. Migration Execution Plan

### Development Environment Migration Order

**Local Development**:
```bash
#!/bin/bash
# migrate_dev.sh

set -e

echo "=== Development Migration ==="

# 1. Pull latest migrations
git pull origin main

# 2. Check current migration status
flyway -configFiles=flyway-dev.conf info

# 3. Validate migrations
flyway -configFiles=flyway-dev.conf validate

# 4. Run migrations
flyway -configFiles=flyway-dev.conf migrate

# 5. Verify success
flyway -configFiles=flyway-dev.conf info

# 6. Run post-migration checks
psql -h localhost -U financeuser -d financeapp_dev -f scripts/post_migration_checks.sql

echo "✅ Development migration completed"
```

### Staging Environment Migration Process

**Staging Migration Runbook**:
```bash
#!/bin/bash
# migrate_staging.sh

set -e

echo "=== Staging Migration Runbook ==="

# 1. Notify team
echo "📢 Starting staging migration at $(date)"

# 2. Backup database
echo "💾 Creating backup..."
pg_dump -h staging-db.example.com -U admin -d financeapp_staging > backup_staging_$(date +%Y%m%d_%H%M%S).sql

# 3. Check disk space
echo "💽 Checking disk space..."
DISK_USAGE=$(df -h /var/lib/postgresql | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    echo "❌ Disk usage above 80%. Aborting migration."
    exit 1
fi

# 4. Run pre-migration checks
echo "🔍 Running pre-migration checks..."
psql -h staging-db.example.com -U admin -d financeapp_staging -f scripts/pre_migration_checks.sql

# 5. Execute migration
echo "🚀 Running migrations..."
flyway -configFiles=flyway-staging.conf migrate

# 6. Run post-migration checks
echo "✅ Running post-migration checks..."
psql -h staging-db.example.com -U admin -d financeapp_staging -f scripts/post_migration_checks.sql

# 7. Verify data integrity
echo "🔐 Verifying data integrity..."
psql -h staging-db.example.com -U admin -d financeapp_staging -f scripts/data_integrity_checks.sql

# 8. Run smoke tests
echo "🧪 Running smoke tests..."
npm run test:smoke

# 9. Check application health
echo "🏥 Checking application health..."
curl -f http://staging.example.com/health || exit 1

echo "✅ Staging migration completed successfully at $(date)"
```

### Production Migration Runbook

**Production Migration Checklist**:
```markdown
# Production Migration Checklist

## Pre-Migration (T-24 hours)
- [ ] Review migration scripts with team
- [ ] Schedule maintenance window
- [ ] Notify stakeholders (email, Slack, status page)
- [ ] Prepare rollback plan
- [ ] Verify staging migration success
- [ ] Check disk space (>30% free required)
- [ ] Backup database (full dump)
- [ ] Snapshot database volume
- [ ] Test backup restoration
- [ ] Verify monitoring alerts active

## Pre-Migration (T-1 hour)
- [ ] Final team sync
- [ ] Verify backup completion
- [ ] Check database connections
- [ ] Review rollback procedure
- [ ] Set up war room (Zoom/Slack channel)
- [ ] Enable verbose logging

## Migration Execution
- [ ] Put application in maintenance mode
- [ ] Verify no active user sessions
- [ ] Run pre-migration checks
- [ ] Execute migrations
- [ ] Run post-migration checks
- [ ] Verify data integrity
- [ ] Test critical user flows
- [ ] Check application health endpoints
- [ ] Monitor error rates
- [ ] Remove maintenance mode

## Post-Migration (T+1 hour)
- [ ] Monitor application metrics
- [ ] Check error logs
- [ ] Verify audit logs
- [ ] Test authentication flows
- [ ] Verify database performance
- [ ] Check index usage
- [ ] Update status page
- [ ] Notify stakeholders of success

## Post-Migration (T+24 hours)
- [ ] Review migration metrics
- [ ] Check for anomalies
- [ ] Verify backup retention
- [ ] Document lessons learned
- [ ] Update runbook
```

**Production Migration Script**:
```bash
#!/bin/bash
# migrate_production.sh

set -e

MAINTENANCE_MODE="ON"
ROLLBACK_ON_FAILURE="YES"

echo "=== PRODUCTION MIGRATION RUNBOOK ==="
echo "⚠️  WARNING: This will modify the production database"
echo ""
read -p "Type 'PROCEED' to continue: " confirmation

if [ "$confirmation" != "PROCEED" ]; then
    echo "❌ Migration cancelled"
    exit 1
fi

# 1. Pre-flight checks
echo "🔍 Running pre-flight checks..."
./scripts/pre_migration_checks.sh || exit 1

# 2. Enable maintenance mode
if [ "$MAINTENANCE_MODE" == "ON" ]; then
    echo "🚧 Enabling maintenance mode..."
    curl -X POST https://api.example.com/admin/maintenance/enable
    sleep 5
fi

# 3. Create backup
echo "💾 Creating production backup..."
BACKUP_FILE="backup_production_$(date +%Y%m%d_%H%M%S).sql"
pg_dump -h prod-db.example.com -U admin -d financeapp_prod > $BACKUP_FILE
echo "✅ Backup saved: $BACKUP_FILE"

# 4. Verify backup
echo "🔍 Verifying backup integrity..."
pg_restore --list $BACKUP_FILE > /dev/null || exit 1

# 5. Run migration
echo "🚀 Executing migrations..."
if flyway -configFiles=flyway-prod.conf migrate; then
    echo "✅ Migration completed successfully"
else
    echo "❌ Migration failed!"
    
    if [ "$ROLLBACK_ON_FAILURE" == "YES" ]; then
        echo "🔄 Rolling back migration..."
        flyway -configFiles=flyway-prod.conf undo
        echo "✅ Rollback completed"
    fi
    
    if [ "$MAINTENANCE_MODE" == "ON" ]; then
        curl -X POST https://api.example.com/admin/maintenance/disable
    fi
    
    exit 1
fi

# 6. Post-migration validation
echo "✅ Running post-migration checks..."
./scripts/post_migration_checks.sh || {
    echo "❌ Validation failed! Manual intervention required."
    exit 1
}

# 7. Smoke tests
echo "🧪 Running smoke tests..."
npm run test:smoke:production || {
    echo "⚠️  Smoke tests failed! Review before disabling maintenance mode."
    exit 1
}

# 8. Disable maintenance mode
if [ "$MAINTENANCE_MODE" == "ON" ]; then
    echo "✅ Disabling maintenance mode..."
    curl -X POST https://api.example.com/admin/maintenance/disable
fi

# 9. Monitor
echo "👀 Monitoring for 5 minutes..."
for i in {1..30}; do
    HEALTH=$(curl -s https://api.example.com/health | jq -r '.status')
    if [ "$HEALTH" != "healthy" ]; then
        echo "❌ Health check failed: $HEALTH"
        exit 1
    fi
    echo "✅ Health check $i/30: $HEALTH"
    sleep 10
done

echo "🎉 Production migration completed successfully!"
echo "📊 Review metrics: https://grafana.example.com/d/migrations"
echo "📝 Backup location: $BACKUP_FILE"
```

### Backup and Restore Procedures

**Backup Strategy**:
```bash
#!/bin/bash
# backup_database.sh

set -e

ENVIRONMENT=$1  # dev, staging, production
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/postgres"
RETENTION_DAYS=30

# Configuration per environment
case $ENVIRONMENT in
    production)
        DB_HOST="prod-db.example.com"
        DB_NAME="financeapp_prod"
        DB_USER="admin"
        ;;
    staging)
        DB_HOST="staging-db.example.com"
        DB_NAME="financeapp_staging"
        DB_USER="admin"
        ;;
    dev)
        DB_HOST="localhost"
        DB_NAME="financeapp_dev"
        DB_USER="financeuser"
        ;;
    *)
        echo "Usage: $0 [dev|staging|production]"
        exit 1
        ;;
esac

BACKUP_FILE="$BACKUP_DIR/${DB_NAME}_${TIMESTAMP}.sql.gz"

echo "📦 Creating backup for $ENVIRONMENT..."

# Full database dump with compression
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
    --verbose \
    --format=custom \
    --compress=9 \
    --file=$BACKUP_FILE

# Verify backup
if [ -f "$BACKUP_FILE" ]; then
    SIZE=$(du -h $BACKUP_FILE | cut -f1)
    echo "✅ Backup created: $BACKUP_FILE ($SIZE)"
else
    echo "❌ Backup failed"
    exit 1
fi

# Cleanup old backups
find $BACKUP_DIR -name "${DB_NAME}_*.sql.gz" -mtime +$RETENTION_DAYS -delete
echo "🧹 Cleaned up backups older than $RETENTION_DAYS days"

# Upload to S3 (optional)
if command -v aws &> /dev/null; then
    aws s3 cp $BACKUP_FILE s3://financeapp-backups/$ENVIRONMENT/
    echo "☁️  Uploaded to S3"
fi
```

**Restore Procedure**:
```bash
#!/bin/bash
# restore_database.sh

set -e

BACKUP_FILE=$1
TARGET_DB=$2

if [ -z "$BACKUP_FILE" ] || [ -z "$TARGET_DB" ]; then
    echo "Usage: $0 <backup_file> <target_database>"
    exit 1
fi

echo "⚠️  WARNING: This will DROP and recreate $TARGET_DB"
read -p "Type 'RESTORE' to continue: " confirmation

if [ "$confirmation" != "RESTORE" ]; then
    echo "❌ Restore cancelled"
    exit 1
fi

# Drop and recreate database
psql -h localhost -U postgres -c "DROP DATABASE IF EXISTS $TARGET_DB;"
psql -h localhost -U postgres -c "CREATE DATABASE $TARGET_DB;"

# Restore from backup
pg_restore -h localhost -U postgres -d $TARGET_DB --verbose $BACKUP_FILE

echo "✅ Restore completed: $TARGET_DB"
```

### Rollback Decision Criteria

**When to Rollback**:
```markdown
# Rollback Decision Matrix

## IMMEDIATE ROLLBACK (Critical)
- Migration fails to complete
- Data corruption detected
- Foreign key violations
- Application cannot start
- Critical functionality broken (login, payments)
- Data loss detected
- Security vulnerability introduced

## CONDITIONAL ROLLBACK (Assess Impact)
- Performance degradation >50%
- Non-critical features broken
- Increased error rates <5%
- User complaints <10% of active users

## MONITOR (Do Not Rollback)
- Minor performance issues
- Non-critical warnings
- Cosmetic issues
- Edge case bugs
```

**Rollback Execution**:
```bash
#!/bin/bash
# rollback_migration.sh

set -e

echo "=== ROLLBACK PROCEDURE ==="
echo "⚠️  This will undo the latest migration"

# 1. Verify rollback script exists
LATEST_VERSION=$(flyway info | grep "Pending\|Success" | tail -1 | awk '{print $2}')
ROLLBACK_SCRIPT="U${LATEST_VERSION}__*.sql"

if [ ! -f "migrations/$ROLLBACK_SCRIPT" ]; then
    echo "❌ Rollback script not found: $ROLLBACK_SCRIPT"
    exit 1
fi

# 2. Enable maintenance mode
echo "🚧 Enabling maintenance mode..."
curl -X POST https://api.example.com/admin/maintenance/enable

# 3. Create pre-rollback backup
echo "💾 Creating pre-rollback backup..."
BACKUP_FILE="backup_pre_rollback_$(date +%Y%m%d_%H%M%S).sql"
pg_dump -h prod-db.example.com -U admin -d financeapp_prod > $BACKUP_FILE

# 4. Execute rollback
echo "🔄 Executing rollback..."
flyway -configFiles=flyway-prod.conf undo

# 5. Verify rollback
echo "✅ Verifying rollback..."
flyway info

# 6. Run validation checks
echo "🔍 Running validation..."
./scripts/post_migration_checks.sh

# 7. Restart application
echo "🔄 Restarting application..."
kubectl rollout restart deployment/finance-app

# 8. Disable maintenance mode
echo "✅ Disabling maintenance mode..."
curl -X POST https://api.example.com/admin/maintenance/disable

echo "✅ Rollback completed successfully"
```

---

## 10. Migration Monitoring

### Migration Duration Tracking

**Monitoring Script**:
```sql
-- Create migration_metrics table
CREATE TABLE IF NOT EXISTS migration_metrics (
    id SERIAL PRIMARY KEY,
    migration_version VARCHAR(50) NOT NULL,
    migration_description TEXT,
    environment VARCHAR(20) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,
    success BOOLEAN,
    error_message TEXT,
    rows_affected INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Log migration start
INSERT INTO migration_metrics (migration_version, migration_description, environment, start_time)
VALUES ('1.5.0', 'Add MFA columns', 'production', NOW())
RETURNING id;

-- Log migration completion
UPDATE migration_metrics 
SET 
    end_time = NOW(),
    duration_ms = EXTRACT(EPOCH FROM (NOW() - start_time)) * 1000,
    success = TRUE,
    rows_affected = 150000
WHERE id = <migration_id>;

-- Query migration performance
SELECT 
    migration_version,
    migration_description,
    environment,
    duration_ms / 1000.0 as duration_seconds,
    rows_affected,
    success,
    created_at
FROM migration_metrics
ORDER BY created_at DESC
LIMIT 20;
```

### Lock Detection and Handling

**Lock Monitoring Query**:
```sql
-- Check for blocking locks during migration
SELECT 
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocked_activity.query AS blocked_statement,
    blocking_activity.query AS blocking_statement,
    blocked_activity.application_name AS blocked_application
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks 
    ON blocking_locks.locktype = blocked_locks.locktype
    AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
    AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
    AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
    AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
    AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
    AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
    AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
    AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
    AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
    AND blocking_locks.pid != blocked_locks.pid
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;

-- Kill blocking query if necessary (use with caution!)
-- SELECT pg_terminate_backend(<blocking_pid>);
```

**Lock Timeout Configuration**:
```sql
-- Set statement timeout for migration (prevent infinite locks)
SET statement_timeout = '30min';
SET lock_timeout = '5min';

-- Execute migration
-- ...

-- Reset timeouts
RESET statement_timeout;
RESET lock_timeout;
```

### Progress Reporting

**Progress Tracking for Large Migrations**:
```sql
-- Create progress tracking table
CREATE TABLE IF NOT EXISTS migration_progress (
    migration_version VARCHAR(50) NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    total_rows INTEGER,
    processed_rows INTEGER NOT NULL DEFAULT 0,
    progress_pct NUMERIC(5,2) GENERATED ALWAYS AS (
        CASE WHEN total_rows > 0 
        THEN (processed_rows::NUMERIC / total_rows::NUMERIC * 100) 
        ELSE 0 END
    ) STORED,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (migration_version, step_name)
);

-- Example: Track backfill progress
DO $$
DECLARE
    batch_size INTEGER := 10000;
    total INTEGER;
    processed INTEGER := 0;
BEGIN
    SELECT COUNT(*) INTO total FROM users WHERE new_field IS NULL;
    
    INSERT INTO migration_progress (migration_version, step_name, total_rows, processed_rows)
    VALUES ('2.1.0', 'backfill_new_field', total, 0);
    
    WHILE processed < total LOOP
        UPDATE users 
        SET new_field = compute_value(old_field)
        WHERE id IN (SELECT id FROM users WHERE new_field IS NULL LIMIT batch_size);
        
        processed := processed + batch_size;
        
        UPDATE migration_progress 
        SET processed_rows = processed, updated_at = NOW()
        WHERE migration_version = '2.1.0' AND step_name = 'backfill_new_field';
        
        COMMIT;
        PERFORM pg_sleep(0.1);
    END LOOP;
END $$;

-- Query progress
SELECT 
    migration_version,
    step_name,
    processed_rows || ' / ' || total_rows as progress,
    progress_pct || '%' as percentage,
    updated_at
FROM migration_progress
ORDER BY updated_at DESC;
```

### Error Handling and Recovery

**Error Logging**:
```sql
-- Create migration_errors table
CREATE TABLE IF NOT EXISTS migration_errors (
    id SERIAL PRIMARY KEY,
    migration_version VARCHAR(50) NOT NULL,
    error_code VARCHAR(10),
    error_message TEXT NOT NULL,
    error_detail TEXT,
    error_context TEXT,
    sql_statement TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Log error during migration
INSERT INTO migration_errors (
    migration_version, 
    error_code, 
    error_message, 
    error_detail, 
    sql_statement
)
VALUES (
    '1.5.0',
    '23505',
    'duplicate key value violates unique constraint "users_email_key"',
    'Key (email)=(test@example.com) already exists.',
    'INSERT INTO users (email, ...) VALUES (...)'
);
```

**Recovery Strategies**:
```sql
-- Check migration status
SELECT * FROM flyway_schema_history 
WHERE success = FALSE 
ORDER BY installed_rank DESC;

-- Repair failed migration (marks as successful without re-running)
-- USE WITH CAUTION
-- flyway repair

-- Manual recovery: Fix data issue, then re-run migration
-- 1. Identify and fix data issue
UPDATE users SET email = LOWER(email) WHERE email != LOWER(email);

-- 2. Delete failed migration record
DELETE FROM flyway_schema_history WHERE version = '1.5.0' AND success = FALSE;

-- 3. Re-run migration
-- flyway migrate
```

### Notification Requirements

**Notification Integration**:
```bash
#!/bin/bash
# notify.sh

MIGRATION_VERSION=$1
STATUS=$2  # started, success, failed
ENVIRONMENT=$3
MESSAGE=$4

# Slack notification
curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  -H 'Content-Type: application/json' \
  -d "{
    \"text\": \"🔧 Migration $STATUS\",
    \"attachments\": [{
      \"color\": \"$([ '$STATUS' = 'success' ] && echo 'good' || echo 'danger')\",
      \"fields\": [
        {\"title\": \"Version\", \"value\": \"$MIGRATION_VERSION\", \"short\": true},
        {\"title\": \"Environment\", \"value\": \"$ENVIRONMENT\", \"short\": true},
        {\"title\": \"Status\", \"value\": \"$STATUS\", \"short\": true},
        {\"title\": \"Time\", \"value\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"short\": true},
        {\"title\": \"Message\", \"value\": \"$MESSAGE\", \"short\": false}
      ]
    }]
  }"

# Email notification (optional)
if [ "$ENVIRONMENT" = "production" ]; then
    echo "$MESSAGE" | mail -s "Migration $STATUS: $MIGRATION_VERSION" ops-team@example.com
fi

# PagerDuty alert (for failures in production)
if [ "$STATUS" = "failed" ] && [ "$ENVIRONMENT" = "production" ]; then
    curl -X POST https://events.pagerduty.com/v2/enqueue \
      -H 'Content-Type: application/json' \
      -d "{
        \"routing_key\": \"YOUR_INTEGRATION_KEY\",
        \"event_action\": \"trigger\",
        \"payload\": {
          \"summary\": \"Production migration failed: $MIGRATION_VERSION\",
          \"severity\": \"critical\",
          \"source\": \"database-migrations\",
          \"custom_details\": {
            \"version\": \"$MIGRATION_VERSION\",
            \"environment\": \"$ENVIRONMENT\",
            \"message\": \"$MESSAGE\"
          }
        }
      }"
fi
```

**Integration in Migration Script**:
```bash
#!/bin/bash
# migrate_with_notifications.sh

MIGRATION_VERSION="1.5.0"
ENVIRONMENT="production"

# Notify start
./scripts/notify.sh "$MIGRATION_VERSION" "started" "$ENVIRONMENT" "Migration started"

# Run migration
if flyway -configFiles=flyway-prod.conf migrate; then
    ./scripts/notify.sh "$MIGRATION_VERSION" "success" "$ENVIRONMENT" "Migration completed successfully"
else
    ERROR_MSG=$(flyway info | tail -5)
    ./scripts/notify.sh "$MIGRATION_VERSION" "failed" "$ENVIRONMENT" "$ERROR_MSG"
    exit 1
fi
```

---

**End of Database Migrations Document**