# DATA MIGRATION PLAN

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Database
**Generated**: 2025-10-29T00:00:00Z

## Executive Summary

This data migration plan covers the implementation of a comprehensive user authentication and registration system for SUMA Finance, a fintech application requiring strict compliance with GDPR, PCI-DSS, SOC 2, and ISO 27001 standards. The migration involves creating new database schemas for user accounts, session management, two-factor authentication, consent tracking, security audit logs, and device management.

The migration follows a zero-downtime, phased approach using the expand-contract pattern to ensure continuous system availability. All personally identifiable information (PII) will be encrypted at rest using AES-256-GCM, and migrations will be executed in batches to minimize performance impact. The estimated migration timeline is 2 weeks from initial schema deployment to final cleanup.

Key migration objectives:
- Establish secure user authentication infrastructure with encrypted credential storage
- Implement session management with Redis integration for high-performance token validation
- Create comprehensive audit logging for all authentication events
- Enable GDPR-compliant consent tracking and data subject rights
- Support two-factor authentication and device management
- Ensure rollback capability at every migration phase

## Migration Strategy

### Zero-Downtime Migrations

**Blue-Green Deployment for Application Layer**
- Deploy new application version with dual-read capability (old and new schema)
- Route traffic gradually from blue (old) to green (new) environment
- Monitor error rates and performance metrics during transition
- Maintain ability to rollback to blue environment within 5 minutes

**Expand-Contract Pattern for Schema Changes**
1. **Expand**: Add new columns, tables, and indexes without removing old structures
2. **Migrate**: Deploy application code that writes to both old and new structures
3. **Backfill**: Populate new structures with historical data in batches
4. **Switch**: Deploy application code that reads from new structures only
5. **Contract**: Remove old structures after validation period (7 days minimum)

**Database Replication with Switch**
- Maintain read replica for validation and testing
- Use logical replication for testing data migration scripts
- Switch application to new schema using connection string update
- Keep old schema available for emergency rollback (72 hours)

### Phased Migration

#### **Phase 1: Schema Changes (Week 1, Days 1-3)**
**Objective**: Create all new tables, indexes, and constraints without affecting existing system

**Actions**:
- Create `users` table with encrypted columns for email, password hash
- Create `user_sessions` table for JWT refresh token storage
- Create `user_security_events` table for audit logging
- Create `user_2fa_settings` table for two-factor authentication
- Create `user_consents` table for GDPR compliance
- Create `user_devices` table for device management
- Create `password_reset_tokens` table for secure password recovery
- Create `email_verification_tokens` table for account activation
- Create all indexes concurrently to avoid locking
- Add database-level encryption key rotation trigger

**Validation**:
- Verify all tables created successfully
- Check index creation completion
- Test encryption/decryption functions
- Validate foreign key constraints
- Run performance benchmarks on empty tables

#### **Phase 2: Data Backfill (Week 1, Days 4-5)**
**Objective**: Migrate existing user data (if any) to new authentication schema

**Actions**:
- Backfill existing user records in batches of 1,000 rows
- Generate secure password hashes using Argon2id for test accounts
- Create initial audit log entries for existing users
- Set default consent values based on historical agreements
- Rate limit backfill operations to 100 rows/second
- Monitor database CPU and memory during backfill

**Validation**:
- Verify row count matches source data
- Check data integrity with checksums
- Validate all encrypted fields are properly encrypted
- Confirm no NULL values in required fields
- Test query performance on migrated data

#### **Phase 3: Application Deployment (Week 2, Days 1-3)**
**Objective**: Deploy authentication services that use new schema

**Actions**:
- Deploy registration endpoint with email verification
- Deploy login endpoint with JWT generation
- Deploy session management with Redis integration
- Deploy 2FA enrollment and verification endpoints
- Deploy password reset flow
- Deploy GDPR consent management endpoints
- Enable security event logging
- Configure rate limiting rules

**Validation**:
- Test all authentication flows end-to-end
- Verify JWT token generation and validation
- Check Redis session storage and retrieval
- Test email delivery for verification and OTP
- Validate audit log entries creation
- Perform load testing (1000 req/s target)
- Check error rates < 0.1%

#### **Phase 4: Cleanup Old Schema (Week 2, Days 4-5)**
**Objective**: Remove temporary structures and finalize migration

**Actions**:
- Drop temporary synchronization triggers
- Remove deprecated columns from legacy tables
- Archive old authentication data to cold storage
- Update database documentation
- Remove migration-specific monitoring alerts
- Final security audit of new schema

**Validation**:
- Verify no application errors after cleanup
- Check database size reduction
- Validate backup/restore procedures
- Confirm monitoring dashboards updated
- Review security scan results

## Migration Scripts

### Creating Core Users Table

```sql
-- Step 1: Create users table with encryption
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash TEXT NOT NULL, -- Argon2id hash
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone VARCHAR(20),
    phone_verified BOOLEAN NOT NULL DEFAULT FALSE,
    account_locked BOOLEAN NOT NULL DEFAULT FALSE,
    account_locked_until TIMESTAMPTZ,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    last_login_at TIMESTAMPTZ,
    last_login_ip INET,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    -- Encryption for PII
    encrypted_email BYTEA, -- AES-256-GCM encrypted
    encrypted_phone BYTEA,
    encryption_key_id VARCHAR(50) NOT NULL DEFAULT 'key-v1',
    
    -- Indexes
    CONSTRAINT users_email_length CHECK (char_length(email) >= 3),
    CONSTRAINT users_password_hash_length CHECK (char_length(password_hash) >= 50)
);

-- Create indexes concurrently (non-blocking)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_account_locked ON users(account_locked) WHERE account_locked = TRUE;

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create encryption function for email
CREATE OR REPLACE FUNCTION encrypt_user_email()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.email IS NOT NULL AND NEW.encrypted_email IS NULL THEN
        -- Use pgcrypto extension for AES-256-GCM
        NEW.encrypted_email = pgp_sym_encrypt(NEW.email, current_setting('app.encryption_key'));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_encrypt_user_email
    BEFORE INSERT OR UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION encrypt_user_email();
```

### Creating Session Management Tables

```sql
-- Step 2: Create user sessions table for JWT refresh tokens
CREATE TABLE IF NOT EXISTS user_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL UNIQUE, -- SHA-256 hash of refresh token
    access_token_jti UUID NOT NULL UNIQUE, -- JWT ID for access token
    device_id VARCHAR(255),
    device_fingerprint TEXT,
    user_agent TEXT,
    ip_address INET NOT NULL,
    country_code CHAR(2),
    city VARCHAR(100),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(255),
    
    CONSTRAINT session_expires_at_future CHECK (expires_at > created_at)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id) WHERE revoked = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_refresh_token ON user_sessions(refresh_token_hash) WHERE revoked = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_access_token_jti ON user_sessions(access_token_jti);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_device_id ON user_sessions(device_id) WHERE device_id IS NOT NULL;

-- Auto-cleanup expired sessions (daily job)
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM user_sessions
    WHERE expires_at < NOW() - INTERVAL '7 days'
      AND revoked = FALSE;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
```

### Creating Two-Factor Authentication Tables

```sql
-- Step 3: Create 2FA settings and OTP storage
CREATE TABLE IF NOT EXISTS user_2fa_settings (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    method VARCHAR(20) NOT NULL DEFAULT 'email', -- email, sms, totp, webauthn
    phone_number VARCHAR(20),
    backup_codes TEXT[], -- Array of hashed backup codes
    backup_codes_generated_at TIMESTAMPTZ,
    enabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT user_2fa_unique UNIQUE(user_id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_2fa_user_id ON user_2fa_settings(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_2fa_enabled ON user_2fa_settings(enabled) WHERE enabled = TRUE;

-- OTP codes table (short-lived, high-churn)
CREATE TABLE IF NOT EXISTS user_otp_codes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL, -- SHA-256 hash of 6-digit code
    purpose VARCHAR(50) NOT NULL, -- login, registration, password_reset
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET NOT NULL,
    
    CONSTRAINT otp_expires_at_future CHECK (expires_at > created_at)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_otp_user_id ON user_otp_codes(user_id) WHERE used = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_otp_expires_at ON user_otp_codes(expires_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_otp_code_hash ON user_otp_codes(code_hash) WHERE used = FALSE;

-- Auto-cleanup expired OTPs (hourly job)
CREATE OR REPLACE FUNCTION cleanup_expired_otps()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM user_otp_codes
    WHERE expires_at < NOW() - INTERVAL '1 hour';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
```

### Creating GDPR Consent Management Tables

```sql
-- Step 4: Create consent tracking for GDPR compliance
CREATE TABLE IF NOT EXISTS user_consents (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_type VARCHAR(50) NOT NULL, -- terms, privacy, marketing, analytics
    version VARCHAR(20) NOT NULL, -- e.g., "1.0", "2.1"
    granted BOOLEAN NOT NULL,
    consent_text TEXT, -- Full text of consent at time of acceptance
    consent_method VARCHAR(50), -- checkbox, explicit_button, implicit
    ip_address INET NOT NULL,
    user_agent TEXT,
    granted_at TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT consent_granted_at_check CHECK (
        (granted = TRUE AND granted_at IS NOT NULL) OR
        (granted = FALSE AND withdrawn_at IS NOT NULL)
    )
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_consents_user_id ON user_consents(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_consents_type ON user_consents(consent_type);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_consents_granted ON user_consents(granted) WHERE granted = TRUE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_consents_created_at ON user_consents(created_at);

-- Track data subject requests (GDPR Article 15-22)
CREATE TABLE IF NOT EXISTS data_subject_requests (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    request_type VARCHAR(50) NOT NULL, -- access, erasure, portability, rectification
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, in_progress, completed, rejected
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    response_data JSONB, -- Store response for access/portability requests
    notes TEXT,
    processed_by_admin_id BIGINT,
    
    CONSTRAINT dsr_status_check CHECK (status IN ('pending', 'in_progress', 'completed', 'rejected'))
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dsr_user_id ON data_subject_requests(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dsr_status ON data_subject_requests(status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dsr_requested_at ON data_subject_requests(requested_at);
```

### Creating Security Audit Log Tables

```sql
-- Step 5: Create comprehensive security event logging
CREATE TABLE IF NOT EXISTS user_security_events (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL, -- login_success, login_failed, password_changed, etc.
    event_category VARCHAR(50) NOT NULL, -- authentication, authorization, data_access, admin_action
    severity VARCHAR(20) NOT NULL DEFAULT 'info', -- info, warning, critical
    ip_address INET NOT NULL,
    user_agent TEXT,
    country_code CHAR(2),
    city VARCHAR(100),
    device_id VARCHAR(255),
    session_id BIGINT REFERENCES user_sessions(id) ON DELETE SET NULL,
    event_data JSONB, -- Additional context (failed_attempts, changed_fields, etc.)
    risk_score INT, -- 0-100 calculated risk score
    blocked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT severity_check CHECK (severity IN ('info', 'warning', 'critical'))
);

-- Partition by month for performance
CREATE TABLE user_security_events_2025_10 PARTITION OF user_security_events
    FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_user_id ON user_security_events(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_type ON user_security_events(event_type);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_created_at ON user_security_events(created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_severity ON user_security_events(severity) WHERE severity IN ('warning', 'critical');
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_ip ON user_security_events(ip_address);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_risk_score ON user_security_events(risk_score) WHERE risk_score > 50;

-- Function to log security events
CREATE OR REPLACE FUNCTION log_security_event(
    p_user_id BIGINT,
    p_event_type VARCHAR,
    p_event_category VARCHAR,
    p_severity VARCHAR,
    p_ip_address INET,
    p_event_data JSONB DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    event_id BIGINT;
BEGIN
    INSERT INTO user_security_events (
        user_id, event_type, event_category, severity, ip_address, event_data
    ) VALUES (
        p_user_id, p_event_type, p_event_category, p_severity, p_ip_address, p_event_data
    ) RETURNING id INTO event_id;
    
    RETURN event_id;
END;
$$ LANGUAGE plpgsql;
```

### Creating Device Management Tables

```sql
-- Step 6: Create device tracking and fingerprinting
CREATE TABLE IF NOT EXISTS user_devices (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255), -- User-provided name
    device_type VARCHAR(50), -- mobile, desktop, tablet
    os VARCHAR(100),
    browser VARCHAR(100),
    fingerprint_hash TEXT NOT NULL, -- Hash of device fingerprint
    trusted BOOLEAN NOT NULL DEFAULT FALSE,
    trusted_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_ip_address INET,
    last_country_code CHAR(2),
    push_token TEXT, -- For push notifications
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    
    CONSTRAINT user_device_unique UNIQUE(user_id, device_id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_devices_user_id ON user_devices(user_id) WHERE revoked = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_devices_device_id ON user_devices(device_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_devices_fingerprint ON user_devices(fingerprint_hash);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_devices_trusted ON user_devices(trusted) WHERE trusted = TRUE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_devices_last_seen ON user_devices(last_seen_at);
```

### Creating Password Reset and Email Verification Tables

```sql
-- Step 7: Create token tables for password reset and email verification
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE, -- HMAC-SHA256 signed token
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    ip_address INET NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT reset_token_expires_future CHECK (expires_at > created_at)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_reset_tokens_user_id ON password_reset_tokens(user_id) WHERE used = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_reset_tokens_hash ON password_reset_tokens(token_hash) WHERE used = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_reset_tokens_expires ON password_reset_tokens(expires_at);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_hash TEXT NOT NULL UNIQUE, -- HMAC-SHA256 signed token
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    ip_address INET NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT verify_token_expires_future CHECK (expires_at > created_at)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_verify_tokens_user_id ON email_verification_tokens(user_id) WHERE used = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_verify_tokens_hash ON email_verification_tokens(token_hash) WHERE used = FALSE;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_verify_tokens_expires ON email_verification_tokens(expires_at);

-- Auto-cleanup expired tokens (daily job)
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS TABLE(reset_deleted INT, verify_deleted INT) AS $$
DECLARE
    reset_count INT;
    verify_count INT;
BEGIN
    DELETE FROM password_reset_tokens
    WHERE expires_at < NOW() - INTERVAL '7 days';
    GET DIAGNOSTICS reset_count = ROW_COUNT;
    
    DELETE FROM email_verification_tokens
    WHERE expires_at < NOW() - INTERVAL '7 days';
    GET DIAGNOSTICS verify_count = ROW_COUNT;
    
    RETURN QUERY SELECT reset_count, verify_count;
END;
$$ LANGUAGE plpgsql;
```

### Data Backfill Script (If Migrating Existing Users)

```sql
-- Batch migration for existing user data
DO $$
DECLARE
    batch_size INTEGER := 1000;
    last_id BIGINT := 0;
    total_migrated INTEGER := 0;
    batch_count INTEGER := 0;
BEGIN
    LOOP
        -- Migrate users in batches
        WITH batch AS (
            SELECT id, email, created_at
            FROM legacy_users
            WHERE id > last_id
            ORDER BY id
            LIMIT batch_size
        )
        INSERT INTO users (
            email,
            email_verified,
            password_hash,
            created_at,
            encryption_key_id
        )
        SELECT
            email,
            TRUE, -- Assume existing users are verified
            '$argon2id$v=19$m=65536,t=3,p=4$PLACEHOLDER', -- Require password reset
            created_at,
            'key-v1'
        FROM batch
        ON CONFLICT (email) DO NOTHING
        RETURNING id INTO last_id;
        
        GET DIAGNOSTICS batch_count = ROW_COUNT;
        EXIT WHEN batch_count = 0;
        
        total_migrated := total_migrated + batch_count;
        
        -- Rate limiting: sleep 100ms between batches
        PERFORM pg_sleep(0.1);
        
        -- Log progress every 10,000 rows
        IF total_migrated % 10000 = 0 THEN
            RAISE NOTICE 'Migrated % users', total_migrated;
        END IF;
    END LOOP;
    
    RAISE NOTICE 'Total users migrated: %', total_migrated;
END $$;

-- Create initial security event for migrated users
INSERT INTO user_security_events (
    user_id,
    event_type,
    event_category,
    severity,
    ip_address,
    event_data
)
SELECT
    id,
    'account_migrated',
    'admin_action',
    'info',
    '127.0.0.1'::INET,
    jsonb_build_object('migration_date', NOW(), 'requires_password_reset', TRUE)
FROM users
WHERE created_at < NOW() - INTERVAL '1 day'
ON CONFLICT DO NOTHING;
```

## Rollback Plan

### Rollback Scripts

```sql
-- ROLLBACK SCRIPT - Execute only if migration fails

-- Step 1: Drop all new tables (cascades to dependent objects)
DROP TABLE IF EXISTS user_security_events CASCADE;
DROP TABLE IF EXISTS data_subject_requests CASCADE;
DROP TABLE IF EXISTS user_consents CASCADE;
DROP TABLE IF EXISTS user_otp_codes CASCADE;
DROP TABLE IF EXISTS user_2fa_settings CASCADE;
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS email_verification_tokens CASCADE;
DROP TABLE IF EXISTS user_devices CASCADE;
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Step 2: Drop functions
DROP FUNCTION IF EXISTS update_updated_at_column CASCADE;
DROP FUNCTION IF EXISTS encrypt_user_email CASCADE;
DROP FUNCTION IF EXISTS cleanup_expired_sessions CASCADE;
DROP FUNCTION IF EXISTS cleanup_expired_otps CASCADE;
DROP FUNCTION IF EXISTS cleanup_expired_tokens CASCADE;
DROP FUNCTION IF EXISTS log_security_event CASCADE;

-- Step 3: Drop indexes (if tables weren't dropped)
DROP INDEX IF EXISTS idx_users_email CASCADE;
DROP INDEX IF EXISTS idx_users_uuid CASCADE;
DROP INDEX IF EXISTS idx_sessions_user_id CASCADE;
DROP INDEX IF EXISTS idx_security_events_user_id CASCADE;

-- Step 4: Restore from backup (execute on backup server)
-- pg_restore -h localhost -U financeuser -d financeapp -v /backups/pre_migration_backup.dump

-- Step 5: Verify rollback
SELECT 'Rollback completed at: ' || NOW();
SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'user%';
```

### Rollback Decision Matrix

| Time Since Migration | Data Impact | Action | Approval Required | Execution Time |
|---------------------|-------------|---------|-------------------|----------------|
| < 1 hour | Minimal | Immediate rollback via SQL script | Engineering Lead | 5-10 minutes |
| 1-4 hours | Low | Rollback after impact assessment | Engineering Lead + Product Owner | 15-30 minutes |
| 4-24 hours | Medium | Evaluate rollback vs forward fix | CTO + Product Owner | 30-60 minutes |
| 1-3 days | High | Forward fix preferred, rollback only for critical issues | CTO + Incident Response Team | 1-2 hours |
| > 3 days | Very High | Forward fix only, rollback not recommended | Executive Team | N/A |

### Rollback Triggers

Execute rollback if any of the following occur:

**Critical (Immediate Rollback)**:
- Database corruption detected
- Data loss exceeds 0.1% of records
- Authentication system completely unavailable (> 5 minutes)
- Security breach detected during migration
- Encryption keys compromised

**High Priority (Rollback within 1 hour)**:
- Error rate > 5% on authentication endpoints
- Login success rate drops below 90%
- Performance degradation > 500ms response time
- Redis session storage failures > 10%
- Email delivery failures > 20%

**Medium Priority (Evaluate, possibly forward fix)**:
- Error rate 1-5% on authentication endpoints
- Performance degradation 200-500ms response time
- Minor data inconsistencies affecting < 1% of users
- Non-critical feature failures (2FA, device management)

### Rollback Validation Checklist

After executing rollback:

- [ ] Verify all new tables dropped successfully
- [ ] Confirm application can connect to database
- [ ] Test legacy authentication endpoints
- [ ] Verify no foreign key constraint errors
- [ ] Check application logs for errors
- [ ] Test user login functionality
- [ ] Verify session management working
- [ ] Monitor error rates (should be < 0.5%)
- [ ] Check database replication lag
- [ ] Notify stakeholders of rollback completion
- [ ] Schedule post-mortem meeting
- [ ] Document rollback reason and lessons learned

## Testing Strategy

### Pre-Migration Testing

#### **Test Environment Setup**
1. Create exact replica of production database structure
2. Load anonymized production data (last 30 days)
3. Configure staging environment with production-equivalent resources
4. Set up monitoring dashboards (Datadog, Sentry)
5. Install Redis cluster for session testing

#### **Migration Dry Run (3 iterations minimum)**

```sql
-- Test script for dry run
BEGIN;

-- Execute all migration scripts
\i migration_001_create_users_table.sql
\i migration_002_create_sessions_table.sql
\i migration_003_create_2fa_tables.sql
\i migration_004_create_consent_tables.sql
\i migration_005_create_security_events_table.sql
\i migration_006_create_device_tables.sql
\i migration_007_create_token_tables.sql

-- Measure migration duration
SELECT NOW() AS migration_start;

-- Run backfill script (if applicable)
\i migration_008_backfill_data.sql

SELECT NOW() AS migration_end;

-- Run validation queries
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM user_sessions;
SELECT COUNT(*) FROM user_security_events;

-- Check for constraint violations
SELECT conname, conrelid::regclass
FROM pg_constraint
WHERE contype = 'f' AND convalidated = FALSE;

ROLLBACK; -- Don't commit during dry run
```

**Expected Dry Run Results**:
- Total migration time: < 30 minutes (empty database)
- Backfill time: ~10 seconds per 1,000 records
- Zero constraint violations
- All indexes created successfully
- All triggers functioning correctly

#### **Data Integrity Verification**

```sql
-- Pre-migration checksum
CREATE TEMP TABLE pre_migration_checksums AS
SELECT
    'legacy_users' AS table_name,
    COUNT(*) AS row_count,
    MD5(STRING_AGG(email, ',' ORDER BY id)) AS checksum
FROM legacy_users
WHERE deleted_at IS NULL;

-- Post-migration checksum comparison
SELECT
    'users' AS table_name,
    COUNT(*) AS row_count,
    MD5(STRING_AGG(email, ',' ORDER BY id)) AS checksum
FROM users
WHERE deleted_at IS NULL;

-- Compare results
SELECT
    pre.table_name,
    pre.row_count AS pre_count,
    post.row_count AS post_count,
    CASE WHEN pre.checksum = post.checksum THEN 'PASS' ELSE 'FAIL' END AS integrity_check
FROM pre_migration_checksums pre
JOIN post_migration_checksums post ON pre.table_name = post.table_name;
```

#### **Performance Baseline Testing**

```bash
# Load testing with k6
k6 run --vus 100 --duration 60s auth_load_test.js

# Expected results:
# - Registration endpoint: < 200ms p95
# - Login endpoint: < 200ms p95
# - Token refresh: < 100ms p95
# - Session lookup: < 10ms p95
# - Throughput: > 1000 req/s
```

### Post-Migration Validation

#### **Immediate Validation (Within 5 minutes of migration)**

```sql
-- Row count verification
SELECT 'users' AS table_name, COUNT(*) AS row_count FROM users
UNION ALL
SELECT 'user_sessions', COUNT(*) FROM user_sessions
UNION ALL
SELECT 'user_security_events', COUNT(*) FROM user_security_events
UNION ALL
SELECT 'user_consents', COUNT(*) FROM user_consents
UNION ALL
SELECT 'user_2fa_settings', COUNT(*) FROM user_2fa_settings;

-- Check for NULL values in required fields
SELECT
    'users' AS table_name,
    COUNT(*) FILTER (WHERE email IS NULL) AS null_emails,
    COUNT(*) FILTER (WHERE password_hash IS NULL) AS null_passwords,
    COUNT(*) FILTER (WHERE encryption_key_id IS NULL) AS null_keys
FROM users;

-- Verify foreign key relationships
SELECT
    conname AS constraint_name,
    conrelid::regclass AS table_name,
    confrelid::regclass AS referenced_table,
    convalidated AS is_valid
FROM pg_constraint
WHERE contype = 'f' AND connamespace = 'public'::regnamespace
ORDER BY conrelid::regclass::text;

-- Check index creation status
SELECT
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE schemaname = 'public' AND tablename LIKE 'user%'
ORDER BY tablename, indexname;

-- Verify encryption is working
SELECT
    id,
    email,
    encryption_key_id,
    encrypted_email IS NOT NULL AS email_encrypted,
    LENGTH(encrypted_email) AS encrypted_length
FROM users
LIMIT 10;
```

#### **Application Smoke Tests (Within 15 minutes)**

```bash
# Test registration flow
curl -X POST https://api.suma-finance.com/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecureP@ssw0rd123!",
    "firstName": "Test",
    "lastName": "User",
    "consents": {
      "terms": true,
      "privacy": true,
      "marketing": false
    }
  }'

# Test login flow
curl -X POST https://api.suma-finance.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecureP@ssw0rd123!"
  }'

# Test token refresh
curl -X POST https://api.suma-finance.com/v1/auth/refresh \
  -H "Authorization: Bearer <refresh_token>"

# Test 2FA enrollment
curl -X POST https://api.suma-finance.com/v1/auth/2fa/enable \
  -H "Authorization: Bearer <access_token>" \
  -d '{"method": "email"}'

# Test password reset request
curl -X POST https://api.suma-finance.com/v1/auth/password-reset/request \
  -d '{"email": "test@example.com"}'
```

#### **Comprehensive Validation (Within 1 hour)**

```sql
-- Data consistency checks
SELECT
    u.id,
    u.email,
    COUNT(DISTINCT s.id) AS active_sessions,
    COUNT(DISTINCT se.id) AS security_events,
    COUNT(DISTINCT c.id) AS consents,
    tfa.enabled AS tfa_enabled
FROM users u
LEFT JOIN user_sessions s ON u.id = s.user_id AND s.revoked = FALSE
LEFT JOIN user_security_events se ON u.id = se.user_id
LEFT JOIN user_consents c ON u.id = c.user_id
LEFT JOIN user_2fa_settings tfa ON u.id = tfa.user_id
WHERE u.deleted_at IS NULL
GROUP BY u.id, u.email, tfa.enabled
HAVING COUNT(DISTINCT c.id) < 2 -- Should have at least 2 consents (terms, privacy)
LIMIT 100;

-- Session integrity check
SELECT
    s.user_id,
    u.email,
    s.refresh_token_hash,
    s.expires_at,
    s.last_used_at,
    CASE
        WHEN s.expires_at < NOW() THEN 'EXPIRED'
        WHEN s.revoked = TRUE THEN 'REVOKED'
        ELSE 'ACTIVE'
    END AS status
FROM user_sessions s
JOIN users u ON s.user_id = u.id
WHERE s.created_at > NOW() - INTERVAL '1 hour'
ORDER BY s.created_at DESC
LIMIT 100;

-- Security event analysis
SELECT
    event_type,
    event_category,
    severity,
    COUNT(*) AS event_count,
    COUNT(DISTINCT user_id) AS affected_users
FROM user_security_events
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY event_type, event_category, severity
ORDER BY event_count DESC;

-- GDPR consent compliance check
SELECT
    u.id,
    u.email,
    BOOL_AND(c.granted) FILTER (WHERE c.consent_type = 'terms') AS terms_granted,
    BOOL_AND(c.granted) FILTER (WHERE c.consent_type = 'privacy') AS privacy_granted,
    MAX(c.granted_at) FILTER (WHERE c.consent_type = 'terms') AS terms_date,
    MAX(c.granted_at) FILTER (WHERE c.consent_type = 'privacy') AS privacy_date
FROM users u
LEFT JOIN user_consents c ON u.id = c.user_id
WHERE u.created_at > NOW() - INTERVAL '1 hour'
GROUP BY u.id, u.email
HAVING BOOL_AND(c.granted) FILTER (WHERE c.consent_type = 'terms') = FALSE
    OR BOOL_AND(c.granted) FILTER (WHERE c.consent_type = 'privacy') = FALSE;
```

#### **Performance Validation**

```sql
-- Query performance benchmarks
EXPLAIN ANALYZE
SELECT * FROM users WHERE email = 'test@example.com';
-- Expected: Index Scan, execution time < 5ms

EXPLAIN ANALYZE
SELECT * FROM user_sessions WHERE refresh_token_hash = 'abc123' AND revoked = FALSE;
-- Expected: Index Scan, execution time < 5ms

EXPLAIN ANALYZE
SELECT * FROM user_security_events WHERE user_id = 1 ORDER BY created_at DESC LIMIT 20;
-- Expected: Index Scan, execution time < 10ms

-- Connection pool status
SELECT
    datname,
    numbackends AS active_connections,
    xact_commit,
    xact_rollback,
    blks_read,
    blks_hit,
    ROUND(100.0 * blks_hit / NULLIF(blks_hit + blks_read, 0), 2) AS cache_hit_ratio
FROM pg_stat_database
WHERE datname = 'financeapp';
-- Expected cache hit ratio: > 95%
```

### Monitoring and Alerting

#### **Datadog Monitors**

1. **High Error Rate**: Alert if authentication endpoint error rate > 1% for 5 minutes
2. **Slow Response Time**: Alert if p95 latency > 300ms for 10 minutes
3. **Database Connection Pool**: Alert if active connections > 80% of max pool size
4. **Failed Login Attempts**: Alert if failed login rate increases by 50% over baseline
5. **Session Creation Failures**: Alert if Redis connection errors > 5 per minute
6. **OTP Delivery Failures**: Alert if email/SMS delivery failure rate > 10%
7. **Account Lockouts**: Alert if account lockouts increase by 100% over baseline
8. **Data Integrity**: Alert if new user registrations drop to 0 for 15 minutes

#### **Log Monitoring Queries**

```sql
-- Monitor failed login attempts
SELECT
    DATE_TRUNC('minute', created_at) AS minute,
    COUNT(*) AS failed_attempts,
    COUNT(DISTINCT user_id) AS affected_users,
    COUNT(DISTINCT ip_address) AS unique_ips
FROM user_security_events
WHERE event_type = 'login_failed'
  AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY DATE_TRUNC('minute', created_at)
ORDER BY minute DESC;

-- Monitor account lockouts
SELECT
    u.id,
    u.email,
    u.account_locked_until,
    u.failed_login_attempts,
    se.ip_address,
    se.created_at AS last_attempt
FROM users u
JOIN user_security_events se ON u.id = se.user_id
WHERE u.account_locked = TRUE
  AND u.account_locked_until > NOW()
ORDER BY se.created_at DESC;

-- Monitor suspicious activities
SELECT
    user_id,
    event_type,
    COUNT(*) AS event_count,
    COUNT(DISTINCT ip_address) AS unique_ips,
    MAX(risk_score) AS max_risk_score
FROM user_security_events
WHERE created_at > NOW() - INTERVAL '1 hour'
  AND risk_score > 50
GROUP BY user_id, event_type
HAVING COUNT(*) > 10
ORDER BY max_risk_score DESC;
```

## Migration Timeline

### **Week 1: Preparation Phase**

#### **Day 1 (Monday): Environment Setup**
- **Morning**:
  - Create staging environment replica of production
  - Load anonymized production data
  - Set up monitoring dashboards (Datadog, Sentry)
  - Configure Redis cluster for session storage
  - Install PostgreSQL extensions (pgcrypto, pg_stat_statements)

- **Afternoon**:
  - Review migration scripts with engineering team
  - Set up backup procedures (automated snapshots every 6 hours)
  - Configure rollback scripts and test restoration
  - Create migration runbook document
  - Schedule stakeholder communication

**Deliverables**: Staging environment ready, monitoring configured, runbook complete

#### **Day 2 (Tuesday): Dry Run #1**
- **Morning**:
  - Execute full migration on staging
  - Measure migration duration and resource usage
  - Validate data integrity checksums
  - Test application deployment with new schema

- **Afternoon**:
  - Run automated test suite (unit, integration, E2E)
  - Perform manual smoke tests on critical flows
  - Execute rollback procedure
  - Document issues and optimization opportunities

**Deliverables**: First dry run complete, issues documented, optimizations identified

#### **Day 3 (Wednesday): Script Optimization**
- **Morning**:
  - Optimize slow migration scripts (add batching, improve indexes)
  - Implement concurrent index creation
  - Add progress logging for long-running operations
  - Optimize backfill queries

- **Afternoon**:
  - Dry Run #2 with optimized scripts
  - Validate performance improvements
  - Test edge cases (large datasets, concurrent operations)
  - Update monitoring queries

**Deliverables**: Optimized migration scripts, dry run #2 complete

#### **Day 4 (Thursday): Security and Compliance Review**
- **Morning**:
  - Security team review of encryption implementation
  - GDPR compliance validation (consent tracking, data subject rights)
  - PCI-DSS compliance check (credential storage, key management)
  - Penetration testing of authentication endpoints

- **Afternoon**:
  - Address security findings
  - Update security documentation
  - Dry Run #3 with security fixes
  - Final validation of rollback procedures

**Deliverables**: Security review complete, compliance validated, dry run #3 complete

#### **Day 5 (Friday): Final Preparation**
- **Morning**:
  - Load testing with production-equivalent traffic (k6, locust)
  - Chaos engineering tests (database failover, Redis failure)
  - Validate monitoring alerts trigger correctly
  - Review migration checklist with stakeholders

- **Afternoon**:
  - Final team walkthrough of migration plan
  - Prepare communication templates (email, Slack, status page)
  - Schedule production migration for following week
  - Ensure on-call engineers available during migration window

**Deliverables**: Load testing complete, team trained, production migration scheduled

### **Week 2: Execution Phase**

#### **Day 1 (Monday): Production Migration - Phase 1**
**Maintenance Window: 02:00 - 06:00 UTC (Low traffic period)**

- **01:30 UTC**: Final go/no-go decision meeting
- **01:45 UTC**: Send customer notification (maintenance mode starting)
- **02:00 UTC**: Enable maintenance mode, stop write traffic
- **02:05 UTC**: Create final production backup (full database dump)
- **02:15 UTC**: Begin Phase 1 - Schema creation
  - Execute all CREATE TABLE statements
  - Execute all CREATE INDEX CONCURRENTLY statements
  - Deploy encryption functions and triggers
  - Validate all objects created successfully

- **03:00 UTC**: Phase 1 validation checkpoint
  - Run validation queries
  - Check constraint creation
  - Verify index status
  - Confirm encryption working

- **03:15 UTC**: Begin Phase 2 - Data backfill (if applicable)
  - Execute batched migration of existing users
  - Monitor progress every 1,000 rows
  - Validate data integrity checksums

- **04:00 UTC**: Phase 2 validation checkpoint
  - Verify row counts match
  - Check foreign key relationships
  - Validate encrypted data

- **04:15 UTC**: Deploy application with new authentication system
  - Blue-green deployment to staging environment first
  - Smoke tests on staging
  - Deploy to production

- **05:00 UTC**: Application validation
  - Test registration, login, 2FA flows
  - Verify Redis session storage
  - Check email delivery
  - Monitor error rates

- **05:30 UTC**: Disable maintenance mode, enable traffic
- **05:45 UTC**: Send customer notification (system operational)
- **06:00 UTC**: Migration complete, begin monitoring period

**Deliverables**: Schema deployed, application live, initial validation passed

#### **Day 2-3 (Tuesday-Wednesday): Monitoring and Validation**
- **Continuous Monitoring**:
  - Watch error rates every 5 minutes (target: < 0.5%)
  - Monitor response times every 5 minutes (target: < 200ms p95)
  - Check Redis connection pool health
  - Review security event logs for anomalies
  - Track user registration and login success rates

- **Daily Validation**:
  - Run comprehensive data integrity checks
  - Review Datadog/Sentry alerts
  - Analyze slow query logs
  - Check database replication lag
  - Validate GDPR consent tracking

- **User Feedback**:
  - Monitor support tickets for authentication issues
  - Review customer feedback channels
  - Address any reported bugs immediately
  - Update FAQ documentation

**Deliverables**: Stable system for 48 hours, no critical issues

#### **Day 4 (Thursday): Phase 3 - Optimization**
- **Morning**:
  - Analyze slow queries and optimize indexes
  - Adjust connection pool settings based on actual usage
  - Tune Redis cache TTL values
  - Optimize security event logging (reduce noise)

- **Afternoon**:
  - Deploy optimization changes to staging first
  - Validate improvements with load testing
  - Deploy optimizations to production during low-traffic window
  - Monitor for regressions

**Deliverables**: Performance optimizations deployed, validated

#### **Day 5 (Friday): Phase 4 - Cleanup and Documentation**
- **Morning**:
  - Remove temporary migration tables/functions
  - Drop old/deprecated columns (if any)
  - Archive migration scripts to version control
  - Update database schema documentation

- **Afternoon**:
  - Final security audit of production system
  - Review monitoring dashboard configuration
  - Schedule post-migration retrospective
  - Update runbooks and incident response procedures
  - Celebrate successful migration! 🎉

**Deliverables**: Migration fully complete, documentation updated, retrospective scheduled

### **Post-Migration: Ongoing Maintenance**

#### **Week 3-4: Extended Monitoring**
- Daily review of authentication metrics
- Weekly security audit log analysis
- Bi-weekly performance optimization review
- Collect user feedback and iterate

#### **Month 2-3: Feature Enhancements**
- Implement additional 2FA methods (SMS, TOTP, WebAuthn)
- Add social login support (OAuth 2.0)
- Enhance device management features
- Implement passwordless authentication (magic links)

## Best Practices

### **DO: Essential Migration Practices**

✅ **Always Test on Production-Like Data**
- Use anonymized production data for staging tests
- Ensure data volume matches production (minimum 80% scale)
- Include edge cases (null values, special characters, max lengths)
- Test with concurrent users (simulate production load)

✅ **Use Transactions for Atomicity**
```sql
BEGIN;
-- All migration steps
ALTER TABLE users ADD COLUMN new_field VARCHAR(255);
UPDATE users SET new_field = old_field;
ALTER TABLE users DROP COLUMN old_field;
COMMIT; -- Only commit if all steps succeed
```

✅ **Batch Large Operations**
- Process 1,000-5,000 rows per batch
- Add sleep delays between batches (100-500ms)
- Log progress every N batches
- Monitor database load during execution
- Use cursor-based pagination for large datasets

✅ **Monitor Progress Continuously**
- Real-time dashboard for migration status
- Alert on unexpected slow queries (> 1 second)
- Track row counts and validation checksums
- Monitor database CPU, memory, and I/O
- Set up automatic rollback triggers for critical failures

✅ **Have Rollback Plan Ready**
- Test rollback procedure before migration
- Document rollback decision matrix
- Keep database backup accessible (< 5 minute restore time)
- Prepare communication templates for rollback scenario
- Assign clear roles for rollback execution

### **DON'T: Migration Anti-Patterns**

❌ **Don't Run Migrations During Peak Hours**
- Avoid 09:00-17:00 weekdays in primary user timezone
- Schedule migrations during lowest traffic periods
- Consider time zones for global user base
- Allow 4-6 hour maintenance window (2x estimated time)

❌ **Don't Skip Testing Phase**
- Never deploy untested migration scripts to production
- Perform minimum 3 dry runs on staging
- Test rollback procedure at least once
- Validate application functionality after each dry run
- Include security testing in migration validation

❌ **Don't Migrate Without Backups**
- Create backup immediately before migration (< 30 minutes old)
- Verify backup integrity (test restore on separate instance)
- Keep backups for minimum 30 days post-migration
- Store backups in multiple locations (local + cloud)
- Document backup restoration procedure

❌ **Don't Ignore Errors**
- Treat all errors as critical until proven otherwise
- Halt migration on first validation failure
- Investigate warnings before proceeding
- Never use `ON ERROR CONTINUE` in production migrations
- Log all errors with full context (query, timestamp, affected rows)

❌ **Don't Make Irreversible Changes Without Validation**
- Never drop tables/columns without backup
- Keep old schema for 7 days minimum after migration
- Use feature flags to toggle between old/new code paths
- Implement soft deletes instead of hard deletes during transition
- Validate data integrity before committing destructive changes

### **Additional Best Practices**

✅ **Database Connection Management**
- Use connection pooling (max 20-50 connections)
- Set statement timeout (30-60 seconds for migrations)
- Configure idle transaction timeout (5 minutes)
- Monitor active connections during migration

✅ **Index Creation Strategy**
- Always use `CREATE INDEX CONCURRENTLY` in production
- Create indexes during low-traffic periods
- Monitor index creation progress (pg_stat_progress_create_index)
- Validate index usage after creation (pg_stat_user_indexes)

✅ **Encryption Best Practices**
- Use hardware security modules (HSM) for key storage
- Implement key rotation policy (90-day cycle)
- Encrypt keys at rest with master key
- Log all key access for audit trail
- Test decryption performance before production

✅ **Compliance Documentation**
- Maintain data flow diagrams for GDPR compliance
- Document all PII fields and encryption methods
- Create audit trail for all data access
- Prepare Data Protection Impact Assessment (DPIA)
- Keep records of processing activities (ROPA)

## Appendix

### **Migration Checklist**

#### **Pre-Migration (1 week before)**
- [ ] Staging environment configured and tested
- [ ] Anonymized production data loaded to staging
- [ ] 3 successful dry runs completed
- [ ] Migration scripts reviewed by 2+ engineers
- [ ] Rollback scripts tested successfully
- [ ] Backup procedures documented and tested
- [ ] Monitoring dashboards configured
- [ ] Alerting rules created and validated
- [ ] Load testing completed (1000+ req/s)
- [ ] Security review passed
- [ ] GDPR compliance validated
- [ ] Migration runbook finalized
- [ ] Stakeholder communication prepared
- [ ] Maintenance window scheduled
- [ ] On-call engineers assigned
- [ ] Go/no-go criteria defined

#### **Migration Day**
- [ ] Final go/no-go decision made
- [ ] Customer notification sent (maintenance mode)
- [ ] Production backup created and verified
- [ ] Maintenance mode enabled
- [ ] Phase 1: Schema creation executed
- [ ] Phase 1: Validation passed
- [ ] Phase 2: Data backfill executed (if applicable)
- [ ] Phase 2: Validation passed
- [ ] Application deployed with new authentication system
- [ ] Smoke tests passed (registration, login, 2FA)
- [ ] Redis session storage validated
- [ ] Email delivery tested
- [ ] Error rate < 0.5%
- [ ] Response time < 200ms p95
- [ ] Maintenance mode disabled
- [ ] Customer notification sent (system operational)
- [ ] Monitoring dashboards reviewed

#### **Post-Migration (48 hours)**
- [ ] Continuous monitoring for 48 hours
- [ ] No critical issues detected
- [ ] Error rate stable (< 0.5%)
- [ ] Performance metrics within targets
- [ ] Data integrity validated daily
- [ ] Security event logs reviewed
- [ ] User feedback monitored
- [ ] Support tickets reviewed
- [ ] Database optimization applied (if needed)
- [ ] Documentation updated
- [ ] Retrospective scheduled

#### **Final Cleanup (1 week after)**
- [ ] Temporary structures removed
- [ ] Old schema archived
- [ ] Migration scripts versioned
- [ ] Runbooks updated
- [ ] Security audit completed
- [ ] Compliance report generated
- [ ] Stakeholder report delivered
- [ ] Retrospective completed
- [ ] Lessons learned documented
- [ ] Celebration organized! 🎉

### **Glossary**

**Argon2id**: Memory-hard password hashing algorithm resistant to GPU-based attacks, recommended by OWASP for credential storage.

**Blue-Green Deployment**: Deployment strategy with two identical environments (blue and old, green is new), allowing instant rollback by switching traffic.

**CQRS (Command Query Responsibility Segregation)**: Pattern separating read and write operations, useful for audit logging and event sourcing.

**Expand-Contract Pattern**: Schema migration strategy adding new structures (expand) before removing old ones (contract), enabling zero-downtime deployments.

**GDPR (General Data Protection Regulation)**: EU regulation (2016/679) governing data protection and privacy for individuals in the European Union.

**HMAC-SHA256**: Hash-based Message Authentication Code using SHA-256, providing data integrity and authenticity verification.

**JWT (JSON Web Token)**: Compact, URL-safe token format for securely transmitting information between parties as a JSON object.

**OTP (One-Time Password)**: Password valid for single login session or transaction, commonly used for two-factor authentication.

**OWASP Top 10**: List of the most critical security risks to web applications, maintained by the Open Web Application Security Project.

**PCI-DSS (Payment Card Industry Data Security Standard)**: Security standard for organizations handling credit card information.

**PKCE (Proof Key for Code Exchange)**: Extension to OAuth 2.0 authorization code flow, preventing interception attacks in mobile/single-page applications.

**Redis**: In-memory data structure store used for caching, session storage, and message brokering.

**SOC 2 (System and Organization Controls 2)**: Audit framework for service organizations storing customer data in the cloud.

**TLS 1.3 (Transport Layer Security)**: Latest version of cryptographic protocol providing secure communication over computer networks.

**WebAuthn**: Web standard for passwordless authentication using public key cryptography, supporting biometrics and security keys.

**Zero-Downtime Migration**: Database migration technique allowing system to remain operational during schema changes, using strategies like blue-green deployment and expand-contract pattern.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Author**: SUMA Finance Engineering Team
**Approval**: Pending CTO Review