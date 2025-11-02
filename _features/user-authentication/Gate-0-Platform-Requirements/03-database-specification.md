

# Database Specification: Secure Authentication System

## 1. Database Architecture Overview

### Database Choice: PostgreSQL 15+
**Justification:**
- Native UUID support for secure, non-sequential identifiers
- JSONB for flexible audit metadata storage
- Row-Level Security (RLS) for multi-tenant isolation
- Robust transaction support for authentication flows
- Advanced indexing (GIN, partial indexes) for performance
- Strong compliance track record (GDPR, SOC 2, PCI-DSS)
- Encryption at rest support with transparent data encryption

### Configuration
- **Version:** PostgreSQL 15.x (minimum)
- **Connection Pool:** PgBouncer (transaction mode, 100-200 connections)
- **Max Connections:** 200 (application tier)
- **Shared Buffers:** 25% of RAM
- **Effective Cache Size:** 75% of RAM
- **Work Mem:** 16MB per operation
- **Maintenance Work Mem:** 512MB

### High Availability Setup
- **Primary-Replica:** 1 primary + 2 replicas (synchronous replication to 1 replica)
- **Failover:** Automatic with Patroni + etcd
- **Load Balancing:** pgpool-II for read distribution
- **Geographic Distribution:** Multi-region replicas (EU, US)

### Backup Strategy
- **Continuous Archiving:** WAL archiving to S3 every 5 minutes
- **Base Backups:** Daily full backups at 2 AM UTC
- **Retention:** 30 days for daily backups, 90 days for WAL archives
- **Backup Encryption:** AES-256-GCM
- **Testing:** Monthly restore validation

## 2. Schema Design

### Users Table

```sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    email_encrypted BYTEA NOT NULL, -- Encrypted with AES-256-GCM
    password_hash VARCHAR(255) NOT NULL, -- Argon2id output
    email_verified BOOLEAN DEFAULT FALSE NOT NULL,
    email_verified_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL,
    mfa_secret_encrypted BYTEA, -- Encrypted TOTP secret
    account_locked_until TIMESTAMPTZ,
    failed_login_attempts INTEGER DEFAULT 0 NOT NULL,
    last_login_at TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMPTZ, -- Soft delete for GDPR compliance

    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'),
    CONSTRAINT email_length CHECK (char_length(email) >= 5 AND char_length(email) <= 255),
    CONSTRAINT failed_attempts_positive CHECK (failed_login_attempts >= 0)
);

-- Indexes
CREATE UNIQUE INDEX idx_users_email_active ON users(LOWER(email)) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email_verified ON users(email_verified) WHERE email_verified = FALSE;
CREATE INDEX idx_users_account_locked ON users(account_locked_until) WHERE account_locked_until IS NOT NULL;
CREATE INDEX idx_users_created_at ON users(created_at DESC);
CREATE INDEX idx_users_last_login ON users(last_login_at DESC) WHERE deleted_at IS NULL;

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row-Level Security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_isolation_policy ON users
    USING (deleted_at IS NULL);
```

### User Consents Table

```sql
CREATE TABLE user_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    consent_type VARCHAR(50) NOT NULL, -- 'terms', 'privacy', 'marketing'
    consented BOOLEAN NOT NULL,
    consented_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    withdrawn_at TIMESTAMPTZ,
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    consent_version VARCHAR(50) NOT NULL, -- Track policy version
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT fk_user_consents_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT valid_consent_type CHECK (consent_type IN ('terms', 'privacy', 'marketing')),
    CONSTRAINT withdrawn_after_consent CHECK (withdrawn_at IS NULL OR withdrawn_at >= consented_at)
);

-- Indexes
CREATE INDEX idx_user_consents_user_id ON user_consents(user_id);
CREATE INDEX idx_user_consents_type ON user_consents(user_id, consent_type);
CREATE INDEX idx_user_consents_created ON user_consents(created_at DESC);
CREATE INDEX idx_user_consents_active ON user_consents(user_id, consent_type, consented) 
    WHERE consented = TRUE AND withdrawn_at IS NULL;
```

### Refresh Tokens Table

```sql
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hash
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoke_reason VARCHAR(100), -- 'user_logout', 'admin_revoke', 'reuse_detected', 'expired'
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT expires_after_creation CHECK (expires_at > created_at),
    CONSTRAINT revoked_after_creation CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

-- Indexes
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE UNIQUE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_device ON refresh_tokens(user_id, device_id);
CREATE INDEX idx_refresh_tokens_active ON refresh_tokens(user_id, revoked_at, expires_at) 
    WHERE revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP;
```

### Auth Events Table

```sql
CREATE TYPE auth_event_type AS ENUM (
    'login_success',
    'login_failed',
    'logout',
    'password_reset_requested',
    'password_reset_completed',
    'password_changed',
    'email_verified',
    'mfa_enabled',
    'mfa_disabled',
    'mfa_verified',
    'mfa_failed',
    'account_locked',
    'account_unlocked',
    'token_refreshed',
    'token_revoked',
    'registration',
    'account_deleted'
);

CREATE TABLE auth_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID, -- Nullable for failed login attempts
    event_type auth_event_type NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255), -- For failed events
    metadata JSONB, -- Additional context (device_id, geolocation, risk_score)
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT fk_auth_events_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE SET NULL
);

-- Indexes
CREATE INDEX idx_auth_events_user_id ON auth_events(user_id, created_at DESC);
CREATE INDEX idx_auth_events_type ON auth_events(event_type, created_at DESC);
CREATE INDEX idx_auth_events_created ON auth_events(created_at DESC);
CREATE INDEX idx_auth_events_failed_logins ON auth_events(ip_address, created_at DESC) 
    WHERE event_type = 'login_failed';
CREATE INDEX idx_auth_events_metadata ON auth_events USING GIN (metadata);

-- Partition by month for performance
CREATE TABLE auth_events_2025_01 PARTITION OF auth_events
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
-- (Create additional partitions as needed)
```

### Password Reset Tokens Table

```sql
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hash
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    ip_address INET NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT fk_password_reset_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT expires_15_minutes CHECK (expires_at <= created_at + INTERVAL '15 minutes'),
    CONSTRAINT used_before_expiry CHECK (used_at IS NULL OR used_at <= expires_at)
);

-- Indexes
CREATE INDEX idx_password_reset_user_id ON password_reset_tokens(user_id);
CREATE UNIQUE INDEX idx_password_reset_hash ON password_reset_tokens(token_hash) 
    WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_expires ON password_reset_tokens(expires_at) 
    WHERE used_at IS NULL;
```

### Email Verification Tokens Table

```sql
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hash with HMAC
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    resend_count INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT fk_email_verification_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT expires_24_hours CHECK (expires_at <= created_at + INTERVAL '24 hours'),
    CONSTRAINT verified_before_expiry CHECK (verified_at IS NULL OR verified_at <= expires_at),
    CONSTRAINT resend_count_positive CHECK (resend_count >= 0)
);

-- Indexes
CREATE INDEX idx_email_verification_user_id ON email_verification_tokens(user_id);
CREATE UNIQUE INDEX idx_email_verification_hash ON email_verification_tokens(token_hash) 
    WHERE verified_at IS NULL;
CREATE INDEX idx_email_verification_expires ON email_verification_tokens(expires_at) 
    WHERE verified_at IS NULL;
```

### OTP Codes Table (Email-based 2FA)

```sql
CREATE TABLE otp_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    code_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of 6-digit code
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    attempts INTEGER DEFAULT 0 NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT fk_otp_codes_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT expires_5_minutes CHECK (expires_at <= created_at + INTERVAL '5 minutes'),
    CONSTRAINT max_attempts CHECK (attempts <= 3),
    CONSTRAINT verified_before_expiry CHECK (verified_at IS NULL OR verified_at <= expires_at)
);

-- Indexes
CREATE INDEX idx_otp_codes_user_id ON otp_codes(user_id, created_at DESC);
CREATE INDEX idx_otp_codes_expires ON otp_codes(expires_at) WHERE verified_at IS NULL;
```

### Backup Codes Table (2FA Recovery)

```sql
CREATE TABLE backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    code_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hash
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT fk_backup_codes_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_backup_codes_user_id ON backup_codes(user_id);
CREATE INDEX idx_backup_codes_unused ON backup_codes(user_id) WHERE used_at IS NULL;
```

### Password History Table

```sql
CREATE TABLE password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    CONSTRAINT fk_password_history_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX idx_password_history_user_id ON password_history(user_id, created_at DESC);

-- Trigger to limit history to last 5 passwords
CREATE OR REPLACE FUNCTION enforce_password_history_limit()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM password_history
    WHERE user_id = NEW.user_id
    AND id NOT IN (
        SELECT id FROM password_history
        WHERE user_id = NEW.user_id
        ORDER BY created_at DESC
        LIMIT 5
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER limit_password_history AFTER INSERT ON password_history
    FOR EACH ROW EXECUTE FUNCTION enforce_password_history_limit();
```

### Trusted Devices Table

```sql
CREATE TABLE trusted_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    device_type VARCHAR(50), -- 'mobile', 'desktop', 'tablet'
    fingerprint_hash VARCHAR(64) NOT NULL, -- SHA-256 of device fingerprint
    first_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    trusted_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,

    CONSTRAINT fk_trusted_devices_user FOREIGN KEY (user_id) 
        REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT unique_user_device UNIQUE (user_id, device_id)
);

-- Indexes
CREATE INDEX idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX idx_trusted_devices_active ON trusted_devices(user_id) 
    WHERE revoked_at IS NULL;
```

## 3. Relationships & Foreign Keys

```
users (1) ---- (many) user_consents
users (1) ---- (many) refresh_tokens
users (1) ---- (many) auth_events
users (1) ---- (many) password_reset_tokens
users (1) ---- (many) email_verification_tokens
users (1) ---- (many) otp_codes
users (1) ---- (many) backup_codes
users (1) ---- (many) password_history
users (1) ---- (many) trusted_devices
```

**Cascade Rules:**
- `ON DELETE CASCADE`: All child records deleted when user is deleted (hard delete)
- `ON DELETE SET NULL`: auth_events.user_id set to NULL (preserve failed login attempts)
- Soft delete strategy: `users.deleted_at` for GDPR right to erasure

## 4. Data Models with Business Rules

### Users
- **email**: Unique, case-insensitive, validated format, encrypted at rest
- **password_hash**: Argon2id with memory=64MB, iterations=3, parallelism=4
- **email_verified**: Must be TRUE before full account access
- **mfa_enabled**: Requires email verification first
- **account_locked_until**: Auto-set after 5 failed login attempts, expires after 30 minutes
- **failed_login_attempts**: Reset to 0 on successful login
- **deleted_at**: Soft delete for GDPR compliance, cascades to consent withdrawal

### User Consents
- **consent_type**: Immutable after creation
- **consented_at**: Immutable timestamp
- **withdrawn_at**: Can only be set if consented = TRUE
- **consent_version**: Track policy changes, re-consent required on major updates
- **ip_address + user_agent**: Audit trail for legal compliance

### Refresh Tokens
- **token_hash**: SHA-256 hash, never store plaintext
- **expires_at**: 7 days from creation
- **revoked_at**: Set on logout, reuse detection, or admin action
- **last_used_at**: Updated on each refresh, detect stale tokens
- **device_id**: Unique per device, limit 5 concurrent devices per user

### Auth Events
- **user_id**: Nullable to log failed login attempts without user context
- **metadata**: Store risk scores, geolocation, device fingerprints
- **Partitioning**: Monthly partitions, 90-day retention for compliance
- **Immutable**: No updates/deletes, append-only log

### Password Reset Tokens
- **expires_at**: 15 minutes from creation
- **used_at**: One-time use, invalidate after consumption
- **Rate Limiting**: Max 3 requests per hour per user (enforced at application layer)

### OTP Codes
- **code_hash**: SHA-256 of 6-digit numeric code
- **expires_at**: 5 minutes from creation
- **attempts**: Max 3 attempts, then invalidate
- **Auto-cleanup**: Delete expired codes older than 1 hour

## 5. Indexing Strategy

### Performance-Critical Indexes

```sql
-- Login flow: Query by email
CREATE UNIQUE INDEX idx_users_email_active ON users(LOWER(email)) WHERE deleted_at IS NULL;
-- Query pattern: SELECT * FROM users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL

-- Token refresh: Query by token hash
CREATE UNIQUE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;
-- Query pattern: SELECT * FROM refresh_tokens WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()

-- Account lockout check
CREATE INDEX idx_users_account_locked ON users(account_locked_until) WHERE account_locked_until IS NOT NULL;
-- Query pattern: SELECT * FROM users WHERE id = $1 AND (account_locked_until IS NULL OR account_locked_until < NOW())

-- Auth events for security monitoring
CREATE INDEX idx_auth_events_failed_logins ON auth_events(ip_address, created_at DESC) 
    WHERE event_type = 'login_failed';
-- Query pattern: Detect brute force attacks by IP

-- Password reset lookup
CREATE UNIQUE INDEX idx_password_reset_hash ON password_reset_tokens(token_hash) 
    WHERE used_at IS NULL;
-- Query pattern: SELECT * FROM password_reset_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()

-- Active refresh tokens per user (device management)
CREATE INDEX idx_refresh_tokens_active ON refresh_tokens(user_id, revoked_at, expires_at) 
    WHERE revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP;
-- Query pattern: List active sessions for user dashboard

-- Consent audit trail
CREATE INDEX idx_user_consents_active ON user_consents(user_id, consent_type, consented) 
    WHERE consented = TRUE AND withdrawn_at IS NULL;
-- Query pattern: Check if user has active consent for specific type
```

### Index Maintenance
- **VACUUM ANALYZE**: Daily at 3 AM UTC
- **REINDEX**: Weekly for high-churn tables (auth_events, refresh_tokens)
- **Index Bloat Monitoring**: Alert if bloat > 30%

## 6. Data Migration Strategy

### Initial Schema Creation
```sql
-- migrations/001_initial_schema.sql
-- Contains all CREATE TABLE, CREATE INDEX, CREATE TRIGGER statements

-- migrations/002_seed_data.sql
-- Development/testing seed data (test users, consents)
```

### Version Control: Flyway
- **Migration Files:** `V{version}__{description}.sql`
- **Baseline Version:** V1
- **Validation:** On application startup
- **Repair:** Available for failed migrations

### Rollback Strategy
```sql
-- migrations/V002__add_trusted_devices.sql
CREATE TABLE trusted_devices (...);

-- migrations/U002__remove_trusted_devices.sql (undo)
DROP TABLE trusted_devices;
```

### Zero-Downtime Migration
1. **Additive Changes:** Add new columns with defaults, deploy application, backfill
2. **Backward Compatibility:** Keep old columns during transition period
3. **Blue-Green Deployment:** Migrate replica, switch traffic, migrate primary
4. **Lock Avoidance:** Use `CREATE INDEX CONCURRENTLY`

### Data Seeding
- **Development:** 100 test users with various states (verified, locked, MFA enabled)
- **Staging:** Anonymized production data subset
- **Production:** No seeding, migrations only

## 7. Data Integrity & Constraints

### Primary Keys Strategy
- **UUID v4:** Non-sequential, secure, distributed-system friendly
- **Generation:** `gen_random_uuid()` for cryptographic randomness
- **Clustering:** Consider `id SERIAL` + UUID for better insert performance if needed

### Foreign Key Constraints
```sql
-- Enforce referential integrity
ALTER TABLE user_consents ADD CONSTRAINT fk_user_consents_user 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE refresh_tokens ADD CONSTRAINT fk_refresh_tokens_user 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE auth_events ADD CONSTRAINT fk_auth_events_user 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
```

### Check Constraints
```sql
-- Email format validation
CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')

-- Expiration logic
CONSTRAINT expires_15_minutes CHECK (expires_at <= created_at + INTERVAL '15 minutes')

-- State consistency
CONSTRAINT withdrawn_after_consent CHECK (withdrawn_at IS NULL OR withdrawn_at >= consented_at)
```

### Unique Constraints
```sql
-- Prevent duplicate active tokens
CREATE UNIQUE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;

-- Case-insensitive email uniqueness
CREATE UNIQUE INDEX idx_users_email_active ON users(LOWER(email)) WHERE deleted_at IS NULL;
```

### Cascade Rules
- **ON DELETE CASCADE:** Child records deleted (consents, tokens, history)
- **ON DELETE SET NULL:** Preserve audit trail (auth_events)
- **ON UPDATE CASCADE:** Propagate changes (not used, UUIDs immutable)

## 8. Security & Access Control

### Database User Roles

```sql
-- Application role (read/write)
CREATE ROLE financeapp_app WITH LOGIN PASSWORD 'strong_random_password';
GRANT CONNECT ON DATABASE financeapp TO financeapp_app;
GRANT USAGE ON SCHEMA public TO financeapp_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO financeapp_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO financeapp_app;

-- Read-only role (analytics, reporting)
CREATE ROLE financeapp_readonly WITH LOGIN PASSWORD 'strong_random_password';
GRANT CONNECT ON DATABASE financeapp TO financeapp_readonly;
GRANT USAGE ON SCHEMA public TO financeapp_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO financeapp_readonly;

-- Migration role (schema changes)
CREATE ROLE financeapp_migration WITH LOGIN PASSWORD 'strong_random_password';
GRANT ALL PRIVILEGES ON DATABASE financeapp TO financeapp_migration;
```

### Row-Level Security (RLS)

```sql
-- Enable RLS on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see non-deleted accounts
CREATE POLICY users_visibility ON users
    FOR SELECT
    USING (deleted_at IS NULL);

-- Policy: Application can update own user records
CREATE POLICY users_update ON users
    FOR UPDATE
    USING (id = current_setting('app.user_id')::UUID);
```

### Column-Level Encryption

```sql
-- Encrypt sensitive columns with pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Application-level encryption key (stored in AWS Secrets Manager)
-- email_encrypted: AES-256-GCM with unique IV per row
INSERT INTO users (email, email_encrypted, ...)
VALUES (
    'user@example.com',
    pgp_sym_encrypt('user@example.com', current_setting('app.encryption_key')),
    ...
);

-- Decrypt on read (application handles key rotation)
SELECT 
    id, 
    email,
    pgp_sym_decrypt(email_encrypted::bytea, current_setting('app.encryption_key')) AS email_decrypted
FROM users;
```

### Sensitive Data Handling

- **PII Fields:** email, ip_address, user_agent (encrypted or pseudonymized)
- **PCI Data:** No credit card storage, tokenized references only
- **Password Hashes:** Argon2id, never logged or transmitted
- **Tokens:** SHA-256 hashed, plaintext never stored

### Connection Security

```sql
-- Force SSL/TLS connections
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/path/to/server.crt';
ALTER SYSTEM SET ssl_key_file = '/path/to/server.key';

-- Require SSL for application role
ALTER ROLE financeapp_app SET ssl = on;

-- pg_hba.conf
hostssl all financeapp_app 0.0.0.0/0 scram-sha-256
```

## 9. Performance Optimization

### Performance Targets

| Metric | Target | Measurement |
|--------|--------|-------------|
| Query Response Time | < 50ms (p95) | Slow query log, APM |
| Write Throughput | 500 auth events/s | Benchmark with pgbench |
| Read Throughput | 2000 user lookups/s | Load testing |
| Connection Pool Utilization | < 70% | PgBouncer stats |
| Index Hit Ratio | > 99% | pg_stat_user_indexes |

### Scalability Projections

| Timeframe | Users | Auth Events/Day | Storage | Strategy |
|-----------|-------|-----------------|---------|----------|
| Day 1 | 1,000 | 10,000 | 500 MB | Single instance |
| 3 Months | 50,000 | 500,000 | 25 GB | Read replicas |
| 1 Year | 500,000 | 5,000,000 | 250 GB | Partitioning |
| 3 Years | 2,000,000 | 20,000,000 | 1 TB | Sharding by region |

**Growth Rate Assumptions:** 15% MoM user growth, 10 auth events per user per day

### Query Optimization Guidelines

```sql
-- Use EXPLAIN ANALYZE for all queries > 10ms
EXPLAIN ANALYZE SELECT * FROM users WHERE LOWER(email) = LOWER('user@example.com');

-- Avoid SELECT *, specify columns
SELECT id, email, email_verified FROM users WHERE id = $1;

-- Use prepared statements (prevents SQL injection, improves performance)
PREPARE get_user (UUID) AS SELECT * FROM users WHERE id = $1;
EXECUTE get_user('uuid-here');

-- Batch inserts for auth_events
INSERT INTO auth_events (user_id, event_type, ip_address, user_agent, success, created_at)
VALUES 
    ($1, $2, $3, $4, $5, $6),
    ($7, $8, $9, $10, $11, $12),
    ... ;
```

### Partitioning Strategy

```sql
-- Partition auth_events by month
CREATE TABLE auth_events (
    id UUID DEFAULT gen_random_uuid(),
    user_id UUID,
    event_type auth_event_type NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ...
) PARTITION BY RANGE (created_at);

CREATE TABLE auth_events_2025_01 PARTITION OF auth_events
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE auth_events_2025_02 PARTITION OF auth_events
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

-- Automated partition management with pg_partman
```

### Materialized Views

```sql
-- User activity summary (refreshed hourly)
CREATE MATERIALIZED VIEW user_activity_summary AS
SELECT 
    user_id,
    COUNT(*) FILTER (WHERE event_type = 'login_success') AS successful_logins,
    COUNT(*) FILTER (WHERE event_type = 'login_failed') AS failed_logins,
    MAX(created_at) AS last_activity
FROM auth_events
WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY user_id;

CREATE UNIQUE INDEX idx_user_activity_summary_user_id ON user_activity_summary(user_id);

-- Refresh schedule (cron job)
REFRESH MATERIALIZED VIEW CONCURRENTLY user_activity_summary;
```

### Connection Pooling (PgBouncer)

```ini
[databases]
financeapp = host=localhost port=5432 dbname=financeapp

[pgbouncer]
listen_port = 6432
listen_addr = *
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
reserve_pool_size = 5
reserve_pool_timeout = 3
```

### Query Caching Strategy (Redis)

- **User Lookups:** Cache for 5 minutes (email → user_id)
- **Session Validation:** Cache refresh token status for 1 minute
- **Rate Limiting:** Store counters in Redis with TTL
- **OTP Codes:** Store in Redis (5-minute TTL) instead of database

## 10. Compliance & Audit

### GDPR Requirements

**Right to Erasure (Article 17):**
```sql
-- Soft delete user and cascade consent withdrawal
UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1;
UPDATE user_consents SET withdrawn_at = CURRENT_TIMESTAMP, consented = FALSE
WHERE user_id = $1 AND withdrawn_at IS NULL;

-- Anonymize auth_events (keep for security audit)
UPDATE auth_events SET user_id = NULL WHERE user_id = $1;

-- Hard delete tokens (no retention needed)
DELETE FROM refresh_tokens WHERE user_id = $1;
DELETE FROM password_reset_tokens WHERE user_id = $1;
DELETE FROM email_verification_tokens WHERE user_id = $1;
```

**Data Portability (Article 20):**
```sql
-- Export user data in JSON format
SELECT json_build_object(
    'user', row_to_json(u),
    'consents', (SELECT json_agg(row_to_json(c)) FROM user_consents c WHERE c.user_id = u.id),
    'auth_events', (SELECT json_agg(row_to_json(ae)) FROM auth_events ae WHERE ae.user_id = u.id)
) AS user_data
FROM users u WHERE u.id = $1;
```

**Consent Tracking:**
- All consents timestamped with IP and user agent
- Consent version tracked for policy changes
- Withdrawal capability with audit trail

### PCI-DSS Requirements

**No Cardholder Data Storage:**
- Use tokenized references (Stripe customer_id, payment_method_id)
- Never store CVV, full PAN, or expiration dates
- If storing last 4 digits, use separate encrypted table

**Access Logging:**
```sql
-- Log all access to users table
CREATE TABLE access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(50) NOT NULL,
    operation VARCHAR(10) NOT NULL, -- SELECT, INSERT, UPDATE, DELETE
    user_role VARCHAR(50) NOT NULL,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Trigger to log all user table access
CREATE OR REPLACE FUNCTION log_users_access()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO access_logs (table_name, operation, user_role, ip_address)
    VALUES ('users', TG_OP, current_user, inet_client_addr());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_access_log AFTER SELECT OR INSERT OR UPDATE OR DELETE ON users
    FOR EACH STATEMENT EXECUTE FUNCTION log_users_access();
```

### Audit Logging

**What to Log:**
- All authentication events (login, logout, failed attempts)
- Password changes and resets
- MFA enrollment and verification
- Consent changes
- Token refresh and revocation
- Account lockouts and unlocks

**Retention:**
- Auth events: 90 days (compliance requirement)
- Consent audit trail: 7 years (legal retention)
- Access logs: 1 year

**Immutability:**
```sql
-- Prevent modification of audit tables
REVOKE UPDATE, DELETE ON auth_events FROM financeapp_app;
GRANT INSERT, SELECT ON auth_events TO financeapp_app;
```

## 11. Backup & Recovery

### Backup Frequency

- **Continuous WAL Archiving:** Every 5 minutes to S3
- **Base Backups:** Daily at 2 AM UTC (low-traffic window)
- **Incremental Backups:** Hourly (WAL segments only)
- **Snapshot Backups:** Weekly full database snapshot

### Backup Retention Policy

- **Daily Backups:** 30 days rolling retention
- **Weekly Snapshots:** 3 months retention
- **Monthly Archives:** 1 year retention
- **WAL Archives:** 90 days (PITR capability)

### Point-in-Time Recovery (PITR)

```bash
# Restore to specific timestamp
pg_restore -d financeapp -t 2025-01-15T14:30:00Z /backups/base_backup

# Restore WAL segments up to target time
restore_command = 'aws s3 cp s3://backups-bucket/wal/%f %p'
recovery_target_time = '2025-01-15 14:30:00 UTC'
recovery_target_action = 'promote'
```

### Disaster Recovery Plan

**RPO (Recovery Point Objective):** 5 minutes
- Continuous WAL archiving ensures max 5-minute data loss

**RTO (Recovery Time Objective):** 1 hour
- Automated failover to replica: 5 minutes
- Full restore from backup: 45 minutes
- Application restart and validation: 10 minutes

**Multi-Region Replication:**
```
Primary (EU-West-1) 
    → Synchronous Replica (EU-West-1b) [automatic failover]
    → Asynchronous Replica (US-East-1) [disaster recovery]
```

**Failover Automation:**
- Patroni monitors primary health (10-second checks)
- Automatic promotion of synchronous replica on failure
- DNS update to redirect application traffic (TTL: 60s)
- Manual promotion of async replica for regional disaster

**DR Testing:**
- Monthly failover drills to replica
- Quarterly full restore from backup
- Annual regional failover simulation

### Backup Testing Schedule

- **Weekly:** Verify backup integrity (checksums)
- **Monthly:** Restore to staging environment
- **Quarterly:** Full disaster recovery simulation
- **Annually:** Cross-region failover test

## 12. Monitoring & Maintenance

### Metrics to Monitor

**Database Health:**
```sql
-- Connection pool usage
SELECT count(*) FROM pg_stat_activity;
SELECT state, count(*) FROM pg_stat_activity GROUP BY state;

-- Query performance (slow queries > 100ms)
SELECT query, mean_exec_time, calls 
FROM pg_stat_statements 
ORDER BY mean_exec_time DESC LIMIT 20;

-- Index hit ratio (target > 99%)
SELECT 
    sum(idx_blks_hit) / nullif(sum(idx_blks_hit + idx_blks_read), 0) AS index_hit_ratio
FROM pg_statio_user_indexes;

-- Disk usage by table
SELECT 
    schemaname, tablename,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS size
FROM pg_tables
ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC;
```

**Application Metrics (via Datadog/Prometheus):**
- Login requests per second
- Failed authentication rate (alert if > 5%)
- Token refresh latency
- Password hashing duration (target < 500ms)
- Email delivery time (via SendGrid webhooks)

**Replication Lag:**
```sql
-- Monitor replica lag
SELECT 
    client_addr,
    state,
    pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes,
    extract(epoch from (now() - pg_last_xact_replay_timestamp())) AS lag_seconds
FROM pg_stat_replication;
```

**Alerts:**
- Replication lag > 1 minute (critical)
- Connection pool usage > 80% (warning)
- Slow query > 200ms (warning)
- Disk usage > 85% (critical)
- Failed authentication rate > 10% (security alert)

### Automated Maintenance Tasks

```sql
-- Daily VACUUM ANALYZE (3 AM UTC)
VACUUM ANALYZE users;
VACUUM ANALYZE auth_events;
VACUUM ANALYZE refresh_tokens;

-- Weekly REINDEX (Sunday 4 AM UTC)
REINDEX TABLE users;
REINDEX TABLE auth_events;

-- Weekly statistics update
ANALYZE VERBOSE;

-- Automated cleanup (run daily)
-- Delete expired tokens
DELETE FROM password_reset_tokens WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '1 day';
DELETE FROM email_verification_tokens WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '1 day';
DELETE FROM otp_codes WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '1 hour';

-- Archive old auth_events (older than 90 days) to cold storage
INSERT INTO auth_events_archive SELECT * FROM auth_events WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days';
DELETE FROM auth_events WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '90 days';
```

**Cron Schedule:**
```cron
# Daily VACUUM at 3 AM
0 3 * * * /usr/bin/psql -d financeapp -c "VACUUM ANALYZE;"

# Weekly REINDEX on Sunday at 4 AM
0 4 * * 0 /usr/bin/psql -d financeapp -c "REINDEX DATABASE financeapp;"

# Daily cleanup at 2 AM
0 2 * * * /scripts/cleanup_expired_tokens.sh

# Hourly partition maintenance
0 * * * * /scripts/maintain_partitions.sh
```

**Index Bloat Monitoring:**
```sql
-- Detect index bloat
SELECT
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,
    idx_scan AS index_scans
FROM pg_stat_user_indexes
WHERE idx_scan = 0 AND pg_relation_size(indexrelid) > 1024 * 1024;
-- Alert if bloat > 30%, schedule REINDEX CONCURRENTLY
```

---

**End of Database Specification**
