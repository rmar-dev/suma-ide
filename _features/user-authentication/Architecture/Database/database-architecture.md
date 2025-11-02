


# DATABASE ARCHITECTURE

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Database
**Generated**: 2025-11-01T00:00:00Z

## Executive Summary

The SUMA Finance authentication system requires a robust, secure, and scalable database architecture to support user registration, authentication, session management, and comprehensive security auditing. This architecture leverages PostgreSQL as the primary relational database for its ACID compliance, robust security features, and excellent support for complex queries and transactions critical for financial applications. Redis serves as a high-performance cache and session store, providing sub-10ms latency for session lookups and OTP storage.

The design emphasizes security-first principles with encryption at rest, comprehensive audit logging, and granular access controls to meet GDPR, PCI-DSS, SOC 2, and ISO 27001 compliance requirements. The schema incorporates soft deletes, versioning, and temporal data tracking to support data subject rights (access, erasure, portability) while maintaining regulatory audit trails. Horizontal scalability is achieved through read replicas and strategic indexing, with a clear path to sharding based on user_id when the system scales beyond 1 million users.

Performance targets are met through strategic indexing, connection pooling, and Redis caching, delivering <200ms response times for authentication operations and <10ms session lookups. The architecture supports 1000+ requests per second with room for 10x growth through vertical scaling and read replicas before requiring sharding strategies.

## Database Selection

### Primary Database
**Technology**: PostgreSQL
**Version**: 15.x (latest stable)
**Rationale**: PostgreSQL is the optimal choice for a fintech authentication system due to its strong ACID compliance, robust security features, and excellent support for complex transactional workflows. Its mature row-level security, native encryption capabilities, and comprehensive audit logging align perfectly with GDPR and PCI-DSS requirements. PostgreSQL's JSONB support enables flexible storage of user preferences and device fingerprints without sacrificing query performance.

**Evaluation Criteria**:
- **Data model fit**: Relational model suits structured user data, authentication tokens, and audit trails with complex relationships
- **Query patterns**: Mixed read/write workload with emphasis on transactional consistency for authentication flows
- **Scalability requirements**: Vertical scaling to 100K users, horizontal scaling (read replicas) beyond that
- **Consistency requirements**: Strong ACID guarantees required for financial data and authentication state
- **Team expertise**: Strong PostgreSQL expertise in organization
- **Cost**: Open-source with mature managed service options (AWS RDS, Azure Database)
- **Managed service availability**: Excellent support across all major cloud providers
- **Community and ecosystem**: Mature ecosystem with extensive tooling, extensions (pgcrypto, pg_trgm), and migration tools

**Alternatives Considered**:
| Database | Pros | Cons | Why Not Chosen |
|----------|------|------|----------------|
| MySQL 8.0 | Good performance, wide adoption, JSON support | Weaker JSON querying than PostgreSQL, less robust transaction isolation | PostgreSQL offers superior JSONB querying and better compliance tooling |
| MongoDB | Flexible schema, horizontal scaling, high write throughput | Eventual consistency risks, weaker transaction support, less mature security features | Authentication requires strong consistency; NoSQL flexibility not needed for structured user data |
| Amazon DynamoDB | Serverless, unlimited scalability, single-digit ms latency | Eventual consistency, complex query limitations, higher cost at scale | Over-engineered for initial scale; ACID transactions critical for auth flows |
| Microsoft SQL Server | Enterprise features, strong security, good Azure integration | Higher licensing costs, limited cross-platform support | Cost prohibitive; PostgreSQL offers equivalent features open-source |

### Secondary Databases (If Applicable)

**Cache Database**: Redis 7.x
- **Use case**: Session storage, JWT refresh token tracking, OTP storage, rate limiting counters, device fingerprint cache
- **Data TTL**: Sessions (15 min idle, 8h absolute), OTPs (5 min), rate limit counters (1 hour), device cache (30 days)
- **Persistence**: AOF (Append-Only File) with fsync every second for durability
- **Topology**: Redis Cluster (3 masters, 3 replicas) via AWS ElastiCache
- **Eviction Policy**: volatile-ttl (evict keys with TTL set, shortest TTL first)

**Email Queue**: PostgreSQL (using SKIP LOCKED pattern)
- **Use case**: Transactional email queue for verification emails, password resets, OTPs
- **Rationale**: Avoid separate message broker; use PostgreSQL's robust transaction support
- **Processing**: Background worker polls for pending emails using SELECT FOR UPDATE SKIP LOCKED

## Schema Design

### Naming Conventions
- **Tables**: Plural, snake_case (e.g., `users`, `auth_sessions`, `security_events`)
- **Columns**: snake_case (e.g., `email_verified_at`, `last_login_ip`)
- **Primary Keys**: `id` (UUID v4 for distributed systems, prevents enumeration attacks)
- **Foreign Keys**: `{table}_id` (e.g., `user_id`, `device_id`)
- **Timestamps**: `created_at`, `updated_at`, `deleted_at` (all TIMESTAMPTZ)
- **Indexes**: `idx_{table}_{column}` (e.g., `idx_users_email`)
- **Unique Constraints**: `{table}_{column}_unique` (e.g., `users_email_unique`)
- **Check Constraints**: `{table}_{column}_check` (e.g., `users_status_check`)

### Core Tables

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMPTZ,
    password_hash VARCHAR(255) NOT NULL, -- Argon2id hash
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone VARCHAR(20),
    phone_verified BOOLEAN DEFAULT FALSE,
    phone_verified_at TIMESTAMPTZ,
    
    -- Status management
    status VARCHAR(20) NOT NULL DEFAULT 'pending_verification'
        CHECK (status IN ('pending_verification', 'active', 'suspended', 'locked', 'deleted')),
    
    -- Security fields
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    last_login_ip INET,
    password_changed_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- 2FA configuration
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_method VARCHAR(20) CHECK (mfa_method IN ('email_otp', 'sms_otp', 'totp', 'biometric')),
    backup_codes_hash TEXT[], -- Array of hashed backup codes
    
    -- GDPR compliance
    gdpr_consent_version VARCHAR(20),
    gdpr_consent_at TIMESTAMPTZ,
    gdpr_consent_ip INET,
    marketing_consent BOOLEAN DEFAULT FALSE,
    marketing_consent_at TIMESTAMPTZ,
    data_processing_consent BOOLEAN DEFAULT FALSE,
    data_processing_consent_at TIMESTAMPTZ,
    
    -- Preferences (JSONB for flexibility)
    preferences JSONB DEFAULT '{}'::jsonb,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb, -- Device info, user agent, etc.
    
    -- Audit timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT users_email_unique UNIQUE (email) WHERE deleted_at IS NULL,
    CONSTRAINT users_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$'),
    CONSTRAINT users_phone_format CHECK (phone IS NULL OR phone ~ '^\+[1-9]\d{1,14}$'),
    CONSTRAINT users_failed_attempts_positive CHECK (failed_login_attempts >= 0)
);

-- Indexes
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_last_login ON users(last_login_at DESC) WHERE status = 'active';
CREATE INDEX idx_users_mfa_enabled ON users(mfa_enabled) WHERE status = 'active';
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NOT NULL;

-- GIN index for JSONB queries
CREATE INDEX idx_users_preferences ON users USING GIN(preferences jsonb_path_ops);
CREATE INDEX idx_users_metadata ON users USING GIN(metadata jsonb_path_ops);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Comments
COMMENT ON TABLE users IS 'User accounts and authentication information';
COMMENT ON COLUMN users.password_hash IS 'Argon2id hashed password with salt';
COMMENT ON COLUMN users.failed_login_attempts IS 'Counter for account lockout policy (locks at 5)';
COMMENT ON COLUMN users.backup_codes_hash IS 'Array of hashed single-use backup codes for 2FA recovery';
COMMENT ON COLUMN users.preferences IS 'User preferences (language, timezone, notifications)';
COMMENT ON COLUMN users.metadata IS 'System metadata (registration device, user agent, source)';
```

#### Auth Sessions Table
```sql
CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Token management
    refresh_token_hash VARCHAR(255) NOT NULL UNIQUE,
    refresh_token_family UUID NOT NULL DEFAULT gen_random_uuid(), -- For rotation detection
    
    -- Device information
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    device_fingerprint VARCHAR(255),
    user_agent TEXT,
    ip_address INET NOT NULL,
    
    -- Geolocation
    country_code CHAR(2),
    city VARCHAR(100),
    
    -- Session metadata
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL, -- 7 days from creation
    
    -- Security flags
    is_suspicious BOOLEAN DEFAULT FALSE,
    suspicious_reason TEXT,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(100),

    CONSTRAINT auth_sessions_expires_after_creation CHECK (expires_at > created_at)
);

-- Indexes
CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_sessions_refresh_token_hash ON auth_sessions(refresh_token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_sessions_device_id ON auth_sessions(device_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_sessions_last_activity ON auth_sessions(last_activity_at DESC);
CREATE INDEX idx_auth_sessions_family ON auth_sessions(refresh_token_family);

-- Automatic cleanup trigger for expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS TRIGGER AS $$
BEGIN
    DELETE FROM auth_sessions
    WHERE expires_at < NOW() - INTERVAL '30 days'
        AND revoked_at IS NOT NULL;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_cleanup_expired_sessions
    AFTER INSERT ON auth_sessions
    EXECUTE FUNCTION cleanup_expired_sessions();

COMMENT ON TABLE auth_sessions IS 'Active refresh token sessions with device tracking';
COMMENT ON COLUMN auth_sessions.refresh_token_family IS 'Groups rotated tokens to detect reuse attacks';
COMMENT ON COLUMN auth_sessions.device_fingerprint IS 'Browser/app fingerprint for anomaly detection';
```

#### Devices Table
```sql
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Device identification
    device_name VARCHAR(100), -- "iPhone 13", "Chrome on MacBook"
    device_type VARCHAR(20) CHECK (device_type IN ('web', 'ios', 'android', 'desktop')),
    device_fingerprint VARCHAR(255) NOT NULL,
    
    -- Device details
    os_name VARCHAR(50),
    os_version VARCHAR(50),
    browser_name VARCHAR(50),
    browser_version VARCHAR(50),
    
    -- Trust status
    is_trusted BOOLEAN DEFAULT FALSE,
    trusted_at TIMESTAMPTZ,
    
    -- Usage tracking
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_ip_address INET,
    
    -- Security
    is_blocked BOOLEAN DEFAULT FALSE,
    blocked_reason TEXT,
    blocked_at TIMESTAMPTZ,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT devices_fingerprint_user_unique UNIQUE (device_fingerprint, user_id)
);

CREATE INDEX idx_devices_user_id ON devices(user_id);
CREATE INDEX idx_devices_fingerprint ON devices(device_fingerprint);
CREATE INDEX idx_devices_last_seen ON devices(last_seen_at DESC);
CREATE INDEX idx_devices_trusted ON devices(is_trusted) WHERE is_trusted = TRUE;

CREATE TRIGGER update_devices_updated_at BEFORE UPDATE ON devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE devices IS 'Registered user devices for trust and anomaly detection';
```

#### Email Verification Tokens Table
```sql
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Token data
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    token_signature VARCHAR(255) NOT NULL, -- HMAC-SHA256 signature
    
    -- Metadata
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    
    -- Usage tracking
    used_at TIMESTAMPTZ,
    attempts INT DEFAULT 0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT email_verification_tokens_expires_valid CHECK (expires_at > created_at)
);

CREATE INDEX idx_email_verification_tokens_token_hash ON email_verification_tokens(token_hash) WHERE used_at IS NULL;
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id) WHERE used_at IS NULL;
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at);

COMMENT ON TABLE email_verification_tokens IS 'One-time email verification tokens with HMAC signatures';
```

#### Password Reset Tokens Table
```sql
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Token data
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    token_signature VARCHAR(255) NOT NULL, -- HMAC-SHA256 signature
    
    -- Security metadata
    ip_address INET NOT NULL,
    user_agent TEXT,
    
    -- Expiration
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '1 hour'),
    
    -- Usage tracking
    used_at TIMESTAMPTZ,
    attempts INT DEFAULT 0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT password_reset_tokens_expires_valid CHECK (expires_at > created_at),
    CONSTRAINT password_reset_tokens_max_attempts CHECK (attempts <= 5)
);

CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash) WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id) WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

COMMENT ON TABLE password_reset_tokens IS 'One-time password reset tokens with rate limiting';
```

#### OTP Codes Table
```sql
CREATE TABLE otp_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- OTP data
    code_hash VARCHAR(255) NOT NULL,
    otp_type VARCHAR(20) NOT NULL CHECK (otp_type IN ('email', 'sms', 'login', 'transaction')),
    
    -- Delivery tracking
    sent_to VARCHAR(255) NOT NULL, -- Email or phone
    delivery_status VARCHAR(20) DEFAULT 'pending' CHECK (delivery_status IN ('pending', 'sent', 'failed')),
    
    -- Expiration
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '5 minutes'),
    
    -- Usage tracking
    used_at TIMESTAMPTZ,
    attempts INT DEFAULT 0,
    
    -- Security
    ip_address INET,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT otp_codes_expires_valid CHECK (expires_at > created_at),
    CONSTRAINT otp_codes_max_attempts CHECK (attempts <= 3)
);

CREATE INDEX idx_otp_codes_user_id ON otp_codes(user_id) WHERE used_at IS NULL;
CREATE INDEX idx_otp_codes_expires_at ON otp_codes(expires_at);
CREATE INDEX idx_otp_codes_code_hash ON otp_codes(code_hash) WHERE used_at IS NULL;

COMMENT ON TABLE otp_codes IS '6-digit OTP codes for 2FA with 5-minute expiry and attempt limiting';
```

#### Security Events Table
```sql
CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Event classification
    event_type VARCHAR(50) NOT NULL,
    event_category VARCHAR(20) NOT NULL CHECK (event_category IN ('auth', 'account', 'security', 'gdpr')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    
    -- Event details
    description TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    session_id UUID REFERENCES auth_sessions(id) ON DELETE SET NULL,
    
    -- Geolocation
    country_code CHAR(2),
    city VARCHAR(100),
    
    -- Result
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition by month for performance
CREATE TABLE security_events_2025_11 PARTITION OF security_events
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

-- Indexes
CREATE INDEX idx_security_events_user_id ON security_events(user_id, created_at DESC);
CREATE INDEX idx_security_events_type ON security_events(event_type, created_at DESC);
CREATE INDEX idx_security_events_severity ON security_events(severity, created_at DESC) WHERE severity IN ('warning', 'critical');
CREATE INDEX idx_security_events_created_at ON security_events(created_at DESC);
CREATE INDEX idx_security_events_ip ON security_events(ip_address, created_at DESC);

-- GIN index for metadata queries
CREATE INDEX idx_security_events_metadata ON security_events USING GIN(metadata jsonb_path_ops);

COMMENT ON TABLE security_events IS 'Comprehensive audit log for all security-related events';
COMMENT ON COLUMN security_events.event_type IS 'login_success, login_failed, password_changed, mfa_enabled, etc.';
```

#### GDPR Consents Table
```sql
CREATE TABLE gdpr_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Consent details
    consent_type VARCHAR(50) NOT NULL CHECK (consent_type IN ('privacy_policy', 'terms_of_service', 'marketing', 'data_processing', 'cookies')),
    consent_version VARCHAR(20) NOT NULL,
    consent_given BOOLEAN NOT NULL,
    
    -- Audit trail
    consented_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address INET NOT NULL,
    user_agent TEXT,
    
    -- Withdrawal tracking
    withdrawn_at TIMESTAMPTZ,
    withdrawal_ip INET,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gdpr_consents_user_id ON gdpr_consents(user_id, consent_type);
CREATE INDEX idx_gdpr_consents_type ON gdpr_consents(consent_type, consent_given);
CREATE INDEX idx_gdpr_consents_consented_at ON gdpr_consents(consented_at DESC);

COMMENT ON TABLE gdpr_consents IS 'Granular consent tracking for GDPR compliance';
```

#### Password History Table
```sql
CREATE TABLE password_history (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    password_hash VARCHAR(255) NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_from_ip INET,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_history_user_id ON password_history(user_id, changed_at DESC);

COMMENT ON TABLE password_history IS 'Password history to prevent reuse of last 5 passwords';
```

#### Email Queue Table
```sql
CREATE TABLE email_queue (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Email details
    recipient_email VARCHAR(255) NOT NULL,
    email_type VARCHAR(50) NOT NULL CHECK (email_type IN ('verification', 'password_reset', 'otp', 'security_alert', 'welcome')),
    subject VARCHAR(255) NOT NULL,
    body_html TEXT NOT NULL,
    body_text TEXT,
    
    -- Metadata
    template_name VARCHAR(100),
    template_variables JSONB,
    
    -- Processing status
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'sent', 'failed')),
    attempts INT DEFAULT 0,
    max_attempts INT DEFAULT 3,
    
    -- Scheduling
    scheduled_for TIMESTAMPTZ DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    
    -- Error tracking
    last_error TEXT,
    
    -- External service tracking
    sendgrid_message_id VARCHAR(255),
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT email_queue_max_attempts_valid CHECK (attempts <= max_attempts)
);

CREATE INDEX idx_email_queue_status ON email_queue(status, scheduled_for) WHERE status = 'pending';
CREATE INDEX idx_email_queue_user_id ON email_queue(user_id, created_at DESC);
CREATE INDEX idx_email_queue_created_at ON email_queue(created_at DESC);

CREATE TRIGGER update_email_queue_updated_at BEFORE UPDATE ON email_queue
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON TABLE email_queue IS 'Transactional email queue processed by background workers';
```

### Relationships

**Entity Relationship Diagram** (ASCII):
```
┌──────────────────┐
│      users       │
├──────────────────┤
│ id (PK)          │──────┐
│ email            │      │
│ password_hash    │      │
│ mfa_enabled      │      │
│ status           │      │
└──────────────────┘      │
         │                │
         │                │
         ├────────────────┼───────────────────┐
         │                │                   │
         │                │                   │
         ▼                ▼                   ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  auth_sessions   │ │     devices      │ │ security_events  │
├──────────────────┤ ├──────────────────┤ ├──────────────────┤
│ id (PK)          │ │ id (PK)          │ │ id (PK)          │
│ user_id (FK)     │ │ user_id (FK)     │ │ user_id (FK)     │
│ refresh_token    │ │ device_fp        │ │ event_type       │
│ device_id (FK)   │─┤ is_trusted       │ │ ip_address       │
│ expires_at       │ │ last_seen_at     │ │ created_at       │
└──────────────────┘ └──────────────────┘ └──────────────────┘
         │
         ├───────────────────────────────────────────┐
         │                                           │
         ▼                                           ▼
┌──────────────────────┐                  ┌──────────────────────┐
│ email_verification_  │                  │ password_reset_      │
│       tokens         │                  │      tokens          │
├──────────────────────┤                  ├──────────────────────┤
│ id (PK)              │                  │ id (PK)              │
│ user_id (FK)         │                  │ user_id (FK)         │
│ token_hash           │                  │ token_hash           │
│ expires_at           │                  │ expires_at           │
└──────────────────────┘                  └──────────────────────┘

         │                                           │
         ▼                                           ▼
┌──────────────────┐                  ┌──────────────────┐
│   otp_codes      │                  │ gdpr_consents    │
├──────────────────┤                  ├──────────────────┤
│ id (PK)          │                  │ id (PK)          │
│ user_id (FK)     │                  │ user_id (FK)     │
│ code_hash        │                  │ consent_type     │
│ expires_at       │                  │ consent_given    │
└──────────────────┘                  └──────────────────┘

         │
         ▼
┌──────────────────┐
│ password_history │
├──────────────────┤
│ id (PK)          │
│ user_id (FK)     │
│ password_hash    │
│ changed_at       │
└──────────────────┘
```

**Foreign Keys**:
```sql
-- Auth sessions
ALTER TABLE auth_sessions
    ADD CONSTRAINT auth_sessions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE auth_sessions
    ADD CONSTRAINT auth_sessions_device_id_fkey
    FOREIGN KEY (device_id) REFERENCES devices(id)
    ON DELETE SET NULL ON UPDATE CASCADE;

-- Devices
ALTER TABLE devices
    ADD CONSTRAINT devices_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE ON UPDATE CASCADE;

-- Email verification tokens
ALTER TABLE email_verification_tokens
    ADD CONSTRAINT email_verification_tokens_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE ON UPDATE CASCADE;

-- Password reset tokens
ALTER TABLE password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE ON UPDATE CASCADE;

-- OTP codes
ALTER TABLE otp_codes
    ADD CONSTRAINT otp_codes_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE ON UPDATE CASCADE;

-- Security events (SET NULL to preserve audit trail)
ALTER TABLE security_events
    ADD CONSTRAINT security_events_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE SET NULL ON UPDATE CASCADE;

-- GDPR consents
ALTER TABLE gdpr_consents
    ADD CONSTRAINT gdpr_consents_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE ON UPDATE CASCADE;

-- Password history
ALTER TABLE password_history
    ADD CONSTRAINT password_history_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id)
    ON DELETE CASCADE ON UPDATE CASCADE;
```

## Indexing Strategy

### Index Types

**B-Tree Indexes** (Default):
- Primary use: Equality and range queries, sorting operations
- Used for: Primary keys, foreign keys, timestamps, status fields
- Performance: O(log n) lookup, efficient for range scans

**Hash Indexes**:
- Primary use: Equality-only queries
- Used for: Token hash lookups (slightly faster than B-tree)
- Limitation: No range queries, not WAL-logged in PostgreSQL < 10

**GIN Indexes** (Generalized Inverted Index):
- Primary use: Full-text search, JSONB queries, array operations
- Used for: User preferences, metadata JSONB fields, array contains
- Trade-off: Larger index size, slower writes, fast reads

**Partial Indexes**:
- Primary use: Index subset of rows matching condition
- Used for: Active users, non-revoked sessions, unexpired tokens
- Benefit: Smaller index size, faster queries on filtered data

### Indexing Guidelines

**Create Index When**:
- Column used in WHERE clauses >50% of queries
- Column used in JOIN conditions
- Column used for sorting (ORDER BY) frequently
- Query execution time >100ms without index
- Foreign key columns (PostgreSQL doesn't auto-index FKs)

**Avoid Index When**:
- Table is small (<1000 rows)
- Column has low cardinality (e.g., boolean with 50/50 distribution)
- Table is write-heavy (>70% writes) and reads are infrequent
- Index maintenance overhead exceeds query performance gain

### Critical Indexes

```sql
-- Users: Authentication lookups
CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;

-- Users: Active user queries
CREATE INDEX idx_users_status_active ON users(status, last_login_at DESC)
    WHERE status = 'active' AND deleted_at IS NULL;

-- Users: MFA-enabled users for security reporting
CREATE INDEX idx_users_mfa ON users(mfa_enabled, created_at)
    WHERE mfa_enabled = TRUE AND deleted_at IS NULL;

-- Auth Sessions: Token validation (most critical path)
CREATE UNIQUE INDEX idx_auth_sessions_refresh_token ON auth_sessions(refresh_token_hash)
    WHERE revoked_at IS NULL;

-- Auth Sessions: User's active sessions
CREATE INDEX idx_auth_sessions_user_active ON auth_sessions(user_id, last_activity_at DESC)
    WHERE revoked_at IS NULL;

-- Auth Sessions: Token family for rotation detection
CREATE INDEX idx_auth_sessions_family_active ON auth_sessions(refresh_token_family, created_at)
    WHERE revoked_at IS NULL;

-- Auth Sessions: Expired session cleanup
CREATE INDEX idx_auth_sessions_expires ON auth_sessions(expires_at)
    WHERE revoked_at IS NULL AND expires_at < NOW();

-- Devices: User device lookup
CREATE INDEX idx_devices_user_trusted ON devices(user_id, is_trusted, last_seen_at DESC);

-- Devices: Fingerprint lookup for device recognition
CREATE INDEX idx_devices_fingerprint_user ON devices(device_fingerprint, user_id)
    WHERE is_blocked = FALSE;

-- Email Verification: Token validation
CREATE UNIQUE INDEX idx_email_verification_token ON email_verification_tokens(token_hash)
    WHERE used_at IS NULL AND expires_at > NOW();

-- Password Reset: Token validation
CREATE UNIQUE INDEX idx_password_reset_token ON password_reset_tokens(token_hash)
    WHERE used_at IS NULL AND expires_at > NOW();

-- OTP: Code validation
CREATE INDEX idx_otp_codes_user_valid ON otp_codes(user_id, code_hash, otp_type)
    WHERE used_at IS NULL AND expires_at > NOW();

-- Security Events: User audit trail
CREATE INDEX idx_security_events_user_timeline ON security_events(user_id, created_at DESC);

-- Security Events: Critical events monitoring
CREATE INDEX idx_security_events_critical ON security_events(severity, event_type, created_at DESC)
    WHERE severity = 'critical';

-- Security Events: Failed login tracking (for anomaly detection)
CREATE INDEX idx_security_events_failed_login ON security_events(ip_address, created_at DESC)
    WHERE event_type = 'login_failed' AND created_at > NOW() - INTERVAL '1 hour';

-- GDPR Consents: Active consents lookup
CREATE INDEX idx_gdpr_consents_active ON gdpr_consents(user_id, consent_type, consent_version)
    WHERE consent_given = TRUE AND withdrawn_at IS NULL;

-- Password History: Recent passwords for reuse prevention
CREATE INDEX idx_password_history_recent ON password_history(user_id, changed_at DESC);

-- Email Queue: Pending emails for background worker
CREATE INDEX idx_email_queue_pending ON email_queue(scheduled_for, status)
    WHERE status = 'pending';

-- Composite covering index for common dashboard query
CREATE INDEX idx_users_dashboard ON users(status, created_at DESC, last_login_at)
    INCLUDE (email, first_name, last_name, mfa_enabled)
    WHERE deleted_at IS NULL;
```

### Index Monitoring

```sql
-- Find unused indexes (candidate for removal)
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan AS index_scans,
    idx_tup_read AS tuples_read,
    idx_tup_fetch AS tuples_fetched,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE idx_scan = 0
    AND indexrelname NOT LIKE 'pg_toast%'
    AND indexrelname NOT LIKE '%_pkey'
ORDER BY pg_relation_size(indexrelid) DESC
LIMIT 20;

-- Find missing indexes (sequential scans on large tables)
SELECT
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    CASE 
        WHEN seq_scan = 0 THEN 0 
        ELSE ROUND(seq_tup_read::NUMERIC / seq_scan, 2) 
    END AS avg_seq_tup_read,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table_size
FROM pg_stat_user_tables
WHERE seq_scan > 0
    AND pg_relation_size(schemaname||'.'||tablename) > 10485760 -- >10MB
ORDER BY seq_tup_read DESC
LIMIT 20;

-- Index hit ratio (target: >99%)
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    ROUND(100.0 * idx_scan / NULLIF(idx_scan + seq_scan, 0), 2) AS index_hit_ratio
FROM pg_stat_user_indexes
JOIN pg_stat_user_tables USING (schemaname, tablename)
WHERE idx_scan + seq_scan > 0
ORDER BY index_hit_ratio ASC
LIMIT 20;

-- Index bloat detection
SELECT
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,
    ROUND(100.0 * pg_relation_size(indexrelid) / NULLIF(pg_total_relation_size(schemaname||'.'||tablename), 0), 2) AS pct_of_table
FROM pg_stat_user_indexes
ORDER BY pg_relation_size(indexrelid) DESC
LIMIT 20;
```

## Data Types & Constraints

### Choosing Data Types

**UUID vs BIGSERIAL**:
```sql
-- UUID: Chosen for users table (prevents enumeration, distributed-friendly)
id UUID PRIMARY KEY DEFAULT gen_random_uuid()

-- BIGSERIAL: Chosen for security_events (performance, chronological ordering)
id BIGSERIAL PRIMARY KEY
```

**VARCHAR vs TEXT**:
```sql
-- VARCHAR(n): Known maximum length (email, phone, status)
email VARCHAR(255)
status VARCHAR(20)

-- TEXT: Unknown or large length (descriptions, error messages, JSON)
description TEXT
last_error TEXT
```

**TIMESTAMP vs TIMESTAMPTZ**:
```sql
-- TIMESTAMPTZ: Always use (stores in UTC, displays in session timezone)
created_at TIMESTAMPTZ DEFAULT NOW()
last_login_at TIMESTAMPTZ

-- NEVER use TIMESTAMP without timezone
```

**DECIMAL vs FLOAT**:
```sql
-- DECIMAL: Not used in auth system, but critical for financial data
price DECIMAL(10, 2)

-- FLOAT: Not used (avoid for precision-critical data)
```

**INET for IP Addresses**:
```sql
-- INET: Native PostgreSQL type for IPv4/IPv6 addresses
ip_address INET
-- Supports CIDR notation and range queries
```

**JSONB vs JSON**:
```sql
-- JSONB: Always use (binary format, supports indexing)
preferences JSONB DEFAULT '{}'::jsonb
metadata JSONB

-- JSON: Never use (slower, no indexing)
```

### Constraints

**Check Constraints**:
```sql
-- Enum-like constraint for status
status VARCHAR(20) CHECK (status IN ('pending_verification', 'active', 'suspended', 'locked', 'deleted'))

-- Email format validation
email VARCHAR(255) CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')

-- Phone format (E.164)
phone VARCHAR(20) CHECK (phone ~ '^\+[1-9]\d{1,14}$')

-- Positive counter
failed_login_attempts INT CHECK (failed_login_attempts >= 0)

-- Expiration after creation
expires_at TIMESTAMPTZ CHECK (expires_at > created_at)

-- Max attempts limit
attempts INT CHECK (attempts <= max_attempts)

-- Severity levels
severity VARCHAR(20) CHECK (severity IN ('info', 'warning', 'critical'))
```

**Unique Constraints**:
```sql
-- Simple unique (with soft delete support)
CONSTRAINT users_email_unique UNIQUE (email) WHERE deleted_at IS NULL

-- Composite unique (device fingerprint per user)
CONSTRAINT devices_fingerprint_user_unique UNIQUE (device_fingerprint, user_id)

-- Token uniqueness
CONSTRAINT email_verification_tokens_token_unique UNIQUE (token_hash)
```

**NOT NULL Constraints**:
```sql
-- Critical fields that must always have values
email VARCHAR(255) NOT NULL
password_hash VARCHAR(255) NOT NULL
created_at TIMESTAMPTZ NOT NULL
expires_at TIMESTAMPTZ NOT NULL
ip_address INET NOT NULL
```

## Transactions & Isolation

### Isolation Levels

| Level | Dirty Read | Non-repeatable Read | Phantom Read | Performance | Use Case |
|-------|------------|---------------------|--------------|-------------|----------|
| Read Uncommitted | Yes | Yes | Yes | Fastest | Not used |
| Read Committed | No | Yes | Yes | Default | Most queries |
| Repeatable Read | No | No | Yes | Slower | Token operations |
| Serializable | No | No | No | Slowest | Not used |

**Default**: Read Committed (PostgreSQL default)

**When to use Repeatable Read**:
```sql
-- Token validation and session creation (prevent race conditions)
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ;

-- Validate refresh token
SELECT * FROM auth_sessions
WHERE refresh_token_hash = $1
    AND revoked_at IS NULL
    AND expires_at > NOW()
FOR UPDATE;

-- Rotate refresh token
UPDATE auth_sessions
SET revoked_at = NOW()
WHERE id = $2;

-- Create new session
INSERT INTO auth_sessions (...) VALUES (...);

COMMIT;
```

### Transaction Patterns

**Safe Login Pattern**:
```sql
BEGIN;

-- Lock user row
SELECT id, password_hash, failed_login_attempts, locked_until, status
FROM users
WHERE email = $1
    AND deleted_at IS NULL
FOR UPDATE;

-- Check if account is locked
IF locked_until > NOW() THEN
    ROLLBACK;
    RAISE EXCEPTION 'Account locked until %', locked_until;
END IF;

-- Verify password (in application code)
-- If password correct:
UPDATE users
SET failed_login_attempts = 0,
    last_login_at = NOW(),
    last_login_ip = $2
WHERE id = $3;

-- If password incorrect:
UPDATE users
SET failed_login_attempts = failed_login_attempts + 1,
    locked_until = CASE
        WHEN failed_login_attempts + 1 >= 5 THEN NOW() + INTERVAL '15 minutes'
        ELSE NULL
    END
WHERE id = $3;

-- Log security event
INSERT INTO security_events (...) VALUES (...);

COMMIT;
```

**Token Rotation Pattern**:
```sql
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ;

-- Lock current session
SELECT * FROM auth_sessions
WHERE refresh_token_hash = $1
    AND revoked_at IS NULL
FOR UPDATE;

-- Check for token reuse (security breach)
IF FOUND = FALSE THEN
    -- Token already revoked, possible reuse attack
    -- Revoke all sessions in family
    UPDATE auth_sessions
    SET revoked_at = NOW(),
        revoked_reason = 'token_reuse_detected'
    WHERE refresh_token_family = $2;
    
    -- Log critical security event
    INSERT INTO security_events (event_type, severity, ...) VALUES ('token_reuse', 'critical', ...);
    
    COMMIT;
    RAISE EXCEPTION 'Token reuse detected - all sessions revoked';
END IF;

-- Revoke old token
UPDATE auth_sessions
SET revoked_at = NOW(),
    revoked_reason = 'rotated'
WHERE id = $3;

-- Create new token (same family)
INSERT INTO auth_sessions (user_id, refresh_token_hash, refresh_token_family, ...)
VALUES ($4, $5, $2, ...);

COMMIT;
```

**OTP Verification Pattern**:
```sql
BEGIN;

-- Lock OTP record
SELECT * FROM otp_codes
WHERE user_id = $1
    AND otp_type = $2
    AND used_at IS NULL
    AND expires_at > NOW()
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- Increment attempts
UPDATE otp_codes
SET attempts = attempts + 1
WHERE id = $3;

-- Check max attempts
IF attempts >= 3 THEN
    UPDATE otp_codes SET used_at = NOW() WHERE id = $3;
    ROLLBACK;
    RAISE EXCEPTION 'Max OTP attempts exceeded';
END IF;

-- Verify code (in application)
-- If correct:
UPDATE otp_codes SET used_at = NOW() WHERE id = $3;

-- Mark user as verified
UPDATE users SET email_verified = TRUE, email_verified_at = NOW() WHERE id = $1;

COMMIT;
```

## Scalability Strategies

### Vertical Scaling (Scale Up)
- **Current Setup**: AWS RDS db.t3.medium (2 vCPU, 4GB RAM)
- **Scale Path**: db.t3.large → db.m5.xlarge → db.m5.2xlarge
- **Maximum**: db.m5.8xlarge (32 vCPU, 128GB RAM)
- **When to Scale**: CPU >70%, Memory >80%, Connection count >50% of max
- **Good for**: 0-100K users, simple to implement

### Horizontal Scaling (Scale Out)

#### Read Replicas
```
                    ┌────────────────┐
                    │  Primary DB    │ (All writes)
                    │  (Master)      │
                    └────────┬───────┘
                             │ Async replication
          ┌──────────────────┼──────────────────┐
          │                  │                  │
     ┌────▼────┐        ┌────▼────┐       ┌────▼────┐
     │ Replica │        │ Replica │       │ Replica │
     │   #1    │        │   #2    │       │   #3    │ (All reads)
     └─────────┘        └─────────┘       └─────────┘
       US-East            US-East           US-West
```

**Configuration**:
- **Primary**: All INSERT, UPDATE, DELETE operations
- **Replicas**: All SELECT queries (99% of auth queries after login)
- **Replication Lag**: Monitor closely (target <500ms)
- **Failover**: Automatic promotion via AWS RDS Multi-AZ
- **Read Distribution**: Application-level load balancing (round-robin)

**Read vs Write Routing**:
```go
// Example routing logic
func getDBConnection(queryType string) *sql.DB {
    if queryType == "write" {
        return primaryDB
    }
    // Round-robin read replicas
    return readReplicas[requestCount % len(readReplicas)]
}
```

**When to Implement**: >50K active users, >2000 qps

#### Connection Pooling
```javascript
// Application-level pooling (Node.js example)
const { Pool } = require('pg');

const primaryPool = new Pool({
  host: 'primary.db.amazonaws.com',
  database: 'suma_auth',
  max: 50, // Maximum connections
  min: 10, // Minimum connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

const replicaPool = new Pool({
  host: 'replica.db.amazonaws.com',
  database: 'suma_auth',
  max: 100, // Higher for read-heavy load
  min: 20,
  idleTimeoutMillis: 30000
});
```

**PgBouncer** (Connection Pooler):
```ini
[databases]
suma_auth = host=primary.db.amazonaws.com port=5432 dbname=suma_auth

[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 50
min_pool_size = 10
reserve_pool_size = 5
reserve_pool_timeout = 3
```

### Partitioning (Within Single Database)

**Range Partitioning** (security_events by month):
```sql
CREATE TABLE security_events (
    id BIGSERIAL,
    user_id UUID,
    event_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ...
) PARTITION BY RANGE (created_at);

-- Auto-create partitions via script
CREATE TABLE security_events_2025_11 PARTITION OF security_events
    FOR VALUES FROM ('2025-11-01') TO ('2025-12-01');

CREATE TABLE security_events_2025_12 PARTITION OF security_events
    FOR VALUES FROM ('2025-12-01') TO ('2026-01-01');

-- Automatically drop old partitions after 90 days
DROP TABLE IF EXISTS security_events_2025_08;
```

**Benefits**:
- **Query Performance**: Only scan relevant monthly partition
- **Data Lifecycle**: Drop old partitions instead of DELETE (instant)
- **Index Size**: Smaller indexes per partition
- **Parallel Queries**: PostgreSQL can query partitions in parallel
- **Maintenance**: VACUUM and REINDEX faster on smaller partitions

**Partition Management Script** (monthly cron):
```bash
#!/bin/bash
# Create next month's partition
next_month=$(date -d "+1 month" +%Y-%m-01)
partition_name="security_events_$(date -d "$next_month" +%Y_%m)"

psql -c "CREATE TABLE IF NOT EXISTS $partition_name PARTITION OF security_events
    FOR VALUES FROM ('$next_month') TO ('$(date -d "$next_month +1 month" +%Y-%m-01)');"

# Drop partitions older than 90 days
old_month=$(date -d "-90 days" +%Y_%m)
psql -c "DROP TABLE IF EXISTS security_events_$old_month;"
```

### Sharding (Future: >1M users)

**Not Implemented Yet** (premature optimization)

**When to Implement**: >1M active users, >10K qps, >500GB database size

**Proposed Sharding Strategy**: Hash-based on user_id
```
Shard 0: user_id hash % 4 = 0 (users 0, 4, 8, ...)
Shard 1: user_id hash % 4 = 1 (users 1, 5, 9, ...)
Shard 2: user_id hash % 4 = 2 (users 2, 6, 10, ...)
Shard 3: user_id hash % 4 = 3 (users 3, 7, 11, ...)
```

**Challenges**:
- Cross-shard queries (user search, admin dashboards)
- Distributed transactions (avoid if possible)
- Schema migrations across shards
- Rebalancing when adding shards

**Alternative**: Vitess or Citus (managed sharding)

## Backup & Recovery

### Backup Strategy

**Automated Backups (AWS RDS)**:
- **Full Backups**: Daily at 3:00 AM UTC (low-traffic window)
- **Retention**: 30 days
- **Storage**: AWS S3 (encrypted with AWS KMS)
- **Encryption**: AES-256-GCM
- **Compression**: Enabled (typically 60-70% reduction)

**Incremental Backups (WAL Archiving)**:
- **Frequency**: Continuous (every 16MB WAL file or 5 minutes)
- **Retention**: 7 days
- **Storage**: AWS S3 (separate bucket from full backups)
- **Purpose**: Point-in-time recovery (PITR)

**Manual Backups** (before major changes):
```bash
# Full database dump
pg_dump -h primary.db.amazonaws.com -U admin -Fc \
    -f "suma_auth_$(date +%Y%m%d_%H%M%S).dump" \
    suma_auth

# With parallel compression
pg_dump -h primary.db.amazonaws.com -U admin -Fd -j 4 \
    -f "suma_auth_$(date +%Y%m%d_%H%M%S)_dir" \
    suma_auth

# Schema-only backup (for testing)
pg_dump -h primary.db.amazonaws.com -U admin --schema-only \
    -f "suma_auth_schema_$(date +%Y%m%d).sql" \
    suma_auth
```

**Application-Level Backups** (for compliance):
```sql
-- Export user data for GDPR compliance (per user)
COPY (
    SELECT u.*, array_agg(gc.*) as consents
    FROM users u
    LEFT JOIN gdpr_consents gc ON gc.user_id = u.id
    WHERE u.id = 'user-uuid'
    GROUP BY u.id
) TO '/backups/user_data_export.csv' WITH CSV HEADER;
```

**Backup Verification** (weekly):
```bash
# Restore to test instance
aws rds restore-db-instance-from-db-snapshot \
    --db-instance-identifier suma-auth-test \
    --db-snapshot-identifier suma-auth-daily-snapshot

# Verify data integrity
psql -h test.db.amazonaws.com -c "SELECT COUNT(*) FROM users;"
psql -h test.db.amazonaws.com -c "SELECT MAX(created_at) FROM security_events;"
```

### Point-in-Time Recovery

**Configuration**:
```sql
-- Enable WAL archiving
ALTER SYSTEM SET wal_level = replica;
ALTER SYSTEM SET archive_mode = on;
ALTER SYSTEM SET archive_command = 'aws s3 cp %p s3://suma-auth-wal-archive/%f';
```

**Recovery Procedure**:
```bash
# Restore to specific timestamp (e.g., before accidental DELETE)
aws rds restore-db-instance-to-point-in-time \
    --source-db-instance-identifier suma-auth-prod \
    --target-db-instance-identifier suma-auth-recovery \
    --restore-time "2025-11-01T14:30:00Z"

# Verify data
psql -h recovery.db.amazonaws.com -c "SELECT * FROM users WHERE deleted_at IS NOT NULL;"

# Promote to production if needed
aws rds promote-read-replica \
    --db-instance-identifier suma-auth-recovery
```

### Disaster Recovery

**RTO (Recovery Time Objective)**: 1 hour
**RPO (Recovery Point Objective)**: 5 minutes (WAL archiving interval)

**Multi-AZ Configuration** (AWS RDS):
```
Primary Region: US-East-1
├── Primary DB (Multi-AZ)
│   ├── AZ-1a: Master
│   └── AZ-1b: Standby (synchronous replication)
└── Read Replicas (3x)
    ├── AZ-1a: Replica 1
    ├── AZ-1b: Replica 2
    └── AZ-1c: Replica 3

Secondary Region: US-West-2 (Cross-Region Replica)
└── Cross-Region Replica (async replication, lag ~1-2 seconds)
```

**Failover Plan**:
1. **Detection**: AWS RDS automatic health checks (30s interval)
2. **Automatic Failover**: Standby promoted to master (1-2 minutes)
3. **DNS Update**: RDS endpoint automatically points to new master
4. **Application**: No code changes needed (connection retry logic)
5. **Verification**: Run smoke tests on critical endpoints
6. **Monitoring**: Check replication lag, query performance

**Manual Regional Failover** (disaster scenario):
```bash
# 1. Promote cross-region replica to standalone
aws rds promote-read-replica \
    --db-instance-identifier suma-auth-us-west-2

# 2. Update application configuration
kubectl set env deployment/auth-service \
    DB_HOST=suma-auth-us-west-2.rds.amazonaws.com

# 3. Verify application health
curl https://api.suma.finance/health/database

# 4. Update DNS (Route53)
aws route53 change-resource-record-sets \
    --hosted-zone-id Z123456 \
    --change-batch file://failover-dns-change.json
```

**Disaster Recovery Testing** (quarterly):
- Simulate primary region failure
- Measure actual RTO vs target
- Verify data integrity after failover
- Document lessons learned

## Monitoring & Performance

### Key Metrics

**Database Health**:
- **Connection Count**: Current vs max (target: <70% of max)
- **Active Queries**: Long-running queries (>10s requires investigation)
- **Transaction Rate**: Commits/rollbacks per second
- **Replication Lag**: <500ms for read replicas
- **Deadlocks**: Count per hour (target: 0)
- **Database Size**: Growth rate (MB per day)

**Performance Metrics**:
- **Query Execution Time**: p50, p95, p99 per query type
  - Login: p95 <150ms
  - Token refresh: p95 <50ms
  - Session lookup: p95 <10ms (Redis)
- **Index Hit Rate**: >99% (cache vs disk reads)
- **Cache Hit Rate**: >95% (shared buffers)
- **Disk I/O**: IOPS, read/write latency
- **Table Bloat**: Percentage (trigger VACUUM at >20%)

**Resource Usage**:
- **CPU Utilization**: Target <70% average, <90% peak
- **Memory Utilization**: Target <80%
- **Disk Space**: Growth rate, free space remaining
- **Disk I/O Wait**: Target <10ms
- **Network Throughput**: Bandwidth usage

### Monitoring Queries

```sql
-- Current connections by state
SELECT state, COUNT(*)
FROM pg_stat_activity
WHERE datname = 'suma_auth'
GROUP BY state
ORDER BY COUNT(*) DESC;

-- Long-running queries (>10 seconds)
SELECT
    pid,
    usename,
    now() - query_start AS duration,
    state,
    LEFT(query, 100) AS query_preview
FROM pg_stat_activity
WHERE state != 'idle'
    AND now() - query_start > interval '10 seconds'
    AND datname = 'suma_auth'
ORDER BY duration DESC;

-- Kill long-running query
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid = 12345;

-- Table sizes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) AS index_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 20;

-- Index hit ratio (target: >99%)
SELECT
    'index hit rate' AS metric,
    ROUND(100.0 * sum(idx_blks_hit) / NULLIF(sum(idx_blks_hit + idx_blks_read), 0), 2) AS percentage
FROM pg_statio_user_indexes
UNION ALL
SELECT
    'table hit rate' AS metric,
    ROUND(100.0 * sum(heap_blks_hit) / NULLIF(sum(heap_blks_hit + heap_blks_read), 0), 2) AS percentage
FROM pg_statio_user_tables;

-- Cache hit ratio (target: >95%)
SELECT
    'cache hit rate' AS metric,
    ROUND(100.0 * sum(heap_blks_hit) / NULLIF(sum(heap_blks_hit + heap_blks_read), 0), 2) AS percentage
FROM pg_statio_user_tables;

-- Most expensive queries (by total time)
SELECT
    calls,
    ROUND(total_exec_time::numeric, 2) AS total_time_ms,
    ROUND(mean_exec_time::numeric, 2) AS avg_time_ms,
    ROUND((100 * total_exec_time / sum(total_exec_time) OVER ())::numeric, 2) AS pct_total,
    LEFT(query, 100) AS query_preview
FROM pg_stat_statements
WHERE dbid = (SELECT oid FROM pg_database WHERE datname = 'suma_auth')
ORDER BY total_exec_time DESC
LIMIT 20;

-- Table bloat estimation
SELECT
    schemaname,
    tablename,
    ROUND(100 * pg_relation_size(schemaname||'.'||tablename) / NULLIF(pg_total_relation_size(schemaname||'.'||tablename), 0), 2) AS table_pct,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) AS bloat_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_relation_size(schemaname||'.'||tablename) DESC;

-- Deadlocks count
SELECT
    datname,
    deadlocks,
    conflicts
FROM pg_stat_database
WHERE datname = 'suma_auth';

-- Replication lag (on replica)
SELECT
    client_addr,
    state,
    sync_state,
    ROUND(EXTRACT(EPOCH FROM (now() - replay_lag))::numeric, 2) AS lag_seconds
FROM pg_stat_replication;
```

### Performance Optimization

**Query Optimization Process**:
```sql
-- 1. Identify slow query
SELECT * FROM users WHERE email = 'user@example.com' AND status = 'active';

-- 2. Analyze with EXPLAIN
EXPLAIN ANALYZE
SELECT * FROM users WHERE email = 'user@example.com' AND status = 'active';

-- 3. Identify issue (e.g., sequential scan)
-- 4. Create index
CREATE INDEX idx_users_email_status ON users(email, status) WHERE deleted_at IS NULL;

-- 5. Re-analyze
EXPLAIN ANALYZE
SELECT * FROM users WHERE email = 'user@example.com' AND status = 'active';

-- 6. Verify improvement (should show Index Scan)
```

**Common Optimizations**:
```sql
-- Use covering indexes to avoid table lookups
CREATE INDEX idx_users_email_covering ON users(email)
    INCLUDE (id, status, email_verified, mfa_enabled)
    WHERE deleted_at IS NULL;

-- Avoid SELECT *
-- Bad:
SELECT * FROM users WHERE email = 'user@example.com';

-- Good:
SELECT id, email, password_hash, status FROM users WHERE email = 'user@example.com';

-- Use partial indexes for filtered queries
CREATE INDEX idx_auth_sessions_active ON auth_sessions(user_id, last_activity_at)
    WHERE revoked_at IS NULL;

-- Use LIMIT for pagination
SELECT id, email, created_at
FROM users
WHERE status = 'active'
ORDER BY created_at DESC
LIMIT 50 OFFSET 0;

-- Better: Use keyset pagination (faster for large offsets)
SELECT id, email, created_at
FROM users
WHERE status = 'active'
    AND created_at < '2025-10-01T00:00:00Z'
ORDER BY created_at DESC
LIMIT 50;
```

**Vacuum Strategy**:
```sql
-- Auto-vacuum configuration (tuned for auth workload)
ALTER TABLE users SET (autovacuum_vacuum_scale_factor = 0.05); -- 5% threshold
ALTER TABLE auth_sessions SET (autovacuum_vacuum_scale_factor = 0.1); -- 10% threshold
ALTER TABLE security_events SET (autovacuum_enabled = off); -- Partitioned table

-- Manual vacuum (during maintenance window)
VACUUM ANALYZE users;
VACUUM ANALYZE auth_sessions;

-- Full vacuum (requires downtime, use sparingly)
VACUUM FULL users;
```

**Connection Pooling** (Application):
```go
// Go example with pgx
config, _ := pgxpool.ParseConfig("postgres://user:pass@host/db")
config.MaxConns = 50
config.MinConns = 10
config.MaxConnLifetime = 1 * time.Hour
config.MaxConnIdleTime = 30 * time.Minute

pool, _ := pgxpool.ConnectConfig(context.Background(), config)
```

## Data Management

### Soft Deletes

**Implementation**:
```sql
-- Soft delete user
UPDATE users
SET deleted_at = NOW(),
    email = email || '.deleted.' || id::text, -- Prevent email reuse
    status = 'deleted'
WHERE id = 'user-uuid';

-- Cascade soft delete to related data
UPDATE devices SET deleted_at = NOW() WHERE user_id = 'user-uuid';
UPDATE gdpr_consents SET withdrawn_at = NOW() WHERE user_id = 'user-uuid';

-- Query only active users
SELECT * FROM users WHERE deleted_at IS NULL;

-- View for active users (simplifies queries)
CREATE VIEW active_users AS
SELECT * FROM users WHERE deleted_at IS NULL;

-- Scheduled hard delete (GDPR: after 90 days)
DELETE FROM users
WHERE deleted_at < NOW() - INTERVAL '90 days';
```

### Data Archiving

**Security Events Archival** (automated monthly):
```sql
-- Create archive table (one-time)
CREATE TABLE security_events_archive (LIKE security_events INCLUDING ALL);

-- Monthly archival job (events older than 90 days)
WITH archived AS (
    DELETE FROM security_events
    WHERE created_at < NOW() - INTERVAL '90 days'
    RETURNING *
)
INSERT INTO security_events_archive
SELECT * FROM archived;

-- Export to S3 for long-term storage
COPY (SELECT * FROM security_events_archive WHERE created_at < NOW() - INTERVAL '1 year')
TO PROGRAM 'aws s3 cp - s3://suma-archives/security-events-$(date +%Y).csv.gz --compression gzip'
WITH CSV HEADER;

-- Delete from archive after export
DELETE FROM security_events_archive WHERE created_at < NOW() - INTERVAL '1 year';
```

### Data Retention Policies

| Data Type | Retention Period | Action After | Rationale |
|-----------|------------------|--------------|-----------|
| User accounts (active) | Indefinite | Soft delete on user request | GDPR: right to erasure |
| User accounts (deleted) | 90 days | Hard delete | GDPR: reasonable retention for dispute resolution |
| Auth sessions (active) | 7 days | Expire automatically | Security: limit session lifetime |
| Auth sessions (revoked) | 30 days | Hard delete | Audit: recent session history |
| Security events | 90 days | Archive to S3 | Compliance: fraud investigation window |
| Security events (archived) | 7 years | Delete | PCI-DSS: audit trail requirement |
| OTP codes | 5 minutes | Expire automatically | Security: limit OTP lifetime |
| OTP codes (expired) | 1 day | Hard delete | Cleanup: no audit value |
| Password reset tokens | 1 hour | Expire automatically | Security: limit reset window |
| Password reset tokens (expired) | 1 day | Hard delete | Cleanup: no audit value |
| Email verification tokens | 24 hours | Expire automatically | UX: reasonable verification window |
| Email verification tokens (expired) | 7 days | Hard delete | Allow token resend investigation |
| Email queue (sent) | 30 days | Delete | Audit: email delivery confirmation |
| Password history | 2 years | Delete | Security: prevent very old password reuse |
| GDPR consents | Indefinite | Keep even after account deletion | Legal: proof of consent |
| Backups (full) | 30 days | Delete | Cost: balance recovery needs vs storage |
| Backups (WAL) | 7 days | Delete | Cost: point-in-time recovery window |

**Automated Cleanup Jobs** (cron):
```sql
-- Daily cleanup job (runs at 4 AM)
-- Delete expired OTPs
DELETE FROM otp_codes WHERE expires_at < NOW() - INTERVAL '1 day';

-- Delete expired password reset tokens
DELETE FROM password_reset_tokens WHERE expires_at < NOW() - INTERVAL '1 day';

-- Delete expired email verification tokens
DELETE FROM email_verification_tokens WHERE expires_at < NOW() - INTERVAL '7 days';

-- Delete old revoked sessions
DELETE FROM auth_sessions WHERE revoked_at < NOW() - INTERVAL '30 days';

-- Delete old email queue records
DELETE FROM email_queue WHERE sent_at < NOW() - INTERVAL '30 days';

-- Hard delete soft-deleted users after 90 days
DELETE FROM users WHERE deleted_at < NOW() - INTERVAL '90 days';
```

## Security

### Encryption

**At Rest**:
- **Database Storage**: AWS RDS encryption enabled (AES-256)
- **Backups**: Encrypted with AWS KMS (AES-256-GCM)
- **Key Management**: AWS KMS with automatic rotation (90 days)
- **Tablespace Encryption**: PostgreSQL transparent data encryption (TDE)

**In Transit**:
- **TLS/SSL**: Required for all database connections (enforced)
- **TLS Version**: TLS 1.3 only (TLS 1.2 disabled)
- **Certificate Verification**: Enabled (`sslmode=verify-full`)
- **Cipher Suites**: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256

**Application Connection String**:
```go
// Go example
connString := "postgres://user:pass@host:5432/db?sslmode=verify-full&sslrootcert=/path/to/ca.pem"
```

**Column-Level Encryption** (for PII beyond database encryption):
```sql
-- Install pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Encrypt sensitive data (not used in current schema, but available)
INSERT INTO users (email, phone_encrypted)
VALUES ($1, pgp_sym_encrypt($2, 'encryption_key_from_vault'));

-- Decrypt when needed (in authorized queries only)
SELECT email, pgp_sym_decrypt(phone_encrypted::bytea, 'encryption_key_from_vault') AS phone
FROM users
WHERE id = $1;
```

### Access Control

**Principle of Least Privilege**:
```sql
-- Application user (read/write on auth tables only)
CREATE USER suma_auth_app WITH PASSWORD 'complex_random_password';
GRANT CONNECT ON DATABASE suma_auth TO suma_auth_app;
GRANT USAGE ON SCHEMA public TO suma_auth_app;

-- Grant table permissions
GRANT SELECT, INSERT, UPDATE ON users TO suma_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_sessions TO suma_auth_app;
GRANT SELECT, INSERT, UPDATE ON devices TO suma_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON otp_codes TO suma_auth_app;
GRANT SELECT, INSERT, UPDATE ON email_verification_tokens TO suma_auth_app;
GRANT SELECT, INSERT, UPDATE ON password_reset_tokens TO suma_auth_app;
GRANT INSERT ON security_events TO suma_auth_app;
GRANT SELECT, INSERT, UPDATE ON gdpr_consents TO suma_auth_app;
GRANT INSERT ON password_history TO suma_auth_app;
GRANT SELECT, INSERT, UPDATE ON email_queue TO suma_auth_app;

-- Grant sequence permissions
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO suma_auth_app;

-- Read-only user (for reporting and analytics)
CREATE USER suma_auth_readonly WITH PASSWORD 'complex_random_password';
GRANT CONNECT ON DATABASE suma_auth TO suma_auth_readonly;
GRANT USAGE ON SCHEMA public TO suma_auth_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO suma_auth_readonly;

-- Admin user (for migrations)
CREATE USER suma_auth_admin WITH PASSWORD 'complex_random_password';
GRANT ALL PRIVILEGES ON DATABASE suma_auth TO suma_auth_admin;

-- Revoke dangerous permissions from PUBLIC
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE suma_auth FROM PUBLIC;
```

**Row-Level Security** (future enhancement):
```sql
-- Enable RLS on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own data
CREATE POLICY user_isolation_policy ON users
    FOR SELECT
    USING (id = current_setting('app.current_user_id')::uuid);

-- Application sets user context
SET app.current_user_id = 'user-uuid';
```

### Audit Logging

**PostgreSQL Logging Configuration**:
```sql
-- Log all DDL (schema changes)
ALTER SYSTEM SET log_statement = 'ddl';

-- Log connections and disconnections
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';

-- Log failed connection attempts
ALTER SYSTEM SET log_failed_authentication_attempts = 'on';

-- Log slow queries (>1 second)
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- Log query execution plans for slow queries
ALTER SYSTEM SET auto_explain.log_min_duration = 1000;
ALTER SYSTEM SET auto_explain.log_analyze = 'on';
```

**Application-Level Audit Trail** (security_events table):
```sql
-- Log login attempt
INSERT INTO security_events (user_id, event_type, event_category, severity, description, ip_address, success)
VALUES ($1, 'login_attempt', 'auth', 'info', 'User login attempt', $2, true);

-- Log failed login
INSERT INTO security_events (user_id, event_type, event_category, severity, description, ip_address, success, failure_reason)
VALUES ($1, 'login_failed', 'auth', 'warning', 'Failed login attempt', $2, false, 'invalid_password');

-- Log account lockout
INSERT INTO security_events (user_id, event_type, event_category, severity, description, ip_address, success)
VALUES ($1, 'account_locked', 'security', 'critical', 'Account locked due to failed login attempts', $2, true);

-- Log password change
INSERT INTO security_events (user_id, event_type, event_category, severity, description, ip_address, success)
VALUES ($1, 'password_changed', 'account', 'info', 'Password changed successfully', $2, true);

-- Log 2FA enabled
INSERT INTO security_events (user_id, event_type, event_category, severity, description, metadata, success)
VALUES ($1, 'mfa_enabled', 'security', 'info', '2FA enabled', '{"method": "email_otp"}', true);

-- Log GDPR data access
INSERT INTO security_events (user_id, event_type, event_category, severity, description, success)
VALUES ($1, 'gdpr_data_access', 'gdpr', 'info', 'User accessed personal data export', true);
```

## Migration Strategy

### Schema Migrations

**Tool**: Flyway (Java-based, version control for database)

**Migration Files Structure**:
```
migrations/
├── V1__initial_schema.sql
├── V2__add_mfa_fields.sql
├── V3__add_devices_table.sql
├── V4__add_security_events_partitioning.sql
├── V5__add_gdpr_consents.sql
└── V6__add_email_queue.sql
```

**Example Migration** (V2__add_mfa_fields.sql):
```sql
-- V2: Add MFA fields to users table
BEGIN;

-- Add MFA columns
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN mfa_method VARCHAR(20) CHECK (mfa_method IN ('email_otp', 'sms_otp', 'totp', 'biometric'));
ALTER TABLE users ADD COLUMN backup_codes_hash TEXT[];

-- Add index for MFA users
CREATE INDEX idx_users_mfa_enabled ON users(mfa_enabled) WHERE status = 'active';

-- Update schema version
INSERT INTO flyway_schema_history (version, description, script, checksum, installed_by, execution_time, success)
VALUES ('2', 'Add MFA fields', 'V2__add_mfa_fields.sql', 12345, 'admin', 150, true);

COMMIT;
```

**Rollback Migration** (V2_rollback__add_mfa_fields.sql):
```sql
BEGIN;

-- Drop index
DROP INDEX IF EXISTS idx_users_mfa_enabled;

-- Drop columns
ALTER TABLE users DROP COLUMN IF EXISTS backup_codes_hash;
ALTER TABLE users DROP COLUMN IF EXISTS mfa_method;
ALTER TABLE users DROP COLUMN IF EXISTS mfa_enabled;

-- Remove schema version
DELETE FROM flyway_schema_history WHERE version = '2';

COMMIT;
```

### Zero-Downtime Migrations

**Adding Column** (safe):
```sql
-- 1. Add column as nullable (fast, no table rewrite)
ALTER TABLE users ADD COLUMN phone VARCHAR(20);

-- 2. Add constraint check (does not lock table)
ALTER TABLE users ADD CONSTRAINT users_phone_format 
    CHECK (phone IS NULL OR phone ~ '^\+[1-9]\d{1,14}$') NOT VALID;

-- 3. Validate constraint (checks existing data, allows reads)
ALTER TABLE users VALIDATE CONSTRAINT users_phone_format;

-- 4. Backfill data in batches (off-peak hours)
DO $$
DECLARE
    batch_size INT := 1000;
    total_updated INT := 0;
BEGIN
    LOOP
        WITH batch AS (
            SELECT id FROM users
            WHERE phone IS NULL
            LIMIT batch_size
            FOR UPDATE SKIP LOCKED
        )
        UPDATE users SET phone = ''
        WHERE id IN (SELECT id FROM batch);
        
        GET DIAGNOSTICS total_updated = ROW_COUNT;
        EXIT WHEN total_updated = 0;
        
        -- Delay between batches
        PERFORM pg_sleep(0.1);
    END LOOP;
END $$;

-- 5. Add NOT NULL constraint (fast after backfill)
ALTER TABLE users ALTER COLUMN phone SET NOT NULL;
```

**Renaming Column** (zero-downtime):
```sql
-- 1. Add new column
ALTER TABLE users ADD COLUMN email_address VARCHAR(255);

-- 2. Backfill data
UPDATE users SET email_address = email WHERE email_address IS NULL;

-- 3. Add index on new column
CREATE INDEX idx_users_email_address ON users(email_address);

-- 4. Deploy application version that writes to both columns

-- 5. Verify both columns in sync (monitoring)

-- 6. Deploy application version that reads from new column

-- 7. Drop old column (after monitoring period)
ALTER TABLE users DROP COLUMN email;

-- 8. Rename new column to old name (if desired)
ALTER TABLE users RENAME COLUMN email_address TO email;
```

**Adding Index** (concurrent, no locks):
```sql
-- CREATE INDEX CONCURRENTLY does not block writes
CREATE INDEX CONCURRENTLY idx_users_last_login ON users(last_login_at DESC);
```

## Best Practices

### DO
- ✅ Use TIMESTAMPTZ for all timestamps (stores UTC, displays in session timezone)
- ✅ Use UUIDs for user-facing IDs (prevents enumeration attacks)
- ✅ Use connection pooling (PgBouncer or application-level)
- ✅ Create indexes on all foreign keys
- ✅ Use prepared statements for all queries (prevents SQL injection)
- ✅ Monitor slow queries daily (>100ms requires investigation)
- ✅ Run VACUUM ANALYZE weekly
- ✅ Test backups monthly (restore to test environment)
- ✅ Use transactions for multi-step operations
- ✅ Add constraints for data integrity (CHECK, UNIQUE, NOT NULL)
- ✅ Use EXPLAIN ANALYZE for query optimization
- ✅ Soft delete user data (support GDPR right to erasure)
- ✅ Log all security events (audit trail)
- ✅ Use partial indexes for filtered queries
- ✅ Partition large tables (>100M rows)

### DON'T
- ❌ Use SELECT * in production (specify columns)
- ❌ Create too many indexes (every index slows writes)
- ❌ Store large files in database (use S3, store URLs)
- ❌ Use LIKE '%search%' without full-text index
- ❌ Forget to vacuum/analyze (causes bloat)
- ❌ Hardcode database credentials (use environment variables or secrets manager)
- ❌ Allow unbounded queries (always use LIMIT or pagination)
- ❌ Ignore connection limits (causes "too many connections" errors)
- ❌ Use TIMESTAMP without timezone (always use TIMESTAMPTZ)
- ❌ Use MD5 or SHA-1 for passwords (use Argon2id)
- ❌ Store plaintext passwords or tokens (always hash)
- ❌ Allow SQL injection (use parameterized queries)
- ❌ Over-normalize (balance normalization vs query complexity)
- ❌ Use OFFSET for large paginations (use keyset pagination)
- ❌ Run migrations without testing rollback

## Appendix

### Database Growth Projections

| Month | Users | Active Sessions | Security Events | Total DB Size | Query Load (qps) | Estimated Cost (AWS RDS) |
|-------|-------|-----------------|-----------------|---------------|------------------|--------------------------|
| 1 | 1K | 500 | 50K | 500 MB | 50 | $75/month (db.t3.medium) |
| 3 | 5K | 2.5K | 300K | 2 GB | 200 | $75/month |
| 6 | 15K | 8K | 1.2M | 6 GB | 600 | $75/month |
| 12 | 50K | 30K | 5M | 20 GB | 2000 | $150/month (db.m5.large) |
| 18 | 100K | 60K | 12M | 40 GB | 4000 | $300/month (db.m5.xlarge + 1 replica) |
| 24 | 200K | 120K | 30M | 80 GB | 8000 | $600/month (db.m5.2xlarge + 2 replicas) |

**Assumptions**:
- Average 5 security events per user per month
- 30% of users have active sessions
- Partition security_events after month 6
- Add read replica at month 12
- Security events archived to S3 after 90 days

### Redis Usage Projections

| Month | Active Sessions | OTPs | Rate Limiters | Memory Used | Estimated Cost (ElastiCache) |
|-------|-----------------|------|---------------|-------------|------------------------------|
| 1 | 500 | 50 | 10K keys | 100 MB | $50/month (cache.t3.micro) |
| 6 | 8K | 500 | 100K keys | 1 GB | $50/month |
| 12 | 30K | 2K | 300K keys | 3 GB | $100/month (cache.t3.small) |
| 24 | 120K | 8K | 1M keys | 10 GB | $250/month (cache.m5.large) |

### Glossary

- **ACID**: Atomicity, Consistency, Isolation, Durability - properties of database transactions
- **PITR**: Point-In-Time Recovery - ability to restore database to any point in time
- **WAL**: Write-Ahead Log - PostgreSQL transaction log for crash recovery and replication
- **RTO**: Recovery Time Objective - maximum acceptable downtime
- **RPO**: Recovery Point Objective - maximum acceptable data loss
- **Soft Delete**: Marking records as deleted without physically removing them
- **Partitioning**: Splitting large tables into smaller physical pieces
- **Sharding**: Splitting data across multiple database servers
- **Connection Pooling**: Reusing database connections to reduce overhead
- **Index Hit Rate**: Percentage of queries using indexes vs sequential scans
- **Cache Hit Rate**: Percentage of queries served from memory vs disk
- **Replication Lag**: Time delay between primary and replica databases
- **JSONB**: Binary JSON storage in PostgreSQL (faster than JSON)
- **GIN Index**: Generalized Inverted Index for full-text search and JSONB
- **B-Tree Index**: Balanced tree index for equality and range queries
- **Partial Index**: Index on subset of rows matching a condition
- **Covering Index**: Index that includes all columns needed by a query
