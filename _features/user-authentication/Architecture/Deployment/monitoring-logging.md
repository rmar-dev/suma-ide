---
layout: default
title: Monitoring Logging
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

```markdown
# arch-monitoring-logging-generator

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Security & Compliance
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Overview

This document defines the comprehensive monitoring and logging strategy for the SUMA Finance user registration and authentication system. Given the critical nature of authentication in a fintech application, robust monitoring and logging are essential for security, compliance (GDPR, PCI-DSS, SOC 2), operational excellence, and incident response.

### 1.1 Objectives

- **Security Monitoring**: Detect and alert on suspicious authentication activities in real-time
- **Compliance**: Maintain comprehensive audit trails for regulatory requirements
- **Performance**: Track system health and identify performance bottlenecks
- **Incident Response**: Enable rapid investigation and resolution of security incidents
- **Business Intelligence**: Provide insights into user authentication patterns

### 1.2 Scope

- Authentication endpoints (login, registration, password reset, 2FA)
- Session management operations
- Security events (failed logins, account lockouts, suspicious activities)
- System performance metrics
- Compliance audit trails
- Error tracking and exception handling

---

## 2. Logging Architecture

### 2.1 Logging Layers

#### Application Logs
- **Purpose**: Capture business logic, authentication flows, and application state
- **Format**: Structured JSON with correlation IDs
- **Storage**: CloudWatch Logs → S3 (30-day retention hot, 7-year cold archive)
- **Tools**: Go structured logging (zerolog/zap)

#### Security Audit Logs
- **Purpose**: GDPR/SOC2 compliance, immutable audit trail
- **Format**: Structured JSON with digital signatures (HMAC-SHA256)
- **Storage**: Dedicated PostgreSQL audit table + S3 (immutable, 10-year retention)
- **Tools**: Custom audit logger with cryptographic integrity

#### Access Logs
- **Purpose**: Track all API requests to authentication endpoints
- **Format**: Extended NCSA/Combined Log Format
- **Storage**: CloudWatch Logs → S3
- **Tools**: AWS ALB access logs

#### System Logs
- **Purpose**: Infrastructure health, container metrics, system errors
- **Format**: Varies by service (Docker logs, ECS logs)
- **Storage**: CloudWatch Logs
- **Tools**: AWS CloudWatch agent, FluentBit

### 2.2 Log Aggregation Pipeline

```
Application → FluentBit → CloudWatch Logs → Datadog
                                ↓
                        S3 (Long-term archive)
                                ↓
                        Athena (Ad-hoc queries)
```

### 2.3 Log Levels

| Level | Use Case | Examples | Retention |
|-------|----------|----------|-----------|
| **TRACE** | Detailed debugging (disabled in production) | Token generation steps, crypto operations | N/A |
| **DEBUG** | Development troubleshooting | Request/response payloads (sanitized), cache hits/misses | 7 days |
| **INFO** | Normal operations | Successful login, registration, password reset initiated | 30 days |
| **WARN** | Non-critical issues | Rate limit approaching, slow query, deprecated endpoint used | 90 days |
| **ERROR** | Recoverable errors | Invalid credentials, expired tokens, email delivery failure | 1 year |
| **FATAL** | System failures | Database connection lost, Redis unavailable, unhandled panic | 7 years |

---

## 3. Security Event Logging

### 3.1 Critical Security Events (OWASP A09 Compliance)

#### Authentication Events
```json
{
  "timestamp": "2025-10-29T12:34:56.789Z",
  "event_type": "authentication",
  "event_name": "login_attempt",
  "status": "success|failure|mfa_required",
  "user_id": "uuid",
  "email": "user@example.com",
  "ip_address": "203.0.113.45",
  "user_agent": "Mozilla/5.0...",
  "device_fingerprint": "hash",
  "geolocation": {"country": "PT", "city": "Lisbon", "lat": 38.7223, "lon": -9.1393},
  "session_id": "uuid",
  "mfa_method": "email_otp|null",
  "failure_reason": "invalid_password|account_locked|mfa_failed",
  "failed_attempt_count": 2,
  "correlation_id": "req-uuid",
  "integrity_signature": "hmac-sha256-hash"
}
```

#### Account Management Events
```json
{
  "timestamp": "2025-10-29T12:34:56.789Z",
  "event_type": "account_management",
  "event_name": "registration|password_change|account_lockout|2fa_enabled",
  "user_id": "uuid",
  "email": "user@example.com",
  "ip_address": "203.0.113.45",
  "changed_fields": ["password", "2fa_enabled"],
  "gdpr_consent": {
    "marketing": true,
    "analytics": true,
    "timestamp": "2025-10-29T12:34:56.789Z"
  },
  "correlation_id": "req-uuid",
  "integrity_signature": "hmac-sha256-hash"
}
```

#### Session Events
```json
{
  "timestamp": "2025-10-29T12:34:56.789Z",
  "event_type": "session_management",
  "event_name": "session_created|token_refreshed|session_expired|logout",
  "user_id": "uuid",
  "session_id": "uuid",
  "access_token_id": "jti",
  "refresh_token_id": "jti",
  "token_expiry": "2025-10-29T12:49:56.789Z",
  "ip_address": "203.0.113.45",
  "device_id": "uuid",
  "correlation_id": "req-uuid"
}
```

#### Security Violations
```json
{
  "timestamp": "2025-10-29T12:34:56.789Z",
  "event_type": "security_violation",
  "event_name": "brute_force_detected|token_reuse_detected|suspicious_geolocation|rate_limit_exceeded",
  "severity": "critical|high|medium|low",
  "user_id": "uuid|null",
  "ip_address": "203.0.113.45",
  "description": "5 failed login attempts in 2 minutes",
  "action_taken": "account_locked|ip_blocked|alert_sent",
  "correlation_id": "req-uuid",
  "alert_id": "uuid"
}
```

### 3.2 PII Handling in Logs

**NEVER LOG**:
- Plaintext passwords
- Raw JWT tokens (log JTI claim only)
- OTP codes
- Security answers
- Payment card data
- Full session tokens

**PSEUDONYMIZATION**:
- Email addresses: Hash or mask (`us**@ex****e.com`)
- IP addresses: Hash with daily rotating salt for analytics
- Device fingerprints: One-way hash

**ENCRYPTED STORAGE**:
- All audit logs containing PII encrypted at rest (AES-256-GCM)
- Encryption keys managed via AWS KMS with 90-day rotation

---

## 4. Monitoring Strategy

### 4.1 Metrics Collection

#### Application Metrics (Datadog)

**Authentication Metrics**:
- `auth.login.attempts.total` (counter) - tags: status, mfa_required
- `auth.login.success.rate` (gauge) - Success rate percentage
- `auth.login.duration` (histogram) - Response time distribution
- `auth.registration.total` (counter)
- `auth.registration.verified` (counter) - Email verification completion
- `auth.password_reset.requests` (counter)
- `auth.2fa.enabled.total` (counter)
- `auth.2fa.verification.attempts` (counter) - tags: status

**Session Metrics**:
- `session.created.total` (counter)
- `session.active.count` (gauge) - Current active sessions
- `session.refresh.total` (counter)
- `session.expired.total` (counter)
- `session.duration` (histogram) - Session lifetime

**Security Metrics**:
- `security.failed_login.total` (counter) - tags: reason
- `security.account_lockout.total` (counter)
- `security.brute_force.detected` (counter)
- `security.suspicious_activity.total` (counter) - tags: type
- `security.rate_limit.exceeded` (counter) - tags: endpoint, user_id

**Performance Metrics**:
- `api.request.duration` (histogram) - tags: endpoint, status_code
- `api.request.rate` (counter) - tags: endpoint
- `db.query.duration` (histogram) - tags: query_type
- `cache.hit.rate` (gauge) - Redis cache effectiveness
- `email.delivery.duration` (histogram)
- `otp.generation.duration` (histogram)

#### Infrastructure Metrics (CloudWatch + Datadog)

- **ECS Metrics**: CPU, memory, network I/O per service
- **RDS Metrics**: Connections, slow queries, replication lag
- **Redis Metrics**: Memory usage, evictions, command latency
- **ALB Metrics**: Request count, target response time, HTTP 5xx errors
- **Lambda Metrics**: Duration, invocations, errors (if using Lambda)

### 4.2 Health Checks

#### Liveness Probe
```http
GET /health/live
Response: 200 OK {"status": "alive"}
```
- **Frequency**: Every 10 seconds
- **Failure Action**: Container restart

#### Readiness Probe
```http
GET /health/ready
Response: 200 OK {
  "status": "ready",
  "dependencies": {
    "database": "ok",
    "redis": "ok",
    "email_service": "ok"
  }
}
```
- **Frequency**: Every 15 seconds
- **Failure Action**: Remove from load balancer

#### Deep Health Check
```http
GET /health/deep
Response: 200 OK {
  "status": "healthy",
  "checks": {
    "database_connection": {"status": "ok", "latency_ms": 12},
    "redis_connection": {"status": "ok", "latency_ms": 3},
    "email_service": {"status": "ok", "latency_ms": 250},
    "jwt_signing": {"status": "ok", "test_sign_ms": 2},
    "encryption_service": {"status": "ok", "test_encrypt_ms": 5}
  },
  "timestamp": "2025-10-29T12:34:56.789Z"
}
```
- **Frequency**: Every 5 minutes
- **Purpose**: Comprehensive system validation

---

## 5. Alerting Strategy

### 5.1 Alert Severity Levels

| Severity | Response Time | Escalation | Examples |
|----------|---------------|------------|----------|
| **P0 - Critical** | Immediate (5 min) | PagerDuty → Phone call | Authentication service down, database unavailable |
| **P1 - High** | 15 minutes | PagerDuty → SMS | >10% login failure rate, brute force attack detected |
| **P2 - Medium** | 1 hour | Email + Slack | >5% email delivery failure, slow API responses |
| **P3 - Low** | 4 hours | Slack | Rate limit warnings, deprecated endpoint usage |

### 5.2 Security Alerts (Datadog Monitors)

#### Brute Force Detection
```
Alert: auth.failed_login.total > 50 in 5 minutes for same IP
Severity: P1 - High
Action: 
  - Block IP at WAF level
  - Send alert to security team
  - Create incident ticket
```

#### Account Lockout Spike
```
Alert: security.account_lockout.total > 10 in 10 minutes
Severity: P1 - High
Action:
  - Alert security team
  - Investigate for credential stuffing attack
```

#### Impossible Travel Detection
```
Alert: Login from two geolocations >500km apart within 1 hour for same user
Severity: P1 - High
Action:
  - Force logout all sessions
  - Require password reset
  - Send email alert to user
```

#### Token Reuse Detection
```
Alert: Refresh token reuse detected (OWASP A07)
Severity: P0 - Critical
Action:
  - Revoke all tokens for user
  - Force logout
  - Lock account
  - Create security incident
```

#### High Login Failure Rate
```
Alert: auth.login.success.rate < 90% for 10 minutes
Severity: P1 - High
Action:
  - Alert on-call engineer
  - Check for system issues
  - Investigate for attack patterns
```

### 5.3 Performance Alerts

#### Slow Authentication API
```
Alert: p95(api.request.duration) > 500ms for /auth/** endpoints
Severity: P2 - Medium
Action:
  - Alert engineering team
  - Check database query performance
  - Verify Redis cache hit rate
```

#### High Error Rate
```
Alert: HTTP 5xx errors > 1% of requests
Severity: P1 - High
Action:
  - Page on-call engineer
  - Check application logs
  - Verify infrastructure health
```

#### Email Delivery Failure
```
Alert: email.delivery.failure.rate > 5%
Severity: P2 - Medium
Action:
  - Check SendGrid status
  - Verify email templates
  - Switch to SES failover if needed
```

### 5.4 Compliance Alerts

#### Audit Log Integrity Failure
```
Alert: Audit log signature verification failed
Severity: P0 - Critical
Action:
  - Immediate security investigation
  - Preserve evidence
  - Notify compliance team
```

#### GDPR Consent Missing
```
Alert: Registration completed without GDPR consent timestamp
Severity: P1 - High
Action:
  - Alert compliance team
  - Review registration flow
  - Audit affected accounts
```

---

## 6. Dashboards

### 6.1 Real-Time Security Dashboard (Datadog)

**Purpose**: 24/7 SOC monitoring

**Widgets**:
- Login success rate (last 1 hour, 24 hours)
- Failed login attempts by reason (pie chart)
- Active sessions count (timeseries)
- Brute force attempts detected (counter)
- Account lockouts (timeseries)
- Suspicious activity heatmap (geolocation)
- Top 10 IPs by failed login attempts
- 2FA adoption rate (gauge)
- Recent security violations (event stream)

### 6.2 Authentication Performance Dashboard

**Purpose**: Engineering team performance monitoring

**Widgets**:
- API response time (p50, p95, p99) by endpoint
- Request rate by endpoint (timeseries)
- Error rate by endpoint (timeseries)
- Database query duration (histogram)
- Redis cache hit rate (gauge)
- Email delivery time (histogram)
- Concurrent sessions (gauge)
- Session creation rate (timeseries)

### 6.3 Compliance Audit Dashboard

**Purpose**: Compliance team, auditor access

**Widgets**:
- Total registrations with GDPR consent (counter)
- Consent withdrawal requests (timeseries)
- Data subject access requests (DSAR) (counter)
- Audit log completeness (gauge - 100% expected)
- Security events logged (counter)
- Password policy compliance rate (gauge)
- 2FA enrollment rate (gauge)
- Account lockout incidents (timeseries)

### 6.4 Business Intelligence Dashboard

**Purpose**: Product and business teams

**Widgets**:
- Daily/weekly/monthly registrations (timeseries)
- Registration funnel completion rate (funnel chart)
- Email verification rate (gauge)
- Login frequency distribution (histogram)
- Authentication method breakdown (OAuth vs email/password)
- Device type distribution (mobile vs web)
- Geographic user distribution (map)
- Session duration average (gauge)

---

## 7. Log Retention and Archival

### 7.1 Retention Policy

| Log Type | Hot Storage (CloudWatch) | Warm Storage (S3) | Cold Archive (Glacier) | Total Retention |
|----------|--------------------------|-------------------|------------------------|-----------------|
| **Security Audit Logs** | 90 days | 1 year | 9 years | 10 years (SOC 2) |
| **GDPR Compliance Logs** | 90 days | 1 year | 6 years | 7 years (GDPR) |
| **Application Logs** | 30 days | 1 year | - | 1 year + 30 days |
| **Access Logs** | 30 days | 1 year | - | 1 year + 30 days |
| **Error Logs** | 90 days | 1 year | - | 1 year + 90 days |
| **System Logs** | 7 days | 30 days | - | 37 days |

### 7.2 Archival Process

**Automated S3 Lifecycle Policies**:
```yaml
- Transition to S3 Intelligent-Tiering after 30 days
- Transition to Glacier after 1 year
- Enable S3 Object Lock for audit logs (immutability)
- Enable versioning for compliance logs
```

**Athena Integration**:
- Enable querying of archived logs via AWS Athena
- Partition by date for efficient queries
- Create materialized views for common compliance queries

---

## 8. Incident Response Integration

### 8.1 Security Incident Workflow

```
Detection (Datadog Alert)
    ↓
Automatic Response (WAF block, account lock)
    ↓
Incident Creation (PagerDuty + Jira)
    ↓
Log Preservation (snapshot to isolated S3 bucket)
    ↓
Forensic Analysis (Athena queries, log export)
    ↓
Remediation
    ↓
Post-Incident Review
```

### 8.2 Log Forensics Tools

**Athena Query Examples**:

```sql
-- Find all activities for compromised user
SELECT *
FROM audit_logs
WHERE user_id = 'uuid'
  AND timestamp BETWEEN '2025-10-29' AND '2025-10-30'
ORDER BY timestamp;

-- Detect credential stuffing attack
SELECT ip_address, COUNT(DISTINCT email) AS unique_emails, COUNT(*) AS attempts
FROM authentication_logs
WHERE event_name = 'login_attempt'
  AND status = 'failure'
  AND timestamp > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
HAVING COUNT(DISTINCT email) > 20;

-- Find impossible travel
WITH login_locations AS (
  SELECT user_id, timestamp, geolocation, 
         LAG(geolocation) OVER (PARTITION BY user_id ORDER BY timestamp) AS prev_location,
         LAG(timestamp) OVER (PARTITION BY user_id ORDER BY timestamp) AS prev_timestamp
  FROM authentication_logs
  WHERE event_name = 'login_attempt' AND status = 'success'
)
SELECT * FROM login_locations
WHERE ST_Distance(geolocation, prev_location) > 500000 -- 500km
  AND EXTRACT(EPOCH FROM (timestamp - prev_timestamp)) < 3600; -- 1 hour
```

---

## 9. GDPR Compliance

### 9.1 Right to Access (Article 15)

**Automated Export**:
```bash
GET /api/v1/users/{user_id}/audit-logs
Authorization: Bearer {admin_token}

Response: 
{
  "user_id": "uuid",
  "email": "user@example.com",
  "audit_trail": [
    {
      "timestamp": "2025-10-29T12:34:56.789Z",
      "event": "login_attempt",
      "ip_address": "203.0.113.45",
      "location": "Lisbon, PT"
    }
  ]
}
```

### 9.2 Right to Erasure (Article 17)

**Log Anonymization**:
- Replace user_id with anonymized hash
- Remove email, IP, geolocation
- Retain aggregated statistics only
- Maintain integrity signatures for remaining data

### 9.3 Data Breach Notification (Article 33)

**Automated Detection**:
- Alert on unauthorized access to audit logs
- Alert on bulk user data export
- Alert on privilege escalation

**72-Hour Notification**:
- Automated incident report generation
- Affected user identification from logs
- Evidence preservation in isolated S3 bucket

---

## 10. Performance Optimization

### 10.1 Log Sampling

**High-Volume Endpoints**:
- Sample INFO logs at 10% for `/auth/refresh-token`
- Sample DEBUG logs at 1% in production
- Always log ERROR and SECURITY events (no sampling)

### 10.2 Asynchronous Logging

**Implementation**:
- Use buffered log writers (10,000 entry buffer)
- Flush every 5 seconds or on buffer full
- Non-blocking writes to prevent request latency impact

### 10.3 Indexing Strategy

**CloudWatch Logs Insights**:
- Index on: `user_id`, `ip_address`, `event_name`, `timestamp`
- Create custom filters for common queries

**PostgreSQL Audit Table**:
```sql
CREATE INDEX idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_correlation ON audit_logs(correlation_id);
```

---

## 11. Tools and Technologies

### 11.1 Logging Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Log Collection** | FluentBit | Lightweight log forwarder from containers |
| **Log Aggregation** | AWS CloudWatch Logs | Central log storage and basic analysis |
| **Log Analysis** | Datadog | Real-time monitoring, dashboards, alerting |
| **Long-term Storage** | S3 + Glacier | Cost-effective archival |
| **Ad-hoc Queries** | AWS Athena | SQL queries on archived logs |
| **Error Tracking** | Sentry | Exception monitoring and stack traces |

### 11.2 Monitoring Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Metrics Collection** | Datadog Agent | System and custom application metrics |
| **APM** | Datadog APM | Distributed tracing, request profiling |
| **Synthetic Monitoring** | Datadog Synthetics | Uptime checks, API tests |
| **RUM** | Datadog RUM | Frontend user experience monitoring |
| **Alerting** | Datadog Monitors + PagerDuty | Alert routing and escalation |

### 11.3 Security Monitoring

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **SIEM** | Datadog Security Monitoring | Threat detection, correlation |
| **WAF** | AWS WAF | DDoS protection, IP blocking |
| **IDS/IPS** | AWS GuardDuty | Threat intelligence, anomaly detection |
| **Vulnerability Scanning** | Snyk | Dependency and container scanning |

---

## 12. Testing Strategy

### 12.1 Log Testing

**Unit Tests**:
```go
func TestSecurityEventLogging(t *testing.T) {
    logger := NewAuditLogger()
    
    event := SecurityEvent{
        EventType: "authentication",
        EventName: "login_attempt",
        Status: "failure",
        UserID: "test-user-id",
    }
    
    logger.LogSecurityEvent(event)
    
    // Verify log entry created
    // Verify integrity signature valid
    // Verify PII redacted
}
```

**Integration Tests**:
- Verify logs appear in CloudWatch within 30 seconds
- Verify Datadog receives metrics within 60 seconds
- Verify alerts trigger correctly
- Verify log integrity signatures

### 12.2 Monitoring Testing

**Chaos Engineering**:
- Simulate database failure → verify alerts fire
- Simulate brute force attack → verify automatic blocking
- Simulate high latency → verify performance alerts
- Inject authentication errors → verify error tracking

**Load Testing**:
- Generate 1000 req/s → verify metrics accuracy
- Verify log sampling doesn't drop critical events
- Verify dashboard performance under high load

---

## 13. Runbook: Common Monitoring Scenarios

### 13.1 High Login Failure Rate

**Investigation Steps**:
1. Check Datadog dashboard for failure reasons
2. Query recent failed attempts by IP:
   ```sql
   SELECT ip_address, COUNT(*) as attempts, failure_reason
   FROM authentication_logs
   WHERE timestamp > NOW() - INTERVAL '15 minutes'
     AND status = 'failure'
   GROUP BY ip_address, failure_reason
   ORDER BY attempts DESC;
   ```
3. Check for credential stuffing pattern (many different emails, same IP)
4. Check for system issues (database slow, Redis down)
5. Take action: block malicious IPs, scale resources, notify users

### 13.2 Missing Audit Logs

**Investigation Steps**:
1. Check FluentBit status: `kubectl logs -n logging fluentbit-*`
2. Verify CloudWatch Logs receiving data
3. Check log integrity signature job status
4. Query for gaps in log sequence numbers
5. Escalate to P0 if tampering suspected

### 13.3 Performance Degradation

**Investigation Steps**:
1. Check APM traces for slow requests
2. Identify slow database queries in RDS Performance Insights
3. Check Redis cache hit rate
4. Verify external service latency (SendGrid, etc.)
5. Scale resources if needed (horizontal or vertical)

---

## 14. Continuous Improvement

### 14.1 Monthly Review Checklist

- [ ] Review alert fatigue (false positive rate)
- [ ] Tune alert thresholds based on actual traffic patterns
- [ ] Analyze security incidents and update detection rules
- [ ] Review log storage costs and optimize retention
- [ ] Audit compliance log completeness
- [ ] Update dashboards based on team feedback
- [ ] Test incident response procedures

### 14.2 Quarterly Security Audit

- [ ] Penetration test authentication endpoints
- [ ] Verify audit log integrity (random sample)
- [ ] Review access controls to monitoring systems
- [ ] Update threat detection rules
- [ ] Compliance framework review (GDPR, SOC 2)
- [ ] Disaster recovery drill for logging infrastructure

---

## 15. Cost Optimization

### 15.1 Estimated Monthly Costs (AWS + Datadog)

| Service | Estimated Cost | Notes |
|---------|----------------|-------|
| CloudWatch Logs | $150 | 100GB ingestion, 90-day retention |
| S3 Storage | $50 | 500GB standard, 5TB Glacier |
| Datadog APM | $500 | 10 hosts, 1M spans/month |
| Datadog Logs | $300 | 50GB ingestion/month |
| Athena Queries | $20 | Ad-hoc forensic queries |
| Sentry | $100 | 100K events/month |
| **Total** | **$1,120/month** | Scales with traffic |

### 15.2 Cost Reduction Strategies

- Use log sampling for high-volume, low-value logs
- Archive cold logs to Glacier Deep Archive
- Use CloudWatch Logs Insights instead of Datadog for simple queries
- Optimize metric cardinality (avoid unbounded tags like user_id)
- Use reserved capacity for predictable workloads

---

## 16. Appendix

### 16.1 Correlation ID Implementation

**Go Example**:
```go
func CorrelationMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        correlationID := c.GetHeader("X-Correlation-ID")
        if correlationID == "" {
            correlationID = uuid.New().String()
        }
        
        c.Set("correlation_id", correlationID)
        c.Header("X-Correlation-ID", correlationID)
        
        c.Next()
    }
}
```

### 16.2 Structured Logging Format

**Standard Log Entry**:
```json
{
  "timestamp": "2025-10-29T12:34:56.789Z",
  "level": "INFO",
  "service": "auth-service",
  "version": "1.2.3",
  "environment": "production",
  "correlation_id": "req-uuid",
  "trace_id": "datadog-trace-id",
  "user_id": "uuid",
  "ip_address": "203.0.113.45",
  "message": "User login successful",
  "context": {
    "endpoint": "/auth/login",
    "method": "POST",
    "status_code": 200,
    "duration_ms": 145,
    "mfa_required": true
  }
}
```

### 16.3 Alert Contact Matrix

| Severity | Contact Method | Recipients |
|----------|---------------|------------|
| P0 | PagerDuty → Phone | On-call engineer, Security lead |
| P1 | PagerDuty → SMS | On-call engineer |
| P2 | Email + Slack | Engineering team |
| P3 | Slack only | Engineering team |

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Owner**: Security & Infrastructure Team
**Review Cycle**: Quarterly
