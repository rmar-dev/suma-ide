---
layout: default
title: Security Architecture
nav_exclude: true
---



# Security Architecture

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Identity and Access Management (IAM)
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Executive Summary

This document defines the security architecture for SUMA Finance's user registration and authentication system. The architecture enforces defense-in-depth principles, zero-trust access controls, and compliance with GDPR, PCI-DSS, SOC 2, and ISO 27001 standards.

**Key Security Objectives:**
- Protect user credentials with military-grade cryptography
- Prevent unauthorized access through multi-factor authentication
- Detect and respond to authentication threats in real-time
- Ensure regulatory compliance across all authentication flows
- Maintain audit trails for forensic analysis and compliance reporting

---

## 2. Threat Model

### 2.1 Assets

| Asset | Classification | Impact if Compromised |
|-------|---------------|----------------------|
| User passwords | Critical | Full account takeover |
| JWT access tokens | High | Session hijacking (15 min window) |
| JWT refresh tokens | Critical | Long-term account access |
| Email verification tokens | High | Unauthorized account activation |
| Password reset tokens | Critical | Account takeover |
| 2FA OTP codes | High | MFA bypass |
| User PII (email, phone) | Critical | GDPR breach, identity theft |
| Session data (Redis) | High | Session hijacking |
| Signing keys | Critical | Token forgery, system-wide compromise |
| Database credentials | Critical | Full data breach |

### 2.2 Threat Actors

| Actor Type | Motivation | Capabilities | Likely Attacks |
|-----------|-----------|-------------|----------------|
| External attackers | Financial gain, data theft | Medium-High | Credential stuffing, phishing, SQL injection, XSS |
| Script kiddies | Notoriety | Low | Brute force, default credentials |
| Insider threats | Fraud, espionage | High | Privilege escalation, data exfiltration |
| APT groups | Espionage, sabotage | Very High | Zero-day exploits, social engineering |
| Competitors | Business intelligence | Medium | Account enumeration, scraping |

### 2.3 Attack Vectors (STRIDE Analysis)

**Spoofing Identity:**
- Credential theft via phishing or malware
- Session token theft from XSS attacks
- JWT forgery if signing keys compromised
- Email enumeration to identify valid accounts

**Tampering:**
- Password reset token manipulation
- JWT payload modification attempts
- SQL injection to modify user roles
- Man-in-the-middle attacks on unencrypted channels

**Repudiation:**
- Attacker denies unauthorized access after compromise
- User denies actions performed under their account
- Insufficient audit logging prevents investigation

**Information Disclosure:**
- Email enumeration via registration/login responses
- PII exposure through verbose error messages
- Session token leakage via insecure storage
- Database exposure via SQL injection

**Denial of Service:**
- Brute force attacks exhausting system resources
- Account lockout abuse (locking legitimate users)
- Email bombing via password reset abuse
- DDoS attacks on authentication endpoints

**Elevation of Privilege:**
- JWT role claim manipulation
- Horizontal privilege escalation (access other users' data)
- Vertical privilege escalation (user → admin)
- Session fixation attacks

### 2.4 Mitigations Mapping

| Threat | OWASP Category | Mitigation | Implementation |
|--------|---------------|-----------|----------------|
| Credential stuffing | A07 | Rate limiting + CAPTCHA | 5 attempts/min, CAPTCHA after 3 fails |
| Password cracking | A02 | Argon2id hashing | Memory-hard, CPU-hard parameters |
| Token theft | A02 | Short-lived tokens + rotation | 15 min access, 7 day refresh with rotation |
| Session hijacking | A07 | Secure cookies + device fingerprinting | HttpOnly, Secure, SameSite=Strict |
| SQL injection | A03 | Parameterized queries | All DB queries use prepared statements |
| XSS attacks | A03 | Output encoding + CSP | Context-aware encoding, strict CSP |
| MITM attacks | A02 | TLS 1.3 enforcement | All traffic encrypted, HSTS enabled |
| Account enumeration | A01 | Generic error messages | Same response for valid/invalid users |
| Privilege escalation | A01 | RBAC + least privilege | Role-based permissions, minimal grants |
| Audit tampering | A09 | Immutable logging | Write-only audit logs, integrity checks |

---

## 3. Security Architecture Layers

### 3.1 Network Security Layer

```
                    Internet
                       │
                       ▼
              ┌─────────────────┐
              │   AWS WAF       │ ◄── DDoS protection, rate limiting
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  CloudFront CDN  │ ◄── SSL/TLS termination, edge caching
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Application     │
              │  Load Balancer   │ ◄── TLS 1.3, X-Forwarded-For validation
              └────────┬────────┘
                       │
        ┌──────────────┴──────────────┐
        ▼                              ▼
   ┌─────────┐                  ┌─────────┐
   │  ECS    │                  │  ECS    │
   │ Container│                  │ Container│
   │ (VPC)   │                  │ (VPC)   │
   └────┬────┘                  └────┬────┘
        │                             │
        └──────────────┬──────────────┘
                       ▼
              ┌─────────────────┐
              │  RDS PostgreSQL  │ ◄── Encrypted at rest, VPC isolated
              │  (Private Subnet)│
              └─────────────────┘
```

**Controls:**
- WAF rules: SQL injection, XSS, rate limiting (1000 req/s global, 5 login/min per IP)
- Security Groups: Whitelist only necessary ports (443 for ALB, 5432 for RDS)
- Network ACLs: Deny traffic from known malicious IPs
- VPC isolation: Database in private subnet, no direct internet access
- TLS 1.3: Mandatory for all client-server communication
- HSTS: Enforce HTTPS with 1-year max-age

### 3.2 Application Security Layer

**Authentication Flow (Secure by Design):**

```
Registration Flow:
1. Client → POST /api/v1/auth/register
   ├─ Input validation (email format, password complexity)
   ├─ Password breach check (HaveIBeenPwned API)
   ├─ Argon2id hashing (time=3, memory=64MB, threads=4)
   ├─ Store user + consent timestamp
   ├─ Generate email verification token (HMAC-SHA256, 24h expiry)
   └─ SendGrid sends verification email

2. Client → GET /api/v1/auth/verify?token=xxx
   ├─ Token signature validation
   ├─ Token expiry check
   ├─ Mark account as verified
   ├─ Log verification event
   └─ Return success

Login Flow:
1. Client → POST /api/v1/auth/login
   ├─ Rate limiting check (5 attempts/min per IP)
   ├─ Account lockout check (5 failed attempts → 15 min cooldown)
   ├─ Retrieve user by email (constant-time lookup)
   ├─ Argon2id password verification (constant-time comparison)
   ├─ Check account verified status
   ├─ Generate 6-digit OTP (5 min expiry)
   ├─ Store OTP in Redis with TTL
   ├─ SendGrid sends OTP email
   └─ Return challenge ID

2. Client → POST /api/v1/auth/verify-otp
   ├─ Retrieve OTP from Redis by challenge ID
   ├─ Constant-time OTP comparison
   ├─ OTP expiry check
   ├─ Rate limiting (3 attempts per challenge)
   ├─ Generate JWT access token (15 min expiry, HS256)
   ├─ Generate JWT refresh token (7 day expiry, random 256-bit)
   ├─ Store refresh token in PostgreSQL (hashed with bcrypt)
   ├─ Store session in Redis (15 min idle timeout)
   ├─ Set HttpOnly, Secure, SameSite=Strict cookies
   ├─ Log successful login event
   └─ Return tokens + user data
```

**Security Controls:**
- Input validation: Server-side validation for all inputs (email regex, password length, special chars)
- Output encoding: Context-aware encoding (HTML, JavaScript, URL)
- Prepared statements: All SQL queries use parameterized inputs
- CSRF protection: Double-submit cookie pattern
- Clickjacking protection: X-Frame-Options: DENY
- XSS protection: Content-Security-Policy header
- Error handling: Generic error messages, detailed logs

### 3.3 Cryptographic Security Layer

**Cryptographic Inventory:**

| Asset | Algorithm | Key Size | Rotation Period | Storage |
|-------|-----------|---------|-----------------|---------|
| Passwords | Argon2id | N/A (memory=64MB) | N/A (one-way) | PostgreSQL |
| JWT signing key | HMAC-SHA256 | 256 bits | 90 days | AWS Secrets Manager |
| Refresh tokens | Random bytes + bcrypt | 256 bits random + bcrypt cost 12 | Per token | PostgreSQL |
| Verification tokens | HMAC-SHA256 | 256 bits | 24 hours (one-time) | Signed, no storage |
| Reset tokens | HMAC-SHA256 | 256 bits | 1 hour (one-time) | Signed, no storage |
| OTP codes | Random 6-digit | N/A | 5 minutes | Redis with TTL |
| TLS certificates | RSA 2048 / ECDSA P-256 | 2048 / 256 bits | 90 days (Let's Encrypt) | AWS Certificate Manager |
| Database encryption | AES-256-GCM | 256 bits | 365 days | AWS KMS |
| PII encryption | AES-256-GCM | 256 bits | 365 days | AWS KMS |

**Key Management:**
- Storage: AWS Secrets Manager for application secrets, AWS KMS for encryption keys
- Access control: IAM policies grant least-privilege access to secrets
- Rotation: Automated 90-day rotation for JWT signing keys, 365-day for KMS keys
- Backup: Cross-region replication for disaster recovery
- Audit: CloudTrail logs all key access events

**Cryptographic Best Practices:**
- Use only NIST-approved algorithms (Argon2id, AES-256, SHA-256, HMAC)
- Never implement custom cryptography
- Use secure random number generator (crypto.rand in Go)
- Constant-time comparison for secrets to prevent timing attacks
- Encrypt all PII at rest using AES-256-GCM with unique keys per record
- Use TLS 1.3 with perfect forward secrecy (ECDHE key exchange)

### 3.4 Data Security Layer

**Data Classification:**

| Data Type | Classification | Encryption at Rest | Encryption in Transit | Retention |
|-----------|---------------|-------------------|---------------------|-----------|
| Passwords (hashed) | Critical | AES-256-GCM | TLS 1.3 | Indefinite (until deletion) |
| Email addresses | PII | AES-256-GCM | TLS 1.3 | Until account deletion |
| Phone numbers | PII | AES-256-GCM | TLS 1.3 | Until account deletion |
| Session tokens | High | Redis with encryption | TLS 1.3 | 15 min idle / 8h absolute |
| Audit logs | High | AES-256-GCM | TLS 1.3 | 7 years (compliance) |
| Consent records | PII | AES-256-GCM | TLS 1.3 | 7 years (GDPR) |
| Login history | High | AES-256-GCM | TLS 1.3 | 90 days (rolling) |
| Device fingerprints | Medium | AES-256-GCM | TLS 1.3 | 365 days (rolling) |

**Database Security:**
- Encrypted storage: PostgreSQL with AWS RDS encryption (AES-256)
- Encrypted backups: Automated daily backups with encryption
- Network isolation: Database in private VPC subnet, no public access
- Access control: Application-specific database user with minimal grants
- Connection security: TLS-encrypted connections only (require_secure_transport=ON)
- Query monitoring: RDS Performance Insights for anomaly detection

**PII Protection (GDPR Compliance):**
- Data minimization: Collect only necessary fields (email required, phone optional)
- Purpose limitation: Use data only for authentication, not marketing (unless consented)
- Storage limitation: Delete data within 30 days of account deletion request
- Pseudonymization: User IDs are UUIDs, not sequential integers
- Encryption: All PII encrypted at rest with per-record keys
- Access logging: All PII access logged with user, timestamp, purpose

---

## 4. Identity and Access Management (IAM)

### 4.1 Authentication Mechanisms

**Primary Authentication: Email + Password**
- Password requirements: Min 12 chars, uppercase, lowercase, number, special char
- Password hashing: Argon2id with time=3, memory=64MB, parallelism=4
- Password breach check: HaveIBeenPwned API integration (k-anonymity model)
- Account lockout: 5 failed attempts → 15 min cooldown
- Generic error messages: "Invalid credentials" (prevent email enumeration)

**Multi-Factor Authentication: Email OTP**
- OTP generation: 6-digit random number (000000-999999)
- OTP storage: Redis with 5-minute TTL
- OTP verification: Constant-time comparison, max 3 attempts per challenge
- Rate limiting: Max 5 OTP requests per user per hour
- Backup codes: 10 single-use codes generated during 2FA setup (bcrypt hashed)

**Token-Based Authentication: JWT**
- Access token: Short-lived (15 min), contains user ID, roles, issued_at, expires_at
- Refresh token: Long-lived (7 days), random 256-bit value stored hashed in DB
- Token rotation: New refresh token issued on each use, old token invalidated
- Reuse detection: If revoked refresh token used, invalidate all user sessions
- Signing algorithm: HMAC-SHA256 with 256-bit key
- Claims validation: Verify signature, expiry, issuer, audience

**Future Authentication Methods:**
- OAuth 2.0 with PKCE: Google, Apple Sign-In
- WebAuthn/Passkeys: Passwordless authentication with hardware keys
- Biometrics: TouchID/FaceID for mobile apps (local verification, backend token exchange)

### 4.2 Authorization Model (RBAC)

**Roles:**

| Role | Description | Permissions |
|------|-------------|-------------|
| user | Default authenticated user | Read own profile, update own profile, delete own account |
| premium_user | Paid subscription user | All user permissions + premium features |
| support | Customer support agent | Read user profiles (excluding passwords), view audit logs |
| admin | System administrator | All permissions + user management, security configurations |
| super_admin | Super administrator | All permissions + role assignments, system settings |

**Permission Matrix:**

| Resource | user | premium_user | support | admin | super_admin |
|----------|------|--------------|---------|-------|-------------|
| /api/v1/auth/register | ✅ | ✅ | ❌ | ❌ | ❌ |
| /api/v1/auth/login | ✅ | ✅ | ✅ | ✅ | ✅ |
| /api/v1/auth/logout | ✅ | ✅ | ✅ | ✅ | ✅ |
| /api/v1/users/me | ✅ | ✅ | ❌ | ✅ | ✅ |
| /api/v1/users/:id | ❌ (own only) | ❌ (own only) | ✅ (read-only) | ✅ | ✅ |
| /api/v1/admin/users | ❌ | ❌ | ❌ | ✅ | ✅ |
| /api/v1/admin/roles | ❌ | ❌ | ❌ | ❌ | ✅ |

**Authorization Enforcement:**
- Middleware: Role-based access control middleware on all protected routes
- JWT claims: User ID and roles embedded in JWT, verified on each request
- Least privilege: Default deny, explicit allow for each resource
- Horizontal access control: Users can only access their own resources (validated by user_id)
- Vertical access control: Role hierarchy enforced (user < support < admin < super_admin)

### 4.3 Session Management

**Session Architecture:**

```
Redis Cluster (Session Store)
Key: session:{user_id}:{device_fingerprint}
Value: {
  "user_id": "uuid",
  "refresh_token_id": "uuid",
  "device_fingerprint": "hash",
  "ip_address": "1.2.3.4",
  "user_agent": "Mozilla/5.0...",
  "created_at": "ISO timestamp",
  "last_activity": "ISO timestamp",
  "expires_at": "ISO timestamp"
}
TTL: 900 seconds (15 min idle timeout)
```

**Session Lifecycle:**
1. **Session Creation** (on successful 2FA verification):
   - Generate unique session ID (UUID v4)
   - Store session data in Redis with 15-min TTL
   - Set refresh token in HttpOnly cookie
   - Set access token in Authorization header (client-side storage)

2. **Session Validation** (on each API request):
   - Extract access token from Authorization header
   - Verify JWT signature and expiry
   - Extract user_id from JWT claims
   - Validate user still has required role
   - Update last_activity timestamp in Redis (resets TTL)

3. **Session Refresh** (when access token expires):
   - Client sends refresh token from HttpOnly cookie
   - Server retrieves hashed refresh token from database
   - Validate refresh token hasn't been revoked
   - Issue new access token (15 min) and refresh token (7 days)
   - Revoke old refresh token (rotation)
   - Detect reuse: If revoked token used, invalidate all user sessions

4. **Session Termination**:
   - Explicit logout: Delete session from Redis, revoke refresh token
   - Idle timeout: Redis TTL expires session after 15 min inactivity
   - Absolute timeout: Session hard limit of 8 hours (regardless of activity)
   - Security event: Revoke all sessions on password change or account compromise

**Session Security:**
- Concurrent session limit: Max 5 active devices per user
- Device binding: Session tied to device fingerprint (IP + User-Agent hash)
- Session fixation prevention: Regenerate session ID after login
- Session hijacking prevention: Validate IP address + User-Agent on each request (warn if changed)
- Cross-device security: User can view and revoke active sessions from account settings

---

## 5. Security Monitoring and Incident Response

### 5.1 Security Event Logging

**Logged Events:**

| Event Type | Log Level | Retention | SIEM Integration |
|-----------|-----------|-----------|------------------|
| Registration attempt | INFO | 90 days | ✅ |
| Successful registration | INFO | 90 days | ✅ |
| Failed registration (validation) | WARNING | 90 days | ✅ |
| Email verification | INFO | 90 days | ✅ |
| Login attempt | INFO | 90 days | ✅ |
| Successful login | INFO | 90 days | ✅ |
| Failed login (invalid credentials) | WARNING | 90 days | ✅ |
| Failed login (account locked) | WARNING | 90 days | ✅ |
| Account lockout triggered | WARNING | 90 days | ✅ |
| OTP generated | INFO | 90 days | ✅ |
| OTP verification success | INFO | 90 days | ✅ |
| OTP verification failed | WARNING | 90 days | ✅ |
| Token refresh | INFO | 30 days | ✅ |
| Token reuse detected | CRITICAL | 365 days | ✅ |
| Logout | INFO | 30 days | ✅ |
| Password change | WARNING | 365 days | ✅ |
| Password reset request | WARNING | 90 days | ✅ |
| Password reset completed | WARNING | 365 days | ✅ |
| Session hijacking detected | CRITICAL | 365 days | ✅ |
| Privilege escalation attempt | CRITICAL | 365 days | ✅ |
| GDPR data access request | INFO | 7 years | ✅ |
| GDPR data deletion request | INFO | 7 years | ✅ |

**Log Format (Structured JSON):**
```json
{
  "timestamp": "2025-10-29T12:34:56.789Z",
  "event_type": "login_success",
  "severity": "INFO",
  "user_id": "uuid-here",
  "email": "user@example.com",
  "ip_address": "1.2.3.4",
  "user_agent": "Mozilla/5.0...",
  "device_fingerprint": "hash",
  "session_id": "uuid",
  "geolocation": {
    "country": "PT",
    "city": "Lisbon"
  },
  "additional_context": {
    "login_method": "email_password_2fa"
  }
}
```

**Log Storage and Analysis:**
- Primary: Datadog APM with 90-day retention
- Long-term: AWS S3 with 7-year retention (compliance)
- SIEM: Datadog Security Monitoring with anomaly detection
- Alerting: Real-time alerts for CRITICAL events via PagerDuty

### 5.2 Security Alerting Rules

**Real-Time Alerts:**

| Alert Name | Trigger Condition | Severity | Response Time | Notification |
|-----------|------------------|----------|---------------|--------------|
| Brute force attack | >10 failed logins from same IP in 5 min | HIGH | 5 min | Security team + PagerDuty |
| Account takeover | Login from new country + new device | MEDIUM | 15 min | User email + Security team |
| Token reuse detected | Revoked refresh token used | CRITICAL | 1 min | Security team + PagerDuty + User notification |
| Privilege escalation | User with role 'user' accessing admin endpoint | CRITICAL | 1 min | Security team + PagerDuty |
| Mass password resets | >50 password reset requests in 10 min | HIGH | 5 min | Security team |
| Database access anomaly | Unusual query patterns or high volume | MEDIUM | 10 min | DevOps + Security team |
| Session hijacking | IP/User-Agent change during active session | HIGH | 5 min | User notification + Session revocation |
| Credential stuffing | >100 failed logins across multiple accounts in 5 min | CRITICAL | 1 min | WAF rule update + Security team |

**Automated Response Actions:**
- Brute force: Temporarily block IP via WAF (1 hour)
- Credential stuffing: Enable CAPTCHA for affected users
- Token reuse: Revoke all user sessions immediately
- Privilege escalation: Block request, log event, alert security team
- Account takeover suspicion: Require 2FA re-verification

### 5.3 Incident Response Plan

**Incident Severity Levels:**

| Level | Description | Example | Response Time |
|-------|-------------|---------|---------------|
| P1 - Critical | Active security breach, data exposure | Database dump leaked | 15 min |
| P2 - High | Potential breach, successful exploit | Token reuse attack | 1 hour |
| P3 - Medium | Security anomaly, unsuccessful exploit | Multiple failed logins | 4 hours |
| P4 - Low | Security concern, no immediate threat | Password policy violation | 24 hours |

**Incident Response Workflow:**

**Phase 1: Detection & Triage (0-15 min)**
1. Security alert triggered via Datadog
2. On-call security engineer paged via PagerDuty
3. Initial triage: Validate alert is not false positive
4. Assign severity level (P1-P4)
5. Create incident ticket in Jira

**Phase 2: Containment (15 min - 1 hour)**
- P1: Immediately isolate affected systems, revoke compromised credentials
- P2: Block attacker IP, revoke suspicious sessions
- P3: Enable additional monitoring, collect evidence
- P4: Document issue, schedule fix

**Phase 3: Investigation (1-4 hours)**
- Analyze logs to determine attack vector and scope
- Identify compromised accounts and affected data
- Preserve forensic evidence
- Notify stakeholders (management, legal, DPO)

**Phase 4: Eradication (4-8 hours)**
- Remove attacker access (revoke tokens, reset passwords)
- Patch exploited vulnerability
- Update WAF rules to block similar attacks
- Rotate compromised secrets (JWT keys, database credentials)

**Phase 5: Recovery (8-24 hours)**
- Restore affected services
- Verify all attacker access removed
- Monitor for reinfection attempts
- Communicate with affected users (GDPR breach notification if required)

**Phase 6: Post-Incident Review (24-72 hours)**
- Root cause analysis
- Document lessons learned
- Update incident response procedures
- Implement preventive controls
- Security team training

**GDPR Breach Notification:**
- If personal data compromised: Notify DPO within 1 hour
- DPO assessment: Determine if breach must be reported to supervisory authority
- If reportable: Notify within 72 hours of becoming aware
- Affected users: Notify without undue delay if high risk to rights/freedoms

---

## 6. Compliance and Audit

### 6.1 OWASP Top 10 Compliance Matrix

| OWASP Risk | Controls Implemented | Evidence | Testing |
|-----------|---------------------|----------|---------|
| A01: Broken Access Control | RBAC, least privilege, horizontal/vertical checks | Permission matrix, middleware code | Automated tests, penetration testing |
| A02: Cryptographic Failures | Argon2id, AES-256, TLS 1.3, key rotation | Crypto inventory, KMS logs | Encryption validation, key rotation tests |
| A03: Injection | Parameterized queries, input validation, output encoding | Code review, static analysis | SAST, SQL injection tests |
| A04: Insecure Design | Threat modeling, security design review | This document, threat model | Architecture review |
| A05: Security Misconfiguration | Security hardening, secure defaults, config management | Infrastructure as code, config audits | Configuration scanning (Prowler) |
| A06: Vulnerable Components | Dependency scanning, automated updates | Snyk reports, Dependabot PRs | Weekly dependency scans |
| A07: Identification & Authentication Failures | MFA, account lockout, secure session management, JWT | Auth flow diagrams, session tests | Authentication penetration testing |
| A08: Software & Data Integrity Failures | Digital signatures, integrity checks, secure CI/CD | HMAC signatures, GitHub Actions logs | Pipeline security audits |
| A09: Security Logging & Monitoring Failures | Comprehensive logging, real-time alerting, audit trails | Log samples, Datadog dashboards | Log injection tests, alert validation |
| A10: SSRF | Input validation, URL allowlisting, network segmentation | Code review, firewall rules | SSRF penetration testing |

### 6.2 GDPR Compliance Requirements

**Lawful Basis for Processing:**
- Consent: Explicit opt-in during registration with timestamp and IP logging
- Contract: Processing necessary to provide authentication service
- Legal obligation: Retention of audit logs for compliance (7 years)

**Data Subject Rights Implementation:**

| Right | Implementation | Response Time | Technical Mechanism |
|-------|---------------|---------------|---------------------|
| Right to be informed | Privacy policy, consent forms | Immediate | /privacy-policy endpoint |
| Right of access | User can download all personal data | 30 days | /api/v1/users/me/export (JSON) |
| Right to rectification | User can update email, phone | Immediate | /api/v1/users/me (PATCH) |
| Right to erasure | User can delete account + all data | 30 days | /api/v1/users/me (DELETE) |
| Right to restrict processing | User can disable account without deletion | Immediate | /api/v1/users/me/disable (POST) |
| Right to data portability | Export in machine-readable format (JSON) | 30 days | /api/v1/users/me/export |
| Right to object | User can withdraw consent | Immediate | /api/v1/users/me/consent (DELETE) |

**Data Retention Policy:**
- Active accounts: Data retained indefinitely
- Deleted accounts: Hard delete within 30 days of request
- Audit logs: 7 years (legal obligation)
- Session data: 15 min idle timeout, 8h absolute timeout
- Email verification tokens: 24 hours
- Password reset tokens: 1 hour
- OTP codes: 5 minutes

**Data Processing Records (Article 30):**
- Controller: SUMA Finance
- DPO contact: dpo@sumafinance.com
- Processing purposes: User authentication, security, compliance
- Data categories: Email, phone (optional), password hashes, login history
- Recipients: Internal engineering team, email service (SendGrid)
- Transfers: No transfers outside EU
- Retention periods: See retention policy above
- Security measures: See sections 2-5 of this document

**Breach Notification Procedures:**
- Internal detection: Security monitoring alerts (Section 5.1)
- Assessment: DPO determines if reportable within 1 hour
- Authority notification: Within 72 hours to Portuguese CNPD
- User notification: Without undue delay if high risk
- Documentation: Maintain breach register with facts, effects, remediation

### 6.3 PCI-DSS Compliance (Relevant Requirements)

**Requirement 1: Network Security**
- Firewalls and security groups isolate authentication systems
- Network segmentation with VPC private subnets for database

**Requirement 2: Secure Configurations**
- No default passwords or credentials
- Disable unnecessary services and ports
- Security hardening checklist applied to all servers

**Requirement 3: Protect Cardholder Data**
- N/A (authentication system doesn't store payment card data)
- Strong cryptography for credentials (Argon2id, AES-256)

**Requirement 4: Encrypt Data in Transit**
- TLS 1.3 for all communications
- Strong cipher suites only (no TLS 1.0/1.1)

**Requirement 6: Secure Development**
- SAST/DAST in CI/CD pipeline
- Code review for all changes
- Security testing before production deployment

**Requirement 7: Access Control**
- RBAC with least privilege principle
- Unique user IDs for all personnel

**Requirement 8: Authentication**
- Multi-factor authentication required
- Password complexity enforcement
- Account lockout after failed attempts

**Requirement 10: Logging and Monitoring**
- Audit trails for all authentication events
- Log retention for 90 days (minimum)
- Real-time alerting for security events

**Requirement 11: Security Testing**
- Quarterly vulnerability scans
- Annual penetration testing
- Automated security scanning in CI/CD

**Requirement 12: Security Policies**
- Information security policy documented
- Incident response plan (Section 5.3)
- Annual security awareness training

### 6.4 SOC 2 Type II Controls

**CC6.1: Logical and Physical Access Controls**
- Control: Multi-factor authentication required for all users
- Test: Verify 2FA enabled for all accounts, test bypass attempts
- Evidence: Auth flow code, 2FA enablement logs

**CC6.2: Authentication and Authorization**
- Control: Role-based access control with least privilege
- Test: Verify unauthorized access blocked, test privilege escalation
- Evidence: Permission matrix, authorization middleware code

**CC6.6: Logical Access - Restriction**
- Control: Account lockout after 5 failed attempts
- Test: Verify lockout triggers correctly, test cooldown period
- Evidence: Lockout logs, rate limiting configuration

**CC6.7: Logical Access - Removal**
- Control: Session termination after 15 min idle, 8h absolute
- Test: Verify sessions expire correctly, test token revocation
- Evidence: Session TTL configuration, expiry logs

**CC7.2: Detection of Security Events**
- Control: Real-time security monitoring with Datadog
- Test: Verify alerts trigger for defined conditions
- Evidence: Datadog configuration, alert history

**CC7.3: Response to Security Events**
- Control: Incident response plan with defined SLAs
- Test: Annual tabletop exercise, test notification workflow
- Evidence: This document (Section 5.3), incident tickets

**A1.2: Change Management**
- Control: All code changes reviewed and approved before deployment
- Test: Verify pull request approval requirements enforced
- Evidence: GitHub branch protection rules, PR history

### 6.5 Audit Trail Requirements

**Immutable Audit Log Structure:**
```json
{
  "audit_id": "uuid",
  "timestamp": "ISO 8601",
  "event_type": "login_success",
  "actor": {
    "user_id": "uuid",
    "email": "user@example.com",
    "role": "user"
  },
  "action": {
    "resource": "/api/v1/auth/login",
    "method": "POST",
    "result": "success"
  },
  "context": {
    "ip_address": "1.2.3.4",
    "user_agent": "Mozilla/5.0...",
    "geolocation": {"country": "PT", "city": "Lisbon"},
    "device_fingerprint": "hash"
  },
  "integrity": {
    "previous_hash": "sha256-hash",
    "current_hash": "sha256-hash"
  }
}
```

**Audit Log Integrity (Chain of Custody):**
- Each log entry contains hash of previous entry (blockchain-like structure)
- Tampering detection: Recalculate hash chain, verify integrity
- Storage: Write-only Datadog logging + immutable S3 backup (Object Lock enabled)
- Access control: Only security team can read audit logs (IAM policies)

**Audit Reporting:**
- Monthly: Security event summary (login stats, failed attempts, lockouts)
- Quarterly: Compliance audit report (GDPR, PCI-DSS, SOC 2 controls)
- Annual: Security posture assessment, penetration test results
- Ad-hoc: Incident investigation reports, breach notifications

---

## 7. Security Testing and Validation

### 7.1 Security Testing Strategy

**Static Application Security Testing (SAST):**
- Tool: Snyk Code, SonarQube
- Frequency: On every pull request
- Checks: SQL injection, XSS, hardcoded secrets, insecure crypto
- Blocking: Critical/High findings block deployment

**Dynamic Application Security Testing (DAST):**
- Tool: OWASP ZAP, Burp Suite
- Frequency: Weekly automated scans on staging environment
- Checks: OWASP Top 10 vulnerabilities, authentication bypass
- Blocking: Critical findings block production deployment

**Dependency Scanning:**
- Tool: Snyk, Dependabot, OWASP Dependency-Check
- Frequency: Daily automated scans
- Checks: Known vulnerabilities in dependencies (CVEs)
- Remediation: Auto-merge minor patches, manual review for major versions

**Secret Scanning:**
- Tool: GitHub Secret Scanning, TruffleHog
- Frequency: On every commit
- Checks: API keys, passwords, private keys in code
- Blocking: Commits with secrets rejected

**Infrastructure Security Scanning:**
- Tool: AWS Prowler, Checkov
- Frequency: Weekly
- Checks: IAM policies, security groups, encryption settings, compliance
- Remediation: Infrastructure-as-code updates

**Penetration Testing:**
- Internal: Quarterly (security team)
- External: Annual (third-party firm)
- Scope: Authentication flows, session management, authorization, API security
- Report: Findings with severity, remediation plan, retest confirmation

**Bug Bounty Program:**
- Platform: HackerOne
- Scope: Authentication system in production
- Rewards: $100-$10,000 based on severity
- Response SLA: 24 hours for critical, 5 days for others

### 7.2 Security Test Cases

**Authentication Tests:**
```
TC-AUTH-001: Verify strong password policy enforced
- Attempt: Register with weak password (e.g., "password")
- Expected: Registration rejected with error message

TC-AUTH-002: Verify account lockout after failed attempts
- Attempt: 5 failed login attempts with wrong password
- Expected: Account locked for 15 minutes

TC-AUTH-003: Verify email enumeration prevention
- Attempt: Login with non-existent email
- Expected: Generic "Invalid credentials" message (same as wrong password)

TC-AUTH-004: Verify OTP expiry
- Attempt: Use OTP code after 5 minutes
- Expected: Verification rejected with "Code expired" error

TC-AUTH-005: Verify token reuse detection
- Attempt: Use same refresh token twice
- Expected: Second use rejected, all sessions revoked

TC-AUTH-006: Verify session timeout
- Attempt: Use access token after 15 minutes with no activity
- Expected: Request rejected with "Session expired" error
```

**Authorization Tests:**
```
TC-AUTHZ-001: Verify RBAC enforcement
- Attempt: User with role 'user' accessing /api/v1/admin/users
- Expected: 403 Forbidden

TC-AUTHZ-002: Verify horizontal privilege escalation prevention
- Attempt: User A accessing /api/v1/users/{user_b_id}
- Expected: 403 Forbidden

TC-AUTHZ-003: Verify JWT tampering detection
- Attempt: Modify JWT payload (change user_id or role)
- Expected: Signature verification failure, 401 Unauthorized
```

**Injection Tests:**
```
TC-INJ-001: Verify SQL injection prevention
- Attempt: Login with email: admin'-- and any password
- Expected: Invalid credentials (parameterized query prevents injection)

TC-INJ-002: Verify XSS prevention
- Attempt: Register with email: <script>alert('xss')</script>@test.com
- Expected: Email validation rejects input or output encoding prevents execution
```

**Cryptography Tests:**
```
TC-CRYPTO-001: Verify password hashing strength
- Attempt: Retrieve password hash from database
- Expected: Argon2id hash, verify with parameters (memory=64MB, iterations=3)

TC-CRYPTO-002: Verify TLS version
- Attempt: Connect with TLS 1.0 or TLS 1.1
- Expected: Connection rejected, only TLS 1.3 accepted

TC-CRYPTO-003: Verify JWT signature algorithm
- Attempt: Submit JWT with "alg": "none"
- Expected: Token rejected, only HMAC-SHA256 accepted
```

**Session Management Tests:**
```
TC-SESS-001: Verify session fixation prevention
- Attempt: Reuse session ID before and after login
- Expected: Session ID regenerated after successful login

TC-SESS-002: Verify concurrent session limit
- Attempt: Login from 6th device when 5 sessions already active
- Expected: Oldest session revoked

TC-SESS-003: Verify CSRF protection
- Attempt: Submit POST /api/v1/auth/logout from different origin without CSRF token
- Expected: Request rejected (CSRF token validation)
```

### 7.3 Security Metrics and KPIs

| Metric | Target | Current | Trend | Owner |
|--------|--------|---------|-------|-------|
| Mean Time to Detect (MTTD) | < 5 min | 3.2 min | ↓ | Security team |
| Mean Time to Respond (MTTR) | < 1 hour (P1) | 45 min | ↓ | Security team |
| Failed login rate | < 5% | 2.8% | → | Product team |
| Account lockout rate | < 1% | 0.4% | → | Product team |
| Password reset rate | < 10% monthly | 6.2% | → | Product team |
| 2FA adoption rate | > 95% | 97.3% | ↑ | Product team |
| Critical vulnerabilities | 0 | 0 | → | Engineering team |
| High vulnerabilities | < 5 | 2 | ↓ | Engineering team |
| Dependency vulnerabilities | < 10 | 4 | ↓ | Engineering team |
| Code coverage (security tests) | > 80% | 86% | ↑ | Engineering team |
| GDPR data subject requests | N/A | 12/month | → | Legal + DPO |
| Security incidents (P1-P2) | 0 | 0 | → | Security team |

---

## 8. Deployment and Operations Security

### 8.1 Secure CI/CD Pipeline

```
Developer Commit
      │
      ▼
┌─────────────────┐
│ GitHub Actions  │
├─────────────────┤
│ 1. Code lint    │ ◄── Enforce code style (gofmt, prettier)
│ 2. SAST scan    │ ◄── Snyk Code, SonarQube
│ 3. Secret scan  │ ◄── TruffleHog, GitHub Secret Scanning
│ 4. Unit tests   │ ◄── 86% coverage requirement
│ 5. Build image  │ ◄── Docker build with hash tagging
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Security Gates  │
├─────────────────┤
│ ✓ No critical   │
│   findings      │
│ ✓ All tests pass│
│ ✓ Code reviewed │ ◄── Require 1 approval from security team
│ ✓ Signed commits│ ◄── GPG signature verification
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Staging Deploy  │
├─────────────────┤
│ 1. Deploy to    │
│    staging ECS  │
│ 2. DAST scan    │ ◄── OWASP ZAP automated scan
│ 3. Integration  │
│    tests        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Manual Approval │ ◄── Engineering manager approval for prod
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Production      │
│ Deployment      │
├─────────────────┤
│ Blue/Green      │ ◄── Zero-downtime deployment
│ Canary (10%)    │ ◄── 10% traffic for 30 min, monitor errors
│ Full rollout    │ ◄── If no errors, 100% traffic
└─────────────────┘
```

**Pipeline Security Controls:**
- Code signing: GPG-signed commits required
- Branch protection: No direct commits to main, PR required
- Review requirements: 1 approval from CODEOWNERS (security team for auth code)
- Immutable builds: Docker images tagged with git commit SHA
- Artifact signing: Sign Docker images with Notary/Cosign
- Secret injection: Secrets injected at runtime from AWS Secrets Manager (never in code/config)
- Rollback capability: Automated rollback if error rate > 1% during canary

### 8.2 Infrastructure Security

**AWS Architecture:**
```
┌─────────────────────────────────────────────────┐
│                  AWS Account                     │
│  ┌───────────────────────────────────────────┐  │
│  │              VPC (10.0.0.0/16)            │  │
│  │  ┌─────────────────┐  ┌─────────────────┐│  │
│  │  │ Public Subnet   │  │ Private Subnet  ││  │
│  │  │                 │  │                 ││  │
│  │  │ ┌────────────┐  │  │ ┌────────────┐ ││  │
│  │  │ │   ALB      │  │  │ │ ECS Tasks  │ ││  │
│  │  │ │ (TLS 1.3)  │  │  │ │ (Auth API) │ ││  │
│  │  │ └──────┬─────┘  │  │ └──────┬─────┘ ││  │
│  │  │        │        │  │        │       ││  │
│  │  └────────┼────────┘  └────────┼───────┘│  │
│  │           │                    │        │  │
│  │           └────────────────────┘        │  │
│  │                                         │  │
│  │  ┌─────────────────────────────────────┐│  │
│  │  │        Private Subnet               ││  │
│  │  │  ┌────────────┐  ┌────────────┐    ││  │
│  │  │  │ RDS        │  │ ElastiCache│    ││  │
│  │  │  │ PostgreSQL │  │ Redis      │    ││  │
│  │  │  │ (encrypted)│  │ (encrypted)│    ││  │
│  │  │  └────────────┘  └────────────┘    ││  │
│  │  └─────────────────────────────────────┘│  │
│  └───────────────────────────────────────────┘  │
│                                                  │
│  Security Services:                              │
│  ├─ AWS WAF (DDoS, rate limiting)               │
│  ├─ GuardDuty (threat detection)                │
│  ├─ CloudTrail (audit logging)                  │
│  ├─ Secrets Manager (credential storage)        │
│  ├─ KMS (encryption keys)                       │
│  └─ Security Hub (compliance dashboard)         │
└─────────────────────────────────────────────────┘
```

**Infrastructure Security Controls:**
- Network segmentation: Public subnet for ALB only, private subnets for application and database
- Security groups: Least-privilege firewall rules (ALB: 443 only, ECS: 8080 from ALB only, RDS: 5432 from ECS only)
- NACLs: Deny known malicious IPs at network layer
- VPC Flow Logs: Enable for anomaly detection
- IMDSv2: Enforce IMDSv2 for EC2 metadata to prevent SSRF
- Systems Manager: Use Session Manager for server access (no SSH keys)
- GuardDuty: Enable threat detection for suspicious API calls
- CloudTrail: Log all API calls for audit and forensics
- Config: Track infrastructure changes and compliance drift
- Security Hub: Centralized security findings dashboard

**Container Security:**
- Base images: Use official slim images (golang:1.22-alpine, node:20-alpine)
- Image scanning: Trivy/Snyk scans on every build
- Vulnerability threshold: No critical/high vulnerabilities in production images
- Non-root user: Run containers as non-root user (UID 1000)
- Read-only filesystem: Mount root filesystem as read-only
- Resource limits: CPU/memory limits to prevent resource exhaustion
- Secret management: Secrets injected as environment variables from AWS Secrets Manager
- Network policies: Restrict egress to only necessary destinations

### 8.3 Disaster Recovery and Business Continuity

**Recovery Time Objective (RTO): 1 hour**
**Recovery Point Objective (RPO): 5 minutes**

**Backup Strategy:**

| Component | Backup Method | Frequency | Retention | Encryption |
|-----------|--------------|-----------|-----------|-----------|
| PostgreSQL | RDS automated backups | Every 5 min (transaction logs) | 35 days | AES-256 |
| PostgreSQL | Manual snapshots | Daily | 90 days | AES-256 |
| Redis | RDS snapshots | Daily | 7 days | AES-256 |
| Secrets | AWS Secrets Manager replication | Real-time | Indefinite | KMS |
| Application config | Git repository | Every commit | Indefinite | N/A (no secrets) |
| Docker images | ECR | Every build | 30 days | AES-256 |

**Disaster Recovery Scenarios:**

**Scenario 1: Database Failure**
- Detection: RDS health check failure alert
- Response: Automatic failover to standby replica (Multi-AZ)
- RTO: 60 seconds (automatic)
- RPO: 0 (synchronous replication)

**Scenario 2: Redis Cache Failure**
- Detection: ElastiCache health check failure
- Response: Automatic failover to replica node
- RTO: 30 seconds (automatic)
- RPO: 0 (replication)
- Degradation: Temporary performance impact, application still functional

**Scenario 3: Region Failure**
- Detection: Multiple service failures, AWS status page
- Response: Manual failover to backup region (requires runbook execution)
- RTO: 1 hour (manual)
- RPO: 5 minutes (async cross-region backup replication)
- Steps:
  1. Restore latest database snapshot in backup region
  2. Update DNS to point to backup region ALB
  3. Deploy latest application version from ECR
  4. Restore secrets from replicated Secrets Manager
  5. Validate authentication flows
  6. Communicate service status to users

**Scenario 4: Data Corruption**
- Detection: Integrity checks, user reports
- Response: Point-in-time recovery from RDS backup
- RTO: 30 minutes
- RPO: 5 minutes
- Steps:
  1. Identify corruption timestamp
  2. Restore database to point before corruption
  3. Replay transaction logs if available
  4. Validate data integrity
  5. Communicate downtime window to users

**Business Continuity:**
- Active-passive multi-region setup (primary: eu-west-1, backup: eu-central-1)
- Quarterly DR drills with runbook execution
- Runbooks stored in secure wiki with 24/7 access
- On-call rotation with escalation path
- Communication plan: Status page, email, in-app notifications

---

## 9. Mobile Application Security

### 9.1 Mobile-Specific Threats

| Threat | Description | Mitigation |
|--------|-------------|-----------|
| Rooted/Jailbroken devices | Attacker bypasses OS security controls | Detect and warn user, disable sensitive features |
| App tampering | Attacker modifies APK/IPA to inject malicious code | Code signing verification, anti-tampering checks |
| Insecure data storage | Credentials stored in plaintext | Use iOS Keychain, Android KeyStore |
| Screen capture | Attacker screenshots sensitive data | Disable screenshots for auth screens |
| Certificate pinning bypass | Attacker intercepts HTTPS traffic | Certificate pinning with backup pins |
| Biometric spoofing | Attacker uses fake biometric (photo, mold) | Use OS-level biometric APIs (TEE/Secure Enclave) |
| Clipboard hijacking | Malicious app reads OTP from clipboard | Clear clipboard after 30 seconds |
| Overlay attacks | Malicious app overlays fake login screen | Detect overlays, warn user |

### 9.2 Mobile Security Controls

**Secure Storage (iOS):**
```swift
// Store refresh token in Keychain
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "refresh_token",
    kSecValueData as String: tokenData,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
SecItemAdd(query as CFDictionary, nil)
```

**Secure Storage (Android):**
```kotlin
// Store refresh token in EncryptedSharedPreferences
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val sharedPreferences = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
sharedPreferences.edit().putString("refresh_token", token).apply()
```

**Certificate Pinning:**
```typescript
// React Native with axios
import axios from 'axios';
import { setupCertificatePinning } from 'react-native-ssl-pinning';

await setupCertificatePinning({
  'api.sumafinance.com': {
    includeSubdomains: true,
    pins: [
      'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // Primary cert
      'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='  // Backup cert
    ]
  }
});
```

**Root/Jailbreak Detection:**
```typescript
// React Native
import JailMonkey from 'jail-monkey';

if (JailMonkey.isJailBroken()) {
  Alert.alert(
    'Security Warning',
    'This device appears to be rooted/jailbroken. Some features may be disabled.',
    [{ text: 'OK' }]
  );
  // Disable biometric login, show warning banner
}
```

**Biometric Authentication:**
```typescript
// React Native with react-native-biometrics
import ReactNativeBiometrics from 'react-native-biometrics';

const { available, biometryType } = await ReactNativeBiometrics.isSensorAvailable();

if (available && (biometryType === 'FaceID' || biometryType === 'TouchID' || biometryType === 'Biometrics')) {
  const { success } = await ReactNativeBiometrics.simplePrompt({
    promptMessage: 'Confirm your identity'
  });
  
  if (success) {
    // Retrieve refresh token from secure storage
    // Exchange for new access token
  }
}
```

**Screen Capture Prevention:**
```swift
// iOS - Disable screenshots on auth screens
NotificationCenter.default.addObserver(
    forName: UIApplication.userDidTakeScreenshotNotification,
    object: nil,
    queue: .main
) { _ in
    // Log security event
    logSecurityEvent("screenshot_attempt")
}

// Blur sensitive content when app backgrounds
NotificationCenter.default.addObserver(
    forName: UIApplication.willResignActiveNotification,
    object: nil,
    queue: .main
) { _ in
    blurView.isHidden = false
}
```

```kotlin
// Android - Disable screenshots on auth screens
window.setFlags(
    WindowManager.LayoutParams.FLAG_SECURE,
    WindowManager.LayoutParams.FLAG_SECURE
)
```

### 9.3 Mobile Authentication Flow

```
Mobile App Login Flow with Biometric:

1. User opens app
   ├─ Check if biometric auth enabled in settings
   ├─ Check if device supports biometric (TouchID/FaceID/Fingerprint)
   └─ If both true: Show biometric prompt

2. Biometric verification (OS-level)
   ├─ iOS: Local Authentication framework (Secure Enclave)
   ├─ Android: BiometricPrompt (Trusted Execution Environment)
   └─ If success: Proceed to step 3

3. Retrieve refresh token from secure storage
   ├─ iOS: Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly
   ├─ Android: EncryptedSharedPreferences with KeyStore
   └─ Token encrypted at rest, decrypted in memory only

4. Exchange refresh token for new access token
   ├─ POST /api/v1/auth/refresh
   ├─ Include device fingerprint in request
   ├─ Server validates refresh token + device fingerprint
   └─ Server returns new access token (15 min) + rotated refresh token

5. Store new refresh token, use access token for API calls
   ├─ Access token stored in memory (Redux/Context)
   ├─ Refresh token stored in secure storage (replaces old token)
   └─ Old refresh token invalidated on server

Fallback: If biometric fails or unavailable, show email/password + OTP flow
```

---

## 10. Security Roadmap and Future Enhancements

### 10.1 Phase 1 (Weeks 1-6) - Critical Security Baseline

**Week 1-2: Core Authentication**
- ✅ Email/password registration with Argon2id hashing
- ✅ Email verification with signed tokens
- ✅ Login with JWT (access + refresh tokens)
- ✅ Password reset flow
- ✅ Account lockout protection
- ✅ Rate limiting

**Week 3-4: Multi-Factor Authentication**
- ✅ Email OTP 2FA implementation
- ✅ Session management with Redis
- ✅ Token rotation and reuse detection
- ✅ Device fingerprinting

**Week 5-6: Compliance and Monitoring**
- ✅ GDPR consent management
- ✅ Security event logging (Datadog)
- ✅ Real-time alerting (PagerDuty)
- ✅ Audit trail implementation

### 10.2 Phase 2 (Weeks 7-10) - Enhanced Security

**Week 7-8: Advanced Authentication**
- 🔲 OAuth 2.0 with PKCE (Google, Apple Sign-In)
- 🔲 Biometric authentication for mobile
- 🔲 Passwordless login (magic links)
- 🔲 Password breach detection (HaveIBeenPwned)

**Week 9-10: Security Hardening**
- 🔲 Web Application Firewall (AWS WAF) rules
- 🔲 DDoS protection configuration
- 🔲 Certificate pinning for mobile apps
- 🔲 Security headers (CSP, HSTS, etc.)

### 10.3 Phase 3 (Weeks 11-14) - Advanced Features

**Week 11-12: Passwordless and Biometric**
- 🔲 WebAuthn/FIDO2 support (hardware keys)
- 🔲 Passkey support (iCloud Keychain, Google Password Manager)
- 🔲 Device trust management
- 🔲 Trusted device notifications

**Week 13-14: Fraud Prevention**
- 🔲 Device fingerprinting enhancements
- 🔲 Impossible travel detection
- 🔲 Behavioral biometrics (typing patterns, mouse movements)
- 🔲 Risk-based authentication (step-up auth for sensitive actions)

### 10.4 Phase 4 (Weeks 15-18) - Enterprise Features

**Week 15-16: Enterprise Authentication**
- 🔲 SAML 2.0 SSO integration
- 🔲 LDAP/Active Directory integration
- 🔲 Organization-level security policies
- 🔲 Centralized session management

**Week 17-18: Advanced Monitoring**
- 🔲 User Entity and Behavior Analytics (UEBA)
- 🔲 Machine learning anomaly detection
- 🔲 Automated threat response (SOAR)
- 🔲 Security operations dashboard

### 10.5 Continuous Improvement

**Quarterly Activities:**
- Penetration testing (internal + external)
- Vulnerability scanning and remediation
- Security awareness training
- Incident response drills
- Compliance audits (GDPR, PCI-DSS, SOC 2)

**Annual Activities:**
- Third-party security audit
- Disaster recovery drill
- Security architecture review
- Threat model update
- Security roadmap planning

---

## 11. Appendices

### 11.1 Security Checklists

**Pre-Deployment Security Checklist:**
- [ ] All secrets stored in AWS Secrets Manager (no hardcoded credentials)
- [ ] TLS 1.3 enforced for all endpoints
- [ ] HSTS enabled with 1-year max-age
- [ ] Security headers configured (CSP, X-Frame-Options, etc.)
- [ ] Rate limiting enabled (WAF + application-level)
- [ ] Database encryption at rest enabled (RDS)
- [ ] Database in private subnet with no public access
- [ ] Security groups configured with least privilege
- [ ] IAM roles use least privilege principle
- [ ] CloudTrail enabled for audit logging
- [ ] GuardDuty enabled for threat detection
- [ ] Datadog monitoring and alerting configured
- [ ] Incident response runbooks documented
- [ ] GDPR consent flow tested
- [ ] Password policy enforced (12 chars, complexity)
- [ ] Account lockout configured (5 attempts, 15 min)
- [ ] 2FA enabled and tested
- [ ] Token rotation implemented
- [ ] Session timeout configured (15 min idle, 8h absolute)
- [ ] Audit logging functional (all events captured)
- [ ] SAST/DAST scans passed (no critical/high findings)
- [ ] Dependency scans passed (no critical/high vulnerabilities)
- [ ] Penetration testing completed
- [ ] Security design review approved
- [ ] Privacy impact assessment completed (GDPR)

**Code Review Security Checklist:**
- [ ] No hardcoded secrets (API keys, passwords, tokens)
- [ ] All database queries use parameterized statements
- [ ] User input validated on server side
- [ ] Output properly encoded to prevent XSS
- [ ] Authentication required for protected endpoints
- [ ] Authorization checked (RBAC enforcement)
- [ ] Cryptography uses approved algorithms (Argon2id, AES-256, HMAC-SHA256)
- [ ] Error messages don't leak sensitive information
- [ ] Logging includes security events (login, logout, password change)
- [ ] No sensitive data logged (passwords, tokens, PII)
- [ ] CSRF protection implemented
- [ ] Session management secure (HttpOnly, Secure, SameSite cookies)
- [ ] Rate limiting applied to authentication endpoints
- [ ] Security headers set correctly
- [ ] TLS required for all communications

### 11.2 Incident Response Contacts

| Role | Name | Email | Phone | Availability |
|------|------|-------|-------|--------------|
| Security Lead | [Name] | security@sumafinance.com | +351-XXX-XXX-XXX | 24/7 |
| Data Protection Officer | [Name] | dpo@sumafinance.com | +351-XXX-XXX-XXX | Business hours |
| Engineering Manager | [Name] | eng-manager@sumafinance.com | +351-XXX-XXX-XXX | 24/7 (on-call) |
| Legal Counsel | [Name] | legal@sumafinance.com | +351-XXX-XXX-XXX | Business hours |
| CEO | [Name] | ceo@sumafinance.com | +351-XXX-XXX-XXX | 24/7 (escalation) |

**External Contacts:**
- AWS Support: +1-XXX-XXX-XXXX (Enterprise Support, 24/7)
- Portuguese CNPD (Data Protection Authority): +351-213-928-400
- PagerDuty Incident Response: incidents@sumafinance.pagerduty.com
- Security Incident Email: security-incident@sumafinance.com

### 11.3 Glossary

| Term | Definition |
|------|------------|
| 2FA | Two-Factor Authentication - second verification factor beyond password |
| APT | Advanced Persistent Threat - sophisticated, long-term cyber attack |
| Argon2id | Memory-hard password hashing algorithm, winner of Password Hashing Competition |
| CAPTCHA | Challenge-Response test to distinguish humans from bots |
| CSRF | Cross-Site Request Forgery - attack forcing user to execute unwanted actions |
| CSP | Content Security Policy - HTTP header to prevent XSS attacks |
| DPO | Data Protection Officer - responsible for GDPR compliance |
| GDPR | General Data Protection Regulation - EU privacy law |
| HMAC | Hash-based Message Authentication Code - cryptographic signature |
| HSTS | HTTP Strict Transport Security - forces HTTPS connections |
| IAM | Identity and Access Management - controls user access |
| JWT | JSON Web Token - compact token format for authentication |
| KMS | Key Management Service - manages encryption keys |
| MFA | Multi-Factor Authentication - requires multiple verification factors |
| OWASP | Open Web Application Security Project - security standards organization |
| OTP | One-Time Password - single-use verification code |
| PCI-DSS | Payment Card Industry Data Security Standard - payment security requirements |
| PII | Personally Identifiable Information - data identifying individuals |
| PKCE | Proof Key for Code Exchange - OAuth extension for mobile security |
| RBAC | Role-Based Access Control - permissions based on user roles |
| RTO | Recovery Time Objective - maximum acceptable downtime |
| RPO | Recovery Point Objective - maximum acceptable data loss |
| SAML | Security Assertion Markup Language - SSO standard |
| SAST | Static Application Security Testing - analyze source code for vulnerabilities |
| SIEM | Security Information and Event Management - centralized logging and alerting |
| SOC 2 | Service Organization Control 2 - security audit standard |
| SOAR | Security Orchestration, Automation and Response - automated incident response |
| SSRF | Server-Side Request Forgery - attack forcing server to make unintended requests |
| SSO | Single Sign-On - one set of credentials for multiple systems |
| STRIDE | Threat modeling framework (Spoofing, Tampering, Repudiation, etc.) |
| TLS | Transport Layer Security - encryption protocol for data in transit |
| UEBA | User Entity and Behavior Analytics - ML-based anomaly detection |
| WAF | Web Application Firewall - filters malicious HTTP traffic |
| XSS | Cross-Site Scripting - injection attack executing malicious scripts |

---

**Document Version:** 1.0  
**Last Updated:** 2025-10-29  
**Next Review:** 2026-01-29 (Quarterly)  
**Owner:** Security Team, SUMA Finance  
**Approval:** [Security Lead], [Engineering Manager], [DPO]

---

**Classification:** Internal - Confidential  
**Distribution:** Engineering team, Security team, Compliance team
