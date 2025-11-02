---
layout: default
title: 05 Security Compliance
nav_exclude: true
---


# Security & Compliance Specification

## 1. Security Architecture Overview

### Security Layers

```
┌─────────────────────────────────────────────────────────────┐
│                     NETWORK LAYER                            │
│  • TLS 1.3 encryption                                        │
│  • DDoS protection (AWS Shield)                              │
│  • WAF rules (AWS WAF)                                       │
│  • Rate limiting (Redis-based)                               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   APPLICATION LAYER                          │
│  • JWT authentication (RS256)                                │
│  • RBAC authorization                                        │
│  • Input validation & sanitization                           │
│  • CSRF protection                                           │
│  • XSS prevention (CSP headers)                              │
│  • Session management                                        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      DATA LAYER                              │
│  • Encryption at rest (AES-256-GCM)                          │
│  • Password hashing (Argon2id)                               │
│  • Database encryption (PostgreSQL TDE)                      │
│  • Secrets management (AWS Secrets Manager)                  │
│  • Audit logging                                             │
└─────────────────────────────────────────────────────────────┘
```

### Defense in Depth Strategy

1. **Perimeter Security**: WAF, DDoS protection, geographic IP filtering
2. **Network Security**: TLS 1.3, certificate pinning (mobile), VPC isolation
3. **Application Security**: Authentication, authorization, input validation
4. **Data Security**: Encryption, tokenization, secure key management
5. **Monitoring**: SIEM integration, real-time alerting, anomaly detection

### Security by Design Principles

- **Least Privilege**: Users and services have minimum necessary permissions
- **Zero Trust**: Never trust, always verify - authenticate every request
- **Fail Securely**: System defaults to secure state on errors
- **Privacy by Design**: GDPR compliance from architecture phase
- **Separation of Duties**: No single user can complete critical operations alone
- **Secure Defaults**: All security features enabled by default

### Threat Model Summary

**STRIDE Analysis:**

- **Spoofing**: Mitigated by JWT with RS256, MFA, device fingerprinting
- **Tampering**: Mitigated by HMAC signatures, TLS 1.3, token integrity checks
- **Repudiation**: Mitigated by comprehensive audit logging with digital signatures
- **Information Disclosure**: Mitigated by AES-256 encryption, TLS 1.3, access controls
- **Denial of Service**: Mitigated by rate limiting, account lockout, DDoS protection
- **Elevation of Privilege**: Mitigated by RBAC, session validation, permission checks

**Critical Assets:**
- User credentials (passwords, tokens)
- Personal Identifiable Information (PII)
- Financial transaction data
- Session tokens and refresh tokens
- Encryption keys

## 2. OWASP Top 10 Protections

### A01: Broken Access Control

**Implementation: RBAC with Least Privilege**

```
Roles Hierarchy:
├── Super Admin
│   └── All permissions + system configuration
├── Admin
│   └── User management + data management
├── Manager
│   └── Read/write for owned resources + team management
└── User
    └── Read/write for own resources only

Permission Matrix:
┌──────────────┬───────┬───────┬─────────┬──────┐
│ Resource     │ User  │ Mgr   │ Admin   │ SA   │
├──────────────┼───────┼───────┼─────────┼──────┤
│ Own Profile  │ RW    │ RW    │ RW      │ RW   │
│ Other Users  │ -     │ R     │ RWD     │ RWD  │
│ Settings     │ R     │ R     │ RW      │ RWD  │
│ Audit Logs   │ -     │ -     │ R       │ RW   │
│ System       │ -     │ -     │ -       │ RWD  │
└──────────────┴───────┴───────┴─────────┴──────┘
R=Read, W=Write, D=Delete
```

**Mitigation Strategies:**
- Session timeout: 15 minutes idle, 24 hours absolute
- Permission checks on every API endpoint
- Resource ownership validation (user can only access own data)
- Horizontal privilege escalation prevention
- Vertical privilege escalation prevention
- Direct object reference protection (use UUIDs, validate ownership)
- Multi-factor authentication for privileged operations
- Refresh token rotation with reuse detection

**Testing Approach:**
```
Unit Tests:
✓ Permission checking functions return correct boolean
✓ RBAC middleware blocks unauthorized access
✓ Resource ownership validation logic

Integration Tests:
✓ User cannot access another user's resources
✓ Manager can access team resources only
✓ Admin can perform privileged operations
✓ Session expires after 15 min idle
✓ Refresh token rotation works correctly

Security Tests:
✓ Direct object reference manipulation blocked
✓ Privilege escalation via token tampering blocked
✓ Session fixation attacks prevented
✓ IDOR (Insecure Direct Object Reference) attempts fail
```

### A02: Cryptographic Failures

**Encryption at Rest: AES-256-GCM**

```
PostgreSQL Database:
├── Transparent Data Encryption (TDE) enabled
├── Column-level encryption for PII
│   ├── Email: AES-256-GCM
│   ├── Phone: AES-256-GCM
│   └── MFA secrets: AES-256-GCM
└── Encrypted backups (separate key)

Redis Cache:
├── Encryption at rest enabled
└── TLS for in-transit encryption

File Storage (if applicable):
├── S3 bucket encryption (AES-256)
├── Server-side encryption with KMS
└── Versioning enabled for audit trail
```

**Encryption in Transit: TLS 1.3**

```
Configuration:
├── TLS 1.3 only (no TLS 1.2 or lower)
├── Cipher suites:
│   ├── TLS_AES_256_GCM_SHA384
│   ├── TLS_AES_128_GCM_SHA256
│   └── TLS_CHACHA20_POLY1305_SHA256
├── Perfect Forward Secrecy (PFS) enabled
├── HSTS header: max-age=31536000; includeSubDomains
├── Certificate: RSA 2048-bit or ECDSA P-256
└── Certificate rotation: Every 90 days (Let's Encrypt or ACM)

Mobile Apps:
├── Certificate pinning (public key pinning)
├── Fallback pins for rotation
└── Pin validation on every HTTPS request
```

**Key Management Strategy**

```
AWS Secrets Manager / HashiCorp Vault:
├── JWT signing keys (RS256, 2048-bit RSA)
│   ├── Private key: Stored in Secrets Manager
│   ├── Public key: Distributed to API servers
│   └── Rotation: Every 90 days with grace period
├── Database encryption keys
│   ├── Master key: AWS KMS
│   ├── Data encryption keys: Generated per environment
│   └── Rotation: Annual with re-encryption
├── HMAC signing keys (for tokens)
│   ├── 256-bit random keys
│   └── Rotation: Every 180 days
└── API keys for third-party services
    ├── SendGrid API key
    ├── Twilio API key
    └── Rotation: Manual, on security events

Key Access Control:
├── Production keys: Only accessible by production services (IAM roles)
├── Staging keys: Separate set for staging environment
├── Development keys: Dummy keys, no production data
└── Audit logging: All key access logged to CloudTrail
```

**Hashing Algorithms**

```
Password Hashing: Argon2id
├── Memory: 64 MB
├── Iterations: 3
├── Parallelism: 4
├── Salt: 128-bit random (generated per password)
├── Output: 256-bit hash
└── Time target: < 500ms per hash

Token Hashing: SHA-256
├── Refresh tokens: SHA-256 hash stored in DB
├── Password reset tokens: SHA-256 hash
├── Email verification tokens: SHA-256 hash
└── Salt: Not required (tokens are random)

HMAC Signing: HMAC-SHA256
├── Email verification links: HMAC signature
├── Password reset links: HMAC signature
└── Key: 256-bit secret from Secrets Manager
```

**Testing:**
- Verify TLS 1.3 only (use SSL Labs)
- Test certificate pinning in mobile apps
- Validate Argon2id parameters (hashcat benchmark)
- Ensure no plaintext sensitive data in logs
- Check S3 bucket encryption status

### A03: Injection

**SQL Injection Prevention: Parameterized Queries**

```go
// Go Example: Using sqlx with parameterized queries

// ✓ CORRECT: Parameterized query
func GetUserByEmail(db *sqlx.DB, email string) (*User, error) {
    var user User
    query := `SELECT id, email, password_hash FROM users WHERE email = $1`
    err := db.Get(&user, query, email)
    return &user, err
}

// ✗ INCORRECT: String concatenation (vulnerable)
func GetUserByEmailBad(db *sqlx.DB, email string) (*User, error) {
    query := "SELECT * FROM users WHERE email = '" + email + "'"
    // NEVER DO THIS!
}

// ✓ CORRECT: Prepared statements for repeated queries
stmt, err := db.Preparex(`SELECT id, email FROM users WHERE id = $1`)
defer stmt.Close()
for _, id := range userIDs {
    stmt.Get(&user, id)
}
```

**NoSQL Injection Prevention (if using MongoDB/DynamoDB)**

```javascript
// MongoDB Example

// ✓ CORRECT: Use typed queries
db.users.findOne({ email: email })

// ✗ INCORRECT: Accepting raw objects from user input
db.users.findOne(req.body.query) // User could pass {"$ne": null}

// ✓ CORRECT: Validate input types
if (typeof email !== 'string') {
    throw new Error('Invalid email type')
}
```

**Command Injection Prevention**

```go
// ✓ CORRECT: Use libraries, not shell commands
import "gopkg.in/gomail.v2"

func SendEmail(to, subject, body string) error {
    m := gomail.NewMessage()
    m.SetHeader("To", to)
    m.SetHeader("Subject", subject)
    m.SetBody("text/plain", body)
    return dialer.DialAndSend(m)
}

// ✗ INCORRECT: Executing shell commands with user input
cmd := exec.Command("sendmail", userEmail) // NEVER DO THIS
```

**LDAP Injection Prevention (if applicable)**

```go
// ✓ CORRECT: Escape special characters
func EscapeLDAP(input string) string {
    replacements := map[string]string{
        "\\": "\\5c", "*": "\\2a", "(": "\\28", 
        ")": "\\29", "\x00": "\\00",
    }
    for old, new := range replacements {
        input = strings.ReplaceAll(input, old, new)
    }
    return input
}

filter := fmt.Sprintf("(uid=%s)", EscapeLDAP(username))
```

**Input Validation**

```go
// Email validation
func ValidateEmail(email string) error {
    if len(email) > 254 {
        return errors.New("email too long")
    }
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(email) {
        return errors.New("invalid email format")
    }
    return nil
}

// Password validation
func ValidatePassword(password string) error {
    if len(password) < 12 || len(password) > 128 {
        return errors.New("password must be 12-128 characters")
    }
    if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
        return errors.New("password must contain uppercase")
    }
    if !regexp.MustCompile(`[a-z]`).MatchString(password) {
        return errors.New("password must contain lowercase")
    }
    if !regexp.MustCompile(`[0-9]`).MatchString(password) {
        return errors.New("password must contain number")
    }
    if !regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password) {
        return errors.New("password must contain special character")
    }
    return nil
}
```

**XSS Prevention**

```javascript
// React: Use framework protection (React escapes by default)
<div>{user.name}</div> // ✓ Auto-escaped

// ✗ INCORRECT: dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />

// ✓ CORRECT: Sanitize if HTML is necessary
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />

// Backend: Content-Security-Policy headers
Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self'; 
  style-src 'self' 'unsafe-inline'; 
  img-src 'self' data: https:; 
  font-src 'self'; 
  connect-src 'self'; 
  frame-ancestors 'none';
```

**CSRF Protection**

```go
// Double-submit cookie pattern
func CSRFMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
            cookieToken, err := r.Cookie("csrf_token")
            headerToken := r.Header.Get("X-CSRF-Token")
            
            if err != nil || cookieToken.Value != headerToken {
                http.Error(w, "CSRF validation failed", http.StatusForbidden)
                return
            }
        }
        next.ServeHTTP(w, r)
    })
}

// Or use SameSite=Strict cookies
http.SetCookie(w, &http.Cookie{
    Name:     "refresh_token",
    Value:    token,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
})
```

**Testing:**
- SQL injection payloads: `' OR '1'='1`, `1; DROP TABLE users;--`
- XSS payloads: `<script>alert('XSS')</script>`, `<img src=x onerror=alert('XSS')>`
- Command injection: `test@example.com; rm -rf /`
- CSRF: Attempt state-changing requests without token

### A04: Insecure Design

**Secure Design Principles Applied**

```
Authentication Flow Design:
┌─────────────────────────────────────────────────────────┐
│ 1. Registration                                         │
│    ├── Email uniqueness check (prevent user enumeration)│
│    ├── Password complexity validation                   │
│    ├── Rate limiting: 10 registrations/hour per IP      │
│    ├── CAPTCHA after 3 attempts                         │
│    ├── GDPR consent collection (checkboxes)             │
│    └── Email verification required before login         │
│                                                          │
│ 2. Email Verification                                   │
│    ├── Signed token (HMAC-SHA256)                       │
│    ├── Token expiration: 24 hours                       │
│    ├── One-time use (mark as used)                      │
│    ├── Rate limiting: 3 resend requests/hour            │
│    └── No sensitive info in email                       │
│                                                          │
│ 3. Login                                                │
│    ├── Email verification status check                  │
│    ├── Account lockout check                            │
│    ├── Password verification (constant-time comparison) │
│    ├── Failed attempt tracking                          │
│    ├── Rate limiting: 5 attempts/15min per IP           │
│    ├── Device fingerprinting                            │
│    ├── Geolocation anomaly detection                    │
│    └── Optional MFA (if enabled)                        │
│                                                          │
│ 4. Session Management                                   │
│    ├── Access token (JWT, 15 min expiry)                │
│    ├── Refresh token (7 days, stored in Redis)          │
│    ├── Token rotation on refresh                        │
│    ├── Reuse detection (revoke all if detected)         │
│    ├── Device tracking                                  │
│    └── Concurrent session limit: 3                      │
│                                                          │
│ 5. Password Reset                                       │
│    ├── Token generation (signed, 15 min expiry)         │
│    ├── Rate limiting: 3 requests/hour per user          │
│    ├── Email notification always sent (no user enum)    │
│    ├── One-time use token                               │
│    ├── Invalidate all sessions on password change       │
│    └── Notification email on successful reset           │
└─────────────────────────────────────────────────────────┘
```

**Threat Modeling Results**

```
Identified Threats:
├── Credential Theft
│   ├── Mitigation: MFA, strong password policy
│   ├── Mitigation: Compromised password detection (HaveIBeenPwned)
│   └── Mitigation: Login notifications for new devices
├── Session Hijacking
│   ├── Mitigation: TLS 1.3, HttpOnly cookies
│   ├── Mitigation: Token rotation, reuse detection
│   └── Mitigation: Device fingerprinting
├── Account Enumeration
│   ├── Mitigation: Generic error messages ("Invalid credentials")
│   ├── Mitigation: Same response time for valid/invalid emails
│   └── Mitigation: Always send reset email (don't reveal if user exists)
├── Brute Force
│   ├── Mitigation: Rate limiting, account lockout
│   ├── Mitigation: CAPTCHA after failed attempts
│   └── Mitigation: Progressive delays
├── Phishing
│   ├── Mitigation: Email link validation (hover to see domain)
│   ├── Mitigation: Short token expiry (15 min)
│   └── Mitigation: User education in emails
└── Man-in-the-Middle (MitM)
    ├── Mitigation: TLS 1.3 with PFS
    ├── Mitigation: HSTS headers
    └── Mitigation: Certificate pinning (mobile)
```

**Security Requirements in Design**

- **Business Requirement**: Users can reset their password
  - **Security Requirement**: Token expires in 15 minutes
  - **Security Requirement**: Rate limit to 3 requests/hour per user
  - **Security Requirement**: Invalidate all sessions on password change
  - **Security Requirement**: Notification email on successful reset

- **Business Requirement**: Users can stay logged in
  - **Security Requirement**: Refresh token rotation
  - **Security Requirement**: Reuse detection revokes all sessions
  - **Security Requirement**: Maximum 3 concurrent sessions
  - **Security Requirement**: 15-minute idle timeout

- **Business Requirement**: Secure user data
  - **Security Requirement**: AES-256-GCM encryption for PII
  - **Security Requirement**: Argon2id for password hashing
  - **Security Requirement**: TLS 1.3 for all data in transit

### A05: Security Misconfiguration

**Configuration Hardening Checklist**

```
Backend (Go API):
□ Debug endpoints disabled in production
  - Remove /debug/pprof
  - Remove /debug/vars
  - Remove any test endpoints
  
□ Error messages sanitized
  - No stack traces in API responses
  - Generic error messages ("An error occurred")
  - Detailed errors logged server-side only
  
□ Default credentials removed
  - No hardcoded passwords
  - No test accounts in production
  - Admin account requires strong password
  
□ Unnecessary features disabled
  - Disable unused HTTP methods (TRACE, OPTIONS if not needed)
  - Remove unused dependencies
  - Disable directory listing
  
□ Security headers configured
  - Strict-Transport-Security: max-age=31536000; includeSubDomains
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - X-XSS-Protection: 1; mode=block
  - Content-Security-Policy: (see A03)
  - Referrer-Policy: strict-origin-when-cross-origin
  - Permissions-Policy: geolocation=(), microphone=(), camera=()
  
□ CORS properly configured
  - Whitelist specific origins (not wildcard *)
  - Credentials: true only for trusted origins
  - Max age: 86400 (24 hours)
  
□ File upload restrictions (if applicable)
  - Max file size: 10 MB
  - Allowed extensions whitelist
  - Virus scanning
  - Store files outside web root
```

```
Frontend (React):
□ Production build used
  - npm run build (not dev mode)
  - Source maps disabled in production
  - React DevTools disabled
  
□ Environment variables secured
  - No secrets in .env (frontend)
  - Public keys only (for JWT verification)
  - Backend URL from environment
  
□ Console logs removed
  - No console.log in production
  - Use proper logging service (Sentry)
```

```
Database (PostgreSQL):
□ Strong authentication
  - No default passwords
  - Password rotation every 90 days
  - Certificate-based auth (if applicable)
  
□ Network isolation
  - Not publicly accessible
  - VPC only access
  - Firewall rules (allow only API servers)
  
□ Encryption enabled
  - TDE (Transparent Data Encryption)
  - SSL connections required
  
□ Audit logging enabled
  - Log all DDL changes
  - Log failed login attempts
  - Log privileged operations
```

```
Redis (Session Store):
□ Authentication enabled
  - requirepass set (strong password)
  - No default password
  
□ Network isolation
  - Bind to localhost or private IP
  - Firewall rules
  
□ Encryption enabled
  - TLS for connections
  - Encryption at rest
  
□ Dangerous commands disabled
  - FLUSHALL, FLUSHDB, KEYS, CONFIG
  - Rename commands in redis.conf
```

```
AWS Infrastructure:
□ IAM least privilege
  - Service-specific roles
  - No root account usage
  - MFA required for privileged users
  
□ S3 bucket hardening (if used)
  - Block public access
  - Encryption enabled
  - Versioning enabled
  - Logging enabled
  
□ Security groups
  - Minimal open ports
  - Source IP restrictions
  - Egress filtering
  
□ CloudTrail enabled
  - All API calls logged
  - Centralized logging
  - Alerts for suspicious activity
```

**Default Credentials Removal**

```bash
# Pre-deployment checklist script
#!/bin/bash

echo "Checking for default credentials..."

# Check for hardcoded secrets
grep -r "password" src/ --exclude-dir=node_modules | grep -v ".env.example"
grep -r "api_key" src/ --exclude-dir=node_modules | grep -v ".env.example"
grep -r "secret" src/ --exclude-dir=node_modules | grep -v ".env.example"

# Check for test accounts
psql -d $DB_NAME -c "SELECT email FROM users WHERE email LIKE '%test%' OR email LIKE '%admin%';"

# Verify environment variables are not committed
git log --all -- .env | head -n 1

echo "Review results above for any security issues."
```

**Error Message Sanitization**

```go
// ✓ CORRECT: Generic error messages to client
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    user, err := GetUserByEmail(email)
    if err != nil {
        // Log detailed error server-side
        logger.Error("Login failed", "email", email, "error", err)
        
        // Return generic error to client
        RespondJSON(w, 401, map[string]string{
            "error": "Invalid email or password",
        })
        return
    }
}

// ✗ INCORRECT: Revealing error details
func LoginHandlerBad(w http.ResponseWriter, r *http.Request) {
    user, err := GetUserByEmail(email)
    if err != nil {
        // NEVER do this - reveals if email exists
        RespondJSON(w, 404, map[string]string{
            "error": fmt.Sprintf("User not found: %s", email),
        })
        return
    }
}
```

**Security Headers Configuration**

```go
// Go middleware for security headers
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        
        next.ServeHTTP(w, r)
    })
}
```

**Testing:**
- Scan with OWASP ZAP or Burp Suite
- Check headers with securityheaders.com
- Verify no debug endpoints in production
- Confirm no default credentials
- Test error messages don't leak info

### A06: Vulnerable and Outdated Components

**Dependency Scanning**

```yaml
# GitHub Dependabot configuration (.github/dependabot.yml)
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    
  - package-ecosystem: "npm"
    directory: "/frontend"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    versioning-strategy: "increase"
```

```yaml
# Snyk configuration (.snyk)
version: v1.22.0
language-settings:
  go:
    severity-threshold: high
  javascript:
    severity-threshold: high

# Fail build on high/critical vulnerabilities
ignore:
  # Example: Ignoring non-exploitable vulnerability
  'SNYK-GO-GITHUBCOMGINGONICGIN-1234567':
    - '*':
        reason: 'Not exploitable in our context'
        expires: '2025-12-31'
```

**Weekly Scan Script**

```bash
#!/bin/bash
# scripts/security-scan.sh

echo "Running security scans..."

# Go dependencies
echo "Scanning Go dependencies..."
go list -json -m all | nancy sleuth

# NPM dependencies
echo "Scanning NPM dependencies..."
cd frontend && npm audit --audit-level=high

# Snyk scan
echo "Running Snyk scan..."
snyk test --severity-threshold=high

# OWASP Dependency Check
echo "Running OWASP Dependency Check..."
dependency-check --project "Finance App" --scan . --format HTML --out reports/

echo "Security scan complete. Review reports/ for details."
```

**Update Policy**

```
Vulnerability Severity Response Times:
├── Critical (CVSS 9.0-10.0)
│   ├── Response: Immediate (< 24 hours)
│   ├── Patching: Emergency deployment
│   └── Communication: Security advisory to users
│
├── High (CVSS 7.0-8.9)
│   ├── Response: Within 7 days
│   ├── Patching: Next scheduled release or hotfix
│   └── Communication: Internal notification
│
├── Medium (CVSS 4.0-6.9)
│   ├── Response: Within 30 days
│   ├── Patching: Next minor version
│   └── Communication: Release notes
│
└── Low (CVSS 0.1-3.9)
    ├── Response: Within 90 days
    ├── Patching: Next major version
    └── Communication: Changelog
```

**Vulnerability Response Process**

```
1. Detection
   ├── Automated: Dependabot/Snyk alerts
   ├── Manual: Security mailing lists (Go, React)
   └── Bug bounty: External researcher report

2. Triage (within 24 hours)
   ├── Assess severity (CVSS score)
   ├── Determine exploitability in our context
   ├── Identify affected systems/components
   └── Assign owner

3. Patching
   ├── Review patch notes from vendor
   ├── Test patch in staging environment
   ├── Schedule deployment based on severity
   └── Document changes

4. Deployment
   ├── Critical: Emergency deployment (24/7)
   ├── High: Hotfix within 7 days
   ├── Medium/Low: Regular release cycle
   └── Rollback plan prepared

5. Verification
   ├── Rescan with vulnerability scanner
   ├── Verify patch applied successfully
   ├── Test functionality not broken
   └── Update vulnerability tracking

6. Communication
   ├── Internal: Slack notification, incident report
   ├── External (if critical): Security advisory
   └── Documentation: Update changelog, runbook
```

**Testing:**
- Weekly automated scans (Snyk, Dependabot)
- Pre-deployment scan in CI/CD pipeline
- Manual review of dependency updates
- Test suite passes after updates

### A07: Identification and Authentication Failures

**Multi-Factor Authentication (MFA)**

```
MFA Flow:
┌──────────────────────────────────────────────────────────┐
│ 1. MFA Enrollment                                        │
│    ├── User opts in to MFA                               │
│    ├── Choose method: Email OTP or TOTP                  │
│    ├── Email OTP: 6-digit code, 5 min expiry             │
│    ├── TOTP: Generate secret, show QR code               │
│    ├── Verify enrollment with test code                  │
│    ├── Generate 10 backup codes (single-use)             │
│    └── Store encrypted MFA secret in database            │
│                                                           │
│ 2. MFA Login Challenge                                   │
│    ├── After password verification                       │
│    ├── Check if MFA enabled for user                     │
│    ├── Send OTP via email OR prompt for TOTP             │
│    ├── Rate limiting: 3 attempts, then 15 min lockout    │
│    ├── Code expiry: 5 minutes                            │
│    ├── Constant-time comparison (prevent timing attacks) │
│    ├── Allow backup code usage                           │
│    └── Invalidate code after successful use              │
│                                                           │
│ 3. Trusted Devices (Optional)                            │
│    ├── "Remember this device for 30 days" checkbox       │
│    ├── Store device fingerprint + random token           │
│    ├── Skip MFA if device recognized                     │
│    └── User can revoke trusted devices                   │
└──────────────────────────────────────────────────────────┘
```

**Email OTP Implementation**

```go
// Generate 6-digit OTP
func GenerateOTP() string {
    n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
    return fmt.Sprintf("%06d", n)
}

// Store OTP in Redis with 5-minute expiry
func StoreOTP(userID, otp string) error {
    key := fmt.Sprintf("otp:%s", userID)
    hashedOTP := HashSHA256(otp) // Store hash, not plaintext
    return redisClient.Set(ctx, key, hashedOTP, 5*time.Minute).Err()
}

// Verify OTP
func VerifyOTP(userID, inputOTP string) bool {
    key := fmt.Sprintf("otp:%s", userID)
    storedHash, err := redisClient.Get(ctx, key).Result()
    if err != nil {
        return false
    }
    
    // Constant-time comparison
    inputHash := HashSHA256(inputOTP)
    if subtle.ConstantTimeCompare([]byte(storedHash), []byte(inputHash)) != 1 {
        // Increment failed attempts
        IncrementFailedMFAAttempts(userID)
        return false
    }
    
    // Delete OTP after successful verification (one-time use)
    redisClient.Del(ctx, key)
    return true
}
```

**Password Policy Enforcement**

```go
type PasswordPolicy struct {
    MinLength         int
    MaxLength         int
    RequireUppercase  bool
    RequireLowercase  bool
    RequireNumbers    bool
    RequireSpecial    bool
    PreventReuse      int // Number of previous passwords
    MaxAge            int // Days until expiration (0 = never)
}

var DefaultPolicy = PasswordPolicy{
    MinLength:         12,
    MaxLength:         128,
    RequireUppercase:  true,
    RequireLowercase:  true,
    RequireNumbers:    true,
    RequireSpecial:    true,
    PreventReuse:      5,
    MaxAge:            0, // Consumer app - no forced expiry
}

func ValidatePasswordPolicy(password string, policy PasswordPolicy) error {
    if len(password) < policy.MinLength {
        return fmt.Errorf("password must be at least %d characters", policy.MinLength)
    }
    if len(password) > policy.MaxLength {
        return fmt.Errorf("password must not exceed %d characters", policy.MaxLength)
    }
    if policy.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
        return errors.New("password must contain at least one uppercase letter")
    }
    if policy.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
        return errors.New("password must contain at least one lowercase letter")
    }
    if policy.RequireNumbers && !regexp.MustCompile(`[0-9]`).MatchString(password) {
        return errors.New("password must contain at least one number")
    }
    if policy.RequireSpecial && !regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password) {
        return errors.New("password must contain at least one special character")
    }
    return nil
}

// Check against compromised passwords (HaveIBeenPwned API)
func IsPasswordCompromised(password string) (bool, error) {
    hash := sha1.Sum([]byte(password))
    hashStr := fmt.Sprintf("%X", hash)
    prefix := hashStr[:5]
    suffix := hashStr[5:]
    
    resp, err := http.Get(fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix))
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    return strings.Contains(string(body), suffix), nil
}

// Prevent password reuse
func CheckPasswordHistory(userID, newPassword string) error {
    history, err := GetPasswordHistory(userID, 5) // Last 5 passwords
    if err != nil {
        return err
    }
    
    for _, oldHash := range history {
        if VerifyArgon2Hash(newPassword, oldHash) {
            return errors.New("password was used recently, choose a different one")
        }
    }
    return nil
}
```

**Session Management**

```go
type Session struct {
    ID           string
    UserID       string
    DeviceID     string
    IPAddress    string
    UserAgent    string
    CreatedAt    time.Time
    LastActivity time.Time
    ExpiresAt    time.Time
}

// Create session with refresh token
func CreateSession(userID, deviceID, ip, userAgent string) (*Session, string, error) {
    session := &Session{
        ID:           uuid.New().String(),
        UserID:       userID,
        DeviceID:     deviceID,
        IPAddress:    ip,
        UserAgent:    userAgent,
        CreatedAt:    time.Now(),
        LastActivity: time.Now(),
        ExpiresAt:    time.Now().Add(7 * 24 * time.Hour), // 7 days
    }
    
    // Generate refresh token
    refreshToken := GenerateSecureToken(32)
    tokenHash := HashSHA256(refreshToken)
    
    // Store session in database
    _, err := db.Exec(`
        INSERT INTO refresh_tokens (id, user_id, token_hash, device_id, ip_address, user_agent, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, session.ID, session.UserID, tokenHash, session.DeviceID, session.IPAddress, session.UserAgent, session.ExpiresAt)
    
    if err != nil {
        return nil, "", err
    }
    
    return session, refreshToken, nil
}

// Refresh token rotation
func RotateRefreshToken(oldToken string) (string, error) {
    tokenHash := HashSHA256(oldToken)
    
    // Check if token exists and not expired
    var session Session
    err := db.Get(&session, `
        SELECT id, user_id, device_id, ip_address, user_agent, created_at, expires_at
        FROM refresh_tokens
        WHERE token_hash = $1 AND expires_at > NOW() AND revoked_at IS NULL
    `, tokenHash)
    
    if err != nil {
        // Check for reuse (token was already used and revoked)
        var reuseDetected bool
        db.Get(&reuseDetected, `
            SELECT EXISTS(SELECT 1 FROM refresh_tokens WHERE token_hash = $1 AND revoked_at IS NOT NULL)
        `, tokenHash)
        
        if reuseDetected {
            // SECURITY: Revoke all sessions for this user (potential token theft)
            RevokeAllUserSessions(session.UserID)
            logger.Error("Refresh token reuse detected", "user_id", session.UserID)
            return "", errors.New("token reuse detected, all sessions revoked")
        }
        
        return "", errors.New("invalid or expired token")
    }
    
    // Mark old token as revoked
    db.Exec(`UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1`, tokenHash)
    
    // Generate new token
    newToken := GenerateSecureToken(32)
    newTokenHash := HashSHA256(newToken)
    
    // Store new token
    db.Exec(`
        INSERT INTO refresh_tokens (id, user_id, token_hash, device_id, ip_address, user_agent, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, uuid.New().String(), session.UserID, newTokenHash, session.DeviceID, session.IPAddress, session.UserAgent, time.Now().Add(7*24*time.Hour))
    
    return newToken, nil
}

// Concurrent session limit
func EnforceConcurrentSessionLimit(userID string, maxSessions int) error {
    var count int
    db.Get(&count, `
        SELECT COUNT(*) FROM refresh_tokens 
        WHERE user_id = $1 AND expires_at > NOW() AND revoked_at IS NULL
    `, userID)
    
    if count >= maxSessions {
        // Revoke oldest session
        db.Exec(`
            UPDATE refresh_tokens 
            SET revoked_at = NOW()
            WHERE id = (
                SELECT id FROM refresh_tokens
                WHERE user_id = $1 AND expires_at > NOW() AND revoked_at IS NULL
                ORDER BY created_at ASC
                LIMIT 1
            )
        `, userID)
    }
    
    return nil
}
```

**Account Lockout Policy**

```go
type AccountLockoutConfig struct {
    MaxFailedAttempts int
    LockoutDuration   time.Duration
    ResetWindow       time.Duration
}

var LockoutPolicy = AccountLockoutConfig{
    MaxFailedAttempts: 5,
    LockoutDuration:   30 * time.Minute,
    ResetWindow:       15 * time.Minute,
}

func CheckAccountLockout(userID string) error {
    var lockedUntil *time.Time
    err := db.Get(&lockedUntil, `
        SELECT account_locked_until FROM users WHERE id = $1
    `, userID)
    
    if err != nil {
        return err
    }
    
    if lockedUntil != nil && time.Now().Before(*lockedUntil) {
        remainingTime := time.Until(*lockedUntil)
        return fmt.Errorf("account locked for %d more minutes", int(remainingTime.Minutes()))
    }
    
    return nil
}

func RecordFailedLogin(userID, ip string) error {
    // Increment failed attempts
    _, err := db.Exec(`
        UPDATE users 
        SET failed_login_attempts = failed_login_attempts + 1
        WHERE id = $1
    `, userID)
    
    if err != nil {
        return err
    }
    
    // Check if lockout threshold reached
    var attempts int
    db.Get(&attempts, `SELECT failed_login_attempts FROM users WHERE id = $1`, userID)
    
    if attempts >= LockoutPolicy.MaxFailedAttempts {
        lockedUntil := time.Now().Add(LockoutPolicy.LockoutDuration)
        db.Exec(`
            UPDATE users 
            SET account_locked_until = $1
            WHERE id = $2
        `, lockedUntil, userID)
        
        // Send notification email
        SendAccountLockoutEmail(userID)
        
        // Log security event
        logger.Warn("Account locked due to failed login attempts", 
            "user_id", userID, "ip", ip, "attempts", attempts)
    }
    
    return nil
}

func ResetFailedAttempts(userID string) error {
    _, err := db.Exec(`
        UPDATE users 
        SET failed_login_attempts = 0, account_locked_until = NULL
        WHERE id = $1
    `, userID)
    return err
}
```

**Testing:**
- Test MFA enrollment and verification
- Test account lockout after 5 failed attempts
- Test password policy enforcement
- Test refresh token rotation
- Test reuse detection
- Test concurrent session limits

### A08: Software and Data Integrity Failures

**Code Signing (GitHub Actions)**

```yaml
# .github/workflows/build.yml
name: Build and Sign

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Run tests
        run: go test -v -race -coverprofile=coverage.out ./...
      
      - name: Build binary
        run: go build -o bin/api-server cmd/server/main.go
      
      - name: Generate checksum
        run: sha256sum bin/api-server > bin/api-server.sha256
      
      - name: Sign binary (cosign)
        if: github.event_name == 'push'
        run: |
          cosign sign-blob \
            --key ${{ secrets.COSIGN_PRIVATE_KEY }} \
            --output-signature bin/api-server.sig \
            bin/api-server
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: signed-binary
          path: |
            bin/api-server
            bin/api-server.sha256
            bin/api-server.sig
```

**Dependency Integrity Checking**

```bash
# Go: go.sum file ensures integrity
go mod verify

# NPM: package-lock.json ensures integrity
npm ci --audit

# Docker: Verify base image digests
FROM golang:1.21@sha256:abc123... AS builder
```

**CI/CD Pipeline Security**

```yaml
# .github/workflows/deploy.yml
name: Secure Deploy

on:
  push:
    branches: [main]

jobs:
  security-checks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Secret scanning
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
      
      - name: SAST (Static Analysis)
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec -fmt json -out gosec-report.json ./...
      
      - name: Dependency check
        run: |
          go list -json -m all | nancy sleuth
      
      - name: Container scanning
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
  
  deploy:
    needs: security-checks
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to staging
        if: github.ref == 'refs/heads/main'
        run: |
          # Deploy logic
          
      - name: DAST (Dynamic Analysis)
        run: |
          # Run OWASP ZAP against staging
          docker run -t owasp/zap2docker-stable zap-baseline.py \
            -t https://staging.example.com -r zap-report.html
```

**Audit Logging with Digital Signatures**

```go
type AuditLog struct {
    ID        string    `json:"id"`
    Timestamp time.Time `json:"timestamp"`
    UserID    string    `json:"user_id"`
    Action    string    `json:"action"`
    Resource  string    `json:"resource"`
    IPAddress string    `json:"ip_address"`
    Signature string    `json:"signature"`
}

// Sign audit log entry
func SignAuditLog(log *AuditLog, privateKey *rsa.PrivateKey) error {
    // Create canonical JSON
    data, _ := json.Marshal(map[string]interface{}{
        "id":         log.ID,
        "timestamp":  log.Timestamp.Unix(),
        "user_id":    log.UserID,
        "action":     log.Action,
        "resource":   log.Resource,
        "ip_address": log.IPAddress,
    })
    
    // Sign with RSA-PSS
    hash := sha256.Sum256(data)
    signature, err := rsa.SignPSS(
        rand.Reader,
        privateKey,
        crypto.SHA256,
        hash[:],
        &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto},
    )
    
    if err != nil {
        return err
    }
    
    log.Signature = base64.StdEncoding.EncodeToString(signature)
    return nil
}

// Verify audit log integrity
func VerifyAuditLog(log *AuditLog, publicKey *rsa.PublicKey) error {
    data, _ := json.Marshal(map[string]interface{}{
        "id":         log.ID,
        "timestamp":  log.Timestamp.Unix(),
        "user_id":    log.UserID,
        "action":     log.Action,
        "resource":   log.Resource,
        "ip_address": log.IPAddress,
    })
    
    hash := sha256.Sum256(data)
    signature, _ := base64.StdEncoding.DecodeString(log.Signature)
    
    return rsa.VerifyPSS(
        publicKey,
        crypto.SHA256,
        hash[:],
        signature,
        &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto},
    )
}
```

**Testing:**
- Verify go.sum integrity with `go mod verify`
- Check NPM package integrity
- Verify Docker image signatures
- Test audit log signature verification

### A09: Security Logging and Monitoring Failures

**Authentication Event Logging**

```go
type AuthEvent struct {
    ID           string    `db:"id"`
    UserID       *string   `db:"user_id"` // Nullable for failed logins
    EventType    string    `db:"event_type"`
    IPAddress    string    `db:"ip_address"`
    UserAgent    string    `db:"user_agent"`
    Success      bool      `db:"success"`
    Metadata     string    `db:"metadata"` // JSON
    CreatedAt    time.Time `db:"created_at"`
}

// Event types
const (
    EventLogin               = "login"
    EventLoginFailed         = "login_failed"
    EventLogout              = "logout"
    EventPasswordReset       = "password_reset"
    EventPasswordResetFailed = "password_reset_failed"
    EventPasswordChanged     = "password_changed"
    EventMFAEnabled          = "mfa_enabled"
    EventMFADisabled         = "mfa_disabled"
    EventMFAVerified         = "mfa_verified"
    EventMFAFailed           = "mfa_failed"
    EventEmailVerified       = "email_verified"
    EventAccountLocked       = "account_locked"
    EventAccountUnlocked     = "account_unlocked"
    EventSessionRevoked      = "session_revoked"
)

func LogAuthEvent(eventType string, userID *string, success bool, ip, userAgent string, metadata map[string]interface{}) {
    metadataJSON, _ := json.Marshal(metadata)
    
    event := AuthEvent{
        ID:        uuid.New().String(),
        UserID:    userID,
        EventType: eventType,
        IPAddress: ip,
        UserAgent: userAgent,
        Success:   success,
        Metadata:  string(metadataJSON),
        CreatedAt: time.Now(),
    }
    
    // Store in database
    db.Exec(`
        INSERT INTO auth_events (id, user_id, event_type, ip_address, user_agent, success, metadata, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, event.ID, event.UserID, event.EventType, event.IPAddress, event.UserAgent, event.Success, event.Metadata, event.CreatedAt)
    
    // Also log to structured logger for SIEM
    logger := structlog.New().
        With("event_id", event.ID).
        With("event_type", event.EventType).
        With("user_id", event.UserID).
        With("ip_address", event.IPAddress).
        With("success", event.Success)
    
    if success {
        logger.Info("Authentication event")
    } else {
        logger.Warn("Authentication event failed")
    }
}

// Usage examples
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    password := r.FormValue("password")
    ip := GetClientIP(r)
    userAgent := r.UserAgent()
    
    user, err := AuthenticateUser(email, password)
    if err != nil {
        LogAuthEvent(EventLoginFailed, nil, false, ip, userAgent, map[string]interface{}{
            "email": email,
            "reason": "invalid_credentials",
        })
        RespondError(w, 401, "Invalid credentials")
        return
    }
    
    LogAuthEvent(EventLogin, &user.ID, true, ip, userAgent, map[string]interface{}{
        "email": email,
    })
    
    // Continue with login...
}
```

**Security Monitoring & Alerting**

```go
// Anomaly detection for suspicious login patterns
func DetectLoginAnomalies(userID string) []string {
    var anomalies []string
    
    // Check for logins from multiple countries in short time
    var countries []string
    db.Select(&countries, `
        SELECT DISTINCT country
        FROM auth_events
        WHERE user_id = $1 AND event_type = 'login' AND success = true
        AND created_at > NOW() - INTERVAL '1 hour'
    `, userID)
    
    if len(countries) > 2 {
        anomalies = append(anomalies, "multiple_countries_short_time")
    }
    
    // Check for high failure rate
    var failureRate float64
    db.Get(&failureRate, `
        SELECT 
            COUNT(*) FILTER (WHERE success = false)::float / 
            NULLIF(COUNT(*), 0) as failure_rate
        FROM auth_events
        WHERE user_id = $1 AND event_type = 'login'
        AND created_at > NOW() - INTERVAL '1 hour'
    `, userID)
    
    if failureRate > 0.5 {
        anomalies = append(anomalies, "high_failure_rate")
    }
    
    // Check for login outside normal hours
    var hour int
    db.Get(&hour, `SELECT EXTRACT(HOUR FROM NOW())`)
    
    if hour < 6 || hour > 22 {
        anomalies = append(anomalies, "unusual_time")
    }
    
    return anomalies
}

// Real-time alerting
func MonitorSecurityEvents() {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        // Alert on multiple failed logins from same IP
        var suspiciousIPs []string
        db.Select(&suspiciousIPs, `
            SELECT ip_address
            FROM auth_events
            WHERE event_type = 'login_failed'
            AND created_at > NOW() - INTERVAL '5 minutes'
            GROUP BY ip_address
            HAVING COUNT(*) >= 10
        `)
        
        for _, ip := range suspiciousIPs {
            SendAlert("Brute force attempt detected", map[string]interface{}{
                "ip": ip,
                "action": "consider_ip_ban",
            })
        }
        
        // Alert on account lockouts
        var lockedAccounts []string
        db.Select(&lockedAccounts, `
            SELECT user_id
            FROM auth_events
            WHERE event_type = 'account_locked'
            AND created_at > NOW() - INTERVAL '5 minutes'
        `)
        
        for _, userID := range lockedAccounts {
            SendAlert("Account locked", map[string]interface{}{
                "user_id": userID,
            })
        }
        
        // Alert on token reuse detection
        var tokenReuse []string
        db.Select(&tokenReuse, `
            SELECT user_id
            FROM auth_events
            WHERE metadata::jsonb @> '{"reason": "token_reuse"}'
            AND created_at > NOW() - INTERVAL '5 minutes'
        `)
        
        for _, userID := range tokenReuse {
            SendCriticalAlert("Token reuse detected (possible compromise)", map[string]interface{}{
                "user_id": userID,
                "action": "all_sessions_revoked",
            })
        }
    }
}
```

**SIEM Integration (Datadog Example)**

```go
import "github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"

func SendToSIEM(event AuthEvent) {
    ctx := datadog.NewDefaultContext(context.Background())
    configuration := datadog.NewConfiguration()
    apiClient := datadog.NewAPIClient(configuration)
    
    logEntry := datadogV2.HTTPLogItem{
        Ddsource: datadog.PtrString("finance-app-api"),
        Ddtags:   datadog.PtrString("env:production,service:auth"),
        Hostname: datadog.PtrString(os.Getenv("HOSTNAME")),
        Message:  datadog.PtrString(fmt.Sprintf("Auth event: %s", event.EventType)),
        Service:  datadog.PtrString("auth-service"),
    }
    
    body := datadogV2.HTTPLogItem{
        Ddsource: logEntry.Ddsource,
        Ddtags:   logEntry.Ddtags,
        Hostname: logEntry.Hostname,
        Message:  logEntry.Message,
        Service:  logEntry.Service,
    }
    
    apiClient.LogsApi.SubmitLog(ctx, []datadogV2.HTTPLogItem{body})
}
```

**Logging Configuration**

```go
// What NOT to log
func SanitizeForLogging(data map[string]interface{}) map[string]interface{} {
    sanitized := make(map[string]interface{})
    
    // Never log sensitive fields
    sensitiveFields := map[string]bool{
        "password":       true,
        "password_hash":  true,
        "token":          true,
        "refresh_token":  true,
        "access_token":   true,
        "mfa_secret":     true,
        "backup_codes":   true,
        "credit_card":    true,
        "ssn":            true,
    }
    
    for key, value := range data {
        if sensitiveFields[key] {
            sanitized[key] = "[REDACTED]"
        } else {
            sanitized[key] = value
        }
    }
    
    return sanitized
}
```

**Retention Policy**

```sql
-- Audit logs: 7 years (compliance)
-- Auth events: 1 year
-- Session logs: 90 days
-- Error logs: 30 days

-- Automated cleanup job
CREATE OR REPLACE FUNCTION cleanup_old_logs()
RETURNS void AS $$
BEGIN
    DELETE FROM auth_events WHERE created_at < NOW() - INTERVAL '1 year';
    DELETE FROM session_logs WHERE created_at < NOW() - INTERVAL '90 days';
    DELETE FROM error_logs WHERE created_at < NOW() - INTERVAL '30 days';
    -- Audit logs kept for 7 years (do not delete)
END;
$$ LANGUAGE plpgsql;

-- Schedule daily at 2 AM
SELECT cron.schedule('cleanup-logs', '0 2 * * *', 'SELECT cleanup_old_logs()');
```

**Testing:**
- Verify all auth events are logged
- Test alerting for suspicious patterns
- Check SIEM integration
- Validate log retention policy

### A10: Server-Side Request Forgery (SSRF)

**URL Validation for Email Verification Links**

```go
// Validate callback URLs to prevent SSRF
func ValidateCallbackURL(rawURL string) error {
    parsedURL, err := url.Parse(rawURL)
    if err != nil {
        return errors.New("invalid URL format")
    }
    
    // Only allow HTTPS
    if parsedURL.Scheme != "https" {
        return errors.New("only HTTPS URLs allowed")
    }
    
    // Allowlist domains
    allowedDomains := []string{
        "example.com",
        "app.example.com",
        "staging.example.com",
    }
    
    allowed := false
    for _, domain := range allowedDomains {
        if parsedURL.Host == domain {
            allowed = true
            break
        }
    }
    
    if !allowed {
        return fmt.Errorf("domain not allowed: %s", parsedURL.Host)
    }
    
    // Block private IP ranges
    host := parsedURL.Hostname()
    ip := net.ParseIP(host)
    if ip != nil {
        if isPrivateIP(ip) {
            return errors.New("private IP addresses not allowed")
        }
    } else {
        // Resolve hostname to check for private IPs
        ips, err := net.LookupIP(host)
        if err != nil {
            return err
        }
        for _, ip := range ips {
            if isPrivateIP(ip) {
                return errors.New("domain resolves to private IP")
            }
        }
    }
    
    return nil
}

func isPrivateIP(ip net.IP) bool {
    privateRanges := []string{
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16", // Link-local
        "::1/128",        // IPv6 loopback
        "fc00::/7",       // IPv6 private
    }
    
    for _, cidr := range privateRanges {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return true
        }
    }
    
    return false
}
```

**Network Segmentation**

```
Architecture:
┌───────────────────────────────────────────────────┐
│ Public Internet                                   │
└───────────────────────────────────────────────────┘
                      ↓
┌───────────────────────────────────────────────────┐
│ AWS WAF / CloudFront (CDN)                        │
└───────────────────────────────────────────────────┘
                      ↓
┌───────────────────────────────────────────────────┐
│ Public Subnet (DMZ)                               │
│ ├── Load Balancer (ALB)                           │
│ └── NAT Gateway                                   │
└───────────────────────────────────────────────────┘
                      ↓
┌───────────────────────────────────────────────────┐
│ Private Subnet (Application Layer)                │
│ ├── API Servers (ECS/Fargate)                     │
│ │   └── No direct internet access                 │
│ │   └── Outbound via NAT Gateway only             │
│ └── Security Group:                               │
│     ├── Inbound: ALB only                         │
│     └── Outbound: Database, Redis, NAT            │
└───────────────────────────────────────────────────┘
                      ↓
┌───────────────────────────────────────────────────┐
│ Private Subnet (Data Layer)                       │
│ ├── PostgreSQL (RDS)                              │
│ ├── Redis (ElastiCache)                           │
│ └── Security Group:                               │
│     ├── Inbound: API servers only                 │
│     └── Outbound: None                            │
└───────────────────────────────────────────────────┘
```

**Testing:**
- Attempt SSRF with private IPs (127.0.0.1, 10.0.0.1, 192.168.1.1)
- Test DNS rebinding attacks
- Verify network segmentation with security group rules
- Test URL validation bypass attempts

## 3. Authentication & Authorization

### 3.1 Authentication

**Multi-Factor Authentication Implementation**

```
MFA Methods:
├── Email OTP (Primary)
│   ├── 6-digit code
│   ├── 5-minute expiration
│   ├── Rate limit: 3 attempts per code
│   ├── Resend limit: 3 per hour
│   └── Constant-time comparison
│
├── TOTP (Recommended for power users)
│   ├── RFC 6238 compliant
│   ├── 30-second time step
│   ├── 6-digit code
│   ├── Compatible with Google Authenticator, Authy
│   └── QR code enrollment
│
└── Backup Codes
    ├── 10 single-use codes
    ├── Generated at MFA enrollment
    ├── 8-character alphanumeric
    └── Stored hashed in database
```

**Password Policy**

```
Requirements:
├── Length: 12-128 characters
├── Complexity:
│   ├── At least 1 uppercase letter (A-Z)
│   ├── At least 1 lowercase letter (a-z)
│   ├── At least 1 number (0-9)
│   └── At least 1 special character (!@#$%^&*(),.?":{}|<>)
├── Validation:
│   ├── Check against HaveIBeenPwned API (compromised passwords)
│   ├── No common passwords (top 10,000 list)
│   ├── No keyboard patterns (qwerty, 12345)
│   └── No user info (name, email local part)
├── History: Cannot reuse last 5 passwords
├── Max Age: No forced expiration (consumer app)
│   └── Enterprise: 90 days (configurable)
└── Reset: Requires email verification + current password (if known)
```

**Account Lockout Policy**

```
Progressive Lockout:
├── Failed Attempts: Track per user + per IP
├── Thresholds:
│   ├── 3 attempts → CAPTCHA required
│   ├── 5 attempts → Account locked for 30 minutes
│   ├── 10 attempts from same IP → IP ban for 1 hour
│   └── 50 attempts from same IP → Permanent IP ban (manual review)
├── Lockout Duration:
│   ├── Temporary: 30 minutes (automatic unlock)
│   ├── Permanent: Requires admin/support unlock
│   └── Email notification sent on lockout
├── CAPTCHA Integration:
│   ├── reCAPTCHA v3 (invisible, score-based)
│   ├── Fallback to v2 checkbox if low score
│   └── Required after 3 failed attempts
└── Geographic Anomaly:
    ├── Alert if login from new country
    ├── Email verification required
    └── Option to block login until verified
```

**Session Timeout Rules**

```
Timeouts:
├── Idle Timeout: 15 minutes
│   └── Activity: Any API request resets timer
├── Absolute Timeout: 24 hours
│   └── Requires re-authentication after 24h
├── Remember Me: 30 days
│   ├── Uses long-lived refresh token
│   ├── Requires re-authentication for sensitive operations
│   └── Device fingerprint stored
├── Concurrent Sessions: Maximum 3 per user
│   └── Oldest session auto-revoked when limit exceeded
└── Session Termination Events:
    ├── Password change → Revoke all sessions
    ├── MFA enable/disable → Revoke all sessions
    ├── Manual logout → Revoke current session
    ├── "Logout all devices" → Revoke all sessions
    └── Admin action → Can revoke specific or all sessions
```

**Token Expiry**

```
JWT Access Token:
├── Algorithm: RS256 (RSA 2048-bit)
├── Expiration: 15 minutes
├── Claims:
│   ├── sub: User ID (UUID)
│   ├── email: User email
│   ├── roles: ["user"] or ["admin"]
│   ├── iat: Issued at
│   ├── exp: Expiration
│   ├── jti: JWT ID (for revocation)
│   └── device_id: Device identifier
├── Signature: Verified on every request
└── Revocation: Not individually revocable (short-lived)

Refresh Token:
├── Format: Cryptographically secure random (32 bytes)
├── Storage: Hashed (SHA-256) in database
├── Expiration: 7 days (standard) or 30 days (remember me)
├── Rotation: New token issued on each refresh
├── Reuse Detection:
│   └── If old token used → Revoke all user sessions
├── Device Tracking:
│   ├── Store device ID, IP, user agent
│   └── User can view/revoke trusted devices
└── Maximum 3 concurrent refresh tokens per user

Email Verification Token:
├── Format: Signed HMAC-SHA256 (user_id + timestamp + random)
├── Expiration: 24 hours
├── One-time use: Marked as verified in database
├── Resend limit: 3 per hour per user
└── Link format: https://app.example.com/verify-email?token={token}

Password Reset Token:
├── Format: Signed HMAC-SHA256
├── Expiration: 15 minutes (short for security)
├── One-time use: Marked as used in database
├── Rate limit: 3 requests per hour per user
├── Always send email: Don't reveal if user exists
└── Link format: https://app.example.com/reset-password?token={token}

MFA OTP Code:
├── Format: 6-digit numeric
├── Expiration: 5 minutes
├── Storage: Hashed in Redis
├── Attempts: 3 max, then regenerate
└── Delivery: Email (primary) or TOTP app

Magic Link (Passwordless - Optional):
├── Format: Signed HMAC-SHA256
├── Expiration: 15 minutes
├── One-time use
└── Auto-login on click
```

### 3.2 Authorization

**Role-Based Access Control (RBAC)**

```
Role Hierarchy:
┌─────────────────────────────────────────────────┐
│ Super Admin                                     │
│ └── All permissions                             │
│     └── System configuration                    │
│         └── User management (all users)         │
│             └── Audit log access                │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│ Admin                                           │
│ └── User management (own organization)          │
│     └── Data management                         │
│         └── Reports access                      │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│ Manager                                         │
│ └── Team management                             │
│     └── Read/write own + team resources         │
│         └── Basic reports                       │
└─────────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────────┐
│ User (Default)                                  │
│ └── Read/write own resources only               │
│     └── Profile management                      │
└─────────────────────────────────────────────────┘
```

**Permission Matrix**

```
┌────────────────────┬──────┬─────────┬───────┬──────────┐
│ Resource           │ User │ Manager │ Admin │ SuperAdm │
├────────────────────┼──────┼─────────┼───────┼──────────┤
│ Own Profile        │ RWD  │ RWD     │ RWD   │ RWD      │
│ Own Data           │ RWD  │ RWD     │ RWD   │ RWD      │
│ Team Profiles      │ R    │ RW      │ RWD   │ RWD      │
│ Team Data          │ -    │ RW      │ RWD   │ RWD      │
│ All Users          │ -    │ -       │ RWD   │ RWD      │
│ Roles              │ -    │ -       │ RW    │ RWD      │
│ Settings           │ R    │ R       │ RW    │ RWD      │
│ Audit Logs         │ -    │ -       │ R     │ RW       │
│ System Config      │ -    │ -       │ -     │ RWD      │
│ API Keys           │ RWD  │ RWD     │ RWD   │ RWD      │
│ Billing            │ R    │ R       │ RW    │ RWD      │
│ Reports (own)      │ R    │ R       │ R     │ R        │
│ Reports (team)     │ -    │ R       │ R     │ R        │
│ Reports (all)      │ -    │ -       │ R     │ R        │
└────────────────────┴──────┴─────────┴───────┴──────────┘
R=Read, W=Write, D=Delete, -=No Access
```

**Granular Permissions**

```
Format: resource:action

User Permissions:
├── users:read (view user profiles)
├── users:write (update user profiles)
├── users:delete (delete user accounts)
├── users:create (create new users)
├── users:list (list all users)
└── users:manage_roles (assign roles)

Data Permissions:
├── data:read_own
├── data:write_own
├── data:delete_own
├── data:read_team
├── data:write_team
├── data:read_all
└── data:write_all

Financial Permissions (if fintech):
├── transactions:read_own
├── transactions:read_all
├── transactions:create
├── transactions:refund
├── transactions:export
└── transactions:reports

System Permissions:
├── system:config_read
├── system:config_write
├── system:logs_read
├── system:logs_export
├── system:maintenance
└── system:backups
```

**Implementation (Go Example)**

```go
type Permission string

const (
    PermUsersRead       Permission = "users:read"
    PermUsersWrite      Permission = "users:write"
    PermUsersDelete     Permission = "users:delete"
    PermDataReadOwn     Permission = "data:read_own"
    PermDataWriteOwn    Permission = "data:write_own"
    PermSystemConfigRW  Permission = "system:config_write"
)

type Role struct {
    Name        string
    Permissions []Permission
}

var Roles = map[string]Role{
    "user": {
        Name: "user",
        Permissions: []Permission{
            PermDataReadOwn,
            PermDataWriteOwn,
        },
    },
    "admin": {
        Name: "admin",
        Permissions: []Permission{
            PermUsersRead,
            PermUsersWrite,
            PermUsersDelete,
            PermDataReadOwn,
            PermDataWriteOwn,
            PermSystemConfigRW,
        },
    },
}

// Middleware to check permissions
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userID := r.Context().Value("user_id").(string)
            
            hasPermission, err := CheckUserPermission(userID, perm)
            if err != nil || !hasPermission {
                http.Error(w, "Forbidden", http.StatusForbidden)
                LogAuthEvent("authorization_failed", &userID, false, 
                    GetClientIP(r), r.UserAgent(), map[string]interface{}{
                        "required_permission": perm,
                        "resource": r.URL.Path,
                    })
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

func CheckUserPermission(userID string, perm Permission) (bool, error) {
    var userRoles []string
    err := db.Select(&userRoles, `
        SELECT role FROM user_roles WHERE user_id = $1
    `, userID)
    
    if err != nil {
        return false, err
    }
    
    for _, roleName := range userRoles {
        role, exists := Roles[roleName]
        if !exists {
            continue
        }
        
        for _, p := range role.Permissions {
            if p == perm {
                return true, nil
            }
        }
    }
    
    return false, nil
}

// Resource ownership validation
func CheckResourceOwnership(userID, resourceID string) (bool, error) {
    var ownerID string
    err := db.Get(&ownerID, `
        SELECT user_id FROM resources WHERE id = $1
    `, resourceID)
    
    if err != nil {
        return false, err
    }
    
    return ownerID == userID, nil
}
```

## 4. Data Protection

### 4.1 Data Classification

```
Data Sensitivity Levels:
┌────────────────────────────────────────────────────────┐
│ PUBLIC                                                 │
│ ├── Marketing materials                                │
│ ├── Public documentation                               │
│ ├── Product information                                │
│ └── Encryption: None required                          │
│     Storage: Public S3 bucket or CDN                   │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ INTERNAL                                               │
│ ├── Business documents                                 │
│ ├── Internal communications                            │
│ ├── Non-sensitive analytics                            │
│ └── Encryption: TLS in transit                         │
│     Storage: Private S3 bucket                         │
│     Access: Authenticated employees only               │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ CONFIDENTIAL (PII)                                     │
│ ├── User emails                                        │
│ ├── Phone numbers                                      │
│ ├── Addresses                                          │
│ ├── Date of birth                                      │
│ ├── IP addresses (logged)                              │
│ └── Encryption: AES-256-GCM at rest + TLS in transit   │
│     Storage: Encrypted database columns                │
│     Access: Need-to-know basis, audit logged           │
│     Retention: Until account deletion + 30 days        │
│     GDPR: Data subject rights apply                    │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ RESTRICTED (Financial & Credentials)                   │
│ ├── Password hashes (Argon2id)                         │
│ ├── MFA secrets                                        │
│ ├── Payment card data (if stored - PCI DSS)            │
│ ├── Bank account numbers                               │
│ ├── Transaction history                                │
│ └── Encryption: AES-256-GCM + tokenization             │
│     Storage: Encrypted database, KMS-managed keys      │
│     Access: Least privilege, MFA required              │
│     Retention: 7 years (compliance)                    │
│     PCI-DSS: Full compliance if storing card data      │
│     Audit: All access logged with digital signatures   │
└────────────────────────────────────────────────────────┘
```

### 4.2 Encryption Strategy

**At Rest Encryption**

```
Database (PostgreSQL):
├── Transparent Data Encryption (TDE)
│   ├── Entire database encrypted with AES-256
│   ├── Managed by AWS RDS (automatic)
│   └── Key rotation: Annual
│
├── Column-Level Encryption (PII fields)
│   ├── Email: AES-256-GCM (application-level)
│   ├── Phone: AES-256-GCM
│   ├── MFA secret: AES-256-GCM
│   ├── Encryption keys: AWS KMS
│   └── Data Encryption Keys (DEK): Per-environment
│
└── Backup Encryption
    ├── Automated RDS snapshots: Encrypted with same key
    ├── Manual backups: Separate encryption key
    └── Stored in separate AWS account

File Storage (S3):
├── Server-Side Encryption: SSE-KMS
├── Bucket default encryption: Enabled
├── Key: AWS KMS customer-managed key
├── Versioning: Enabled
└── Access logging: Enabled

Redis (Session Store):
├── Encryption at rest: Enabled (ElastiCache)
├── In-transit encryption: TLS 1.3
└── Auth token: Required for all connections

Secrets (AWS Secrets Manager):
├── JWT signing keys (RSA private key)
├── Database passwords
├── API keys (SendGrid, Twilio, etc.)
├── Encryption: AES-256-GCM (managed by AWS)
└── Rotation: Automatic for DB passwords, manual for others
```

**In Transit Encryption**

```
TLS 1.3 Configuration:
├── Protocols: TLS 1.3 only (no TLS 1.2 or lower)
├── Cipher Suites:
│   ├── TLS_AES_256_GCM_SHA384 (preferred)
│   ├── TLS_AES_128_GCM_SHA256
│   └── TLS_CHACHA20_POLY1305_SHA256
├── Perfect Forward Secrecy: Enabled
├── Certificate:
│   ├── Type: RSA 2048-bit or ECDSA P-256
│   ├── Issuer: Let's Encrypt or AWS Certificate Manager
│   ├── Validity: 90 days (auto-renewal)
│   └── Wildcard: *.example.com
├── HSTS Header:
│   └── Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
└── OCSP Stapling: Enabled

Mobile App Certificate Pinning:
├── Public key pinning (not certificate pinning)
├── Pin both current + backup keys
├── Validation: On every HTTPS request
├── Failure: Block request, log security event
└── Update mechanism: App update for key rotation
```

**Key Management**

```
AWS KMS (Key Management Service):
┌─────────────────────────────────────────────────────┐
│ Customer Master Key (CMK)                           │
│ ├── finance-app-production-master                   │
│ ├── Purpose: Encrypt Data Encryption Keys (DEKs)    │
│ ├── Rotation: Automatic annual rotation             │
│ └── Access: IAM policies (least privilege)          │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ Data Encryption Keys (DEKs)                         │
│ ├── database-encryption-key (AES-256)               │
│ │   └── Used for column-level encryption            │
│ ├── jwt-signing-key (RSA 2048-bit private key)      │
│ │   └── Rotation: Every 90 days with grace period   │
│ ├── hmac-signing-key (256-bit)                      │
│ │   └── Used for token signatures                   │
│ └── session-encryption-key (AES-256)                │
│     └── Used for Redis session encryption           │
└─────────────────────────────────────────────────────┘

Key Rotation Schedule:
├── CMK: Automatic annual rotation (AWS KMS)
├── Database DEK: Annual with re-encryption (planned)
├── JWT signing key: Every 90 days
│   └── Grace period: 7 days (accept old + new keys)
├── HMAC signing key: Every 180 days
└── TLS certificates: Every 90 days (Let's Encrypt auto-renewal)

Key Access Audit:
├── All key access logged to AWS CloudTrail
├── Alerts on unauthorized access attempts
├── Quarterly access review
└── Immediate revocation on security incident
```

### 4.3 Data Retention & Deletion

```
GDPR-Compliant Retention:
┌────────────────────────────────────────────────────────┐
│ User Account Data                                      │
│ ├── Active account: Retained indefinitely              │
│ ├── Account deletion request: 30-day grace period      │
│ │   └── User can restore within 30 days                │
│ ├── After 30 days: Permanent deletion                  │
│ │   ├── Hard delete from users table                   │
│ │   ├── Anonymize auth_events (replace user_id with   │
│ │   │   "deleted_user_{uuid}" for audit purposes)      │
│ │   ├── Delete refresh tokens                          │
│ │   ├── Delete MFA secrets                             │
│ │   └── Delete associated PII                          │
│ └── Export user data before deletion (GDPR right)      │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ Audit Logs (Compliance Requirement)                    │
│ ├── Retention: 7 years                                 │
│ ├── Reason: Financial regulations, fraud prevention    │
│ ├── Anonymization: Replace deleted user PII            │
│ └── Storage: Append-only, immutable (S3 Glacier)       │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ Authentication Events                                  │
│ ├── Retention: 1 year                                  │
│ ├── Purpose: Security monitoring, fraud detection      │
│ └── Deletion: Automated job (monthly)                  │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ Session Tokens                                         │
│ ├── Access tokens (JWT): Self-expiring (15 min)        │
│ ├── Refresh tokens: Deleted after 7/30 days            │
│ ├── Expired tokens: Deleted immediately                │
│ └── Revoked tokens: Kept for 90 days (fraud analysis)  │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ Database Backups                                       │
│ ├── Full backups: 90 days retention                    │
│ ├── Incremental backups: 30 days                       │
│ ├── Deleted user data: Remains in backups              │
│ │   └── GDPR compliance: Document retention policy     │
│ └── Encryption: All backups encrypted                  │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│ Application Logs                                       │
│ ├── Error logs: 30 days                                │
│ ├── Debug logs: 7 days (non-production only)           │
│ ├── Access logs: 90 days                               │
│ └── Security logs: 1 year                              │
└────────────────────────────────────────────────────────┘
```

**GDPR Right to Erasure Implementation**

```go
func DeleteUserAccount(userID string) error {
    // Step 1: Mark account for deletion (30-day grace period)
    _, err := db.Exec(`
        UPDATE users 
        SET deletion_requested_at = NOW(),
            account_status = 'pending_deletion'
        WHERE id = $1
    `, userID)
    
    if err != nil {
        return err
    }
    
    // Send confirmation email
    SendAccountDeletionEmail(userID)
    
    return nil
}

// Automated job runs daily
func ProcessPendingDeletions() error {
    var usersToDelete []string
    err := db.Select(&usersToDelete, `
        SELECT id FROM users
        WHERE deletion_requested_at < NOW() - INTERVAL '30 days'
        AND account_status = 'pending_deletion'
    `)
    
    if err != nil {
        return err
    }
    
    for _, userID := range usersToDelete {
        err := PermanentlyDeleteUser(userID)
        if err != nil {
            logger.Error("Failed to delete user", "user_id", userID, "error", err)
            continue
        }
        
        logger.Info("User permanently deleted (GDPR)", "user_id", userID)
    }
    
    return nil
}

func PermanentlyDeleteUser(userID string) error {
    tx, err := db.Beginx()
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    // Delete refresh tokens
    tx.Exec(`DELETE FROM refresh_tokens WHERE user_id = $1`, userID)
    
    // Delete MFA secrets
    tx.Exec(`DELETE FROM mfa_secrets WHERE user_id = $1`, userID)
    
    // Delete consents
    tx.Exec(`DELETE FROM user_consents WHERE user_id = $1`, userID)
    
    // Anonymize auth events (keep for audit purposes)
    anonymizedID := fmt.Sprintf("deleted_user_%s", uuid.New().String())
    tx.Exec(`UPDATE auth_events SET user_id = $1 WHERE user_id = $2`, anonymizedID, userID)
    
    // Delete user account (cascades to related tables via foreign keys)
    tx.Exec(`DELETE FROM users WHERE id = $1`, userID)
    
    // Commit transaction
    return tx.Commit()
}
```

## 5. Compliance Requirements

### 5.1 GDPR Compliance (EU Regulation 2016/679)

**Lawful Basis for Processing**

```
Data Processing Basis:
├── Consent: Marketing communications
│   ├── Explicit opt-in required
│   ├── Granular controls (email, SMS, push)
│   ├── Easy withdrawal mechanism
│   └── Documented consent timestamp + IP
│
├── Contract: Account creation and service delivery
│   ├── Necessary for providing authentication
│   ├── Session management
│   └── Account recovery
│
└── Legitimate Interest: Fraud prevention and security
    ├── Security event logging
    ├── Anomaly detection
    └── Incident response
```

**Data Minimization**

```
Principle: Collect only necessary data

Required for Authentication System:
✓ Email address (for login + recovery)
✓ Password hash (Argon2id)
✓ Email verification status
✓ MFA settings (if enabled)
✓ Account creation timestamp

Optional (for enhanced security):
✓ Phone number (for SMS 2FA - opt-in)
✓ Device fingerprints (for trusted devices)
✓ IP address (for fraud detection)

NOT Collected Unless Business Need:
✗ Full name (not required for this system)
✗ Date of birth
✗ Address
✗ Social media profiles
```

**Right to Access (Data Portability)**

```go
// Export user data in machine-readable format (JSON)
func ExportUserData(userID string) (map[string]interface{}, error) {
    data := make(map[string]interface{})
    
    // User profile
    var user struct {
        Email            string    `db:"email"`
        EmailVerified    bool      `db:"email_verified"`
        MFAEnabled       bool      `db:"mfa_enabled"`
        CreatedAt        time.Time `db:"created_at"`
        LastLoginAt      *time.Time `db:"last_login_at"`
    }
    db.Get(&user, `SELECT email, email_verified, mfa_enabled, created_at, last_login_at FROM users WHERE id = $1`, userID)
    data["profile"] = user
    
    // Consents
    var consents []struct {
        Type        string    `db:"consent_type"`
        Consented   bool      `db:"consented"`
        ConsentedAt time.Time `db:"consented_at"`
    }
    db.Select(&consents, `SELECT consent_type, consented, consented_at FROM user_consents WHERE user_id = $1`, userID)
    data["consents"] = consents
    
    // Active sessions (devices)
    var sessions []struct {
        DeviceID  string    `db:"device_id"`
        IPAddress string    `db:"ip_address"`
        UserAgent string    `db:"user_agent"`
        CreatedAt time.Time `db:"created_at"`
    }
    db.Select(&sessions, `
        SELECT device_id, ip_address, user_agent, created_at 
        FROM refresh_tokens 
        WHERE user_id = $1 AND expires_at > NOW() AND revoked_at IS NULL
    `, userID)
    data["active_sessions"] = sessions
    
    // Recent auth events (last 90 days)
    var authEvents []struct {
        EventType string    `db:"event_type"`
        IPAddress string    `db:"ip_address"`
        Success   bool      `db:"success"`
        CreatedAt time.Time `db:"created_at"`
    }
    db.Select(&authEvents, `
        SELECT event_type, ip_address, success, created_at 
        FROM auth_events 
        WHERE user_id = $1 AND created_at > NOW() - INTERVAL '90 days'
        ORDER BY created_at DESC
    `, userID)
    data["recent_auth_events"] = authEvents
    
    return data, nil
}

// API endpoint for data export
func HandleDataExportRequest(w http.ResponseWriter, r *http.Request) {
    userID := r.Context().Value("user_id").(string)
    
    // Generate export (may be async for large datasets)
    data, err := ExportUserData(userID)
    if err != nil {
        http.Error(w, "Failed to export data", http.StatusInternalServerError)
        return
    }
    
    // Log the access request (GDPR requirement)
    LogAuthEvent("data_export", &userID, true, GetClientIP(r), r.UserAgent(), nil)
    
    // Return JSON
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Content-Disposition", "attachment; filename=\"my-data.json\"")
    json.NewEncoder(w).Encode(data)
}
```

**Right to Erasure ("Right to be Forgotten")**

See section 4.3 for implementation details.

**Right to Portability**

Same as Right to Access - JSON export format allows import to other services.

**Data Breach Notification**

```
Breach Response Timeline:
├── Detection (T+0):
│   ├── Automated alerts (anomaly detection)
│   ├── Manual discovery (security audit)
│   └── External report (researcher, user)
│
├── Containment (T+1 hour):
│   ├── Isolate affected systems
│   ├── Revoke compromised credentials
│   └── Block attacker access
│
├── Assessment (T+24 hours):
│   ├── Determine scope (how many users affected)
│   ├── Identify data types compromised
│   ├── Assess risk to individuals
│   └── Document timeline and actions
│
├── Notification to DPA (T+72 hours):
│   ├── GDPR requirement: Within 72 hours
│   ├── Report to supervisory authority
│   ├── Include: Nature of breach, data affected, mitigation
│   └── Ongoing investigation updates
│
└── User Notification (T+72-96 hours):
    ├── Email to affected users
    ├── Public disclosure (if high risk)
    ├── Recommended actions (password reset, MFA enable)
    └── Contact information for questions
```

**Privacy by Design & Default**

```
Default Privacy Settings:
✓ Account: Private by default
✓ Marketing emails: Opt-in (not opt-out)
✓ Data sharing: Disabled by default
✓ Session timeout: 15 minutes (most restrictive)
✓ Password visibility: Hidden by default
✓ MFA: Recommended on first login
```

**Data Protection Officer (DPO)**

```
DPO Contact:
Name: [To be assigned]
Email: dpo@example.com
Phone: +1-XXX-XXX-XXXX
Address: [Company address]

Responsibilities:
├── Monitor GDPR compliance
├── Advise on data protection impact assessments (DPIA)
├── Cooperate with supervisory authorities
├── Handle data subject requests
└── Training and awareness programs
```

### 5.2 PCI-DSS Compliance (if applicable)

**Note:** Only applicable if storing, processing, or transmitting payment card data. If using a payment processor (Stripe, PayPal), they handle PCI compliance.

**Requirement 1: Install and Maintain Firewall**
- AWS Security Groups (stateful firewall)
- Network ACLs for subnet-level filtering
- WAF rules to block malicious traffic

**Requirement 2: Change Vendor Defaults**
- No default passwords (enforced in deployment)
- All system components hardened
- Unnecessary services disabled

**Requirement 3: Protect Stored Cardholder Data**
- **CRITICAL:** Do NOT store full PAN (Primary Account Number)
- Use tokenization (Stripe, PayPal tokens only)
- If storing: Encrypt with AES-256, separate encryption keys
- Never store CVV/CVC, PIN, or magnetic stripe data

**Requirement 4: Encrypt Transmission of Cardholder Data**
- TLS 1.3 for all payment data transmission
- Certificate pinning for mobile apps
- No card data in URLs or logs

**Requirement 5: Use Anti-Virus**
- Endpoint protection on development machines
- Container scanning (Trivy, Snyk)
- Malware scanning for file uploads

**Requirement 6: Develop Secure Systems**
- SAST/DAST in CI/CD pipeline
- Security code review for all changes
- Patch management (see A06)

**Requirement 7: Restrict Access (Need-to-Know)**
- RBAC with least privilege
- No access to card data unless absolutely necessary
- MFA required for privileged access

**Requirement 8: Identify and Authenticate Access**
- See section 3.1 (Authentication)
- Unique user IDs
- MFA for administrative access

**Requirement 9: Restrict Physical Access**
- Data center physical security (AWS responsibility)
- No card data on developer machines
- Secure disposal of media

**Requirement 10: Track and Monitor All Access**
- See section A09 (Logging and Monitoring)
- Audit trail for all cardholder data access
- Log review: Daily (automated), Weekly (manual)

**Requirement 11: Regularly Test Security**
- Quarterly vulnerability scans (ASV)
- Annual penetration testing
- File integrity monitoring (FIM)

**Requirement 12: Maintain Information Security Policy**
- Security policy document (separate)
- Annual review and updates
- Employee training: Quarterly

### 5.3 SOC 2 Type II Compliance

**Security**
- Access controls: RBAC (see 3.2)
- Encryption: AES-256 at rest, TLS 1.3 in transit (see 4.2)
- Firewall: AWS Security Groups, WAF (see 5.2)
- MFA: Required for privileged accounts (see 3.1)

**Availability**
- SLA: 99.9% uptime target
- Monitoring: Datadog for infrastructure, Sentry for errors
- Incident response: 24/7 on-call rotation
- Backup: Automated daily backups, 90-day retention
- Disaster recovery: RTO 4 hours, RPO 1 hour

**Processing Integrity**
- Input validation: All user inputs validated (see A03)
- Error handling: Graceful degradation, no data loss
- Transaction logging: All critical operations logged
- Testing: See testingStrategy in input data

**Confidentiality**
- Encryption: See 4.2
- NDAs: All employees sign NDA
- Third-party: Vendor security assessments
- Data classification: See 4.1

**Privacy**
- GDPR alignment: See 5.1
- Consent management: Granular controls
- Data minimization: Only collect necessary data
- Breach notification: See 5.1

### 5.4 HIPAA Compliance (if applicable)

**Note:** Only applicable if handling Protected Health Information (PHI). Not typically required for fintech authentication systems unless healthcare integration.

**Physical Safeguards**
- Data center security (AWS responsibility)
- Workstation security policies
- Device and media controls

**Technical Safeguards**
- Access controls: RBAC with MFA
- Audit controls: Comprehensive logging
- Integrity controls: Digital signatures, checksums
- Transmission security: TLS 1.3

**Administrative Safeguards**
- Security management process
- Assigned security responsibility (CISO)
- Workforce training: Annual HIPAA training
- Contingency planning: Disaster recovery

**Breach Notification**
- Timeline: Within 60 days of discovery
- Notification: To HHS, affected individuals, media (if >500 people)

**Business Associate Agreements (BAA)**
- Required with all vendors handling PHI
- Specify permitted uses and disclosures
- Liability and indemnification clauses

## 6. API Security

```
API Security Layers:
┌─────────────────────────────────────────────────────┐
│ 1. Rate Limiting (per user + per IP)                │
│    ├── Anonymous: 10 req/min                        │
│    ├── Authenticated: 100 req/min                   │
│    ├── Premium users: 500 req/min                   │
│    ├── Burst: 2x sustained rate for 10 seconds      │
│    └── 429 Too Many Requests response               │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 2. Authentication (Bearer JWT)                      │
│    ├── Header: Authorization: Bearer {jwt}          │
│    ├── Verify signature (RS256)                     │
│    ├── Check expiration                             │
│    ├── Validate claims (sub, roles, etc.)           │
│    └── 401 Unauthorized if invalid                  │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 3. Authorization (Permission-Based)                 │
│    ├── Extract user roles from JWT                  │
│    ├── Check required permissions for endpoint      │
│    ├── Validate resource ownership                  │
│    └── 403 Forbidden if insufficient permissions    │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 4. Input Validation (Schema Validation)             │
│    ├── JSON schema validation                       │
│    ├── Type checking (string, int, email, etc.)     │
│    ├── Length limits (email max 254, etc.)          │
│    ├── Regex patterns (email, UUID, etc.)           │
│    └── 400 Bad Request if invalid                   │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 5. Output Encoding (Prevent XSS)                    │
│    ├── JSON responses (auto-encoded)                │
│    ├── HTML escape if returning HTML                │
│    ├── Content-Type header set correctly            │
│    └── CSP headers (see A03)                        │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│ 6. CORS Policy (Whitelist Origins)                  │
│    ├── Allowed origins: https://app.example.com     │
│    ├── Credentials: true (for cookies)              │
│    ├── Methods: GET, POST, PUT, DELETE, OPTIONS     │
│    ├── Headers: Authorization, Content-Type         │
│    └── Max-Age: 86400 (24 hours)                    │
└─────────────────────────────────────────────────────┘
```

**Rate Limiting Implementation (Go + Redis)**

```go
import "github.com/go-redis/redis_rate/v10"

func RateLimitMiddleware(limiter *redis_rate.Limiter) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Determine limit based on authentication
            var limit redis_rate.Limit
            userID := r.Context().Value("user_id")
            
            if userID == nil {
                // Anonymous user
                limit = redis_rate.PerMinute(10)
            } else {
                // Authenticated user
                limit = redis_rate.PerMinute(100)
            }
            
            // Use IP + user ID as key
            key := fmt.Sprintf("rate:%s:%s", GetClientIP(r), userID)
            
            res, err := limiter.Allow(r.Context(), key, limit)
            if err != nil {
                http.Error(w, "Internal error", http.StatusInternalServerError)
                return
            }
            
            // Set rate limit headers
            w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit.Rate))
            w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", res.Remaining))
            w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", res.ResetAfter.Unix()))
            
            if res.Allowed == 0 {
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                
                // Log rate limit violation
                logger.Warn("Rate limit exceeded", "ip", GetClientIP(r), "user_id", userID)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
```

## 7. Secure Development Lifecycle (SDL)

### 7.1 Design Phase

**Threat Modeling (STRIDE)**
- Conducted during architecture design
- Identify assets, threats, and mitigations
- Document in threat model document
- Review and update quarterly

**Security Requirements**
- All security requirements documented (see input data)
- Mapped to OWASP Top 10, GDPR, etc.
- Reviewed by security team

**Privacy Impact Assessment (PIA)**
- For all features handling PII
- Assess necessity, proportionality, safeguards
- Document in PIA report
- DPO approval required

### 7.2 Development Phase

**Secure Coding Guidelines**
- Follow OWASP Secure Coding Practices
- Language-specific guides (Go, JavaScript)
- Code examples in internal wiki
- Training: Bi-annual secure coding workshop

**Code Reviews (Security Focus)**
- All PRs require 1 security-focused review
- Checklist: Input validation, authentication, authorization, secrets
- Security team review for critical changes
- Automated checks (gosec, ESLint security plugin)

**Static Analysis (SAST)**
- Gosec for Go code
- ESLint security plugin for JavaScript
- SonarQube for comprehensive analysis
- Runs on every commit (GitHub Actions)

### 7.3 Testing Phase

**SAST (Static Application Security Testing)**
- Tools: Gosec, SonarQube, Checkmarx
- Frequency: Every commit
- Fail build on: Critical/High vulnerabilities

**DAST (Dynamic Application Security Testing)**
- Tools: OWASP ZAP, Burp Suite
- Frequency: Every deployment to staging
- Scope: All API endpoints
- Authenticated scans (with test account)

**Penetration Testing**
- Frequency: Annually (or after major changes)
- Scope: Full application (black-box + gray-box)
- Conducted by: Third-party security firm
- Report: Vulnerabilities, risk ratings, recommendations
- Remediation: Critical within 7 days, High within 30 days

**Vulnerability Scanning**
- Dependency scanning: Weekly (Snyk, Dependabot)
- Container scanning: Every build (Trivy)
- Infrastructure scanning: Monthly (AWS Inspector)

### 7.4 Deployment Phase

**Security Configuration Validation**
- Automated checks in CI/CD
- Verify security headers
- Confirm TLS configuration
- Check firewall rules

**Secrets Management**
- No secrets in code or config files
- All secrets in AWS Secrets Manager
- Rotation: Automated where possible
- Access logging: All secret access logged

**Infrastructure as Code (IaC) Security**
- Terraform for infrastructure
- Checkin for security misconfigurations
- Tfsec for Terraform scanning
- Automated in CI/CD pipeline

## 8. Incident Response

### 8.1 Incident Response Plan

```
1. Detection & Analysis (0-1 hour)
   ├── Identify security event via:
   │   ├── Automated alerts (Datadog, Sentry)
   │   ├── User report
   │   ├── Security team monitoring
   │   └── External researcher (bug bounty)
   ├── Initial triage:
   │   ├── Severity assessment (Critical/High/Medium/Low)
   │   ├── Scope determination (affected systems/users)
   │   └── Assign incident commander
   └── Activate incident response team

2. Containment (1-4 hours)
   ├── Short-term containment:
   │   ├── Isolate affected systems
   │   ├── Block attacker IP addresses
   │   ├── Revoke compromised credentials
   │   ├── Disable vulnerable endpoints
   │   └── Preserve evidence (logs, snapshots)
   └── Long-term containment:
       ├── Apply temporary patches
       ├── Implement additional monitoring
       └── Prepare for eradication

3. Eradication (4-24 hours)
   ├── Remove threat:
   │   ├── Delete malware/backdoors
   │   ├── Close vulnerability (patch/fix)
   │   ├── Reset all potentially compromised credentials
   │   └── Update security rules
   └── Verify threat removed:
       ├── Re-scan systems
       └── Confirm no persistence mechanisms

4. Recovery (24-72 hours)
   ├── Restore systems from clean backups (if needed)
   ├── Gradually restore services
   ├── Enhanced monitoring during recovery
   ├── Verify system integrity
   └── Communicate status to stakeholders

5. Post-Incident (1-2 weeks)
   ├── Lessons learned meeting
   ├── Incident report:
   │   ├── Timeline of events
   │   ├── Root cause analysis
   │   ├── Impact assessment
   │   ├── Response effectiveness
   │   └── Recommendations
   ├── Update runbooks and procedures
   ├── Implement preventive measures
   └── GDPR notification (if applicable)
```

### 8.2 Security Incident Categories

```
Critical (P0): Immediate response, 24/7
├── Data breach (PII, financial data exposed)
├── Unauthorized admin access
├── Ransomware/destructive malware
├── Production system compromise
└── Response time: < 1 hour

High (P1): Urgent response, business hours
├── Credential compromise (non-admin)
├── Successful phishing attack
├── DDoS attack
├── Unauthorized data access
└── Response time: < 4 hours

Medium (P2): Standard response
├── Failed intrusion attempt
├── Malware detected (contained)
├── Policy violation
└── Response time: < 24 hours

Low (P3): Routine response
├── Suspicious activity (unconfirmed)
├── Security scan findings
└── Response time: < 72 hours
```

## 9. Security Monitoring

### 9.1 Logging Requirements

See section A09 for implementation details.

**What to Log:**
- Authentication events (login, logout, failed attempts)
- Authorization failures
- Data access (especially PII)
- Configuration changes
- Security-relevant errors
- Admin actions
- Password resets, MFA changes
- Session management events
- API rate limiting violations

**What NOT to Log:**
- Passwords (plaintext or hashed)
- Tokens (access tokens, refresh tokens)
- API keys
- Credit card numbers
- Other secrets

### 9.2 Monitoring & Alerting

See section A09 for implementation details.

**SIEM Integration:** Datadog, Splunk, or AWS Security Hub

**Real-Time Alerts:**
- Multiple failed login attempts (>5 in 5 min)
- Account lockouts
- Token reuse detected
- Privilege escalation attempts
- Unusual data access patterns
- Geographic anomalies
- Brute force attempts (>10 failures from same IP)

**Anomaly Detection:**
- Login from new country
- Login at unusual time
- High failure rate for user
- Rapid successive logins from different IPs

## 10. Email Templates & Notifications

### 10.1 Transactional Email Templates

**1. Welcome Email**
```
Subject: Welcome to [App Name] - Verify Your Email

Hi there,

Welcome to [App Name]! To get started, please verify your email address by clicking the button below:

[Verify Email Button]

This link expires in 24 hours.

Security Tips:
• Never share your password with anyone
• Enable two-factor authentication for extra security
• Contact us if you didn't create this account

Questions? Reply to this email or visit our Help Center.

[Privacy Policy Link] | [Terms of Service Link]
```

**2. Email Verification**
```
Subject: Verify your email address

Hi,

Please verify your email address by clicking the button below:

[Verify Email Button]

Or copy and paste this link: https://app.example.com/verify-email?token={token}

This link expires in 24 hours.

Didn't request this? You can safely ignore this email.

Need help? Contact us at support@example.com
```

**3. Password Reset Request**
```
Subject: Reset your password

Hi,

We received a request to reset your password. Click the button below to choose a new password:

[Reset Password Button]

This link expires in 15 minutes for your security.

⚠️ If you didn't request this, please ignore this email. Your password will not be changed.

Someone may have entered your email address by mistake. If you're concerned about unauthorized access, please contact our security team immediately.
```

**4. Password Reset Confirmation**
```
Subject: Your password was changed

Hi,

This is a confirmation that your password was successfully changed.

If this wasn't you, please contact our security team immediately at security@example.com

Active sessions on other devices have been logged out for your security.

View your active sessions: [Link to account settings]
```

**5. MFA/OTP Code**
```
Subject: Your verification code

Hi,

Your verification code is:

  {6-digit code}

This code expires in 5 minutes.

⚠️ Security Warning:
• Never share this code with anyone
• Our team will NEVER ask for this code
• Beware of phishing attempts

Didn't request this code? Please secure your account immediately.
```

**6. New Device Login Alert**
```
Subject: New device login detected

Hi,

We detected a login to your account from a new device:

Device: {Browser} on {OS}
Location: {City, Country} (approximate)
IP Address: {IP}
Time: {Timestamp}

Was this you?
[Yes, this was me] [No, secure my account]

If this wasn't you, please secure your account immediately by changing your password.

View all active sessions: [Link]
```

**7. Account Lockout Notification**
```
Subject: Your account has been locked

Hi,

Your account has been temporarily locked due to multiple failed login attempts.

Lockout reason: Too many failed login attempts
Locked until: {Timestamp} (30 minutes from now)

If this wasn't you, your account may be under attack. Please:
1. Wait 30 minutes for automatic unlock
2. Reset your password
3. Enable two-factor authentication

Need help? Contact security@example.com
```

**8. Session Revoked**
```
Subject: Your session was logged out

Hi,

A session on your account was logged out:

Device: {Browser} on {OS}
Logged out by: {User action / System / Admin}
Time: {Timestamp}

Active sessions remaining: {Count}

Manage your sessions: [Link]

If you didn't do this, please secure your account immediately.
```

**9. Privacy Policy Update**
```
Subject: We've updated our Privacy Policy

Hi,

We've updated our Privacy Policy to provide more clarity on how we handle your data.

What changed:
• {Summary of key changes}

Effective date: {Date}

Please review the updated policy: [Link]

By continuing to use our service after {Date}, you accept the new terms.

Questions? Contact privacy@example.com
```

**10. Data Export Ready**
```
Subject: Your data export is ready

Hi,

Your requested data export is ready for download.

[Download Data Button]

This link expires in 7 days.

File format: JSON
File size: {Size} MB

This export contains:
• Your profile information
• Account activity
• Consents and preferences

Learn more about your data rights: [GDPR Info Link]
```

### 10.2 Email Service Requirements

```
Email Service Provider (ESP):
├── Primary: SendGrid (or AWS SES, Postmark)
├── SLA: 99.9% delivery success rate
├── Fallback: Secondary ESP for redundancy
└── Rate limits: 10,000 emails/hour capacity

Performance Targets:
├── Delivery time: < 30 seconds for OTP emails
├── Throughput: 100 emails/second
└── Bounce handling: Automatic retry with exponential backoff

Authentication & Compliance:
├── SPF: Configured for domain
├── DKIM: Signed emails
├── DMARC: Policy set to "quarantine" or "reject"
├── Unsubscribe: CAN-SPAM Act compliant
└── Tracking: Open/click tracking (opt-in only, GDPR compliant)

Email Categories (for separate tracking):
├── Transactional: Account-related (no unsubscribe)
├── Notification: Security alerts (no unsubscribe)
└── Marketing: Promotional (with unsubscribe link)

Monitoring:
├── Delivery rate tracking
├── Bounce rate alerts (>5%)
├── Spam complaint alerts
└── Integration with Datadog/Sentry
```

## 11. Vulnerability Management

See section A06 for full details.

**Summary:**
- Critical: 24-48 hours
- High: 7 days
- Medium: 30 days
- Low: 90 days

## 12. Security Testing

See section 7.3 for full details.

**Summary:**
- Penetration testing: Annually
- Vulnerability scanning: Weekly
- SAST/DAST: Every build/deployment
- Code review: Every PR
- Security regression testing: Every release
- Third-party audit: Annually (SOC 2)

## 13. Security Training

**Security Awareness Training**
- Frequency: Quarterly (all employees)
- Topics:
  - Password security
  - Phishing recognition
  - Social engineering
  - Data handling best practices
  - Incident reporting procedures
- Format: Interactive online modules + quizzes
- Tracking: Completion tracked in HR system

**Secure Coding Training**
- Frequency: Bi-annually (developers)
- Topics:
  - OWASP Top 10
  - Secure coding practices for Go/JavaScript
  - Input validation and output encoding
  - Authentication and session management
  - Cryptography best practices
- Format: Workshop with hands-on exercises

**Phishing Simulations**
- Frequency: Monthly
- Randomly selected employees receive simulated phishing emails
- Metrics tracked: Click rate, report rate
- Follow-up: Additional training for those who click

**Incident Response Drills**
- Frequency: Bi-annually
- Tabletop exercises simulating security incidents
- Participants: Security team, DevOps, management
- Goal: Test and improve incident response procedures
