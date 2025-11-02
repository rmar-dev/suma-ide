# arch-data-encryption-generator

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Security & Data Protection
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Executive Summary

This document defines the comprehensive data encryption strategy for SUMA Finance's user registration and authentication system. Given the fintech nature of the application and the handling of Personally Identifiable Information (PII), authentication credentials, and financial data, robust encryption is critical for regulatory compliance (GDPR, PCI-DSS, SOC 2) and user trust.

### Key Objectives
- **Confidentiality**: Protect sensitive user data from unauthorized access
- **Integrity**: Ensure data has not been tampered with during storage or transit
- **Compliance**: Meet GDPR, PCI-DSS, SOC 2, and ISO 27001 requirements
- **Performance**: Maintain encryption overhead < 50ms for authentication flows
- **Key Management**: Implement secure, auditable key lifecycle management

---

## 2. Data Classification & Encryption Requirements

### 2.1 Sensitive Data Inventory

| Data Type | Classification | Storage Location | Encryption Requirement | Retention Period |
|-----------|---------------|------------------|------------------------|------------------|
| Passwords | Critical | PostgreSQL | Argon2id hashing | Until account deletion |
| Email Addresses | PII | PostgreSQL | AES-256-GCM | Until account deletion |
| Phone Numbers | PII | PostgreSQL | AES-256-GCM | Until account deletion |
| Full Names | PII | PostgreSQL | AES-256-GCM | Until account deletion |
| Session Tokens | Critical | Redis | TLS in transit only | 15 min (access), 7 days (refresh) |
| 2FA Secrets | Critical | PostgreSQL | AES-256-GCM | Until 2FA disabled |
| OTP Codes | Critical | Redis | TLS in transit + TTL | 5 minutes |
| Password Reset Tokens | Critical | Redis | HMAC-SHA256 signature | 1 hour |
| Email Verification Tokens | High | Redis | HMAC-SHA256 signature | 24 hours |
| Device Fingerprints | Medium | PostgreSQL | SHA-256 hash | Until device removed |
| IP Addresses | PII (GDPR) | PostgreSQL (audit logs) | AES-256-GCM | 90 days |
| GDPR Consent Records | Legal | PostgreSQL | AES-256-GCM + digital signature | 7 years |
| Security Audit Logs | High | PostgreSQL + S3 | AES-256-GCM | 7 years |

### 2.2 Encryption Requirements by Compliance Framework

#### GDPR Requirements
- **Article 32**: Encryption of personal data at rest and in transit
- **Article 5(1)(f)**: Integrity and confidentiality through appropriate security measures
- **Recital 83**: Pseudonymization and encryption to reduce risk

#### PCI-DSS v4.0 Requirements
- **Requirement 3.5**: Strong cryptography for protection of PAN (if applicable)
- **Requirement 4.2**: TLS 1.2+ for transmission of cardholder data
- **Requirement 8.3**: Strong cryptography for authentication credentials

#### SOC 2 Requirements
- **CC6.1**: Encryption controls for sensitive data
- **CC6.6**: Cryptographic key management
- **CC6.7**: Encryption key rotation policies

---

## 3. Encryption Architecture

### 3.1 Data at Rest Encryption

#### Primary Encryption: AES-256-GCM

**Algorithm Selection Rationale**:
- **AES-256**: NIST-approved, industry standard, hardware-accelerated (AES-NI)
- **GCM Mode**: Provides both encryption and authentication (AEAD)
- **Performance**: ~2-5 GB/s throughput with AES-NI on modern CPUs

**Implementation Strategy**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Go Application (Backend)                             │  │
│  │  - crypto/aes + crypto/cipher (GCM)                  │  │
│  │  - Envelope encryption pattern                        │  │
│  │  - Field-level encryption for PII                     │  │
│  └───────────────┬───────────────────────────────────────┘  │
└──────────────────┼──────────────────────────────────────────┘
                   │
                   │ Encrypted Data + IV + Auth Tag
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                   Data Storage Layer                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  PostgreSQL Database                                  │  │
│  │  - Encrypted columns (bytea type)                     │  │
│  │  - Storage format: IV(12) + Ciphertext + Tag(16)     │  │
│  │  - Transparent Data Encryption (TDE) for disk        │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Redis Cache                                          │  │
│  │  - TLS 1.3 encryption in transit                      │  │
│  │  - No at-rest encryption (ephemeral data only)       │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Field-Level Encryption Schema**:

```sql
-- Users table with encrypted PII
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email_encrypted BYTEA NOT NULL,              -- AES-256-GCM encrypted
    email_hash VARCHAR(64) NOT NULL UNIQUE,      -- SHA-256 for lookups
    phone_encrypted BYTEA,                       -- AES-256-GCM encrypted
    full_name_encrypted BYTEA,                   -- AES-256-GCM encrypted
    password_hash VARCHAR(128) NOT NULL,         -- Argon2id hash
    encryption_key_id UUID NOT NULL,             -- Reference to DEK
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Two-Factor Authentication secrets
CREATE TABLE user_2fa (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    secret_encrypted BYTEA NOT NULL,             -- AES-256-GCM encrypted
    backup_codes_encrypted BYTEA,                -- AES-256-GCM encrypted
    encryption_key_id UUID NOT NULL,
    enabled_at TIMESTAMP NOT NULL
);

-- GDPR Consent with digital signatures
CREATE TABLE user_consents (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    consent_type VARCHAR(50) NOT NULL,
    consent_given BOOLEAN NOT NULL,
    consent_text_hash VARCHAR(64) NOT NULL,      -- SHA-256 of consent text
    ip_address_encrypted BYTEA,                  -- AES-256-GCM encrypted
    user_agent_hash VARCHAR(64),                 -- SHA-256 hash
    signature BYTEA NOT NULL,                    -- HMAC-SHA256 signature
    granted_at TIMESTAMP NOT NULL,
    withdrawn_at TIMESTAMP
);
```

#### Password Hashing: Argon2id

**Configuration**:
```go
// Password hashing parameters (OWASP recommendations)
const (
    Argon2Memory      = 64 * 1024  // 64 MB
    Argon2Iterations  = 3           // Time cost
    Argon2Parallelism = 4           // Number of threads
    Argon2SaltLength  = 16          // 128 bits
    Argon2KeyLength   = 32          // 256 bits
)

// Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
```

**Rationale**:
- **Memory-hard**: Resistant to GPU/ASIC attacks
- **Side-channel resistant**: Protection against timing attacks
- **OWASP recommended**: Current best practice for password storage
- **PCI-DSS compliant**: Meets strong cryptography requirements

---

### 3.2 Data in Transit Encryption

#### TLS 1.3 Configuration

**Cipher Suite Priority**:
```
1. TLS_AES_256_GCM_SHA384          (Preferred - AEAD, 256-bit)
2. TLS_CHACHA20_POLY1305_SHA256    (Mobile optimization)
3. TLS_AES_128_GCM_SHA256          (Fallback - AEAD, 128-bit)
```

**Certificate Strategy**:
- **Root CA**: DigiCert or Let's Encrypt (automated renewal)
- **Certificate Type**: RSA 4096-bit or ECDSA P-384
- **Validity Period**: 90 days (automated rotation)
- **OCSP Stapling**: Enabled for revocation checking
- **HSTS**: max-age=31536000; includeSubDomains; preload

**Implementation (Go Backend)**:
```go
// TLS configuration
tlsConfig := &tls.Config{
    MinVersion:               tls.VersionTLS13,
    CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP384},
    PreferServerCipherSuites: true,
    CipherSuites: []uint16{
        tls.TLS_AES_256_GCM_SHA384,
        tls.TLS_CHACHA20_POLY1305_SHA256,
        tls.TLS_AES_128_GCM_SHA256,
    },
}

// HTTP headers
w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("Content-Security-Policy", "default-src 'self'")
```

**Redis TLS Configuration**:
```go
// Redis client with TLS
redisClient := redis.NewClient(&redis.Options{
    Addr:      "redis.suma.internal:6379",
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS13,
        ServerName: "redis.suma.internal",
    },
})
```

---

### 3.3 Token & Signature Cryptography

#### JWT Token Structure

**Access Token (15-minute expiry)**:
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "suma-auth-key-2025-10"
  },
  "payload": {
    "sub": "user-uuid",
    "iat": 1698624000,
    "exp": 1698624900,
    "iss": "suma-auth-service",
    "aud": "suma-api",
    "scope": "read:profile write:profile",
    "jti": "token-uuid"
  }
}
```

**Signing Algorithm**: RS256 (RSA-SHA256)
- **Key Size**: 4096-bit RSA
- **Rotation**: Every 90 days
- **Previous Keys**: Retained for 7 days for validation

**Refresh Token (7-day expiry)**:
- **Storage**: Redis with encryption at rest (TLS in transit)
- **Format**: Opaque token (cryptographically random, 256-bit)
- **Generation**: crypto/rand (Go standard library)
- **Rotation**: New refresh token issued on each use
- **Reuse Detection**: Single-use tokens with family tracking

#### Password Reset Token

**Generation**:
```go
// Token structure: {userId}:{timestamp}:{randomBytes}
// HMAC-SHA256 signature ensures integrity
func generateResetToken(userID string) (string, error) {
    timestamp := time.Now().Unix()
    randomBytes := make([]byte, 32)
    rand.Read(randomBytes)
    
    payload := fmt.Sprintf("%s:%d:%s", userID, timestamp, hex.EncodeToString(randomBytes))
    signature := hmac.New(sha256.New, resetTokenSecret)
    signature.Write([]byte(payload))
    
    token := fmt.Sprintf("%s.%s", payload, hex.EncodeToString(signature.Sum(nil)))
    return base64.URLEncoding.EncodeToString([]byte(token)), nil
}
```

**Validation**:
- **Expiry Check**: 1-hour maximum lifetime
- **Signature Verification**: HMAC-SHA256
- **Single-Use**: Token invalidated after use
- **Rate Limiting**: 3 requests per hour per user

#### Email Verification Token

**Format**: Similar to password reset with HMAC-SHA256 signature
**Expiry**: 24 hours
**Storage**: Redis with automatic expiration

#### OTP Generation (2FA)

**Algorithm**: TOTP (Time-Based One-Time Password) - RFC 6238
**Configuration**:
```go
const (
    OTPDigits     = 6
    OTPPeriod     = 300  // 5 minutes
    OTPAlgorithm  = sha256.New
    OTPSecretSize = 32   // 256 bits
)
```

**Email OTP** (alternative to TOTP):
```go
// 6-digit random OTP
func generateEmailOTP() string {
    otp := rand.Intn(900000) + 100000
    return fmt.Sprintf("%06d", otp)
}
// Stored in Redis with 5-minute TTL
// Rate limit: 3 OTP requests per 15 minutes
```

---

## 4. Key Management Strategy

### 4.1 Key Hierarchy (Envelope Encryption)

```
┌─────────────────────────────────────────────────────────────┐
│                  Master Encryption Key (MEK)                 │
│  - Stored in AWS KMS / HashiCorp Vault                      │
│  - Never leaves key management service                       │
│  - Rotation: Annual (with key versioning)                   │
│  - Access: Restricted to key management service only        │
└────────────────────────┬────────────────────────────────────┘
                         │ Encrypts/Decrypts
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Data Encryption Keys (DEKs)                     │
│  - AES-256 keys for encrypting user data                    │
│  - Stored encrypted in PostgreSQL (by MEK)                  │
│  - Rotation: Quarterly (90 days)                            │
│  - One DEK per time period (all users share same DEK)       │
└────────────────────────┬────────────────────────────────────┘
                         │ Encrypts/Decrypts
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                     User Data (PII)                          │
│  - Email, phone, name, etc.                                 │
│  - Each field encrypted with current DEK                    │
│  - DEK ID stored alongside encrypted data                   │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Key Storage & Access Control

#### AWS KMS Integration

**MEK Configuration**:
```yaml
Key Spec: SYMMETRIC_DEFAULT (AES-256)
Key Usage: ENCRYPT_DECRYPT
Origin: AWS_KMS
Multi-Region: Enabled (us-east-1, eu-west-1)
Automatic Rotation: Enabled (annual)
Deletion Window: 30 days
```

**IAM Policy** (Least Privilege):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:account:key/suma-auth-mek",
      "Condition": {
        "StringEquals": {
          "kms:EncryptionContext:Service": "suma-auth",
          "kms:EncryptionContext:Environment": "production"
        }
      }
    }
  ]
}
```

#### DEK Management

**Storage Schema**:
```sql
CREATE TABLE encryption_keys (
    id UUID PRIMARY KEY,
    key_encrypted BYTEA NOT NULL,        -- DEK encrypted by MEK
    kms_key_id VARCHAR(255) NOT NULL,    -- AWS KMS key ARN
    algorithm VARCHAR(50) NOT NULL,       -- "AES-256-GCM"
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    status VARCHAR(20) NOT NULL          -- "active", "expired", "revoked"
);

CREATE INDEX idx_encryption_keys_status ON encryption_keys(status, expires_at);
```

**Key Lifecycle**:
1. **Generation**: New DEK generated quarterly via AWS KMS GenerateDataKey
2. **Activation**: DEK marked as "active" and used for all new encryptions
3. **Expiration**: Previous DEK marked "expired" after 90 days (still used for decryption)
4. **Retention**: Expired DEKs retained for 7 years (compliance requirement)
5. **Revocation**: Emergency revocation triggers re-encryption of all data

### 4.3 Key Rotation Strategy

#### Automatic Rotation Schedule

| Key Type | Rotation Frequency | Trigger | Downtime |
|----------|-------------------|---------|----------|
| MEK (AWS KMS) | Annual | Automated | None |
| DEK (Data Encryption) | Quarterly (90 days) | Automated cron job | None |
| JWT Signing Key (RSA) | Quarterly (90 days) | Automated cron job | None |
| TLS Certificate | 90 days | Let's Encrypt auto-renewal | None |
| Password Reset Secret | Annual | Manual (audited) | < 1 minute |
| Session Secret | Semi-annual | Manual (audited) | < 1 minute |

#### DEK Rotation Process

**Automated Rotation Workflow**:
```go
// Executed via scheduled job (cron: 0 0 1 */3 *)
func rotateDEK() error {
    // 1. Generate new DEK via AWS KMS
    newDEK, err := kmsClient.GenerateDataKey(&kms.GenerateDataKeyInput{
        KeyId:   aws.String(mekARN),
        KeySpec: aws.String("AES_256"),
        EncryptionContext: map[string]*string{
            "Service":     aws.String("suma-auth"),
            "Environment": aws.String("production"),
            "Purpose":     aws.String("user-data-encryption"),
        },
    })
    
    // 2. Store encrypted DEK in database
    _, err = db.Exec(`
        INSERT INTO encryption_keys (id, key_encrypted, kms_key_id, algorithm, created_at, expires_at, status)
        VALUES ($1, $2, $3, $4, NOW(), NOW() + INTERVAL '90 days', 'active')
    `, uuid.New(), newDEK.CiphertextBlob, mekARN, "AES-256-GCM")
    
    // 3. Mark previous DEK as expired
    _, err = db.Exec(`
        UPDATE encryption_keys 
        SET status = 'expired', expires_at = NOW()
        WHERE status = 'active' AND id != $1
    `, newDEKID)
    
    // 4. Log rotation event
    auditLog("DEK_ROTATED", map[string]interface{}{
        "new_key_id": newDEKID,
        "rotated_at": time.Now(),
    })
    
    return nil
}
```

**Re-encryption Strategy** (Background Process):
```go
// Optional: Re-encrypt old data with new DEK
// Executed as background job to avoid performance impact
func reEncryptUserData(oldDEKID, newDEKID uuid.UUID) error {
    // Process in batches of 1000 users
    for offset := 0; ; offset += 1000 {
        users, err := db.Query(`
            SELECT id, email_encrypted, encryption_key_id 
            FROM users 
            WHERE encryption_key_id = $1 
            LIMIT 1000 OFFSET $2
        `, oldDEKID, offset)
        
        if len(users) == 0 {
            break
        }
        
        for _, user := range users {
            // Decrypt with old DEK
            plaintext, err := decrypt(user.EmailEncrypted, oldDEK)
            
            // Encrypt with new DEK
            ciphertext, err := encrypt(plaintext, newDEK)
            
            // Update database
            _, err = db.Exec(`
                UPDATE users 
                SET email_encrypted = $1, encryption_key_id = $2 
                WHERE id = $3
            `, ciphertext, newDEKID, user.ID)
        }
    }
    return nil
}
```

#### Emergency Key Revocation

**Trigger Scenarios**:
- Key compromise detected
- Security breach investigation
- Compliance audit failure
- Insider threat detection

**Revocation Procedure**:
```bash
# 1. Immediately revoke compromised DEK
UPDATE encryption_keys SET status = 'revoked', revoked_at = NOW() WHERE id = '<compromised-key-id>';

# 2. Generate new DEK (emergency rotation)
./scripts/rotate-dek-emergency.sh

# 3. Re-encrypt all data encrypted with compromised key (high priority)
./scripts/reencrypt-data.sh --key-id '<compromised-key-id>' --priority high

# 4. Notify security team and log incident
./scripts/notify-security-incident.sh --type KEY_COMPROMISE --key-id '<compromised-key-id>'

# 5. Update key management documentation
# 6. Conduct post-incident review within 24 hours
```

---

## 5. Implementation Guidelines

### 5.1 Go Backend Encryption Library

**Encryption Service Interface**:
```go
package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
)

type Service struct {
    kmsClient  *kms.KMS
    dekCache   *DEKCache  // In-memory cache for active DEK
    auditLog   *AuditLogger
}

// Encrypt encrypts plaintext with current active DEK
func (s *Service) Encrypt(plaintext string) (string, error) {
    // 1. Get current active DEK (with caching)
    dek, err := s.getActiveDEK()
    if err != nil {
        return "", fmt.Errorf("failed to get DEK: %w", err)
    }
    
    // 2. Decrypt DEK using KMS (MEK)
    dekPlaintext, err := s.kmsClient.Decrypt(&kms.DecryptInput{
        CiphertextBlob: dek.KeyEncrypted,
        EncryptionContext: map[string]*string{
            "Service":     aws.String("suma-auth"),
            "Environment": aws.String("production"),
        },
    })
    
    // 3. Create AES-GCM cipher
    block, err := aes.NewCipher(dekPlaintext.Plaintext)
    if err != nil {
        return "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    
    // 4. Generate random nonce (IV)
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return "", err
    }
    
    // 5. Encrypt and authenticate
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    
    // 6. Format: DEK_ID|BASE64(IV+Ciphertext+Tag)
    result := fmt.Sprintf("%s|%s", dek.ID, base64.StdEncoding.EncodeToString(ciphertext))
    
    return result, nil
}

// Decrypt decrypts ciphertext using the DEK ID embedded in the value
func (s *Service) Decrypt(encryptedValue string) (string, error) {
    // 1. Parse DEK ID and ciphertext
    parts := strings.Split(encryptedValue, "|")
    if len(parts) != 2 {
        return "", errors.New("invalid encrypted value format")
    }
    
    dekID, ciphertextB64 := parts[0], parts[1]
    
    // 2. Get DEK by ID (with caching)
    dek, err := s.getDEKByID(dekID)
    if err != nil {
        return "", fmt.Errorf("failed to get DEK: %w", err)
    }
    
    // 3. Decrypt DEK using KMS
    dekPlaintext, err := s.kmsClient.Decrypt(&kms.DecryptInput{
        CiphertextBlob: dek.KeyEncrypted,
    })
    
    // 4. Decode ciphertext
    ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
    if err != nil {
        return "", err
    }
    
    // 5. Create AES-GCM cipher
    block, err := aes.NewCipher(dekPlaintext.Plaintext)
    gcm, err := cipher.NewGCM(block)
    
    // 6. Extract nonce and decrypt
    nonceSize := gcm.NonceSize()
    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", fmt.Errorf("decryption failed: %w", err)
    }
    
    return string(plaintext), nil
}

// EncryptField encrypts a database field (helper method)
func (s *Service) EncryptField(fieldName, value string) ([]byte, string, error) {
    encrypted, err := s.Encrypt(value)
    if err != nil {
        return nil, "", err
    }
    
    // Also generate searchable hash for lookups
    hash := sha256.Sum256([]byte(value))
    hashHex := hex.EncodeToString(hash[:])
    
    s.auditLog.Log("FIELD_ENCRYPTED", map[string]interface{}{
        "field": fieldName,
        "hash":  hashHex[:8], // Log only first 8 chars for debugging
    })
    
    return []byte(encrypted), hashHex, nil
}
```

**Password Hashing Service**:
```go
package auth

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "fmt"
    "golang.org/x/crypto/argon2"
    "strings"
)

const (
    Argon2Memory      = 64 * 1024
    Argon2Iterations  = 3
    Argon2Parallelism = 4
    Argon2SaltLength  = 16
    Argon2KeyLength   = 32
)

// HashPassword hashes a password using Argon2id
func HashPassword(password string) (string, error) {
    // Generate random salt
    salt := make([]byte, Argon2SaltLength)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }
    
    // Hash password
    hash := argon2.IDKey(
        []byte(password),
        salt,
        Argon2Iterations,
        Argon2Memory,
        Argon2Parallelism,
        Argon2KeyLength,
    )
    
    // Format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    encoded := fmt.Sprintf(
        "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version,
        Argon2Memory,
        Argon2Iterations,
        Argon2Parallelism,
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(hash),
    )
    
    return encoded, nil
}

// VerifyPassword checks if password matches hash (constant-time comparison)
func VerifyPassword(password, encodedHash string) (bool, error) {
    // Parse encoded hash
    parts := strings.Split(encodedHash, "$")
    if len(parts) != 6 {
        return false, fmt.Errorf("invalid hash format")
    }
    
    // Extract parameters
    var memory, iterations uint32
    var parallelism uint8
    _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
    
    salt, err := base64.RawStdEncoding.DecodeString(parts[4])
    hash, err := base64.RawStdEncoding.DecodeString(parts[5])
    
    // Hash provided password with same parameters
    computedHash := argon2.IDKey(
        []byte(password),
        salt,
        iterations,
        memory,
        parallelism,
        uint32(len(hash)),
    )
    
    // Constant-time comparison (prevent timing attacks)
    if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
        return true, nil
    }
    
    return false, nil
}
```

### 5.2 React Frontend Security

**Secure Data Handling**:
```typescript
// src/utils/security.ts

// IMPORTANT: Never store sensitive data in localStorage
// Use secure, httpOnly cookies for tokens

export class SecurityUtils {
  // Password strength validation (client-side only, server validates too)
  static validatePasswordStrength(password: string): {
    valid: boolean;
    score: number;
    feedback: string[];
  } {
    const feedback: string[] = [];
    let score = 0;
    
    if (password.length >= 12) score += 25;
    else feedback.push("Password must be at least 12 characters");
    
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 25;
    else feedback.push("Include both uppercase and lowercase letters");
    
    if (/[0-9]/.test(password)) score += 25;
    else feedback.push("Include at least one number");
    
    if (/[^A-Za-z0-9]/.test(password)) score += 25;
    else feedback.push("Include at least one special character");
    
    return {
      valid: score === 100,
      score,
      feedback,
    };
  }
  
  // Secure form submission (prevents XSS)
  static sanitizeInput(input: string): string {
    return input
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;")
      .replace(/\//g, "&#x2F;");
  }
  
  // CSRF token management
  static getCSRFToken(): string | null {
    const cookies = document.cookie.split(";");
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split("=");
      if (name === "csrf-token") {
        return decodeURIComponent(value);
      }
    }
    return null;
  }
}

// API client with automatic CSRF token injection
export class SecureAPIClient {
  private baseURL: string;
  
  constructor(baseURL: string) {
    this.baseURL = baseURL;
  }
  
  async request(method: string, endpoint: string, data?: any): Promise<Response> {
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };
    
    // Add CSRF token for state-changing operations
    if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
      const csrfToken = SecurityUtils.getCSRFToken();
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken;
      }
    }
    
    return fetch(`${this.baseURL}${endpoint}`, {
      method,
      headers,
      credentials: "include", // Send cookies
      body: data ? JSON.stringify(data) : undefined,
    });
  }
}
```

**Secure Cookie Configuration** (Backend):
```go
// Set secure authentication cookie
http.SetCookie(w, &http.Cookie{
    Name:     "session_token",
    Value:    sessionToken,
    Path:     "/",
    MaxAge:   900, // 15 minutes
    HttpOnly: true,  // Prevent JavaScript access
    Secure:   true,  // HTTPS only
    SameSite: http.SameSiteStrictMode, // CSRF protection
})

// Set CSRF token cookie (readable by JavaScript)
http.SetCookie(w, &http.Cookie{
    Name:     "csrf-token",
    Value:    csrfToken,
    Path:     "/",
    MaxAge:   900,
    HttpOnly: false, // Must be readable by JS
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
})
```

---

## 6. Security Monitoring & Audit Logging

### 6.1 Encryption Audit Events

**Events to Log**:
```go
const (
    EventEncrypt           = "DATA_ENCRYPTED"
    EventDecrypt           = "DATA_DECRYPTED"
    EventDEKGenerated      = "DEK_GENERATED"
    EventDEKRotated        = "DEK_ROTATED"
    EventDEKRevoked        = "DEK_REVOKED"
    EventKMSKeyAccessed    = "KMS_KEY_ACCESSED"
    EventDecryptionFailed  = "DECRYPTION_FAILED"
    EventPasswordHashed    = "PASSWORD_HASHED"
    EventPasswordVerified  = "PASSWORD_VERIFIED"
)
```

**Audit Log Schema**:
```sql
CREATE TABLE security_audit_logs (
    id UUID PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    user_id UUID,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address_encrypted BYTEA,
    user_agent_hash VARCHAR(64),
    metadata JSONB,
    severity VARCHAR(20) NOT NULL,  -- "INFO", "WARNING", "CRITICAL"
    timestamp TIMESTAMP NOT NULL,
    
    INDEX idx_audit_event_type (event_type, timestamp),
    INDEX idx_audit_user (user_id, timestamp),
    INDEX idx_audit_severity (severity, timestamp)
);

-- Partition by month for performance
CREATE TABLE security_audit_logs_2025_10 PARTITION OF security_audit_logs
FOR VALUES FROM ('2025-10-01') TO ('2025-11-01');
```

**Example Audit Log Entry**:
```json
{
  "event_type": "DATA_ENCRYPTED",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "resource_type": "user_email",
  "resource_id": "550e8400-e29b-41d4-a716-446655440000",
  "ip_address_encrypted": "<encrypted-ip>",
  "user_agent_hash": "a3b2c1...",
  "metadata": {
    "dek_id": "dek-2025-10-29",
    "algorithm": "AES-256-GCM",
    "field": "email",
    "duration_ms": 12
  },
  "severity": "INFO",
  "timestamp": "2025-10-29T14:32:15Z"
}
```

### 6.2 Decryption Failure Monitoring

**Alert Thresholds**:
- **Warning**: > 10 decryption failures per minute
- **Critical**: > 50 decryption failures per minute
- **Emergency**: > 100 decryption failures per minute (potential key compromise)

**Automated Response**:
```go
// Decryption failure handler
func (s *Service) handleDecryptionFailure(err error, context map[string]interface{}) {
    // Log failure
    s.auditLog.Log("DECRYPTION_FAILED", context)
    
    // Increment failure counter
    failureCount := s.metrics.IncrementCounter("decryption_failures")
    
    // Check threshold
    if failureCount > 100 {
        // CRITICAL: Potential key compromise
        s.alerting.SendAlert(AlertCritical, "High decryption failure rate detected", context)
        
        // Optional: Auto-trigger key rotation
        if s.config.AutoRotateOnBreach {
            go s.emergencyKeyRotation()
        }
    } else if failureCount > 50 {
        s.alerting.SendAlert(AlertWarning, "Elevated decryption failures", context)
    }
}
```

### 6.3 Compliance Reporting

**GDPR Encryption Report**:
```sql
-- Generate monthly encryption compliance report
SELECT 
    'Users' AS data_type,
    COUNT(*) AS total_records,
    COUNT(CASE WHEN email_encrypted IS NOT NULL THEN 1 END) AS encrypted_records,
    ROUND(100.0 * COUNT(CASE WHEN email_encrypted IS NOT NULL THEN 1 END) / COUNT(*), 2) AS encryption_percentage
FROM users
UNION ALL
SELECT 
    'Consents' AS data_type,
    COUNT(*) AS total_records,
    COUNT(CASE WHEN ip_address_encrypted IS NOT NULL THEN 1 END) AS encrypted_records,
    ROUND(100.0 * COUNT(CASE WHEN ip_address_encrypted IS NOT NULL THEN 1 END) / COUNT(*), 2) AS encryption_percentage
FROM user_consents;
```

**Expected Output**:
```
| data_type | total_records | encrypted_records | encryption_percentage |
|-----------|---------------|-------------------|----------------------|
| Users     | 50000         | 50000             | 100.00               |
| Consents  | 75000         | 75000             | 100.00               |
```

---

## 7. Performance Optimization

### 7.1 Encryption Performance Targets

| Operation | Target Latency | Actual (Benchmark) | Notes |
|-----------|---------------|-------------------|-------|
| AES-256-GCM Encrypt (1KB) | < 10 μs | ~5 μs | With AES-NI |
| AES-256-GCM Decrypt (1KB) | < 10 μs | ~5 μs | With AES-NI |
| Argon2id Hash | < 100 ms | ~80 ms | Tuned parameters |
| KMS Decrypt DEK | < 50 ms | ~30 ms | With caching |
| JWT Signing (RS256) | < 5 ms | ~3 ms | 4096-bit RSA |
| JWT Verification | < 3 ms | ~2 ms | Cached public key |

### 7.2 DEK Caching Strategy

**In-Memory Cache**:
```go
type DEKCache struct {
    cache   *lru.Cache
    ttl     time.Duration
    mu      sync.RWMutex
}

// GetActiveDEK retrieves active DEK with caching
func (c *DEKCache) GetActiveDEK() (*DEK, error) {
    c.mu.RLock()
    cached, found := c.cache.Get("active_dek")
    c.mu.RUnlock()
    
    if found {
        dek := cached.(*DEK)
        if time.Now().Before(dek.CachedUntil) {
            return dek, nil
        }
    }
    
    // Cache miss: Fetch from database
    c.mu.Lock()
    defer c.mu.Unlock()
    
    dek, err := c.fetchActiveDEKFromDB()
    if err != nil {
        return nil, err
    }
    
    dek.CachedUntil = time.Now().Add(c.ttl)
    c.cache.Add("active_dek", dek)
    
    return dek, nil
}
```

**Cache Configuration**:
- **TTL**: 5 minutes (balance between performance and rotation responsiveness)
- **Size**: 10 DEKs (active + recently expired)
- **Eviction**: LRU policy

### 7.3 Batch Encryption Operations

**Bulk User Data Encryption**:
```go
// Encrypt multiple fields in parallel
func (s *Service) EncryptUserBatch(users []*User) error {
    const batchSize = 100
    var wg sync.WaitGroup
    errChan := make(chan error, len(users))
    
    for i := 0; i < len(users); i += batchSize {
        end := i + batchSize
        if end > len(users) {
            end = len(users)
        }
        
        batch := users[i:end]
        wg.Add(1)
        
        go func(batch []*User) {
            defer wg.Done()
            for _, user := range batch {
                if err := s.encryptUser(user); err != nil {
                    errChan <- err
                    return
                }
            }
        }(batch)
    }
    
    wg.Wait()
    close(errChan)
    
    if len(errChan) > 0 {
        return <-errChan
    }
    
    return nil
}
```

---

## 8. Disaster Recovery & Business Continuity

### 8.1 Key Backup Strategy

**MEK Backup** (AWS KMS):
- **Multi-Region Replication**: Enabled (us-east-1 → eu-west-1)
- **CloudHSM Backup**: Weekly snapshots to S3
- **Backup Retention**: 7 years (compliance requirement)

**DEK Backup**:
```bash
#!/bin/bash
# Daily backup of encryption keys table
pg_dump \
  --table=encryption_keys \
  --format=custom \
  --file=/backups/encryption_keys_$(date +%Y%m%d).dump \
  financeapp

# Encrypt backup with GPG
gpg --encrypt \
  --recipient security@suma.com \
  /backups/encryption_keys_$(date +%Y%m%d).dump

# Upload to S3 with versioning
aws s3 cp \
  /backups/encryption_keys_$(date +%Y%m%d).dump.gpg \
  s3://suma-encryption-backups/ \
  --storage-class STANDARD_IA
```

### 8.2 Key Recovery Procedures

**Scenario 1: Primary KMS Region Failure**
```bash
# 1. Switch to secondary region (automated failover)
export AWS_REGION=eu-west-1

# 2. Update application configuration
kubectl set env deployment/suma-auth AWS_KMS_REGION=eu-west-1

# 3. Verify encryption/decryption works
./scripts/test-encryption.sh

# 4. Monitor for issues
./scripts/monitor-encryption-health.sh
```

**Scenario 2: DEK Table Corruption**
```bash
# 1. Stop writes to encryption_keys table
kubectl scale deployment/suma-auth --replicas=0

# 2. Restore from latest backup
pg_restore \
  --table=encryption_keys \
  --clean \
  /backups/encryption_keys_latest.dump

# 3. Verify data integrity
./scripts/verify-encryption-keys.sh

# 4. Resume operations
kubectl scale deployment/suma-auth --replicas=5
```

### 8.3 Key Compromise Response Plan

**Immediate Actions** (T+0 to T+1 hour):
1. **Isolate**: Revoke compromised DEK immediately
2. **Alert**: Notify security team and stakeholders
3. **Assess**: Determine scope of compromise
4. **Rotate**: Generate new DEK and MEK (if needed)

**Short-term Actions** (T+1 to T+24 hours):
5. **Re-encrypt**: Re-encrypt all data with new DEK
6. **Audit**: Review access logs for suspicious activity
7. **Notify**: Inform affected users (GDPR requirement)

**Long-term Actions** (T+24 hours to T+30 days):
8. **Investigate**: Root cause analysis
9. **Remediate**: Fix security gaps
10. **Report**: Submit breach notification to authorities (if required)

---

## 9. Testing & Validation

### 9.1 Encryption Unit Tests

```go
// encryption_test.go
package encryption

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
    service := NewService(mockKMSClient, mockDEKCache)
    
    plaintext := "user@example.com"
    
    // Encrypt
    ciphertext, err := service.Encrypt(plaintext)
    assert.NoError(t, err)
    assert.NotEqual(t, plaintext, ciphertext)
    
    // Decrypt
    decrypted, err := service.Decrypt(ciphertext)
    assert.NoError(t, err)
    assert.Equal(t, plaintext, decrypted)
}

func TestEncryptionDeterminism(t *testing.T) {
    service := NewService(mockKMSClient, mockDEKCache)
    
    plaintext := "test@example.com"
    
    // Encrypt twice
    ciphertext1, _ := service.Encrypt(plaintext)
    ciphertext2, _ := service.Encrypt(plaintext)
    
    // Should be different (randomized IV)
    assert.NotEqual(t, ciphertext1, ciphertext2)
    
    // But decrypt to same value
    decrypted1, _ := service.Decrypt(ciphertext1)
    decrypted2, _ := service.Decrypt(ciphertext2)
    assert.Equal(t, decrypted1, decrypted2)
}

func TestPasswordHashing(t *testing.T) {
    password := "SecureP@ssw0rd123!"
    
    // Hash
    hash, err := HashPassword(password)
    assert.NoError(t, err)
    assert.Contains(t, hash, "$argon2id$")
    
    // Verify correct password
    valid, err := VerifyPassword(password, hash)
    assert.NoError(t, err)
    assert.True(t, valid)
    
    // Verify incorrect password
    valid, err = VerifyPassword("WrongPassword", hash)
    assert.NoError(t, err)
    assert.False(t, valid)
}

func BenchmarkEncryption(b *testing.B) {
    service := NewService(mockKMSClient, mockDEKCache)
    plaintext := "test@example.com"
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        service.Encrypt(plaintext)
    }
}
```

### 9.2 Integration Tests

```go
// encryption_integration_test.go
package encryption

import (
    "testing"
    "github.com/aws/aws-sdk-go/service/kms"
)

func TestKMSIntegration(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping integration test")
    }
    
    // Use real KMS client (against test environment)
    kmsClient := kms.New(awsSession)
    service := NewService(kmsClient, NewDEKCache())
    
    // Test full encryption flow
    plaintext := "integration-test@example.com"
    
    encrypted, err := service.Encrypt(plaintext)
    assert.NoError(t, err)
    
    decrypted, err := service.Decrypt(encrypted)
    assert.NoError(t, err)
    assert.Equal(t, plaintext, decrypted)
}

func TestDEKRotation(t *testing.T) {
    // Setup
    db := setupTestDB(t)
    defer db.Close()
    
    kmsClient := kms.New(awsSession)
    service := NewService(kmsClient, NewDEKCache())
    
    // Encrypt data with DEK version 1
    plaintext := "test@example.com"
    encrypted, err := service.Encrypt(plaintext)
    assert.NoError(t, err)
    
    // Rotate DEK (generate version 2)
    err = service.RotateDEK()
    assert.NoError(t, err)
    
    // Should still decrypt data encrypted with version 1
    decrypted, err := service.Decrypt(encrypted)
    assert.NoError(t, err)
    assert.Equal(t, plaintext, decrypted)
    
    // New encryption should use version 2
    encrypted2, err := service.Encrypt(plaintext)
    assert.NoError(t, err)
    assert.Contains(t, encrypted2, "v2")
}
```

### 9.3 Security Penetration Testing

**Test Scenarios**:
1. **Ciphertext Tampering**: Modify encrypted data and verify authentication tag failure
2. **Replay Attacks**: Attempt to reuse old JWT tokens
3. **Key Extraction**: Try to extract DEK from memory dumps
4. **Timing Attacks**: Measure password verification timing for information leakage
5. **SQL Injection**: Attempt to bypass encryption via injection
6. **Man-in-the-Middle**: Test TLS certificate validation

**Automated Security Scans**:
```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Snyk Security Scan
        uses: snyk/actions/golang@master
        with:
          args: --severity-threshold=high
      
      - name: Run Trivy Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'CRITICAL,HIGH'
      
      - name: Run gosec (Go Security Checker)
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec -fmt json -out gosec-report.json ./...
      
      - name: Check for Hard-coded Secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: main
```

---

## 10. Compliance Validation Checklist

### 10.1 GDPR Compliance

- [x] **Article 32(1)(a)**: Pseudonymization and encryption of personal data
  - AES-256-GCM for PII at rest
  - TLS 1.3 for data in transit
  
- [x] **Article 5(1)(f)**: Integrity and confidentiality
  - AEAD encryption (authenticated encryption)
  - Digital signatures for consent records
  
- [x] **Article 33**: Data breach notification
  - Audit logging for all encryption operations
  - Real-time alerting for suspicious activities
  
- [x] **Article 17**: Right to erasure
  - Cryptographic erasure (DEK deletion)
  - Secure data deletion procedures

### 10.2 PCI-DSS Compliance

- [x] **Requirement 3.4**: Strong cryptography for credential storage
  - Argon2id for password hashing
  - AES-256-GCM for sensitive data
  
- [x] **Requirement 3.5**: Key management procedures
  - Envelope encryption with AWS KMS
  - Quarterly key rotation
  
- [x] **Requirement 4.1**: TLS for transmission of cardholder data
  - TLS 1.3 with approved cipher suites
  - HSTS enforcement

### 10.3 SOC 2 Compliance

- [x] **CC6.1**: Encryption controls documented and implemented
- [x] **CC6.6**: Cryptographic key management with access controls
- [x] **CC6.7**: Key rotation policy (90-day cycle)
- [x] **CC7.2**: Monitoring and alerting for encryption failures

---

## 11. Maintenance & Operations

### 11.1 Operational Runbooks

**Daily Tasks**:
- Monitor decryption failure rates (< 0.1%)
- Verify DEK cache hit rate (> 95%)
- Check KMS API latency (< 50ms p99)

**Weekly Tasks**:
- Review encryption audit logs for anomalies
- Verify backup integrity (test restore)
- Update security dashboards

**Monthly Tasks**:
- Generate compliance reports (GDPR, PCI-DSS)
- Review and update key rotation schedule
- Conduct security team training

**Quarterly Tasks**:
- Rotate DEKs (automated)
- Rotate JWT signing keys (automated)
- Conduct penetration testing
- Review and update this document

### 11.2 Troubleshooting Guide

**Issue**: High decryption latency
- **Check**: DEK cache hit rate
- **Fix**: Increase cache TTL or size

**Issue**: KMS API errors
- **Check**: IAM permissions and KMS key status
- **Fix**: Verify IAM policy and check AWS Service Health Dashboard

**Issue**: Encryption failures after DEK rotation
- **Check**: Application has access to both old and new DEKs
- **Fix**: Ensure expired DEKs are retained for 7 days

---

## 12. References & Resources

### Standards & Frameworks
- **NIST SP 800-57**: Key Management Recommendations
- **NIST SP 800-38D**: GCM Mode Specification
- **RFC 5869**: HKDF (HMAC-based Key Derivation Function)
- **RFC 6238**: TOTP Algorithm
- **OWASP ASVS v4.0**: Application Security Verification Standard

### Go Libraries
- `crypto/aes`: AES block cipher
- `crypto/cipher`: GCM mode
- `golang.org/x/crypto/argon2`: Argon2 password hashing
- `github.com/aws/aws-sdk-go/service/kms`: AWS KMS client

### Tools
- **AWS KMS**: Managed key management service
- **HashiCorp Vault**: Alternative key management (if self-hosted)
- **gosec**: Go security checker
- **Snyk**: Dependency vulnerability scanner

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-10-29 | Security Team | Initial draft |

**Approval**

- [ ] Security Lead
- [ ] CTO
- [ ] Compliance Officer
- [ ] Data Protection Officer (DPO)

**Next Review Date**: 2026-01-29 (Quarterly)