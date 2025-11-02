

{
  "projectType": "fintech",
  "detectedKeywords": [
    "authentication",
    "registration",
    "jwt",
    "2fa",
    "gdpr",
    "session management",
    "password reset",
    "email verification",
    "financial application",
    "mobile"
  ],
  "recommendedTechStack": {
    "backend": "go",
    "frontend": "react",
    "database": "postgresql",
    "infrastructure": "docker",
    "mobile": "react-native",
    "cache": "redis",
    "email": "sendgrid"
  },
  "architecturePatterns": [
    "RESTful API",
    "microservices",
    "token-based authentication",
    "event-driven (for email notifications)",
    "CQRS for audit logging"
  ],
  "securityRequirements": {
    "mandatory": [
      "OWASP A01: Role-Based Access Control (RBAC) with least privilege principle",
      "OWASP A01: Session timeout enforcement (15 min idle, 8h absolute)",
      "OWASP A02: Password hashing with Argon2id (memory-hard algorithm)",
      "OWASP A02: AES-256-GCM encryption at rest for PII and sensitive data",
      "OWASP A02: TLS 1.3 for all data in transit",
      "OWASP A02: Secure key management with rotation policy (90 days)",
      "OWASP A03: SQL injection prevention via prepared statements",
      "OWASP A03: Input validation (email format, password complexity, length limits)",
      "OWASP A03: Output encoding to prevent XSS attacks",
      "OWASP A04: Threat modeling for authentication flows",
      "OWASP A04: Security design review for session management",
      "OWASP A05: Security hardening (disable debug endpoints, remove default credentials)",
      "OWASP A05: Secure cookie configuration (HttpOnly, Secure, SameSite=Strict)",
      "OWASP A06: Automated dependency scanning (Snyk, Dependabot, OWASP Dependency-Check)",
      "OWASP A06: Quarterly vulnerability assessments",
      "OWASP A07: Multi-factor authentication (email OTP with 6-digit code, 5-min expiry)",
      "OWASP A07: Account lockout after 5 failed login attempts (15-min cooldown)",
      "OWASP A07: Password complexity requirements (min 12 chars, uppercase, lowercase, number, special)",
      "OWASP A07: JWT with short expiration (15 min access, 7-day refresh)",
      "OWASP A07: Refresh token rotation with reuse detection",
      "OWASP A07: Session fixation prevention (regenerate session ID after login)",
      "OWASP A08: Digital signatures for password reset tokens (HMAC-SHA256)",
      "OWASP A08: Email verification token integrity checks",
      "OWASP A09: Security event logging (login attempts, password changes, 2FA events)",
      "OWASP A09: Audit trail for all authentication events with timestamps and IP addresses",
      "OWASP A09: Real-time alerting for suspicious activities (multiple failed logins, impossible travel)",
      "OWASP A10: SSRF prevention in email verification callbacks",
      "GDPR: Privacy by design and data minimization",
      "GDPR: Explicit consent collection with timestamp and IP logging",
      "GDPR: Consent withdrawal mechanism",
      "GDPR: Data subject rights implementation (access, erasure, portability)",
      "GDPR: Data breach notification procedures (72-hour requirement)",
      "GDPR: Privacy policy and terms of service acceptance",
      "PCI-DSS: Strong cryptography for credential storage",
      "PCI-DSS: Secure authentication mechanisms",
      "SOC2: Change management and approval workflow for auth system changes",
      "SOC2: Incident response plan for authentication breaches",
      "SOC2: Regular access control reviews"
    ],
    "recommended": [
      "OAuth 2.0 with PKCE for social login integration (Google, Apple)",
      "Passkey/WebAuthn support for passwordless authentication",
      "Biometric authentication for mobile apps (TouchID, FaceID)",
      "Device fingerprinting for fraud detection",
      "Geolocation-based access controls",
      "IP whitelisting for administrative accounts",
      "Password breach detection (HaveIBeenPwned API integration)",
      "Rate limiting: 5 login attempts per minute per IP, 10 per user per hour",
      "CAPTCHA after 3 failed login attempts",
      "Email enumeration prevention (same response for existing/non-existing users)",
      "Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)",
      "Certificate pinning for mobile apps",
      "Jailbreak/root detection for mobile apps",
      "Secure storage (iOS Keychain, Android KeyStore)",
      "Anti-screen capture for mobile apps",
      "Automated penetration testing for auth endpoints",
      "Bug bounty program for authentication vulnerabilities",
      "Password expiration policy (optional, 90-180 days)",
      "Password history enforcement (prevent reuse of last 5 passwords)",
      "Single Sign-On (SSO) integration capability"
    ],
    "compliance_frameworks": [
      "OWASP Top 10 2021",
      "GDPR (EU Regulation 2016/679)",
      "PCI-DSS v4.0",
      "SOC 2 Type II",
      "ISO 27001",
      "NIST Cybersecurity Framework"
    ]
  },
  "complianceNeeds": [
    "GDPR",
    "PCI DSS",
    "SOC 2",
    "ISO 27001"
  ],
  "integrationSuggestions": [
    {
      "service": "SendGrid",
      "purpose": "Transactional email delivery (verification, password reset, OTP)",
      "priority": "critical"
    },
    {
      "service": "Twilio",
      "purpose": "SMS-based 2FA as alternative to email OTP",
      "priority": "high"
    },
    {
      "service": "Redis",
      "purpose": "Session storage and OTP caching with TTL",
      "priority": "critical"
    },
    {
      "service": "Auth0",
      "purpose": "Alternative managed authentication solution",
      "priority": "medium"
    },
    {
      "service": "HaveIBeenPwned",
      "purpose": "Password breach detection",
      "priority": "medium"
    },
    {
      "service": "Datadog",
      "purpose": "Security monitoring and alerting",
      "priority": "high"
    },
    {
      "service": "Sentry",
      "purpose": "Error tracking and exception monitoring",
      "priority": "medium"
    }
  ],
  "estimatedTimeline": {
    "total_weeks": 6,
    "phases": {
      "phase0_requirements": 1,
      "phase1_design": 1,
      "phase2_development": 3,
      "phase3_testing": 1
    }
  },
  "recommendedFeatures": [
    {
      "feature": "Email/Password Registration",
      "priority": "critical",
      "description": "User signup with email validation, password complexity enforcement, and GDPR consent capture"
    },
    {
      "feature": "Email Verification System",
      "priority": "critical",
      "description": "Send verification email with signed token, handle verification callback, resend capability"
    },
    {
      "feature": "Secure Login with JWT",
      "priority": "critical",
      "description": "Email/password authentication with JWT access tokens (15 min) and refresh tokens (7 days)"
    },
    {
      "feature": "Session Management",
      "priority": "critical",
      "description": "Redis-backed session storage, refresh token rotation, concurrent session limits"
    },
    {
      "feature": "Password Reset Flow",
      "priority": "critical",
      "description": "Email-based password reset with signed tokens (1-hour expiry), rate limiting"
    },
    {
      "feature": "Two-Factor Authentication (Email OTP)",
      "priority": "critical",
      "description": "6-digit OTP with 5-minute expiry, rate limiting, backup codes"
    },
    {
      "feature": "GDPR Consent Management",
      "priority": "critical",
      "description": "Granular consent tracking with timestamps, withdrawal mechanism, audit trail"
    },
    {
      "feature": "Account Lockout Protection",
      "priority": "high",
      "description": "Lock account after 5 failed attempts, 15-minute cooldown, admin unlock capability"
    },
    {
      "feature": "Security Event Logging",
      "priority": "high",
      "description": "Comprehensive audit trail for login, logout, password changes, 2FA events"
    },
    {
      "feature": "Device Management",
      "priority": "high",
      "description": "Track trusted devices, device fingerprinting, suspicious device alerts"
    },
    {
      "feature": "Social Login (OAuth 2.0)",
      "priority": "medium",
      "description": "Google and Apple Sign-In with account linking"
    },
    {
      "feature": "Biometric Authentication",
      "priority": "medium",
      "description": "TouchID/FaceID for mobile apps with fallback to password"
    },
    {
      "feature": "Passwordless Login (Magic Link)",
      "priority": "low",
      "description": "Email-based one-time login link as alternative to password"
    },
    {
      "feature": "Password Strength Indicator",
      "priority": "low",
      "description": "Real-time password strength feedback during registration"
    }
  ],
  "infrastructureRecommendations": {
    "hosting": "AWS",
    "containerization": "Docker + ECS",
    "cicd": "GitHub Actions",
    "monitoring": "Datadog + Sentry",
    "cache": "Redis Cluster (ElastiCache)",
    "email": "SendGrid + SES failover",
    "cdn": "CloudFront",
    "waf": "AWS WAF"
  },
  "performanceTargets": {
    "apiResponseTime": "< 200ms (login/registration), < 100ms (token refresh)",
    "throughput": "1000 req/s (authentication endpoints)",
    "availability": "99.95%",
    "emailDeliveryTime": "< 5 seconds",
    "otpGenerationTime": "< 1 second",
    "sessionLookupTime": "< 10ms (Redis)"
  }
}
