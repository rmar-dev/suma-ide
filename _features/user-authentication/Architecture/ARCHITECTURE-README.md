# Architecture Documentation

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Generated**: 2025-10-29T00:00:00Z
**Architecture Gate Version**: 1.0

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture Vision](#architecture-vision)
- [Architecture Domains](#architecture-domains)
- [Key Design Decisions](#key-design-decisions)
- [Technology Stack](#technology-stack)
- [Architecture Principles](#architecture-principles)
- [Documentation Structure](#documentation-structure)
- [How to Navigate](#how-to-navigate)
- [Diagrams](#diagrams)
- [Non-Functional Requirements Summary](#non-functional-requirements-summary)
- [Dependencies](#dependencies)
- [Risks and Mitigations](#risks-and-mitigations)
- [Next Steps](#next-steps)

## Overview

### Feature Summary

The SUMA Finance User Registration & Authentication system provides a secure, compliant foundation for user identity management in a fintech application. This system enables users to create accounts through email/password registration with comprehensive email verification, authenticate securely using JWT-based tokens with multi-factor authentication, and manage their sessions across web and mobile platforms. The architecture prioritizes security-by-design principles, implementing OWASP Top 10 protections, GDPR compliance for user consent and data rights, and PCI-DSS requirements for credential management.

The authentication system supports both traditional email/password flows and modern authentication methods including social login (Google, Apple) and biometric authentication for mobile devices. It includes sophisticated security features such as account lockout protection, device fingerprinting, security event logging, and real-time fraud detection. The system is designed to scale to 1000 requests per second while maintaining sub-200ms response times and 99.95% availability.

This architecture serves as the security gateway for all SUMA Finance services, providing centralized authentication, session management, and user lifecycle management that other microservices will depend upon for identity verification and authorization decisions.

### Architecture Goals

The architecture design for this feature aims to achieve:

1. **Security-First Design**: Implement defense-in-depth security with multiple layers of protection including encryption at rest (AES-256-GCM) and in transit (TLS 1.3), token-based authentication with short-lived JWTs (15-min access, 7-day refresh), multi-factor authentication via email OTP, and comprehensive audit logging for all security events. Prevent common vulnerabilities through SQL injection protection, XSS prevention, CSRF protection, and rate limiting.

2. **Regulatory Compliance**: Achieve full compliance with GDPR (data minimization, consent management, right to erasure), PCI-DSS v4.0 (strong cryptography, secure authentication), SOC 2 Type II (access controls, change management, incident response), and ISO 27001 requirements. Implement privacy-by-design principles with explicit consent collection, data breach notification procedures, and comprehensive audit trails.

3. **High Performance & Scalability**: Deliver sub-200ms authentication response times with 99.95% availability supporting 1000+ concurrent authentication requests per second. Utilize Redis cluster for sub-10ms session lookups, implement efficient token refresh mechanisms, and design for horizontal scaling across multiple availability zones with zero-downtime deployments.

### Scope

**In Scope**:
- Email/password registration with validation and GDPR consent capture
- Email verification system with secure token generation and validation
- JWT-based authentication with access and refresh token management
- Redis-backed session management with concurrent session limits
- Password reset flow with secure token delivery via email
- Two-factor authentication using email OTP with 6-digit codes
- Account lockout protection after failed login attempts
- Security event logging and audit trail generation
- GDPR consent management with granular consent tracking
- Device management and fingerprinting for fraud detection
- Social login integration (Google, Apple) via OAuth 2.0
- Biometric authentication for mobile apps (TouchID/FaceID)
- Password strength validation and breach detection
- Rate limiting and CAPTCHA integration
- Mobile app security (root/jailbreak detection, secure storage)

**Out of Scope**:
- Payment processing authentication (separate PCI-DSS scope)
- Third-party financial institution integrations (Tink, Plaid)
- Advanced fraud detection ML models (future enhancement)
- WebAuthn/Passkey support (Phase 2)
- SMS-based 2FA (initial version uses email OTP only)
- Single Sign-On (SSO) for enterprise customers
- Passwordless magic link authentication (future enhancement)
- Multi-tenancy and organization management
- Admin user management UI (separate admin portal feature)

## Architecture Vision

### High-Level Architecture Pattern

The authentication system follows a **microservices architecture pattern** with **API-first design** and **token-based authentication**. The architecture separates authentication concerns into dedicated services (Auth Service, User Service, Email Service) that communicate via RESTful APIs and asynchronous event messaging. An API Gateway handles request routing, rate limiting, and initial request validation before forwarding to backend services.

The system implements **CQRS (Command Query Responsibility Segregation)** for audit logging, separating write operations (authentication events) from read operations (audit queries). Session management leverages **Redis cluster** for distributed caching with sub-10ms read performance. Email delivery uses an **event-driven architecture** with message queues to ensure reliable, asynchronous processing of verification emails, OTP codes, and password reset notifications.

### Architecture Diagram (Conceptual)

```
┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
│   Mobile App    │         │   Web Frontend  │         │  Admin Portal   │
│  (React Native) │         │     (React)     │         │     (React)     │
└────────┬────────┘         └────────┬────────┘         └────────┬────────┘
         │                           │                           │
         └───────────────────────────┼───────────────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────┐
                          │    API Gateway      │
                          │  (Rate Limiting,    │
                          │   WAF, Routing)     │
                          └──────────┬──────────┘
                                     │
                 ┏───────────────────┼───────────────────┓
                 ▼                   ▼                   ▼
      ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
      │   Auth Service   │ │   User Service   │ │  Email Service   │
      │  (JWT, 2FA,      │ │ (Profile, GDPR,  │ │ (SendGrid,       │
      │   Sessions)      │ │  Consent)        │ │  Templates)      │
      └─────────┬────────┘ └─────────┬────────┘ └─────────┬────────┘
                │                    │                    │
                │                    │                    │
      ┌─────────▼────────┐ ┌─────────▼────────┐         │
      │  Redis Cluster   │ │   PostgreSQL     │         │
      │  (Sessions, OTP) │ │  (Users, Audit)  │         │
      └──────────────────┘ └──────────────────┘         │
                                     │                   │
                                     ▼                   ▼
                          ┌──────────────────┐ ┌──────────────────┐
                          │  Event Bus (SNS) │ │  SendGrid API    │
                          │  (Audit Events)  │ │  (Email Delivery)│
                          └──────────────────┘ └──────────────────┘
                                     │
                                     ▼
                          ┌──────────────────┐
                          │ Security Monitor │
                          │ (Datadog/Sentry) │
                          └──────────────────┘
```

### Design Philosophy

The architecture is designed around **zero-trust security principles**: every request is authenticated, every action is logged, and every data access is validated. We prioritize security over convenience, implementing multiple layers of defense including network-level (WAF), application-level (input validation), and data-level (encryption) protections.

**Trade-offs Made**:
- **Security vs. Latency**: We accept 150-200ms authentication latency to perform comprehensive security checks (password hashing with Argon2id, token signature verification, session validation) rather than optimizing for sub-50ms responses with weaker security.
- **Compliance vs. Complexity**: We implement full GDPR consent management and audit logging despite increased complexity, as regulatory compliance is non-negotiable for fintech applications.
- **Availability vs. Consistency**: We use eventual consistency for audit logs (acceptable for 2-3 second delay) but strong consistency for authentication state (sessions, tokens) to prevent security vulnerabilities.
- **Microservices vs. Monolith**: We separate authentication into dedicated services despite increased operational complexity, as this enables independent scaling, security isolation, and technology flexibility.

**Key Priorities**:
1. Security and compliance are never compromised
2. User experience is optimized within security constraints
3. System observability and auditability are built-in from day one
4. Performance targets must be met without sacrificing security
5. Architecture supports future enhancements (WebAuthn, SSO) without major refactoring

## Architecture Domains

This architecture is organized into 6 technical domains:

### 1. 🏗️ Services Architecture

**Location**: `/Services/`  
**Purpose**: Define service boundaries, responsibilities, and communication patterns

**Key Documents**:
- **service-architecture.md**: Overall service design with Auth, User, and Email service definitions
- **api-gateway.md**: Kong API Gateway configuration, rate limiting (5 login/min per IP), WAF rules
- **microservices-design.md**: Service-to-service communication, circuit breakers, retry policies
- **service-communication.md**: RESTful API contracts, event-driven messaging via AWS SNS/SQS

**Key Decisions**:
- **Service Boundary**: Separated authentication logic (Auth Service) from user profile management (User Service) to enable independent scaling and security isolation
- **Communication Protocol**: Synchronous REST for user-facing operations (login, registration), asynchronous events for audit logging and email notifications to ensure high availability and fault tolerance

### 2. 🔌 APIs Architecture

**Location**: `/APIs/`  
**Purpose**: Design API contracts, versioning strategy, and documentation

**Key Documents**:
- **rest-api-design.md**: RESTful endpoint design following OpenAPI 3.0 specification
- **api-versioning.md**: URL-based versioning strategy (v1, v2) with 12-month deprecation policy
- **api-documentation.md**: Complete API reference with authentication, rate limits, error codes
- **error-handling.md**: Standardized error response format with security-safe messages

**Key Decisions**:
- **API Style**: REST-only for authentication to maximize client compatibility (web, mobile, third-party) and simplicity
- **Versioning Strategy**: URL-based versioning (/v1/auth/login) with semantic versioning and backward compatibility guarantees

### 3. 🗄️ Database Architecture

**Location**: `/Database/`  
**Purpose**: Design data models, storage strategy, and data access patterns

**Key Documents**:
- **database-architecture.md**: PostgreSQL schema design with users, sessions, audit_logs tables
- **data-access-layer.md**: Repository pattern with prepared statements for SQL injection prevention
- **caching-strategy.md**: Redis caching for sessions (15-min TTL) and OTP codes (5-min TTL)
- **data-migration-plan.md**: Flyway migration strategy with rollback procedures

**Key Decisions**:
- **Database Technology**: PostgreSQL for relational integrity, ACID compliance, and audit trail requirements
- **Caching Strategy**: Redis cluster for session management with write-through caching to ensure sub-10ms session lookups and support 1000+ req/s throughput

### 4. 🎨 Frontend Architecture

**Location**: `/Frontend/`  
**Purpose**: Design frontend structure, component hierarchy, and state management

**Key Documents**:
- **frontend-architecture.md**: React SPA with TypeScript, component-based architecture
- **component-architecture.md**: Authentication components (LoginForm, RegistrationForm, MFA), reusable UI library
- **state-management.md**: Redux Toolkit for authentication state, React Query for API caching
- **routing-navigation.md**: React Router with protected routes, authentication guards

**Key Decisions**:
- **Framework**: React with TypeScript for type safety and developer productivity
- **State Management**: Redux Toolkit for centralized authentication state with Redux Persist for token storage, React Query for server state caching

### 5. 🔒 Security Architecture

**Location**: `/Security/`  
**Purpose**: Design authentication, authorization, and data protection

**Key Documents**:
- **security-architecture.md**: Defense-in-depth security model with network, application, data layers
- **authentication-design.md**: JWT authentication flows, token lifecycle, refresh token rotation
- **authorization-design.md**: Role-Based Access Control (RBAC) with user, admin, super_admin roles
- **data-encryption.md**: AES-256-GCM at rest, TLS 1.3 in transit, key rotation every 90 days

**Key Decisions**:
- **Authentication Mechanism**: JWT with RS256 signing (asymmetric keys) for stateless authentication, 15-min access tokens with 7-day refresh tokens
- **Authorization Model**: RBAC with granular permissions stored in JWT claims, validated on every request by API Gateway

### 6. 🚀 Deployment Architecture

**Location**: `/Deployment/`  
**Purpose**: Design infrastructure, CI/CD, and operational procedures

**Key Documents**:
- **deployment-architecture.md**: AWS ECS Fargate for containerized services, multi-AZ deployment
- **infrastructure-as-code.md**: Terraform for infrastructure provisioning with state management in S3
- **cicd-pipeline.md**: GitHub Actions pipeline with automated testing, security scanning, blue-green deployment
- **monitoring-logging.md**: Datadog for metrics and alerting, Sentry for error tracking, CloudWatch for logs

**Key Decisions**:
- **Cloud Provider**: AWS for comprehensive security services (WAF, GuardDuty, Secrets Manager)
- **Container Orchestration**: ECS Fargate for serverless container management, eliminating EC2 instance management overhead

## Key Design Decisions

### Architecture Decision Records (ADRs)

#### ADR-001: JWT with Refresh Token Rotation

**Status**: Accepted  
**Context**: Need to balance stateless authentication (scalability) with security requirements (token revocation, session management)  
**Decision**: Implement JWT access tokens (15-min expiry) with refresh tokens (7-day expiry) stored in Redis. Refresh tokens rotate on every use with reuse detection to prevent token theft.  
**Consequences**: 
- **Positive**: Stateless authentication scales horizontally, short-lived access tokens limit exposure window, refresh token rotation detects stolen tokens
- **Negative**: Requires Redis for token storage, adds complexity for token refresh flow, network latency for Redis lookups (mitigated by sub-10ms performance)  
**Alternatives Considered**: 
- Session-based authentication (rejected: doesn't scale horizontally, requires sticky sessions)
- Long-lived JWTs without refresh (rejected: security risk, no revocation mechanism)

#### ADR-002: Argon2id for Password Hashing

**Status**: Accepted  
**Context**: Need to protect user passwords against brute-force attacks and rainbow tables while meeting PCI-DSS requirements for strong cryptography  
**Decision**: Use Argon2id (winner of Password Hashing Competition) with 64MB memory cost, 3 iterations, 4 parallelism  
**Consequences**: 
- **Positive**: Resistant to GPU and ASIC cracking, memory-hard algorithm prevents parallelization, meets OWASP and PCI-DSS requirements
- **Negative**: Increased CPU/memory usage on authentication server (acceptable: login is low-frequency operation), 200-300ms hashing time  
**Alternatives Considered**: 
- bcrypt (rejected: not memory-hard, vulnerable to GPU attacks)
- PBKDF2 (rejected: weaker than Argon2id, not recommended by OWASP)

#### ADR-003: Email-Based OTP for Two-Factor Authentication

**Status**: Accepted  
**Context**: Need second factor authentication to meet OWASP A07 requirements while maintaining user experience for fintech application  
**Decision**: Implement email-based OTP with 6-digit codes, 5-minute expiry, rate limiting (3 codes per hour per user)  
**Consequences**: 
- **Positive**: No additional user setup required (phone number), works across all platforms, low implementation complexity
- **Negative**: Email compromise = account compromise, relies on email delivery speed (5s SLA with SendGrid), less secure than TOTP or hardware tokens  
**Alternatives Considered**: 
- SMS OTP (rejected for Phase 1: higher cost, phone number collection, SMS phishing risks)
- TOTP authenticator apps (planned for Phase 2: requires user setup, friction for non-technical users)
- Hardware security keys (rejected: too high friction for consumer fintech)

#### ADR-004: PostgreSQL for User Data and Audit Logs

**Status**: Accepted  
**Context**: Need to store user credentials, profile data, GDPR consents, and audit logs with ACID guarantees and queryability  
**Decision**: Use PostgreSQL 15 with row-level security for multi-tenancy, JSONB for flexible consent storage, and partitioned tables for audit logs (monthly partitions)  
**Consequences**: 
- **Positive**: ACID compliance ensures data integrity, mature ecosystem with excellent security features, JSONB supports evolving consent requirements, strong audit trail support
- **Negative**: Higher operational complexity than NoSQL, vertical scaling limitations (mitigated by read replicas), requires careful index design for audit queries  
**Alternatives Considered**: 
- NoSQL (MongoDB/DynamoDB) (rejected: lack of ACID guarantees critical for financial data, weaker security controls)
- MySQL (rejected: PostgreSQL has superior JSONB and audit features)

#### ADR-005: Redis Cluster for Session Storage

**Status**: Accepted  
**Context**: Need distributed session storage with sub-10ms read latency to support 1000+ req/s authentication throughput  
**Decision**: Deploy Redis 7 cluster (3 primary nodes, 3 replicas) on AWS ElastiCache with automatic failover and cluster mode enabled  
**Consequences**: 
- **Positive**: Sub-10ms read latency achieves performance targets, horizontal scalability to 100K+ concurrent sessions, automatic failover provides 99.99% availability
- **Negative**: Additional infrastructure cost ($200-400/month), eventual consistency during failover (1-2 seconds), requires connection pool management  
**Alternatives Considered**: 
- In-memory session storage (rejected: doesn't scale horizontally, lost on pod restart)
- Database-backed sessions (rejected: 20-50ms latency doesn't meet performance targets)
- Memcached (rejected: lacks persistence, no cluster mode in ElastiCache)

#### ADR-006: Microservices with Auth, User, and Email Services

**Status**: Accepted  
**Context**: Need to separate concerns for authentication logic, user management, and email delivery to enable independent scaling and security isolation  
**Decision**: Create three microservices: Auth Service (JWT, 2FA, sessions), User Service (profile, GDPR), Email Service (SendGrid, templates)  
**Consequences**: 
- **Positive**: Independent scaling (auth service can scale to handle login spikes), security isolation (email service has no database access), team autonomy, fault isolation
- **Negative**: Increased operational complexity (3 deployments vs 1), distributed tracing required, network latency between services (10-20ms), transaction management complexity  
**Alternatives Considered**: 
- Monolithic architecture (rejected: single point of failure, shared security boundary, difficult to scale specific components)
- Serverless functions (rejected: cold start latency incompatible with 200ms target)

#### ADR-007: API Gateway with Kong for Rate Limiting and WAF

**Status**: Accepted  
**Context**: Need centralized request routing, rate limiting (prevent brute force), WAF protection, and request/response logging  
**Decision**: Deploy Kong API Gateway with rate limiting plugin (5 login attempts/min per IP, 10/hour per user), AWS WAF integration, and Datadog APM  
**Consequences**: 
- **Positive**: Centralized security enforcement, prevents credential stuffing attacks, reduces load on backend services, comprehensive request logging
- **Negative**: Single point of failure (mitigated by multi-AZ deployment), additional latency (10-15ms), operational complexity, licensing cost  
**Alternatives Considered**: 
- AWS API Gateway (rejected: limited rate limiting capabilities, higher cost at scale)
- NGINX (rejected: requires custom rate limiting implementation, no managed service)
- Application-level rate limiting (rejected: can't prevent DDoS, doesn't protect against bad traffic)

## Technology Stack

### Frontend

- **Framework**: React 18 with TypeScript 5.0
- **UI Library**: Material-UI (MUI) v5 for consistent, accessible component design
- **State Management**: Redux Toolkit for authentication state, React Query v4 for server state caching
- **Build Tool**: Vite 4 for fast development and optimized production builds
- **Mobile**: React Native 0.72 with TypeScript for iOS and Android
- **Form Validation**: React Hook Form with Zod schema validation
- **HTTP Client**: Axios with interceptors for token refresh

### Backend

- **Language/Runtime**: Go 1.21 for high performance and low memory footprint
- **Framework**: Gin v1.9 for HTTP routing with custom middleware for logging, CORS, rate limiting
- **Authentication**: JWT (golang-jwt/jwt v5) with RS256 signing
- **Password Hashing**: Argon2id via golang.org/x/crypto/argon2
- **API Style**: RESTful APIs following OpenAPI 3.0 specification
- **Validation**: go-playground/validator v10 for request validation

### Database

- **Primary Database**: PostgreSQL 15 with pgcrypto extension for encryption
- **ORM**: GORM v2 with prepared statements for SQL injection prevention
- **Cache**: Redis 7 Cluster (AWS ElastiCache) for session storage and OTP caching
- **Search**: Not applicable for authentication service
- **Migration**: Flyway for database version control with rollback support

### Infrastructure

- **Cloud Provider**: AWS (US-East-1 primary, US-West-2 DR)
- **Container Platform**: Docker with AWS ECS Fargate (serverless containers)
- **Container Orchestration**: ECS with Application Load Balancer
- **CI/CD**: GitHub Actions with automated testing, Snyk security scanning, blue-green deployment
- **Monitoring**: Datadog for APM and metrics, Sentry for error tracking
- **Logging**: AWS CloudWatch Logs with structured JSON logging
- **Secrets Management**: AWS Secrets Manager with 90-day rotation policy
- **Infrastructure as Code**: Terraform 1.6 for all AWS resources

### Third-Party Services

- **Email**: SendGrid Platinum (99.9% SLA) with AWS SES as failover
- **SMS**: Twilio (planned for Phase 2 SMS-based 2FA)
- **CDN**: AWS CloudFront for static asset delivery
- **WAF**: AWS WAF with OWASP Core Rule Set and custom rules
- **Security Monitoring**: AWS GuardDuty for threat detection
- **Password Breach Detection**: HaveIBeenPwned API (v3)
- **Analytics**: Not applicable for authentication service (privacy-focused)
- **Social Login**: Google OAuth 2.0, Apple Sign In (Sign in with Apple)

## Architecture Principles

The architecture follows these guiding principles:

1. **Security by Default**: Every component is hardened from the start with encryption, input validation, rate limiting, and audit logging built into the foundation rather than added later. All endpoints require authentication except public registration/login, all data is encrypted at rest and in transit, and security headers (CSP, HSTS, X-Frame-Options) are enforced globally.

2. **Privacy by Design (GDPR Principle)**: Collect only the minimum data necessary for authentication (email, password hash, consent records), implement explicit consent collection with timestamps and IP logging, provide self-service data access and deletion, and ensure all PII is encrypted with regular key rotation. Users control their data from day one.

3. **Fail Securely**: When errors occur, fail closed rather than open. Failed authentication attempts deny access (vs. allowing), expired tokens are rejected immediately, and suspicious activities trigger account lockouts. Error messages are generic to prevent information disclosure (e.g., "Invalid credentials" instead of "Email not found").

4. **Observability First**: Every authentication event is logged with context (user ID, IP, device fingerprint, timestamp), metrics are collected for latency and error rates, and alerts fire for anomalies (impossible travel, brute force attacks, token reuse). Developers can trace requests across all services with distributed tracing.

5. **Scalability Through Statelessness**: Authentication is stateless via JWTs, allowing horizontal scaling without sticky sessions. Session data stored in Redis cluster scales independently of application servers. Each service can scale from 1 to 100+ instances based on load without architectural changes.

6. **Defense in Depth**: Multiple security layers protect against failures: network layer (WAF, VPC), application layer (input validation, authentication), data layer (encryption, access controls), and operational layer (monitoring, incident response). Compromise of one layer doesn't compromise the system.

7. **Compliance as a Feature**: GDPR, PCI-DSS, SOC 2, and ISO 27001 requirements are implemented as core features with audit trails, consent management, data encryption, and access controls built into every component. Compliance is continuously validated, not achieved once and forgotten.

8. **Performance Within Security Constraints**: Meet aggressive performance targets (sub-200ms authentication, 99.95% availability) without compromising security. Use caching intelligently (Redis for sessions), optimize database queries (indexed lookups), and implement efficient token validation, but never sacrifice security for speed.

## Documentation Structure

```
Architecture/
├── user-stories.md                    # User stories derived from requirements
├── feature-intention.md               # Business intent and strategic value
├── acceptance-criteria.md             # Complete acceptance criteria
├── ARCHITECTURE-README.md             # This document
│
├── Services/
│   ├── service-architecture.md        # Auth, User, Email service boundaries
│   ├── api-gateway.md                 # Kong gateway, rate limiting, WAF
│   ├── microservices-design.md        # Service communication, circuit breakers
│   └── service-communication.md       # REST contracts, event messaging (SNS/SQS)
│
├── APIs/
│   ├── rest-api-design.md             # OpenAPI 3.0 spec, endpoint definitions
│   ├── api-versioning.md              # URL-based versioning (v1, v2), deprecation
│   ├── api-documentation.md           # Complete API reference with examples
│   └── error-handling.md              # Standardized error responses
│
├── Database/
│   ├── database-architecture.md       # PostgreSQL schema, users, sessions, audit
│   ├── data-access-layer.md           # GORM repository pattern, prepared statements
│   ├── caching-strategy.md            # Redis session caching, OTP storage
│   └── data-migration-plan.md         # Flyway migrations, rollback procedures
│
├── Frontend/
│   ├── frontend-architecture.md       # React SPA, TypeScript, component structure
│   ├── component-architecture.md      # Auth components (Login, Register, MFA)
│   ├── state-management.md            # Redux Toolkit, React Query
│   └── routing-navigation.md          # Protected routes, auth guards
│
├── Security/
│   ├── security-architecture.md       # Defense-in-depth security model
│   ├── authentication-design.md       # JWT flows, token lifecycle, refresh rotation
│   ├── authorization-design.md        # RBAC model, role definitions
│   ├── data-encryption.md             # AES-256-GCM at rest, TLS 1.3 in transit
│   ├── 2fa-design.md                  # Email OTP implementation, backup codes
│   ├── password-security.md           # Argon2id hashing, complexity rules
│   └── security-monitoring.md         # Security event logging, alerting, SIEM
│
└── Deployment/
    ├── deployment-architecture.md     # AWS ECS Fargate, multi-AZ deployment
    ├── infrastructure-as-code.md      # Terraform modules, state management
    ├── cicd-pipeline.md               # GitHub Actions, blue-green deployment
    ├── monitoring-logging.md          # Datadog APM, Sentry, CloudWatch
    ├── disaster-recovery.md           # Backup strategy, RTO/RPO, failover
    └── runbooks/
        ├── incident-response.md       # Security incident procedures
        ├── scaling-procedures.md      # Manual and auto-scaling guides
        └── troubleshooting.md         # Common issues and resolutions
```

## How to Navigate

### For Developers

1. Start with this README to understand the big picture and architecture vision
2. Read **Services/service-architecture.md** to understand Auth, User, and Email service boundaries
3. Review **APIs/rest-api-design.md** for API contracts and **APIs/api-documentation.md** for endpoint specifications
4. Check **Database/database-architecture.md** for schema design and **Database/data-access-layer.md** for GORM patterns
5. Review **Security/authentication-design.md** for JWT implementation and **Security/2fa-design.md** for OTP flows
6. Check **Frontend/component-architecture.md** for React components and **Frontend/state-management.md** for Redux patterns
7. Review **Deployment/cicd-pipeline.md** for build and deployment procedures

### For Product Managers

1. Read **user-stories.md** to understand user requirements and personas
2. Read **feature-intention.md** to understand business value and ROI
3. Review **acceptance-criteria.md** to understand what "done" means and validation criteria
4. Review this README's **Architecture Goals** section to understand technical objectives
5. Check **Risks and Mitigations** section to understand project risks

### For QA/Testers

1. Start with **acceptance-criteria.md** for comprehensive test scenarios
2. Review **APIs/api-documentation.md** for endpoint testing with request/response examples
3. Check **Security/authentication-design.md** to understand security test cases (token expiry, replay attacks)
4. Review **Security/2fa-design.md** to test OTP flows, rate limiting, and edge cases
5. Review **Frontend/component-architecture.md** for UI testing scenarios
6. Check **Deployment/runbooks/troubleshooting.md** for error scenarios

### For DevOps/SRE

1. Start with **Deployment/deployment-architecture.md** for infrastructure overview
2. Review **Deployment/infrastructure-as-code.md** for Terraform module structure
3. Check **Database/database-architecture.md** for PostgreSQL and Redis deployment requirements
4. Review **Deployment/monitoring-logging.md** for observability setup (Datadog, Sentry, CloudWatch)
5. Review **Deployment/disaster-recovery.md** for backup and failover procedures
6. Check **Deployment/runbooks/** for operational procedures
7. Review **Services/api-gateway.md** for Kong gateway configuration

### For Security Engineers

1. Review **Security/** domain entirely for comprehensive security design
2. Focus on **Security/security-architecture.md** for defense-in-depth model
3. Check **Security/authentication-design.md** and **Security/2fa-design.md** for auth security
4. Review **Security/data-encryption.md** for encryption implementation
5. Review **APIs/api-documentation.md** for security headers and rate limiting
6. Check **Deployment/runbooks/incident-response.md** for security incident procedures

## Diagrams

### System Context Diagram (C4 Level 1)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SUMA Finance Platform                         │
│                                                                       │
│  ┌──────────────┐              ┌──────────────────────┐             │
│  │   End User   │──────────────▶│   Authentication    │             │
│  │ (Web/Mobile) │  Login, 2FA  │      System         │             │
│  └──────────────┘              └──────────┬───────────┘             │
│                                           │                          │
│                                           │ Validates                │
│                                           │ Identity                 │
│                                           ▼                          │
│                            ┌────────────────────────┐                │
│                            │   Other SUMA Services  │                │
│                            │ (Transactions, Budget, │                │
│                            │   Subscriptions, etc.) │                │
│                            └────────────────────────┘                │
└─────────────────────────────────────────────────────────────────────┘
         │                               │
         │ Email                         │ Email
         ▼                               ▼
┌──────────────────┐          ┌──────────────────────┐
│  SendGrid API    │          │ HaveIBeenPwned API   │
│ (Email Delivery) │          │ (Password Breach)    │
└──────────────────┘          └──────────────────────┘
```

### Container Diagram (C4 Level 2)

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│  Web App    │         │ Mobile App  │         │ Admin Portal│
│  (React)    │         │(React Native│         │  (React)    │
└──────┬──────┘         └──────┬──────┘         └──────┬──────┘
       │                       │                       │
       └───────────────────────┼───────────────────────┘
                               │ HTTPS
                               ▼
                    ┌──────────────────────┐
                    │    API Gateway       │
                    │  (Kong + AWS WAF)    │
                    │  - Rate Limiting     │
                    │  - Request Logging   │
                    └──────────┬───────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│  Auth Service   │   │  User Service   │   │ Email Service   │
│  (Go + Gin)     │   │  (Go + Gin)     │   │  (Go + Gin)     │
│  - JWT Issuing  │   │  - Profiles     │   │  - Templates    │
│  - 2FA/OTP      │   │  - GDPR Consent │   │  - SendGrid     │
│  - Sessions     │   │  - Data Export  │   │  - SNS Events   │
└────────┬────────┘   └────────┬────────┘   └────────┬────────┘
         │                     │                     │
         │                     │                     │
┌────────▼─────────┐  ┌────────▼─────────┐         │
│  Redis Cluster   │  │   PostgreSQL 15  │         │
│  (ElastiCache)   │  │   - Users        │         │
│  - Sessions      │  │   - Audit Logs   │         │
│  - OTP Codes     │  │   - Consents     │         │
└──────────────────┘  └──────────────────┘         │
                               │                   │
                               │                   ▼
                               │          ┌──────────────────┐
                               │          │   SendGrid API   │
                               │          │ (Email Delivery) │
                               │          └──────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │   AWS SNS/SQS        │
                    │  (Event Bus)         │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  Datadog + Sentry    │
                    │  (Monitoring)        │
                    └──────────────────────┘
```

### Component Diagram (C4 Level 3 - Auth Service)

```
┌────────────────────────────────────────────────────────────────┐
│                      Auth Service (Go)                         │
│                                                                 │
│  ┌────────────────┐  ┌────────────────┐  ┌─────────────────┐  │
│  │  HTTP Handler  │  │  HTTP Handler  │  │  HTTP Handler   │  │
│  │  /auth/login   │  │ /auth/register │  │ /auth/refresh   │  │
│  └───────┬────────┘  └───────┬────────┘  └────────┬────────┘  │
│          │                   │                    │            │
│          └───────────────────┼────────────────────┘            │
│                              ▼                                 │
│                  ┌───────────────────────┐                     │
│                  │  Validation Middleware│                     │
│                  │  (go-playground)      │                     │
│                  └───────────┬───────────┘                     │
│                              ▼                                 │
│         ┌────────────────────────────────────────┐             │
│         │       Authentication Controller        │             │
│         │  - Login()      - Refresh()            │             │
│         │  - Register()   - Logout()             │             │
│         │  - VerifyEmail()- ResetPassword()      │             │
│         └────────────┬───────────────────────────┘             │
│                      │                                         │
│         ┌────────────┼───────────────────────────┐             │
│         ▼            ▼                           ▼             │
│  ┌────────────┐ ┌──────────┐            ┌──────────────┐      │
│  │   JWT      │ │   OTP    │            │   Session    │      │
│  │  Service   │ │ Service  │            │   Service    │      │
│  │ - Generate │ │ - Create │            │ - Create     │      │
│  │ - Verify   │ │ - Verify │            │ - Validate   │      │
│  │ - Refresh  │ │ - Resend │            │ - Revoke     │      │
│  └─────┬──────┘ └────┬─────┘            └──────┬───────┘      │
│        │             │                         │              │
│        ▼             ▼                         ▼              │
│  ┌────────────┐ ┌──────────────┐      ┌──────────────┐       │
│  │  Crypto    │ │   Redis      │      │  PostgreSQL  │       │
│  │  (RS256,   │ │  Repository  │      │  Repository  │       │
│  │  Argon2id) │ │  (Sessions,  │      │  (Users,     │       │
│  └────────────┘ │   OTP)       │      │   Audit)     │       │
│                 └──────────────┘      └──────────────┘       │
└────────────────────────────────────────────────────────────────┘
```

### Data Flow Diagram (Login with 2FA)

```
┌──────┐                                                    ┌─────────┐
│Client│                                                    │Services │
└───┬──┘                                                    └────┬────┘
    │                                                            │
    │ 1. POST /auth/login {email, password}                     │
    ├──────────────────────────────────────────────────────────▶│
    │                                                            │
    │                        2. Validate credentials            │
    │                        3. Check password (Argon2id)       │
    │                        4. Generate OTP code               │
    │                        5. Store OTP in Redis (5-min TTL)  │
    │                        6. Send email via SNS event        │
    │                                                            │
    │◀───────────────────────────────────────────────────────────┤
    │ 7. Response: {requires_2fa: true, session_id}             │
    │                                                            │
    │ 8. POST /auth/verify-otp {session_id, otp_code}           │
    ├──────────────────────────────────────────────────────────▶│
    │                                                            │
    │                        9. Validate OTP from Redis         │
    │                        10. Generate JWT (15-min access)   │
    │                        11. Generate refresh token (7-day) │
    │                        12. Store session in Redis         │
    │                        13. Log audit event to PostgreSQL  │
    │                                                            │
    │◀───────────────────────────────────────────────────────────┤
    │ 14. Response: {access_token, refresh_token}               │
    │                                                            │
    │ 15. GET /api/protected (Authorization: Bearer <token>)    │
    ├──────────────────────────────────────────────────────────▶│
    │                                                            │
    │                        16. Verify JWT signature           │
    │                        17. Check expiry                   │
    │                        18. Validate session in Redis      │
    │                                                            │
    │◀───────────────────────────────────────────────────────────┤
    │ 19. Response: {data}                                      │
    │                                                            │
```

### Deployment Diagram (AWS Infrastructure)

```
┌─────────────────────────────────────────────────────────────────────┐
│                           AWS Cloud (US-East-1)                      │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                    Public Subnet (AZ-A)                      │    │
│  │  ┌──────────────┐              ┌──────────────┐             │    │
│  │  │ CloudFront   │              │   AWS WAF    │             │    │
│  │  │   (CDN)      │─────────────▶│   (Firewall) │             │    │
│  │  └──────────────┘              └──────┬───────┘             │    │
│  │                                       │                      │    │
│  │                               ┌───────▼────────┐             │    │
│  │                               │  Application   │             │    │
│  │                               │  Load Balancer │             │    │
│  │                               └───────┬────────┘             │    │
│  └───────────────────────────────────────┼──────────────────────┘    │
│                                          │                           │
│  ┌──────────────────────────────────────┼─────────────────────────┐ │
│  │              Private Subnet (AZ-A, AZ-B)                        │ │
│  │                                      │                          │ │
│  │  ┌───────────────────────────────────▼─────────────────┐       │ │
│  │  │          ECS Fargate Cluster                        │       │ │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │       │ │
│  │  │  │ Auth Service │  │ User Service │  │   Email   │ │       │ │
│  │  │  │   (3 tasks)  │  │   (2 tasks)  │  │  Service  │ │       │ │
│  │  │  │              │  │              │  │ (2 tasks) │ │       │ │
│  │  │  └──────┬───────┘  └──────┬───────┘  └─────┬─────┘ │       │ │
│  │  │         │                 │                │       │       │ │
│  │  └─────────┼─────────────────┼────────────────┼───────┘       │ │
│  │            │                 │                │               │ │
│  │  ┌─────────▼─────────┐  ┌────▼──────────────┐ │               │ │
│  │  │  Redis Cluster    │  │   PostgreSQL RDS  │ │               │ │
│  │  │  (ElastiCache)    │  │   (Multi-AZ)      │ │               │ │
│  │  │  3 Primary + 3    │  │   Primary + 2     │ │               │ │
│  │  │  Replicas         │  │   Read Replicas   │ │               │ │
│  │  └───────────────────┘  └───────────────────┘ │               │ │
│  │                                                                │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                     Supporting Services                         │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │  │
│  │  │ Secrets Mgr  │  │  CloudWatch  │  │   GuardDuty  │         │  │
│  │  │ (Keys, Creds)│  │   (Logs)     │  │  (Threats)   │         │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘         │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
        │                                  │
        │ External                         │ External
        ▼                                  ▼
┌──────────────────┐            ┌──────────────────┐
│   SendGrid API   │            │   Datadog APM    │
│ (Email Delivery) │            │  (Monitoring)    │
└──────────────────┘            └──────────────────┘
```

## Non-Functional Requirements Summary

### Performance

- **Response Time**: 
  - Login/Registration: < 200ms (P95)
  - Token Refresh: < 100ms (P95)
  - Session Validation: < 50ms (P95)
  - OTP Generation: < 1 second
  - Email Delivery: < 5 seconds
  - Redis Session Lookup: < 10ms

- **Throughput**: 
  - Authentication Endpoints: 1000 requests/second sustained
  - Token Refresh: 500 requests/second sustained
  - Concurrent Sessions: 100,000+ active sessions

- **Scalability**: 
  - Horizontal scaling: 1 to 100+ ECS tasks without code changes
  - Database: PostgreSQL with 2 read replicas supporting 5000 queries/second
  - Cache: Redis cluster supporting 100K ops/second with < 1ms latency

### Reliability

- **Availability**: 99.95% uptime (21.6 minutes downtime per month maximum)
- **RTO (Recovery Time Objective)**: 15 minutes for complete service restoration
- **RPO (Recovery Point Objective)**: 5 minutes maximum data loss for audit logs, zero data loss for user credentials
- **Fault Tolerance**: Multi-AZ deployment with automatic failover, Redis cluster with automatic replica promotion, PostgreSQL with synchronous replication

### Security

- **Authentication**: JWT with RS256 asymmetric signing, 15-minute access token expiry, 7-day refresh token with rotation
- **Encryption**: 
  - In Transit: TLS 1.3 with perfect forward secrecy
  - At Rest: AES-256-GCM for database encryption, encrypted EBS volumes
  - Key Rotation: 90-day rotation policy with automated key management via AWS Secrets Manager
- **Compliance**: 
  - GDPR: Consent management, right to erasure, data portability, breach notification
  - PCI-DSS v4.0: Strong cryptography, secure authentication, quarterly vulnerability scanning
  - SOC 2 Type II: Access controls, change management, incident response procedures
  - ISO 27001: Information security management system with documented policies

### Audit & Logging

- **Audit Trail**: All authentication events logged with user_id, IP address, device fingerprint, timestamp, action type
- **Retention**: 13 months for audit logs (GDPR requirement), 7 years for compliance logs (financial regulations)
- **Real-time Monitoring**: Security events streamed to Datadog with alerting for anomalies
- **Tamper Protection**: Audit logs write-only with cryptographic signatures (HMAC-SHA256)

## Dependencies

### Internal Dependencies

- **Subscription Service**: Depends on Auth Service for user authentication and authorization to manage subscription lifecycle
- **Transaction Service**: Depends on Auth Service for user identity to associate financial transactions
- **Budget Service**: Depends on Auth Service for user session validation
- **Notification Service**: Depends on Email Service for transactional email delivery infrastructure
- **Admin Portal**: Depends on Auth Service for admin user authentication with elevated permissions

### External Dependencies

- **SendGrid API**: Critical dependency for email delivery (verification, OTP, password reset). SLA: 99.9% uptime. Mitigation: AWS SES as failover provider.
- **AWS ElastiCache (Redis)**: Critical dependency for session storage and OTP caching. SLA: 99.99% uptime. Mitigation: Multi-AZ cluster with automatic failover.
- **AWS RDS (PostgreSQL)**: Critical dependency for user data and audit logs. SLA: 99.95% uptime. Mitigation: Multi-AZ deployment with automated backups.
- **AWS Secrets Manager**: Critical dependency for encryption key management. SLA: 99.99% uptime. Mitigation: Local key caching for 5-minute failover window.
- **HaveIBeenPwned API**: Non-critical dependency for password breach detection. Mitigation: Graceful degradation, skip check if API unavailable.
- **Datadog APM**: Non-critical dependency for monitoring. Mitigation: CloudWatch Logs as backup monitoring solution.

### Third-Party Service SLAs

| Service | SLA | Failover Strategy |
|---------|-----|-------------------|
| SendGrid | 99.9% | AWS SES automatic failover |
| AWS ElastiCache | 99.99% | Multi-AZ cluster with replica promotion |
| AWS RDS | 99.95% | Multi-AZ synchronous replication |
| AWS Secrets Manager | 99.99% | Local key caching (5-min TTL) |
| Datadog | 99.9% | CloudWatch Logs fallback |

## Risks and Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Redis cluster failure causing session loss** | High - All users logged out, service degradation | Low | Multi-AZ Redis cluster with automatic failover (1-2 second downtime), session data replicated across 3 nodes, monitoring alerts fire within 30 seconds |
| **SendGrid outage preventing email delivery** | High - Users cannot verify emails or reset passwords | Low | Automatic failover to AWS SES within 30 seconds, retry queue holds emails for 24 hours, monitoring tracks delivery rates |
| **JWT signing key compromise** | Critical - Attacker can issue valid tokens | Very Low | Key rotation every 90 days, asymmetric RS256 keys stored in AWS Secrets Manager with access logging, separate keys per environment, intrusion detection alerts |
| **Argon2id performance degradation under high load** | Medium - Login latency increases during spikes | Medium | Horizontal scaling of Auth Service (auto-scale at 70% CPU), caching of user lookup queries, load testing validates 1000 req/s capacity, circuit breaker prevents cascading failures |
| **SQL injection vulnerability in custom queries** | Critical - Database breach, data exfiltration | Low | 100% use of prepared statements enforced by code review, automated SQL injection scanning in CI/CD (Snyk), quarterly penetration testing, WAF SQL injection rules |
| **GDPR compliance violation (consent not captured)** | High - Legal penalties up to €20M or 4% revenue | Low | Explicit consent required at registration with timestamp logging, consent audit trail with cryptographic signatures, quarterly compliance reviews, automated testing validates consent flows |
| **Brute force credential stuffing attack** | High - Account takeovers, data breach | Medium | Rate limiting (5 attempts/min per IP at gateway, 10/hour per user), account lockout after 5 failures (15-min cooldown), CAPTCHA after 3 failures, AWS WAF geo-blocking, device fingerprinting, impossible travel detection |
| **Token replay attack after theft** | High - Unauthorized access to user account | Medium | Short-lived access tokens (15 min), refresh token rotation with reuse detection (instant revocation), device binding via fingerprint, IP address validation, security event alerting for suspicious sessions |
| **Database performance degradation from audit logging** | Medium - Increased latency for authentication | Medium | PostgreSQL table partitioning (monthly partitions for audit logs), async event-driven audit logging via SNS/SQS (decoupled from auth flow), database connection pooling (50 connections), read replicas for audit queries |
| **Third-party dependency vulnerability (Go modules)** | Medium - Known CVE exploited | Medium | Automated dependency scanning in CI/CD (Snyk, Dependabot), weekly security patches applied, vulnerability SLA (critical: 24h, high: 7 days), container image scanning |
| **Insufficient monitoring missing security incident** | High - Delayed breach detection increases damage | Low | Comprehensive security event logging (login, logout, password change, 2FA), real-time alerting in Datadog (impossible travel, multiple failures, token anomalies), AWS GuardDuty threat detection, 24/7 on-call rotation |
| **Multi-AZ AWS outage affecting service** | High - Complete service unavailability | Very Low | Multi-region disaster recovery plan (US-West-2 standby), RTO 15 minutes via automated failover, daily backup testing, quarterly DR drills, status page communication |

## Next Steps

### Implementation Phases

**Phase 1: Core Authentication (Weeks 1-2)**
- Implement Auth Service with email/password registration
- Build JWT generation and validation with RS256
- Create PostgreSQL schema (users, audit_logs tables)
- Implement Argon2id password hashing
- Set up Redis cluster for session storage
- Build email verification flow with SendGrid integration
- Deploy to AWS ECS Fargate (development environment)

**Phase 2: Security Hardening (Week 3)**
- Implement two-factor authentication (email OTP)
- Add rate limiting and account lockout protection
- Build password reset flow with secure tokens
- Implement security event logging and audit trail
- Set up AWS WAF with OWASP rules
- Configure Kong API Gateway with rate limiting
- Add GDPR consent management

**Phase 3: Frontend & Mobile (Week 4)**
- Build React authentication components (Login, Register, MFA)
- Implement Redux Toolkit state management
- Create React Native mobile app with biometric auth
- Build protected routes and authentication guards
- Implement automatic token refresh
- Add error handling and user feedback

**Phase 4: Monitoring & Testing (Week 5)**
- Set up Datadog APM and alerting
- Configure Sentry error tracking
- Implement distributed tracing across services
- Build comprehensive test suite (unit, integration, e2e)
- Perform load testing (validate 1000 req/s target)
- Security testing (OWASP Top 10 validation)

**Phase 5: Production Readiness (Week 6)**
- Configure multi-AZ production deployment
- Set up CI/CD pipeline with GitHub Actions
- Implement blue-green deployment strategy
- Create runbooks for incident response
- Perform disaster recovery drill
- Conduct security audit and penetration testing
- Launch to production with limited beta users

### Recommended Reading Order

1. **Start here** (ARCHITECTURE-README.md) - Get the big picture
2. **user-stories.md** - Understand user requirements and acceptance criteria
3. **feature-intention.md** - Understand business goals and strategic value
4. **Services/service-architecture.md** - Understand service boundaries and responsibilities
5. **Security/authentication-design.md** - Deep dive into JWT and token management
6. **Security/2fa-design.md** - Understand multi-factor authentication flows
7. **Database/database-architecture.md** - Review schema design and data model
8. **APIs/api-documentation.md** - Reference API contracts and endpoints
9. **Frontend/component-architecture.md** - Understand React component structure
10. **Deployment/deployment-architecture.md** - Review AWS infrastructure design
11. **acceptance-criteria.md** - Final validation of what "done" means

### Questions or Feedback

For questions about this architecture:

- **Technical Questions - Backend**: Auth Service team lead (Go, JWT, database design)
- **Technical Questions - Frontend**: Frontend team lead (React, Redux, mobile)
- **Security Questions**: Security architect (OWASP compliance, encryption, audit)
- **Infrastructure Questions**: DevOps team lead (AWS, ECS, Terraform)
- **Compliance Questions**: Compliance officer (GDPR, PCI-DSS, SOC 2)
- **Business Questions**: Product manager (feature prioritization, timeline)
- **Feedback**: Submit architecture change requests via GitHub Issues with label `architecture-feedback`

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-10-29 | Architecture Gate | Initial architecture design based on Pre-Gate 0 enriched requirements |

---

**Generated by Architecture Gate** - Comprehensive architecture design from Pre-Gate 0 research