---
layout: default
title: Deployment Architecture
nav_exclude: true
---



```markdown
# Deployment Architecture

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Authentication & Identity Management
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Executive Summary

This document defines the deployment architecture for the SUMA Finance user registration and authentication system. The architecture prioritizes security, scalability, compliance (GDPR, PCI-DSS, SOC 2), and high availability while supporting JWT-based authentication, email verification, 2FA, and session management.

**Key Architecture Principles:**
- **Security-First**: Defense in depth with multiple security layers
- **Compliance-Ready**: Built-in GDPR, PCI-DSS, and SOC 2 controls
- **High Availability**: 99.95% uptime target with multi-AZ deployment
- **Scalability**: Horizontal scaling to support 1000+ req/s
- **Observability**: Comprehensive logging, monitoring, and alerting

---

## 2. Deployment Environment Overview

### 2.1 Environment Strategy

| Environment | Purpose | Infrastructure | Data Isolation |
|------------|---------|----------------|----------------|
| **Development** | Local developer testing | Docker Compose | Synthetic test data |
| **Staging** | Pre-production validation | AWS ECS (single AZ) | Anonymized production data |
| **Production** | Live user traffic | AWS ECS (multi-AZ) | Live customer data (encrypted) |
| **DR (Disaster Recovery)** | Failover environment | AWS ECS (secondary region) | Real-time replication |

### 2.2 Infrastructure Stack

- **Cloud Provider**: AWS (primary region: eu-west-1, DR region: eu-central-1)
- **Container Orchestration**: Amazon ECS with Fargate
- **Container Registry**: Amazon ECR
- **Networking**: AWS VPC with private/public subnets
- **Load Balancing**: Application Load Balancer (ALB)
- **DNS**: Route 53 with health checks
- **CDN/WAF**: CloudFront + AWS WAF

---

## 3. Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet                                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
                    ┌────▼────┐
                    │ Route 53│ (DNS + Health Checks)
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │CloudFront│ (CDN)
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │ AWS WAF │ (Security Rules)
                    └────┬────┘
                         │
        ┌────────────────┴────────────────┐
        │                                  │
   ┌────▼────┐                        ┌───▼────┐
   │   ALB   │ (eu-west-1)            │  ALB   │ (eu-central-1 - DR)
   └────┬────┘                        └────────┘
        │
┌───────┴────────────────────────────────────────────┐
│              AWS VPC (eu-west-1)                    │
│  ┌──────────────────────────────────────────────┐  │
│  │         Public Subnets (Multi-AZ)            │  │
│  │  ┌─────────────┐      ┌─────────────┐       │  │
│  │  │   NAT GW    │      │   NAT GW    │       │  │
│  │  │   (AZ-1)    │      │   (AZ-2)    │       │  │
│  │  └──────┬──────┘      └──────┬──────┘       │  │
│  └─────────┼─────────────────────┼──────────────┘  │
│            │                     │                  │
│  ┌─────────┴─────────────────────┴──────────────┐  │
│  │         Private Subnets (Multi-AZ)           │  │
│  │                                               │  │
│  │  ┌──────────────────────────────────────┐   │  │
│  │  │      ECS Fargate Cluster             │   │  │
│  │  │                                       │   │  │
│  │  │  ┌────────────┐  ┌────────────┐     │   │  │
│  │  │  │Auth Service│  │Auth Service│     │   │  │
│  │  │  │  (Task 1)  │  │  (Task 2)  │ ... │   │  │
│  │  │  │            │  │            │     │   │  │
│  │  │  │ Go Backend │  │ Go Backend │     │   │  │
│  │  │  └─────┬──────┘  └─────┬──────┘     │   │  │
│  │  └────────┼───────────────┼────────────┘   │  │
│  │           │               │                 │  │
│  │  ┌────────┴───────────────┴────────────┐   │  │
│  │  │    ElastiCache Redis Cluster        │   │  │
│  │  │  (Session Store + OTP Cache)        │   │  │
│  │  │  - Primary: AZ-1                    │   │  │
│  │  │  - Replica: AZ-2                    │   │  │
│  │  └─────────────────┬───────────────────┘   │  │
│  │                    │                        │  │
│  │  ┌─────────────────▼───────────────────┐   │  │
│  │  │    RDS PostgreSQL (Multi-AZ)        │   │  │
│  │  │  - Primary: AZ-1                    │   │  │
│  │  │  - Standby: AZ-2                    │   │  │
│  │  │  - Encrypted at Rest (AES-256)      │   │  │
│  │  └─────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│           External Services                          │
├─────────────────────────────────────────────────────┤
│  - SendGrid (Email Delivery)                        │
│  - Twilio (SMS for 2FA)                             │
│  - Datadog (Monitoring & Alerting)                  │
│  - Sentry (Error Tracking)                          │
│  - AWS KMS (Key Management)                         │
│  - AWS Secrets Manager (Credential Storage)         │
│  - HaveIBeenPwned (Password Breach Detection)       │
└─────────────────────────────────────────────────────┘
```

---

## 4. Component Deployment Specifications

### 4.1 Authentication Service (Go Backend)

**Container Image**: `suma-finance/auth-service:latest`

**ECS Task Definition:**
```yaml
family: auth-service
networkMode: awsvpc
requiresCompatibilities:
  - FARGATE
cpu: 1024 (1 vCPU)
memory: 2048 (2 GB)
executionRoleArn: arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole
taskRoleArn: arn:aws:iam::ACCOUNT:role/authServiceTaskRole

containerDefinitions:
  - name: auth-service
    image: ACCOUNT.dkr.ecr.eu-west-1.amazonaws.com/auth-service:latest
    essential: true
    portMappings:
      - containerPort: 8080
        protocol: tcp
    environment:
      - name: ENVIRONMENT
        value: production
      - name: PORT
        value: "8080"
      - name: REDIS_ENDPOINT
        value: auth-redis.cluster.cache.amazonaws.com:6379
      - name: DB_HOST
        value: auth-db.cluster.eu-west-1.rds.amazonaws.com
      - name: DB_PORT
        value: "5432"
      - name: JWT_ALGORITHM
        value: RS256
      - name: SESSION_TIMEOUT_IDLE
        value: "900" # 15 minutes
      - name: SESSION_TIMEOUT_ABSOLUTE
        value: "28800" # 8 hours
      - name: MFA_ENABLED
        value: "true"
      - name: OTP_EXPIRY_SECONDS
        value: "300" # 5 minutes
    secrets:
      - name: DB_PASSWORD
        valueFrom: arn:aws:secretsmanager:eu-west-1:ACCOUNT:secret:auth/db-password
      - name: JWT_PRIVATE_KEY
        valueFrom: arn:aws:secretsmanager:eu-west-1:ACCOUNT:secret:auth/jwt-private-key
      - name: JWT_PUBLIC_KEY
        valueFrom: arn:aws:secretsmanager:eu-west-1:ACCOUNT:secret:auth/jwt-public-key
      - name: ENCRYPTION_KEY
        valueFrom: arn:aws:secretsmanager:eu-west-1:ACCOUNT:secret:auth/encryption-key
      - name: SENDGRID_API_KEY
        valueFrom: arn:aws:secretsmanager:eu-west-1:ACCOUNT:secret:sendgrid/api-key
      - name: TWILIO_API_KEY
        valueFrom: arn:aws:secretsmanager:eu-west-1:ACCOUNT:secret:twilio/api-key
    logConfiguration:
      logDriver: awslogs
      options:
        awslogs-group: /ecs/auth-service
        awslogs-region: eu-west-1
        awslogs-stream-prefix: ecs
    healthCheck:
      command:
        - CMD-SHELL
        - curl -f http://localhost:8080/health || exit 1
      interval: 30
      timeout: 5
      retries: 3
      startPeriod: 60
```

**ECS Service Configuration:**
```yaml
serviceName: auth-service
cluster: suma-finance-production
taskDefinition: auth-service:latest
desiredCount: 4
launchType: FARGATE
platformVersion: LATEST

networkConfiguration:
  awsvpcConfiguration:
    subnets:
      - subnet-private-1a
      - subnet-private-1b
    securityGroups:
      - sg-auth-service
    assignPublicIp: DISABLED

loadBalancers:
  - targetGroupArn: arn:aws:elasticloadbalancing:eu-west-1:ACCOUNT:targetgroup/auth-service
    containerName: auth-service
    containerPort: 8080

deploymentConfiguration:
  maximumPercent: 200
  minimumHealthyPercent: 100
  deploymentCircuitBreaker:
    enable: true
    rollback: true

healthCheckGracePeriodSeconds: 120

autoScaling:
  minCapacity: 4
  maxCapacity: 20
  targetCPUUtilization: 70
  targetMemoryUtilization: 80
  scaleInCooldown: 300
  scaleOutCooldown: 60
```

### 4.2 PostgreSQL Database (Amazon RDS)

**Instance Configuration:**
```yaml
engine: postgres
engineVersion: "15.4"
instanceClass: db.r6g.xlarge (4 vCPU, 32 GB RAM)
allocatedStorage: 500 GB
storageType: gp3
iops: 12000
multiAZ: true
publiclyAccessible: false
storageEncrypted: true
kmsKeyId: arn:aws:kms:eu-west-1:ACCOUNT:key/auth-db-key

backupRetentionPeriod: 30 days
preferredBackupWindow: "03:00-04:00"
preferredMaintenanceWindow: "sun:04:00-sun:05:00"

monitoringInterval: 60
enablePerformanceInsights: true
performanceInsightsRetentionPeriod: 731 # 2 years

parameterGroup: auth-db-pg15
  parameters:
    - name: log_statement
      value: mod # Log modifications only
    - name: log_connections
      value: "1"
    - name: log_disconnections
      value: "1"
    - name: shared_preload_libraries
      value: pg_stat_statements
```

**Database Schema:**
- `users` - User accounts with encrypted PII
- `auth_sessions` - Active sessions (backed by Redis)
- `auth_events` - Security audit log
- `mfa_devices` - Registered 2FA devices
- `consent_records` - GDPR consent tracking
- `password_history` - Last 5 password hashes

### 4.3 Redis Cache (Amazon ElastiCache)

**Cluster Configuration:**
```yaml
engine: redis
engineVersion: "7.0"
cacheNodeType: cache.r6g.large (2 vCPU, 13.07 GB RAM)
numCacheNodes: 2 (1 primary + 1 replica)
replicationGroupId: auth-redis-cluster
automaticFailoverEnabled: true
multiAZEnabled: true
transitEncryptionEnabled: true
atRestEncryptionEnabled: true
authTokenEnabled: true

snapshotRetentionLimit: 7
snapshotWindow: "02:00-03:00"
maintenanceWindow: "sun:03:00-sun:04:00"

parameterGroup: auth-redis-7
  parameters:
    - name: maxmemory-policy
      value: allkeys-lru
    - name: timeout
      value: "300"
```

**Data Stored:**
- Session tokens (TTL: 8 hours)
- Refresh tokens (TTL: 7 days)
- OTP codes (TTL: 5 minutes)
- Rate limiting counters (TTL: 1 hour)
- Failed login attempts (TTL: 15 minutes)

---

## 5. Network Architecture

### 5.1 VPC Configuration

```yaml
VPC:
  cidr: 10.0.0.0/16
  enableDnsHostnames: true
  enableDnsSupport: true

PublicSubnets:
  - subnet-public-1a: 10.0.1.0/24 (eu-west-1a)
  - subnet-public-1b: 10.0.2.0/24 (eu-west-1b)

PrivateSubnets:
  - subnet-private-1a: 10.0.10.0/24 (eu-west-1a)
  - subnet-private-1b: 10.0.11.0/24 (eu-west-1b)

DatabaseSubnets:
  - subnet-db-1a: 10.0.20.0/24 (eu-west-1a)
  - subnet-db-1b: 10.0.21.0/24 (eu-west-1b)
```

### 5.2 Security Groups

**ALB Security Group (sg-alb):**
- Inbound: 443 (HTTPS) from 0.0.0.0/0
- Outbound: 8080 to sg-auth-service

**Auth Service Security Group (sg-auth-service):**
- Inbound: 8080 from sg-alb
- Outbound: 5432 to sg-rds
- Outbound: 6379 to sg-redis
- Outbound: 443 to 0.0.0.0/0 (external APIs)

**RDS Security Group (sg-rds):**
- Inbound: 5432 from sg-auth-service
- Outbound: None

**Redis Security Group (sg-redis):**
- Inbound: 6379 from sg-auth-service
- Outbound: None

### 5.3 Network ACLs

**Private Subnet NACL:**
```yaml
Inbound:
  - Rule 100: Allow TCP 8080 from Public Subnets
  - Rule 200: Allow TCP 5432 from Private Subnets
  - Rule 300: Allow TCP 6379 from Private Subnets
  - Rule 400: Allow HTTPS (443) from NAT Gateway
  - Rule *: Deny All

Outbound:
  - Rule 100: Allow TCP 1024-65535 to Public Subnets
  - Rule 200: Allow HTTPS (443) to 0.0.0.0/0
  - Rule *: Deny All
```

---

## 6. Security Configuration

### 6.1 TLS/SSL Configuration

**ALB HTTPS Listener:**
```yaml
protocol: HTTPS
port: 443
certificate: arn:aws:acm:eu-west-1:ACCOUNT:certificate/auth-suma-finance
sslPolicy: ELBSecurityPolicy-TLS13-1-2-2021-06
  - TLS 1.3 (preferred)
  - TLS 1.2 (fallback)
  - Ciphers: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384

actions:
  - type: forward
    targetGroupArn: arn:aws:elasticloadbalancing:eu-west-1:ACCOUNT:targetgroup/auth-service
```

**HTTP to HTTPS Redirect:**
```yaml
protocol: HTTP
port: 80
actions:
  - type: redirect
    redirectConfig:
      protocol: HTTPS
      port: 443
      statusCode: HTTP_301
```

### 6.2 AWS WAF Rules

**WAF Web ACL: auth-protection**

```yaml
rules:
  - name: RateLimitRule
    priority: 1
    action: BLOCK
    statement:
      rateBasedStatement:
        limit: 300 # 300 requests per 5 minutes per IP
        aggregateKeyType: IP
    
  - name: GeoBlockRule
    priority: 2
    action: BLOCK
    statement:
      geoMatchStatement:
        countryCodes: [KP, IR, SY, CU] # Block sanctioned countries
    
  - name: SQLInjectionRule
    priority: 3
    action: BLOCK
    statement:
      sqliMatchStatement:
        fieldToMatch:
          body: {}
        textTransformations:
          - priority: 0
            type: URL_DECODE
          - priority: 1
            type: HTML_ENTITY_DECODE
    
  - name: XSSProtectionRule
    priority: 4
    action: BLOCK
    statement:
      xssMatchStatement:
        fieldToMatch:
          body: {}
        textTransformations:
          - priority: 0
            type: URL_DECODE
          - priority: 1
            type: HTML_ENTITY_DECODE
    
  - name: AWSManagedRulesCommonRuleSet
    priority: 5
    statement:
      managedRuleGroupStatement:
        vendorName: AWS
        name: AWSManagedRulesCommonRuleSet
```

### 6.3 Secrets Management

**AWS Secrets Manager Structure:**

```
/suma-finance/auth/production/
├── db-password (Auto-rotation: 90 days)
├── redis-auth-token (Auto-rotation: 90 days)
├── jwt-private-key (RSA 4096-bit, Manual rotation)
├── jwt-public-key (RSA 4096-bit, Manual rotation)
├── encryption-key (AES-256 key, Auto-rotation: 90 days)
├── sendgrid-api-key (Manual rotation)
├── twilio-api-key (Manual rotation)
└── hmac-signing-key (For password reset tokens, Auto-rotation: 90 days)
```

**IAM Policy for ECS Task:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:eu-west-1:ACCOUNT:secret:/suma-finance/auth/production/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:eu-west-1:ACCOUNT:key/auth-secrets-key"
    }
  ]
}
```

### 6.4 KMS Key Configuration

**CMK for Database Encryption:**
```yaml
keyId: auth-db-encryption-key
keyPolicy:
  - sid: Enable RDS Encryption
    principal:
      service: rds.amazonaws.com
    actions:
      - kms:Encrypt
      - kms:Decrypt
      - kms:GenerateDataKey
    resources: "*"
    
keyRotation: enabled (automatic annual rotation)
```

---

## 7. Monitoring & Observability

### 7.1 CloudWatch Metrics

**Custom Metrics (Datadog Agent):**
- `auth.login.attempts` (counter)
- `auth.login.failures` (counter)
- `auth.login.success` (counter)
- `auth.login.duration` (histogram)
- `auth.registration.total` (counter)
- `auth.email.verification.sent` (counter)
- `auth.email.verification.completed` (counter)
- `auth.password.reset.requests` (counter)
- `auth.mfa.challenges.sent` (counter)
- `auth.mfa.challenges.verified` (counter)
- `auth.session.created` (counter)
- `auth.session.expired` (counter)
- `auth.token.refresh` (counter)
- `auth.account.lockouts` (counter)

**AWS CloudWatch Metrics:**
- ECS: CPU utilization, memory utilization, task count
- RDS: CPU utilization, DB connections, read/write latency
- ElastiCache: CPU utilization, cache hits/misses, evictions
- ALB: request count, target response time, HTTP 4xx/5xx

### 7.2 CloudWatch Alarms

```yaml
alarms:
  - name: HighLoginFailureRate
    metric: auth.login.failures
    threshold: 100 per minute
    evaluationPeriods: 2
    datapointsToAlarm: 2
    action: SNS topic -> PagerDuty
    
  - name: DatabaseCPUHigh
    metric: RDS CPUUtilization
    threshold: 80%
    evaluationPeriods: 3
    datapointsToAlarm: 2
    action: SNS topic -> Ops team
    
  - name: RedisCacheMissRateHigh
    metric: CacheMissRate
    threshold: 20%
    evaluationPeriods: 5
    datapointsToAlarm: 3
    action: SNS topic -> Ops team
    
  - name: ECSServiceUnhealthy
    metric: HealthyHostCount
    threshold: < 2
    evaluationPeriods: 1
    datapointsToAlarm: 1
    action: SNS topic -> PagerDuty
    
  - name: ALBHighLatency
    metric: TargetResponseTime
    threshold: 1 second (p99)
    evaluationPeriods: 3
    datapointsToAlarm: 2
    action: SNS topic -> Ops team
```

### 7.3 Logging Strategy

**CloudWatch Log Groups:**
- `/ecs/auth-service` - Application logs
- `/aws/rds/instance/auth-db/postgresql` - Database logs
- `/aws/elasticache/auth-redis` - Cache logs
- `/aws/waf/auth-protection` - WAF logs
- `/aws/alb/auth-alb` - Load balancer access logs

**Log Retention:**
- Application logs: 90 days (then archive to S3)
- Security audit logs: 7 years (compliance requirement)
- WAF logs: 180 days
- ALB access logs: 90 days

**Structured Logging Format (JSON):**
```json
{
  "timestamp": "2025-10-29T12:34:56.789Z",
  "level": "INFO",
  "service": "auth-service",
  "traceId": "abc123-def456",
  "userId": "user-789",
  "event": "login.success",
  "ipAddress": "203.0.113.45",
  "userAgent": "Mozilla/5.0...",
  "metadata": {
    "mfaEnabled": true,
    "loginMethod": "email_password"
  }
}
```

### 7.4 Distributed Tracing

**AWS X-Ray Integration:**
- Trace all API requests end-to-end
- Capture service-to-service calls (ECS -> RDS, ECS -> Redis)
- Identify performance bottlenecks
- Track error rates by endpoint

**Sampling Strategy:**
- 100% of errors and throttled requests
- 10% of successful requests
- 100% of requests > 1 second duration

---

## 8. CI/CD Pipeline

### 8.1 GitHub Actions Workflow

**File**: `.github/workflows/deploy-auth-service.yml`

```yaml
name: Deploy Auth Service

on:
  push:
    branches: [main]
    paths:
      - 'backend/auth-service/**'
      - '.github/workflows/deploy-auth-service.yml'

env:
  AWS_REGION: eu-west-1
  ECR_REPOSITORY: auth-service
  ECS_SERVICE: auth-service
  ECS_CLUSTER: suma-finance-production
  CONTAINER_NAME: auth-service

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Run unit tests
        run: |
          cd backend/auth-service
          go test ./... -v -coverprofile=coverage.out
      
      - name: Check test coverage
        run: |
          coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          if (( $(echo "$coverage < 80" | bc -l) )); then
            echo "Coverage $coverage% is below 80% threshold"
            exit 1
          fi
      
      - name: Run security scan (Snyk)
        uses: snyk/actions/golang@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1
      
      - name: Build, tag, and push image
        id: build-image
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          IMAGE_TAG: ${{ github.sha }}
        run: |
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG \
            -t $ECR_REGISTRY/$ECR_REPOSITORY:latest \
            -f backend/auth-service/Dockerfile \
            backend/auth-service
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:latest
          echo "image=$ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG" >> $GITHUB_OUTPUT
      
      - name: Scan image for vulnerabilities (Trivy)
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ steps.build-image.outputs.image }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
      
      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Update ECS task definition
        id: task-def
        run: |
          TASK_DEFINITION=$(aws ecs describe-task-definition \
            --task-definition auth-service \
            --query taskDefinition)
          NEW_TASK_DEF=$(echo $TASK_DEFINITION | jq --arg IMAGE "${{ steps.build-image.outputs.image }}" \
            '.containerDefinitions[0].image = $IMAGE | del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)')
          echo $NEW_TASK_DEF > task-definition.json
      
      - name: Deploy to ECS
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: task-definition.json
          service: ${{ env.ECS_SERVICE }}
          cluster: ${{ env.ECS_CLUSTER }}
          wait-for-service-stability: true
      
      - name: Verify deployment
        run: |
          sleep 60
          HEALTH_CHECK=$(curl -f https://auth.suma-finance.com/health || echo "failed")
          if [ "$HEALTH_CHECK" = "failed" ]; then
            echo "Health check failed after deployment"
            exit 1
          fi
      
      - name: Notify Slack
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "Auth Service deployed successfully to production",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Deployment Successful* :white_check_mark:\n*Service*: Auth Service\n*Environment*: Production\n*Commit*: ${{ github.sha }}"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### 8.2 Deployment Rollback Strategy

**Automatic Rollback Triggers:**
- Health check failures (3 consecutive failures)
- CloudWatch alarms: HighErrorRate, HighLatency
- ECS deployment circuit breaker activation

**Manual Rollback Procedure:**
```bash
# Get previous task definition revision
aws ecs describe-services \
  --cluster suma-finance-production \
  --services auth-service \
  --query 'services[0].deployments[1].taskDefinition'

# Rollback to previous revision
aws ecs update-service \
  --cluster suma-finance-production \
  --service auth-service \
  --task-definition auth-service:N-1 \
  --force-new-deployment
```

---

## 9. Disaster Recovery & High Availability

### 9.1 Multi-AZ Strategy

**Active Components:**
- ALB: Distributed across 2 AZs (eu-west-1a, eu-west-1b)
- ECS Tasks: Minimum 2 tasks per AZ (total: 4 tasks)
- RDS: Primary in 1a, synchronous standby in 1b
- ElastiCache: Primary node in 1a, replica in 1b

**Failover Times:**
- ALB: Instant (health check removes failed targets)
- ECS: 60 seconds (new task launch time)
- RDS: 60-120 seconds (automatic failover)
- ElastiCache: 30-60 seconds (automatic failover)

### 9.2 Cross-Region DR (eu-central-1)

**DR Infrastructure:**
- Warm standby environment (scaled down to 50% capacity)
- Read replica of RDS in DR region (5-minute replication lag)
- S3 backup replication (cross-region)
- Route 53 health checks with automatic failover

**DR Activation Steps:**
1. Route 53 detects primary region failure (3 failed health checks)
2. DNS routes traffic to DR region ALB (TTL: 60 seconds)
3. Promote RDS read replica to standalone instance
4. Scale up ECS service to full capacity (2 minutes)
5. Verify application functionality

**Recovery Time Objective (RTO)**: 15 minutes
**Recovery Point Objective (RPO)**: 5 minutes

### 9.3 Backup Strategy

**RDS Automated Backups:**
- Daily snapshots at 03:00 UTC
- 30-day retention
- Cross-region copy to DR region (encrypted)
- Transaction logs backed up every 5 minutes

**Manual Backup Triggers:**
- Before major deployments
- Before schema changes
- On-demand via AWS Console/CLI

**Backup Testing:**
- Monthly restore test to verify backup integrity
- Quarterly full DR drill

---

## 10. Scalability & Performance

### 10.1 Auto-Scaling Configuration

**ECS Service Auto-Scaling:**

```yaml
targetTrackingScaling:
  - metricType: ECSServiceAverageCPUUtilization
    targetValue: 70
    scaleInCooldown: 300
    scaleOutCooldown: 60
  
  - metricType: ECSServiceAverageMemoryUtilization
    targetValue: 80
    scaleInCooldown: 300
    scaleOutCooldown: 60
  
  - metricType: ALBRequestCountPerTarget
    targetValue: 1000
    scaleInCooldown: 300
    scaleOutCooldown: 60

scheduledScaling:
  - name: scale-up-business-hours
    schedule: cron(0 7 * * MON-FRI)
    minCapacity: 6
    maxCapacity: 20
  
  - name: scale-down-off-hours
    schedule: cron(0 19 * * MON-FRI)
    minCapacity: 4
    maxCapacity: 12
```

**RDS Read Replica Scaling:**
- Add read replicas when CPU > 80% for 15 minutes
- Up to 5 read replicas for read-heavy queries
- Route read-only queries (user profile lookups) to replicas

**ElastiCache Scaling:**
- Add cache nodes when memory utilization > 80%
- Increase node size for higher throughput
- Enable cluster mode for horizontal scaling

### 10.2 Performance Optimization

**Database Query Optimization:**
- Index on `users.email` (unique)
- Index on `auth_sessions.token` (hash)
- Index on `auth_events.user_id, created_at` (composite)
- Materialized view for active user counts

**Redis Performance:**
- Use Redis pipelining for batch operations
- Optimize key naming for efficient memory usage
- Use Redis Cluster for sharding (if needed)

**Application-Level Caching:**
- Cache user profiles for 5 minutes
- Cache public keys for JWT verification (1 hour)
- Cache rate limit counters in Redis

**CDN Configuration (CloudFront):**
- Cache static assets (images, JS, CSS)
- Cache API responses for public endpoints (e.g., password strength checker)
- Use Lambda@Edge for geolocation-based routing

---

## 11. Cost Optimization

### 11.1 Resource Right-Sizing

**ECS Fargate:**
- Use Fargate Spot for non-production environments (70% cost savings)
- Analyze CPU/memory utilization weekly and adjust task definitions
- Use ARM-based Graviton2 instances (20% cost savings)

**RDS:**
- Use Reserved Instances for production (40% savings vs. on-demand)
- Schedule non-production databases to stop during off-hours
- Use Provisioned IOPS only when necessary

**ElastiCache:**
- Use Reserved Nodes for production (30% savings)
- Right-size cache nodes based on memory utilization

### 11.2 Cost Monitoring

**AWS Cost Allocation Tags:**
```yaml
tags:
  Environment: production
  Service: auth-service
  Team: platform
  CostCenter: engineering
```

**Budget Alerts:**
- Monthly budget: $2,000
- Alert at 80% threshold ($1,600)
- Alert at 100% threshold ($2,000)
- Notify engineering lead and finance team

---

## 12. Compliance & Audit

### 12.1 GDPR Compliance

**Data Residency:**
- All data stored in EU regions (eu-west-1, eu-central-1)
- No cross-border data transfers to non-EU regions
- DPA (Data Processing Agreement) with AWS

**Data Protection Measures:**
- AES-256-GCM encryption at rest
- TLS 1.3 in transit
- PII pseudonymization where possible
- Database column-level encryption for sensitive fields

**User Rights Implementation:**
- Right to access: API endpoint to download user data
- Right to erasure: Soft delete with 30-day retention, then hard delete
- Right to portability: JSON/CSV export of user data
- Right to rectification: Self-service profile update

### 12.2 Audit Logging

**Audit Trail Requirements:**
- All authentication events logged
- Tamper-proof logs (AWS CloudWatch Logs Insights)
- 7-year retention for compliance
- Log fields: timestamp, user ID, IP, action, result

**Audit Events:**
- User registration
- Email verification
- Login success/failure
- Password change/reset
- 2FA enable/disable
- Session creation/termination
- Account lockout/unlock
- Consent granted/withdrawn
- Data export/deletion requests

### 12.3 PCI-DSS Controls

**Applicable Requirements:**
- Requirement 3: Protect stored data (encryption)
- Requirement 4: Encrypt transmission of cardholder data (TLS)
- Requirement 8: Identify and authenticate access (MFA)
- Requirement 10: Track and monitor all access (audit logs)

**Implementation:**
- No cardholder data stored in auth service
- Tokenization for payment processing (handled separately)
- Compliance attestation via AWS Artifact

---

## 13. Operational Runbooks

### 13.1 Incident Response

**Severity Levels:**
- **P1 (Critical)**: Service down, affects all users (SLA: 15 min response)
- **P2 (High)**: Partial outage, affects subset of users (SLA: 1 hour)
- **P3 (Medium)**: Degraded performance (SLA: 4 hours)
- **P4 (Low)**: Minor issue, no customer impact (SLA: 1 business day)

**P1 Incident Procedure:**
1. Acknowledge alert in PagerDuty
2. Create Slack incident channel
3. Check CloudWatch dashboards and logs
4. Verify infrastructure health (ECS, RDS, Redis)
5. If deployment-related, initiate rollback
6. Communicate status to stakeholders every 30 minutes
7. Post-incident review within 48 hours

### 13.2 Common Issues & Resolutions

**Issue: High Login Failure Rate**
- **Cause**: Brute force attack or credential stuffing
- **Resolution**: Verify WAF rules are active, check account lockouts, consider temporary rate limit reduction
- **Prevention**: Implement CAPTCHA, monitor HaveIBeenPwned integration

**Issue: Database Connection Pool Exhausted**
- **Cause**: Connection leak or high traffic
- **Resolution**: Restart ECS tasks to reset connections, verify connection pool settings
- **Prevention**: Increase max connections, add connection pool monitoring

**Issue: Redis Cache Misses Spike**
- **Cause**: Cache eviction due to memory pressure or Redis restart
- **Resolution**: Verify Redis memory utilization, increase cache node size if needed
- **Prevention**: Set appropriate maxmemory-policy, monitor eviction rate

---

## 14. Security Hardening Checklist

- [x] TLS 1.3 enforced on ALB
- [x] AWS WAF rules enabled (rate limiting, SQL injection, XSS)
- [x] Security groups follow least privilege
- [x] No public IPs assigned to ECS tasks
- [x] Database not publicly accessible
- [x] Secrets stored in AWS Secrets Manager (not environment variables)
- [x] KMS encryption for all data at rest
- [x] IAM roles follow least privilege
- [x] CloudTrail enabled for API audit logging
- [x] GuardDuty enabled for threat detection
- [x] VPC Flow Logs enabled
- [x] Container image scanning (Trivy/Snyk)
- [x] Dependency vulnerability scanning
- [x] Automated security patching for base images
- [x] DDoS protection via AWS Shield Standard
- [x] Regular penetration testing (quarterly)

---

## 15. Deployment Checklist

**Pre-Deployment:**
- [ ] Code review completed and approved
- [ ] All tests passing (unit, integration, e2e)
- [ ] Security scan passed (Snyk, Trivy)
- [ ] Performance testing completed
- [ ] Database migration scripts tested
- [ ] Rollback plan documented
- [ ] Stakeholders notified of deployment window
- [ ] Backup taken (RDS snapshot)

**During Deployment:**
- [ ] Monitor CloudWatch metrics in real-time
- [ ] Verify health checks passing
- [ ] Check error rates and latency
- [ ] Verify new tasks are running
- [ ] Test critical user flows (login, registration)

**Post-Deployment:**
- [ ] Verify application functionality
- [ ] Check logs for errors
- [ ] Monitor for 1 hour post-deployment
- [ ] Update deployment log
- [ ] Notify stakeholders of successful deployment
- [ ] Close deployment ticket

---

## 16. Maintenance Windows

**Scheduled Maintenance:**
- **Time**: Sundays 03:00-05:00 UTC (lowest traffic period)
- **Frequency**: Monthly for database maintenance, quarterly for infrastructure updates
- **Notification**: 7 days advance notice to stakeholders

**Emergency Maintenance:**
- **Trigger**: Critical security patches, P1 incidents
- **Approval**: CTO approval required
- **Notification**: 2 hours advance notice (if possible)

---

## 17. Contact Information

**On-Call Rotation:**
- Primary: Platform Engineering Team
- Secondary: Backend Engineering Team
- Escalation: Engineering Manager

**Incident Channels:**
- Slack: #incidents-auth-service
- PagerDuty: Platform Engineering Team
- Email: platform-oncall@suma-finance.com

**Key Stakeholders:**
- Product Owner: [Name]
- Engineering Manager: [Name]
- Security Lead: [Name]
- Compliance Officer: [Name]

---

## 18. References

- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [GDPR Requirements](https://gdpr-info.eu/)
- [PCI-DSS v4.0](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Next Review**: 2025-11-29 (Monthly review cycle)

---
