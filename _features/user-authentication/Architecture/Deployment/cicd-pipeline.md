


# CI/CD Pipeline Architecture

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: DevOps
**Generated**: 2025-11-01T00:00:00Z

---

## 1. CI/CD Architecture Overview

### Pipeline Philosophy
The SUMA Finance authentication system pipeline adheres to strict security-first principles with automated compliance validation at every stage. Given the critical nature of authentication and financial data handling, the pipeline implements:

- **Shift-Left Security**: Security scanning at build time, not post-deployment
- **Zero-Trust Deployment**: Every deployment requires cryptographic verification
- **Compliance-as-Code**: GDPR, PCI-DSS, SOC2 checks automated in pipeline
- **Fast Feedback Loops**: <5 minute build-to-feedback cycle
- **Immutable Infrastructure**: Container-based deployments with versioned artifacts
- **Progressive Delivery**: Canary deployments with automated rollback on security/performance degradation

### Pipeline Stages

```mermaid
graph LR
    A[Code Commit] --> B[Build & Lint]
    B --> C[Unit Tests]
    C --> D[Security Scan]
    D --> E[Integration Tests]
    E --> F[Container Build]
    F --> G[Container Security Scan]
    G --> H[Deploy Staging]
    H --> I[E2E Tests]
    I --> J[Compliance Validation]
    J --> K[Manual Approval]
    K --> L[Canary Deploy]
    L --> M[Production Rollout]
```

**Stage Durations (Target)**:
- Build & Lint: 90 seconds
- Unit Tests: 2 minutes
- Security Scan: 3 minutes
- Integration Tests: 5 minutes
- Container Build: 4 minutes
- E2E Tests: 8 minutes
- Total Commit-to-Staging: <15 minutes
- Total Commit-to-Production: <30 minutes (excluding approval wait)

### Tool Ecosystem
- **Version Control**: GitHub with branch protection rules
- **CI/CD Platform**: GitHub Actions (native integration, secrets management, OIDC for AWS)
- **Container Registry**: AWS ECR with image scanning
- **Artifact Storage**: GitHub Packages (npm), AWS S3 (reports)
- **Secrets Management**: AWS Secrets Manager + GitHub OIDC
- **Deployment Target**: AWS ECS Fargate (staging/production)
- **Infrastructure as Code**: Terraform with remote state in S3
- **Monitoring Integration**: Datadog APM, Sentry

### Integration Points
- **GitHub → GitHub Actions**: Automatic trigger on push/PR
- **GitHub Actions → AWS**: OIDC-based authentication (no long-lived credentials)
- **ECS → Datadog**: APM tracing, deployment markers
- **Pipeline → Sentry**: Release tracking, source map uploads
- **Pipeline → Slack**: Build status, deployment notifications

### Deployment Strategy
**Primary Strategy**: **Canary Deployment with Automated Rollback**

For authentication systems, canary deployments minimize blast radius while maintaining high confidence:
- 10% traffic → 5 minutes observation → 50% traffic → 10 minutes → 100%
- Real-time error rate monitoring (<0.5% threshold)
- P95 latency monitoring (<200ms login, <100ms token refresh)
- Automated rollback on threshold breach

**Fallback Strategy**: **Blue-Green** for emergency hotfixes requiring instant rollback capability

---

## 2. CI/CD Platform Selection

### Platform Comparison

| Feature | GitHub Actions | GitLab CI | Jenkins | CircleCI | Azure DevOps |
|---------|---------------|-----------|---------|----------|--------------|
| Cloud-hosted | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| Self-hosted | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Cost | 2,000 min/mo free | 400 min/mo free | Free (self-host) | 6,000 min/mo (paid) | 1,800 min/mo free |
| AWS OIDC Integration | ✅ Native | ⚠️ Manual | ⚠️ Plugin | ⚠️ Manual | ❌ Limited |
| Container support | ✅ Excellent | ✅ Excellent | ⚠️ Good | ✅ Excellent | ✅ Excellent |
| Marketplace | 18,000+ actions | 2,000+ | 1,800+ plugins | Limited | Limited |
| Secrets Management | ✅ Built-in + OIDC | ✅ Built-in | ⚠️ Plugin-based | ✅ Built-in | ✅ Built-in |
| Matrix Builds | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Caching | ✅ GitHub Cache | ✅ Built-in | ⚠️ Manual | ✅ Built-in | ✅ Built-in |
| Learning Curve | Low | Medium | High | Low | Medium |
| SOC2/GDPR Compliance | ✅ Yes | ✅ Yes | ⚠️ Self-managed | ✅ Yes | ✅ Yes |

### Selected Platform: **GitHub Actions**

**Rationale**:
1. **Native AWS OIDC Support**: Eliminates long-lived AWS credentials (SOC2 compliance requirement)
2. **GitHub Native**: Code and CI/CD in single platform (reduced context switching)
3. **Extensive Marketplace**: Pre-built actions for Snyk, Trivy, Datadog, Sentry integration
4. **Cost-Effective**: 2,000 free minutes covers estimated 1,500 min/month usage
5. **Security Features**: CODEOWNERS, required status checks, deployment protection rules
6. **Team Familiarity**: Development team already using GitHub

**Scaling Plan**:
- **Current**: GitHub-hosted runners (2,000 min/month free tier)
- **Future (>10 deploys/day)**: Self-hosted runners on AWS EC2 Spot instances (cost reduction)

---

## 3. Pipeline Architecture Design

### Multi-Stage Pipeline

```yaml
# .github/workflows/auth-service-pipeline.yml
name: Authentication Service CI/CD

on:
  push:
    branches: [main, develop]
    paths:
      - 'services/auth/**'
      - '.github/workflows/auth-service-pipeline.yml'
  pull_request:
    branches: [main, develop]
    paths:
      - 'services/auth/**'

env:
  GO_VERSION: '1.21'
  NODE_VERSION: '18.x'
  AWS_REGION: eu-west-1
  ECR_REPOSITORY: suma-finance/auth-service
  ECS_SERVICE: auth-service
  ECS_CLUSTER: suma-finance-cluster

permissions:
  id-token: write   # Required for AWS OIDC
  contents: read
  packages: write
  security-events: write

jobs:
  # ============================================
  # Stage 1: Build & Test Backend (Go)
  # ============================================
  build-backend:
    name: Build & Test Go Backend
    runs-on: ubuntu-latest
    timeout-minutes: 10
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for SonarQube

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}
          cache: true
          cache-dependency-path: services/auth/go.sum

      - name: Verify dependencies
        working-directory: services/auth
        run: |
          go mod verify
          go mod download

      - name: Run golangci-lint
        uses: golangci/golangci-lint-action@v3
        with:
          version: latest
          working-directory: services/auth
          args: --timeout=5m --config=.golangci.yml

      - name: Run unit tests
        working-directory: services/auth
        run: |
          go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
          go tool cover -func=coverage.out

      - name: Check test coverage threshold
        working-directory: services/auth
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          echo "Coverage: $COVERAGE%"
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "❌ Coverage $COVERAGE% is below 80% threshold"
            exit 1
          fi
          echo "✅ Coverage $COVERAGE% meets threshold"

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./services/auth/coverage.out
          flags: backend
          fail_ci_if_error: true

      - name: Build binary
        working-directory: services/auth
        run: |
          CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o bin/auth-service ./cmd/server

      - name: Upload build artifact
        uses: actions/upload-artifact@v4
        with:
          name: auth-service-binary
          path: services/auth/bin/auth-service
          retention-days: 7

  # ============================================
  # Stage 2: Build & Test Frontend (React)
  # ============================================
  build-frontend:
    name: Build & Test React Frontend
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'
          cache-dependency-path: frontend/package-lock.json

      - name: Install dependencies
        working-directory: frontend
        run: npm ci --prefer-offline --no-audit

      - name: Run ESLint
        working-directory: frontend
        run: npm run lint

      - name: Run Prettier check
        working-directory: frontend
        run: npm run format:check

      - name: Run TypeScript type check
        working-directory: frontend
        run: npm run type-check

      - name: Run unit tests
        working-directory: frontend
        run: npm run test:unit -- --coverage --watchAll=false

      - name: Check test coverage threshold
        working-directory: frontend
        run: |
          COVERAGE=$(jq -r '.total.lines.pct' coverage/coverage-summary.json)
          echo "Coverage: $COVERAGE%"
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "❌ Coverage $COVERAGE% is below 80% threshold"
            exit 1
          fi

      - name: Build production bundle
        working-directory: frontend
        run: npm run build
        env:
          NODE_ENV: production

      - name: Upload build artifact
        uses: actions/upload-artifact@v4
        with:
          name: frontend-build
          path: frontend/build/
          retention-days: 7

  # ============================================
  # Stage 3: Security Scanning (SAST)
  # ============================================
  security-sast:
    name: Static Application Security Testing
    runs-on: ubuntu-latest
    needs: [build-backend, build-frontend]
    timeout-minutes: 15

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      # CodeQL for Go backend
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: go
          queries: security-and-quality

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:go"

      # Semgrep for security patterns
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/jwt
            p/sql-injection
            p/xss
            p/secrets

      # Snyk Code for vulnerability scanning
      - name: Run Snyk Code Test
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high --fail-on=all

  # ============================================
  # Stage 4: Dependency Scanning (SCA)
  # ============================================
  security-dependencies:
    name: Software Composition Analysis
    runs-on: ubuntu-latest
    needs: [build-backend, build-frontend]
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      # Go dependency audit
      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}

      - name: Run govulncheck
        working-directory: services/auth
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...

      # npm dependency audit
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}

      - name: Run npm audit
        working-directory: frontend
        run: npm audit --audit-level=high

      # Snyk dependency scan
      - name: Run Snyk Dependency Scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          command: test
          args: --all-projects --severity-threshold=high

      # License compliance check
      - name: Check license compliance
        working-directory: frontend
        run: |
          npx license-checker --onlyAllow "MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC"

  # ============================================
  # Stage 5: Build Docker Images
  # ============================================
  build-docker:
    name: Build & Push Docker Images
    runs-on: ubuntu-latest
    needs: [security-sast, security-dependencies]
    timeout-minutes: 15
    outputs:
      image-tag: ${{ steps.meta.outputs.tags }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsECRPush
          role-session-name: GitHubActions-ECR-Push
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=sha,prefix={{branch}}-
            type=raw,value=latest,enable={{is_default_branch}}

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: services/auth
          file: services/auth/Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          build-args: |
            GO_VERSION=${{ env.GO_VERSION }}
            BUILD_DATE=${{ github.event.head_commit.timestamp }}
            VCS_REF=${{ github.sha }}

      - name: Output image digest
        run: echo "Image digest ${{ steps.docker_build.outputs.digest }}"

  # ============================================
  # Stage 6: Container Security Scanning
  # ============================================
  security-container:
    name: Container Security Scan
    runs-on: ubuntu-latest
    needs: build-docker
    timeout-minutes: 10

    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsECRRead
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      # Trivy vulnerability scan
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: 'trivy-results.sarif'

      # Grype additional scan
      - name: Run Grype vulnerability scanner
        uses: anchore/scan-action@v3
        with:
          image: ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}
          fail-build: true
          severity-cutoff: high

  # ============================================
  # Stage 7: Integration Tests
  # ============================================
  integration-tests:
    name: Run Integration Tests
    runs-on: ubuntu-latest
    needs: build-docker
    timeout-minutes: 15

    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_DB: suma_finance_test
          POSTGRES_USER: testuser
          POSTGRES_PASSWORD: testpass
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}

      - name: Run database migrations
        working-directory: services/auth
        run: |
          go run ./cmd/migrate up
        env:
          DATABASE_URL: postgres://testuser:testpass@localhost:5432/suma_finance_test?sslmode=disable

      - name: Run integration tests
        working-directory: services/auth
        run: |
          go test -v -tags=integration ./tests/integration/...
        env:
          DATABASE_URL: postgres://testuser:testpass@localhost:5432/suma_finance_test?sslmode=disable
          REDIS_URL: redis://localhost:6379
          JWT_SECRET: test-secret-key-for-integration-tests
          ENV: test

  # ============================================
  # Stage 8: Deploy to Staging
  # ============================================
  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: [build-docker, security-container, integration-tests]
    if: github.ref == 'refs/heads/develop'
    environment:
      name: staging
      url: https://staging-auth.sumafinance.com
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsECSDeploy
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Download task definition
        run: |
          aws ecs describe-task-definition \
            --task-definition ${{ env.ECS_SERVICE }}-staging \
            --query taskDefinition > task-definition.json

      - name: Update task definition with new image
        id: task-def
        uses: aws-actions/amazon-ecs-render-task-definition@v1
        with:
          task-definition: task-definition.json
          container-name: auth-service
          image: ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}

      - name: Deploy to ECS
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: ${{ steps.task-def.outputs.task-definition }}
          service: ${{ env.ECS_SERVICE }}-staging
          cluster: ${{ env.ECS_CLUSTER }}-staging
          wait-for-service-stability: true

      - name: Create Datadog deployment marker
        run: |
          curl -X POST "https://api.datadoghq.com/api/v1/events" \
            -H "Content-Type: application/json" \
            -H "DD-API-KEY: ${{ secrets.DATADOG_API_KEY }}" \
            -d @- <<EOF
          {
            "title": "Deployed auth-service to staging",
            "text": "Deployed version ${{ github.sha }} to staging",
            "tags": ["environment:staging", "service:auth-service"],
            "alert_type": "info"
          }
          EOF

  # ============================================
  # Stage 9: Smoke Tests (Staging)
  # ============================================
  smoke-tests-staging:
    name: Run Smoke Tests (Staging)
    runs-on: ubuntu-latest
    needs: deploy-staging
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}

      - name: Install dependencies
        working-directory: tests/e2e
        run: npm ci

      - name: Run smoke tests
        working-directory: tests/e2e
        run: npm run test:smoke
        env:
          BASE_URL: https://staging-auth.sumafinance.com
          TEST_EMAIL: smoke-test@sumafinance.com
          TEST_PASSWORD: ${{ secrets.STAGING_TEST_PASSWORD }}

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: smoke-test-results
          path: tests/e2e/reports/

  # ============================================
  # Stage 10: Compliance Validation
  # ============================================
  compliance-validation:
    name: GDPR & PCI-DSS Compliance Checks
    runs-on: ubuntu-latest
    needs: smoke-tests-staging
    timeout-minutes: 10

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run GDPR compliance checks
        run: |
          # Check for GDPR-required endpoints
          ./scripts/check_gdpr_endpoints.sh https://staging-auth.sumafinance.com

      - name: Validate data retention policies
        run: |
          ./scripts/validate_data_retention.sh

      - name: Check encryption at rest
        run: |
          # Verify RDS encryption enabled
          aws rds describe-db-instances \
            --db-instance-identifier suma-finance-staging \
            --query 'DBInstances[0].StorageEncrypted' \
            --output text | grep -q true || exit 1

      - name: Validate TLS configuration
        run: |
          # Check TLS 1.3 support
          curl -sS --tlsv1.3 https://staging-auth.sumafinance.com/health || exit 1
          
          # Test SSL Labs rating (must be A or better)
          ./scripts/check_ssl_rating.sh staging-auth.sumafinance.com

      - name: Audit logging validation
        run: |
          # Verify audit logs contain required fields
          ./scripts/validate_audit_logs.sh

  # ============================================
  # Stage 11: Deploy to Production (Canary)
  # ============================================
  deploy-production-canary:
    name: Deploy to Production (Canary 10%)
    runs-on: ubuntu-latest
    needs: [smoke-tests-staging, compliance-validation]
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://auth.sumafinance.com
    timeout-minutes: 15

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsECSDeploy
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      # Deploy canary task definition (10% traffic)
      - name: Download canary task definition
        run: |
          aws ecs describe-task-definition \
            --task-definition ${{ env.ECS_SERVICE }}-production-canary \
            --query taskDefinition > task-definition-canary.json

      - name: Update canary task definition
        id: task-def-canary
        uses: aws-actions/amazon-ecs-render-task-definition@v1
        with:
          task-definition: task-definition-canary.json
          container-name: auth-service
          image: ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}

      - name: Deploy canary to ECS
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: ${{ steps.task-def-canary.outputs.task-definition }}
          service: ${{ env.ECS_SERVICE }}-production-canary
          cluster: ${{ env.ECS_CLUSTER }}-production
          wait-for-service-stability: true

      - name: Create Sentry release
        run: |
          curl -sL https://sentry.io/get-cli/ | bash
          sentry-cli releases new ${{ github.sha }}
          sentry-cli releases set-commits ${{ github.sha }} --auto
          sentry-cli releases finalize ${{ github.sha }}
          sentry-cli releases deploys ${{ github.sha }} new -e production
        env:
          SENTRY_AUTH_TOKEN: ${{ secrets.SENTRY_AUTH_TOKEN }}
          SENTRY_ORG: suma-finance
          SENTRY_PROJECT: auth-service

      - name: Monitor canary metrics (5 minutes)
        run: |
          ./scripts/monitor_canary.sh \
            --duration 300 \
            --error-threshold 0.5 \
            --latency-p95 200 \
            --service auth-service \
            --environment production
        env:
          DATADOG_API_KEY: ${{ secrets.DATADOG_API_KEY }}
          DATADOG_APP_KEY: ${{ secrets.DATADOG_APP_KEY }}

  # ============================================
  # Stage 12: Production Rollout
  # ============================================
  deploy-production-full:
    name: Deploy to Production (Full Rollout)
    runs-on: ubuntu-latest
    needs: deploy-production-canary
    environment:
      name: production-full
      url: https://auth.sumafinance.com
    timeout-minutes: 20

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsECSDeploy
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      # Scale canary to 50%
      - name: Scale canary to 50%
        run: |
          aws ecs update-service \
            --cluster ${{ env.ECS_CLUSTER }}-production \
            --service ${{ env.ECS_SERVICE }}-production-canary \
            --desired-count 5

      - name: Monitor 50% canary (10 minutes)
        run: |
          ./scripts/monitor_canary.sh \
            --duration 600 \
            --error-threshold 0.5 \
            --latency-p95 200 \
            --service auth-service \
            --environment production
        env:
          DATADOG_API_KEY: ${{ secrets.DATADOG_API_KEY }}
          DATADOG_APP_KEY: ${{ secrets.DATADOG_APP_KEY }}

      # Deploy to stable (100%)
      - name: Download stable task definition
        run: |
          aws ecs describe-task-definition \
            --task-definition ${{ env.ECS_SERVICE }}-production \
            --query taskDefinition > task-definition-stable.json

      - name: Update stable task definition
        id: task-def-stable
        uses: aws-actions/amazon-ecs-render-task-definition@v1
        with:
          task-definition: task-definition-stable.json
          container-name: auth-service
          image: ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}

      - name: Deploy stable to ECS
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: ${{ steps.task-def-stable.outputs.task-definition }}
          service: ${{ env.ECS_SERVICE }}-production
          cluster: ${{ env.ECS_CLUSTER }}-production
          wait-for-service-stability: true

      - name: Scale down canary
        run: |
          aws ecs update-service \
            --cluster ${{ env.ECS_CLUSTER }}-production \
            --service ${{ env.ECS_SERVICE }}-production-canary \
            --desired-count 0

      - name: Create Datadog deployment marker
        run: |
          curl -X POST "https://api.datadoghq.com/api/v1/events" \
            -H "Content-Type: application/json" \
            -H "DD-API-KEY: ${{ secrets.DATADOG_API_KEY }}" \
            -d @- <<EOF
          {
            "title": "✅ Deployed auth-service to production (100%)",
            "text": "Successfully deployed version ${{ github.sha }} to production",
            "tags": ["environment:production", "service:auth-service", "deployment:success"],
            "alert_type": "success"
          }
          EOF

      - name: Notify Slack
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "✅ Production deployment successful",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Production Deployment Complete*\n\n*Service*: auth-service\n*Version*: `${{ github.sha }}`\n*Deployed by*: ${{ github.actor }}\n*Status*: Success ✅"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_DEPLOYMENTS }}

  # ============================================
  # Rollback Job (Manual Trigger)
  # ============================================
  rollback-production:
    name: Rollback Production Deployment
    runs-on: ubuntu-latest
    if: github.event_name == 'workflow_dispatch'
    environment:
      name: production-rollback
    timeout-minutes: 10

    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsECSDeploy
          aws-region: ${{ env.AWS_REGION }}

      - name: Get previous stable task definition
        run: |
          PREVIOUS_TASK_DEF=$(aws ecs describe-services \
            --cluster ${{ env.ECS_CLUSTER }}-production \
            --services ${{ env.ECS_SERVICE }}-production \
            --query 'services[0].taskDefinition' \
            --output text | sed 's/:.*/:1/g')
          
          echo "Rolling back to: $PREVIOUS_TASK_DEF"
          
          aws ecs update-service \
            --cluster ${{ env.ECS_CLUSTER }}-production \
            --service ${{ env.ECS_SERVICE }}-production \
            --task-definition $PREVIOUS_TASK_DEF \
            --force-new-deployment

      - name: Notify Slack
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "⚠️ Production rollback triggered",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Production Rollback*\n\n*Service*: auth-service\n*Triggered by*: ${{ github.actor }}\n*Reason*: Manual rollback\n*Status*: In Progress ⚠️"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_ALERTS }}
```

---

## 4. Build Stage Architecture

### Source Code Checkout

```yaml
# Optimized checkout configuration
- name: Checkout code
  uses: actions/checkout@v4
  with:
    fetch-depth: 0          # Full history for SonarQube/versioning
    submodules: recursive   # Include submodules (shared libraries)
    lfs: true              # Download Git LFS files (design assets)
    persist-credentials: false  # Security: Don't persist credentials
```

**Monorepo Support** (SUMA Finance uses monorepo structure):
```yaml
# Detect changed services
- name: Detect changed services
  id: changes
  uses: dorny/paths-filter@v2
  with:
    filters: |
      auth:
        - 'services/auth/**'
      payment:
        - 'services/payment/**'
      frontend:
        - 'frontend/**'

# Conditional job execution
build-auth:
  if: steps.changes.outputs.auth == 'true'
  # ... auth build steps
```

### Dependency Management

#### Go Dependency Caching
```yaml
- name: Setup Go with caching
  uses: actions/setup-go@v5
  with:
    go-version: '1.21'
    cache: true
    cache-dependency-path: services/auth/go.sum

# Cache hit ratio: ~95% (saves 30-45 seconds per build)
```

#### npm Dependency Caching
```yaml
- name: Setup Node.js with caching
  uses: actions/setup-node@v4
  with:
    node-version: '18.x'
    cache: 'npm'
    cache-dependency-path: frontend/package-lock.json

# Cache restoration time: <10 seconds
# Fresh install time: ~90 seconds
```

#### Private Package Registry Authentication
```yaml
# Go private modules
- name: Configure Go private modules
  run: |
    git config --global url."https://${{ secrets.GITHUB_TOKEN }}@github.com/".insteadOf "https://github.com/"
  env:
    GOPRIVATE: github.com/suma-finance/*

# npm private packages
- name: Configure npm registry
  run: |
    echo "//npm.pkg.github.com/:_authToken=${{ secrets.GITHUB_TOKEN }}" > ~/.npmrc
    echo "@suma-finance:registry=https://npm.pkg.github.com" >> ~/.npmrc
```

### Build Process

#### Go Backend Build
```yaml
- name: Build Go binaries
  working-directory: services/auth
  run: |
    # Static binary with optimizations
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build \
      -ldflags="-w -s -X main.Version=${{ github.sha }} -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      -trimpath \
      -o bin/auth-service \
      ./cmd/server

    # Verify binary
    file bin/auth-service
    ls -lh bin/auth-service  # Should be ~10-15MB

# Build time: ~60 seconds (with cache)
# Binary size: ~12MB (stripped)
```

#### React Frontend Build
```yaml
- name: Build React production bundle
  working-directory: frontend
  run: npm run build
  env:
    NODE_ENV: production
    REACT_APP_API_URL: https://api.sumafinance.com
    REACT_APP_VERSION: ${{ github.sha }}
    GENERATE_SOURCEMAP: true  # For Sentry error tracking

# Upload source maps to Sentry (don't serve to users)
- name: Upload source maps to Sentry
  run: |
    sentry-cli releases files ${{ github.sha }} upload-sourcemaps ./build/static/js
    rm ./build/static/js/*.map  # Remove from deployment bundle
  env:
    SENTRY_AUTH_TOKEN: ${{ secrets.SENTRY_AUTH_TOKEN }}
```

#### Multi-Platform Builds (Future: Desktop App)
```yaml
build-desktop:
  strategy:
    matrix:
      os: [ubuntu-latest, macos-latest, windows-latest]
      include:
        - os: ubuntu-latest
          goos: linux
          goarch: amd64
        - os: macos-latest
          goos: darwin
          goarch: arm64
        - os: windows-latest
          goos: windows
          goarch: amd64

  steps:
    - name: Build platform binary
      run: |
        GOOS=${{ matrix.goos }} GOARCH=${{ matrix.goarch }} \
        go build -o bin/suma-finance-${{ matrix.goos }}-${{ matrix.goarch }}
```

### Build Artifacts

```yaml
- name: Upload build artifacts
  uses: actions/upload-artifact@v4
  with:
    name: auth-service-${{ github.sha }}
    path: |
      services/auth/bin/auth-service
      services/auth/migrations/
      services/auth/config/
    retention-days: 30  # Production artifacts kept longer
    compression-level: 9

- name: Upload test reports
  if: always()  # Upload even if tests fail
  uses: actions/upload-artifact@v4
  with:
    name: test-reports-${{ github.sha }}
    path: |
      services/auth/coverage.out
      services/auth/test-results.xml
      frontend/coverage/
    retention-days: 7
```

---

## 5. Test Stage Architecture

### Test Pyramid Implementation

```
         /\
        /  \  E2E (10%)
       /____\    ~20 tests, 8 min
      /      \
     / Integ. \ (20%)
    /__________\  ~50 tests, 5 min
   /            \
  /   Unit Tests \ (70%)
 /________________\  ~200 tests, 2 min
```

### Unit Tests (70%)

#### Go Unit Tests
```yaml
- name: Run Go unit tests
  working-directory: services/auth
  run: |
    go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
  env:
    CGO_ENABLED: 1  # Required for race detector

# Coverage by package
- name: Display coverage by package
  run: |
    go tool cover -func=coverage.out | grep -E '^total:|^github.com/suma-finance/auth'
```

**Key Unit Test Patterns**:
- **Repository Layer**: Mocked database using `sqlmock`
- **Service Layer**: Mocked repositories, real business logic
- **Controller Layer**: Mocked services, test HTTP handlers
- **Utilities**: Pure functions, no mocks needed

#### React Unit Tests
```yaml
- name: Run React unit tests
  working-directory: frontend
  run: npm run test:unit -- --coverage --watchAll=false --maxWorkers=4
  env:
    CI: true

# Coverage report
- name: Check coverage thresholds
  working-directory: frontend
  run: |
    npx jest --coverage --coverageThreshold='{"global":{"lines":80,"functions":80,"branches":75}}'
```

### Integration Tests (20%)

```yaml
integration-tests:
  services:
    postgres:
      image: postgres:15-alpine
      env:
        POSTGRES_DB: suma_finance_test
        POSTGRES_USER: testuser
        POSTGRES_PASSWORD: testpass
      ports:
        - 5432:5432
      options: >-
        --health-cmd pg_isready
        --health-interval 10s
        --health-timeout 5s
        --health-retries 5

    redis:
      image: redis:7-alpine
      ports:
        - 6379:6379
      options: >-
        --health-cmd "redis-cli ping"

  steps:
    - name: Run integration tests
      run: go test -v -tags=integration ./tests/integration/...
      env:
        DATABASE_URL: postgres://testuser:testpass@localhost:5432/suma_finance_test
        REDIS_URL: redis://localhost:6379
```

**Integration Test Scenarios**:
- User registration flow with email verification
- Login with JWT token generation
- Password reset with email delivery (mocked SendGrid)
- 2FA enrollment and verification
- Session management (Redis)
- GDPR consent workflows

### End-to-End Tests (10%)

```yaml
e2e-tests:
  steps:
    - name: Start auth service
      run: |
        docker-compose -f docker-compose.test.yml up -d
        ./scripts/wait-for-services.sh

    - name: Run Playwright E2E tests
      working-directory: tests/e2e
      run: npm run test:e2e
      env:
        BASE_URL: http://localhost:8080
        HEADLESS: true

    - name: Upload Playwright report
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: playwright-report
        path: tests/e2e/playwright-report/
```

**E2E Test Coverage**:
- Critical path: Registration → Email verification → Login → 2FA setup → Dashboard
- Password reset flow
- Account lockout after failed attempts
- Mobile responsive design validation
- Cross-browser testing (Chrome, Firefox, Safari)

### Code Coverage Enforcement

```yaml
- name: Enforce coverage thresholds
  run: |
    # Backend coverage
    BACKEND_COVERAGE=$(go tool cover -func=services/auth/coverage.out | grep total | awk '{print $3}' | sed 's/%//')
    
    # Frontend coverage
    FRONTEND_COVERAGE=$(jq -r '.total.lines.pct' frontend/coverage/coverage-summary.json)
    
    echo "Backend coverage: $BACKEND_COVERAGE%"
    echo "Frontend coverage: $FRONTEND_COVERAGE%"
    
    if (( $(echo "$BACKEND_COVERAGE < 80" | bc -l) )); then
      echo "❌ Backend coverage below 80%"
      exit 1
    fi
    
    if (( $(echo "$FRONTEND_COVERAGE < 80" | bc -l) )); then
      echo "❌ Frontend coverage below 80%"
      exit 1
    fi
    
    echo "✅ All coverage thresholds met"
```

### Coverage Trending

```yaml
- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v3
  with:
    files: ./services/auth/coverage.out,./frontend/coverage/coverage-final.json
    flags: backend,frontend
    fail_ci_if_error: true

- name: Comment coverage on PR
  uses: codecov/codecov-action@v3
  with:
    comment: true
    require_ci_to_pass: true
```

---

## 6. Security Scanning Stage

### Static Application Security Testing (SAST)

#### CodeQL Analysis
```yaml
security-codeql:
  steps:
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: go, javascript
        queries: security-and-quality, security-extended

    - name: Autobuild
      uses: github/codeql-action/autobuild@v3

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v3
      with:
        category: "/language:${{ matrix.language }}"
        upload: true  # Upload to GitHub Security tab

# Detected vulnerabilities block merge
```

#### Semgrep Security Patterns
```yaml
- name: Run Semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: >-
      p/owasp-top-ten
      p/jwt
      p/sql-injection
      p/xss
      p/security-audit
      p/secrets
      p/golang
      p/react

# Custom rules for SUMA Finance
- name: Run custom Semgrep rules
  run: |
    semgrep --config=.semgrep/suma-finance-rules.yml \
      --error --strict \
      services/auth/
```

**Custom Semgrep Rules** (`.semgrep/suma-finance-rules.yml`):
```yaml
rules:
  - id: argon2-password-hashing
    message: Passwords must be hashed with Argon2id
    languages: [go]
    severity: ERROR
    patterns:
      - pattern: bcrypt.GenerateFromPassword(...)
      - pattern: sha256.Sum256(...)
    fix: Use argon2.IDKey() for password hashing

  - id: jwt-expiration-check
    message: JWT tokens must have expiration time ≤ 15 minutes
    languages: [go]
    severity: ERROR
    pattern: |
      jwt.NewWithClaims(..., jwt.MapClaims{
        ...
        "exp": ...,
        ...
      })
```

#### Snyk Code
```yaml
- name: Run Snyk Code SAST
  uses: snyk/actions/node@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    command: code test
    args: --severity-threshold=medium --policy-path=.snyk
```

### Dependency Scanning (SCA)

#### Go Vulnerability Check
```yaml
- name: Run govulncheck
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck -json ./... > govulncheck-report.json

- name: Parse vulnerabilities
  run: |
    if grep -q '"Vulnerability"' govulncheck-report.json; then
      echo "❌ Vulnerabilities detected"
      cat govulncheck-report.json | jq '.Vulnerability'
      exit 1
    fi
```

#### npm Audit
```yaml
- name: Run npm audit
  working-directory: frontend
  run: |
    npm audit --audit-level=high --json > npm-audit.json || true

- name: Check for high/critical vulnerabilities
  run: |
    HIGH=$(jq '.metadata.vulnerabilities.high' frontend/npm-audit.json)
    CRITICAL=$(jq '.metadata.vulnerabilities.critical' frontend/npm-audit.json)
    
    if [ "$HIGH" -gt 0 ] || [ "$CRITICAL" -gt 0 ]; then
      echo "❌ Found $CRITICAL critical and $HIGH high vulnerabilities"
      npm audit --audit-level=high
      exit 1
    fi
```

#### Snyk Dependency Scan
```yaml
- name: Run Snyk dependency scan
  uses: snyk/actions/golang@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    command: test
    args: --severity-threshold=high --all-projects --json > snyk-report.json

- name: Upload Snyk report
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: snyk-report.json
```

### License Compliance

```yaml
- name: Check license compliance
  run: |
    npx license-checker --onlyAllow "MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC" \
      --excludePackages "some-gpl-package" \
      --summary
```

**Allowed Licenses** (per legal review):
- MIT
- Apache-2.0
- BSD-2-Clause, BSD-3-Clause
- ISC

**Prohibited Licenses**:
- GPL (any version) - copyleft concerns
- AGPL - network copyleft
- Unknown/Unlicensed

---

## 7. Artifact Management

### Container Image Storage

#### AWS ECR Configuration
```yaml
# Terraform ECR setup
resource "aws_ecr_repository" "auth_service" {
  name                 = "suma-finance/auth-service"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key        = aws_kms_key.ecr.arn
  }

  lifecycle_policy {
    policy = jsonencode({
      rules = [
        {
          rulePriority = 1
          description  = "Keep last 30 production images"
          selection = {
            tagStatus     = "tagged"
            tagPrefixList = ["v", "main-"]
            countType     = "imageCountMoreThan"
            countNumber   = 30
          }
          action = {
            type = "expire"
          }
        },
        {
          rulePriority = 2
          description  = "Expire untagged images after 7 days"
          selection = {
            tagStatus   = "untagged"
            countType   = "sinceImagePushed"
            countUnit   = "days"
            countNumber = 7
          }
          action = {
            type = "expire"
          }
        }
      ]
    })
  }
}
```

### Artifact Versioning Strategy

```yaml
# Semantic versioning with metadata
- name: Generate version tags
  id: version
  run: |
    # Extract version from package.json or git tags
    VERSION=$(jq -r .version package.json)  # e.g., 1.2.3
    
    # Build metadata
    BUILD_NUMBER=${{ github.run_number }}
    GIT_SHA=$(git rev-parse --short HEAD)
    BRANCH=$(echo ${{ github.ref }} | sed 's/refs\/heads\///')
    
    # Tag formats
    echo "semantic_version=v${VERSION}" >> $GITHUB_OUTPUT
    echo "build_version=v${VERSION}-build.${BUILD_NUMBER}" >> $GITHUB_OUTPUT
    echo "commit_version=v${VERSION}+sha.${GIT_SHA}" >> $GITHUB_OUTPUT
    echo "branch_version=${BRANCH}-${GIT_SHA}" >> $GITHUB_OUTPUT
    
    # Docker tags
    if [ "$BRANCH" = "main" ]; then
      echo "docker_tags=latest,v${VERSION},v${VERSION}-build.${BUILD_NUMBER}" >> $GITHUB_OUTPUT
    else
      echo "docker_tags=${BRANCH}-${GIT_SHA}" >> $GITHUB_OUTPUT
    fi
```

**Tag Examples**:
- `v1.2.3` - Semantic release version
- `v1.2.3-build.456` - Build number metadata
- `v1.2.3+sha.abc123f` - Git commit SHA
- `develop-abc123f` - Branch + short SHA
- `latest` - Latest production release

### Artifact Retention Policy

```yaml
# Retention configuration
artifact_retention:
  production:
    docker_images: 90 days  # Regulatory compliance
    build_artifacts: 90 days
    test_reports: 90 days
    audit_logs: 7 years  # SOC2/GDPR requirement

  staging:
    docker_images: 30 days
    build_artifacts: 30 days
    test_reports: 14 days

  development:
    docker_images: 7 days
    build_artifacts: 7 days
    test_reports: 7 days

  pull_requests:
    docker_images: 7 days
    build_artifacts: 3 days
    test_reports: 3 days
```

### Build Artifact Storage

```yaml
# Upload artifacts to S3 with lifecycle policies
- name: Upload build artifacts to S3
  run: |
    aws s3 cp services/auth/bin/auth-service \
      s3://suma-finance-artifacts/auth-service/${{ github.sha }}/auth-service \
      --metadata "version=${{ steps.version.outputs.semantic_version }},build=${{ github.run_number }},commit=${{ github.sha }}"

    aws s3 cp services/auth/coverage.out \
      s3://suma-finance-artifacts/auth-service/${{ github.sha }}/coverage.out

# S3 lifecycle policy (Terraform)
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-builds"
    status = "Enabled"

    filter {
      prefix = "auth-service/"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 90
    }
  }
}
```

---

## 8. Deployment Strategies

### Canary Deployment (Primary Strategy)

#### Canary Architecture
```yaml
# ECS Service Configuration
resource "aws_ecs_service" "auth_stable" {
  name            = "auth-service-stable"
  cluster         = aws_ecs_cluster.suma_finance.id
  task_definition = aws_ecs_task_definition.auth_stable.arn
  desired_count   = 9  # 90% traffic

  load_balancer {
    target_group_arn = aws_lb_target_group.auth_stable.arn
    container_name   = "auth-service"
    container_port   = 8080
  }

  deployment_configuration {
    minimum_healthy_percent = 100
    maximum_percent         = 200
  }
}

resource "aws_ecs_service" "auth_canary" {
  name            = "auth-service-canary"
  cluster         = aws_ecs_cluster.suma_finance.id
  task_definition = aws_ecs_task_definition.auth_canary.arn
  desired_count   = 1  # 10% traffic

  load_balancer {
    target_group_arn = aws_lb_target_group.auth_canary.arn
    container_name   = "auth-service"
    container_port   = 8080
  }
}

# ALB Listener Rule (weighted routing)
resource "aws_lb_listener_rule" "auth_weighted" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 100

  action {
    type = "forward"

    forward {
      target_group {
        arn    = aws_lb_target_group.auth_stable.arn
        weight = 90
      }

      target_group {
        arn    = aws_lb_target_group.auth_canary.arn
        weight = 10
      }

      stickiness {
        enabled  = true
        duration = 3600  # 1 hour session stickiness
      }
    }
  }

  condition {
    path_pattern {
      values = ["/api/auth/*"]
    }
  }
}
```

#### Canary Monitoring Script
```bash
#!/bin/bash
# scripts/monitor_canary.sh

DURATION=300  # 5 minutes
ERROR_THRESHOLD=0.5  # 0.5% error rate
LATENCY_P95=200  # 200ms

echo "Monitoring canary deployment for ${DURATION} seconds..."

START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))

while [ $(date +%s) -lt $END_TIME ]; do
  # Query Datadog for canary metrics
  ERROR_RATE=$(curl -s -X GET "https://api.datadoghq.com/api/v1/query" \
    -H "DD-API-KEY: ${DATADOG_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DATADOG_APP_KEY}" \
    -d "query=sum:auth.service.error_rate{version:canary}" | jq -r '.series[0].pointlist[-1][1]')

  LATENCY=$(curl -s -X GET "https://api.datadoghq.com/api/v1/query" \
    -H "DD-API-KEY: ${DATADOG_API_KEY}" \
    -H "DD-APPLICATION-KEY: ${DATADOG_APP_KEY}" \
    -d "query=p95:auth.service.latency{version:canary}" | jq -r '.series[0].pointlist[-1][1]')

  echo "Error rate: ${ERROR_RATE}% | Latency P95: ${LATENCY}ms"

  # Check thresholds
  if (( $(echo "$ERROR_RATE > $ERROR_THRESHOLD" | bc -l) )); then
    echo "❌ Error rate ${ERROR_RATE}% exceeds threshold ${ERROR_THRESHOLD}%"
    exit 1
  fi

  if (( $(echo "$LATENCY > $LATENCY_P95" | bc -l) )); then
    echo "❌ Latency ${LATENCY}ms exceeds threshold ${LATENCY_P95}ms"
    exit 1
  fi

  sleep 30
done

echo "✅ Canary validation successful"
```

#### Progressive Traffic Shifting
```yaml
# Canary rollout stages
- name: Deploy canary (10% traffic)
  run: ./scripts/deploy_canary.sh --weight 10

- name: Monitor 10% canary (5 minutes)
  run: ./scripts/monitor_canary.sh --duration 300

- name: Increase to 50% traffic
  run: ./scripts/update_canary_weight.sh --weight 50

- name: Monitor 50% canary (10 minutes)
  run: ./scripts/monitor_canary.sh --duration 600

- name: Full rollout (100% traffic)
  run: ./scripts/promote_canary.sh
```

### Blue-Green Deployment (Fallback)

```yaml
# Blue-Green with instant cutover
resource "aws_lb_listener" "auth" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-3"
  certificate_arn   = aws_acm_certificate.suma_finance.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.auth_blue.arn  # Switch to auth_green for cutover
  }
}

# Deployment script
#!/bin/bash
# Deploy to green environment
aws ecs update-service \
  --cluster suma-finance-production \
  --service auth-service-green \
  --task-definition auth-service:$NEW_VERSION \
  --desired-count 10

# Wait for green to be healthy
aws ecs wait services-stable \
  --cluster suma-finance-production \
  --services auth-service-green

# Run smoke tests on green
./scripts/smoke_tests.sh https://green.auth.sumafinance.com

# Cutover: Update ALB to point to green
aws elbv2 modify-listener \
  --listener-arn $LISTENER_ARN \
  --default-actions Type=forward,TargetGroupArn=$GREEN_TARGET_GROUP_ARN

# Keep blue running for 15 minutes (fast rollback window)
sleep 900

# Scale down blue
aws ecs update-service \
  --cluster suma-finance-production \
  --service auth-service-blue \
  --desired-count 0
```

### Rolling Deployment

```yaml
# Kubernetes-style rolling update (if using EKS)
deployment:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1        # One extra pod during update
      maxUnavailable: 0  # No downtime

  # Update pods one at a time
  # Health check: readinessProbe must pass before next pod updates
```

### Feature Flags (Gradual Rollout)

```yaml
# LaunchDarkly feature flag configuration
feature_flags:
  new-password-policy:
    enabled: true
    rollout:
      - percentage: 10
        user_segment: internal_users
      - percentage: 50
        user_segment: beta_testers
      - percentage: 100
        user_segment: all_users
    
  biometric-auth:
    enabled: true
    rollout:
      - percentage: 5
        countries: [PT, ES]
      - percentage: 100
        countries: [ALL]
```

**Feature Flag Integration**:
```go
// Go backend
import "github.com/launchdarkly/go-server-sdk/v6"

ldClient, _ := ld.MakeClient(os.Getenv("LAUNCHDARKLY_SDK_KEY"), 5*time.Second)

user := ldcontext.NewBuilder(userID).
    SetString("country", "PT").
    SetString("tier", "premium").
    Build()

showBiometric := ldClient.BoolVariation("biometric-auth", user, false)
```

---

## 9. Environment Management

### Environment Tiers

```yaml
environments:
  development:
    description: "Local development and PR previews"
    auto_deploy: true
    branch: develop
    url: https://dev-auth.sumafinance.com
    approvers: []
    aws_account: "111111111111"
    ecs_cluster: suma-finance-dev
    database: suma_finance_dev
    log_retention: 7 days
    monitoring: basic
    cost_limit: $200/month

  staging:
    description: "Pre-production testing"
    auto_deploy: true
    branch: develop
    url: https://staging-auth.sumafinance.com
    approvers: []
    aws_account: "222222222222"
    ecs_cluster: suma-finance-staging
    database: suma_finance_staging
    log_retention: 30 days
    monitoring: full
    smoke_tests: required
    load_tests: optional
    cost_limit: $500/month

  production:
    description: "Live customer-facing environment"
    auto_deploy: false
    branch: main
    url: https://auth.sumafinance.com
    approvers: [devops-team, tech-leads]
    aws_account: "333333333333"
    ecs_cluster: suma-finance-production
    database: suma_finance_production
    log_retention: 90 days
    monitoring: full
    alerting: pagerduty
    smoke_tests: required
    canary_deployment: required
    rollback_on_failure: true
    change_window: ["Tue-Thu 10:00-16:00 UTC"]
    cost_limit: $5000/month
```

### GitHub Environment Protection Rules

```yaml
# .github/environments/production.yml
environment:
  name: production
  protection_rules:
    required_reviewers:
      count: 2
      teams:
        - devops-team
        - backend-team
    wait_timer: 30  # 30-minute wait before deployment
    prevent_self_review: true
    required_status_checks:
      - security-sast
      - security-dependencies
      - integration-tests
      - compliance-validation
    deployment_branch_policy:
      protected_branches: true
      custom_branch_policies:
        branches:
          - main
```

### Environment-Specific Configuration

#### AWS Secrets Manager Integration
```yaml
- name: Load environment secrets
  run: |
    # Fetch secrets from AWS Secrets Manager
    aws secretsmanager get-secret-value \
      --secret-id suma-finance/${{ env.ENVIRONMENT }}/auth-service \
      --query SecretString \
      --output text > .env

    # Export to environment
    export $(cat .env | xargs)
```

#### Kubernetes ConfigMaps (if using EKS)
```yaml
# configmap-production.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
  namespace: production
data:
  APP_ENV: production
  LOG_LEVEL: info
  JWT_EXPIRATION: 900  # 15 minutes
  REFRESH_TOKEN_EXPIRATION: 604800  # 7 days
  RATE_LIMIT_LOGIN: "5"
  RATE_LIMIT_WINDOW: "60"
  GDPR_DATA_RETENTION_DAYS: "2555"  # 7 years

---
apiVersion: v1
kind: Secret
metadata:
  name: auth-service-secrets
  namespace: production
type: Opaque
data:
  DATABASE_URL: <base64-encoded>
  JWT_SECRET: <base64-encoded>
  SENDGRID_API_KEY: <base64-encoded>
  REDIS_URL: <base64-encoded>
```

---

## 10. Secrets Management

### AWS Secrets Manager Architecture

```yaml
# Terraform: Secrets Manager setup
resource "aws_secretsmanager_secret" "auth_service" {
  name                    = "suma-finance/${var.environment}/auth-service"
  description             = "Authentication service secrets for ${var.environment}"
  recovery_window_in_days = 30
  kms_key_id             = aws_kms_key.secrets.id

  rotation_rules {
    automatically_after_days = 90
  }
}

resource "aws_secretsmanager_secret_version" "auth_service" {
  secret_id = aws_secretsmanager_secret.auth_service.id
  secret_string = jsonencode({
    DATABASE_URL      = "postgres://..."
    JWT_SECRET        = random_password.jwt_secret.result
    SENDGRID_API_KEY  = var.sendgrid_api_key
    REDIS_URL         = "redis://..."
    DATADOG_API_KEY   = var.datadog_api_key
    SENTRY_DSN        = var.sentry_dsn
  })
}
```

### GitHub OIDC for AWS (No Long-Lived Credentials)

```yaml
# Terraform: OIDC provider
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  client_id_list = ["sts.amazonaws.com"]

  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1"
  ]
}

resource "aws_iam_role" "github_actions_ecr_push" {
  name = "GitHubActionsECRPush"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:suma-finance/auth-service:*"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecr_push" {
  name = "ECRPushPolicy"
  role = aws_iam_role.github_actions_ecr_push.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = "arn:aws:ecr:eu-west-1:123456789012:repository/suma-finance/auth-service"
      }
    ]
  })
}
```

**GitHub Actions Usage**:
```yaml
- name: Configure AWS credentials (OIDC)
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsECRPush
    role-session-name: GitHubActions-${{ github.run_id }}
    aws-region: eu-west-1

# No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY needed!
```

### Secret Rotation Strategy

```yaml
# Lambda function for automatic secret rotation
resource "aws_lambda_function" "rotate_jwt_secret" {
  filename      = "rotate_jwt_secret.zip"
  function_name = "rotate-jwt-secret"
  role          = aws_iam_role.lambda_rotation.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300

  environment {
    variables = {
      SECRET_ARN = aws_secretsmanager_secret.auth_service.arn
    }
  }
}

# Rotation configuration
resource "aws_secretsmanager_secret_rotation" "auth_service" {
  secret_id           = aws_secretsmanager_secret.auth_service.id
  rotation_lambda_arn = aws_lambda_function.rotate_jwt_secret.arn

  rotation_rules {
    automatically_after_days = 90
  }
}
```

**Zero-Downtime Secret Rotation** (JWT):
1. Generate new JWT secret (JWT_SECRET_NEW)
2. Application accepts tokens signed with OLD or NEW secret
3. After 15 minutes (max token lifetime), retire OLD secret
4. Rename NEW → CURRENT

### Secret Access Audit Logging

```yaml
# CloudTrail logging for Secrets Manager access
resource "aws_cloudtrail" "secrets_audit" {
  name                          = "suma-finance-secrets-audit"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::SecretsManager::Secret"
      values = ["arn:aws:secretsmanager:*:*:secret:suma-finance/*"]
    }
  }
}

# Alert on unauthorized secret access
resource "aws_cloudwatch_metric_alarm" "unauthorized_secret_access" {
  alarm_name          = "unauthorized-secret-access"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "UnauthorizedSecretAccess"
  namespace           = "AWS/SecretsManager"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alert on unauthorized secret access attempts"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

---

## 11. Monitoring & Observability

### Pipeline Metrics (Datadog)

```yaml
# Send pipeline metrics to Datadog
- name: Send build metrics to Datadog
  if: always()
  run: |
    BUILD_STATUS="${{ job.status }}"
    BUILD_DURATION=$(($(date +%s) - ${{ steps.start_time.outputs.timestamp }}))
    
    curl -X POST "https://api.datadoghq.com/api/v1/series" \
      -H "Content-Type: application/json" \
      -H "DD-API-KEY: ${{ secrets.DATADOG_API_KEY }}" \
      -d @- <<EOF
    {
      "series": [
        {
          "metric": "ci.build.duration",
          "points": [[$(date +%s), $BUILD_DURATION]],
          "type": "gauge",
          "tags": [
            "service:auth-service",
            "status:$BUILD_STATUS",
            "branch:${{ github.ref_name }}",
            "environment:${{ env.ENVIRONMENT }}"
          ]
        },
        {
          "metric": "ci.build.count",
          "points": [[$(date +%s), 1]],
          "type": "count",
          "tags": [
            "service:auth-service",
            "status:$BUILD_STATUS"
          ]
        }
      ]
    }
    EOF
```

**Key Pipeline Metrics**:
- `ci.build.duration` - Time from commit to deployment
- `ci.build.success_rate` - Percentage of successful builds
- `ci.test.duration` - Test execution time
- `ci.deploy.frequency` - Deploys per day/week
- `ci.deploy.lead_time` - Commit to production time
- `ci.rollback.count` - Number of rollbacks

### Datadog Dashboard Configuration

```json
{
  "title": "SUMA Finance - CI/CD Pipeline",
  "widgets": [
    {
      "definition": {
        "type": "timeseries",
        "title": "Build Duration (by stage)",
        "requests": [
          {
            "q": "avg:ci.build.duration{service:auth-service} by {stage}"
          }
        ]
      }
    },
    {
      "definition": {
        "type": "query_value",
        "title": "Build Success Rate (24h)",
        "requests": [
          {
            "q": "sum:ci.build.count{status:success}.rollup(sum, 86400) / sum:ci.build.count{*}.rollup(sum, 86400) * 100",
            "aggregator": "last"
          }
        ],
        "precision": 2,
        "unit": "%"
      }
    },
    {
      "definition": {
        "type": "timeseries",
        "title": "Deployment Frequency",
        "requests": [
          {
            "q": "sum:ci.deploy.count{environment:production}.rollup(sum, 86400)"
          }
        ]
      }
    },
    {
      "definition": {
        "type": "timeseries",
        "title": "Mean Time to Recovery (MTTR)",
        "requests": [
          {
            "q": "avg:ci.incident.recovery_time{service:auth-service}"
          }
        ]
      }
    }
  ]
}
```

### Pipeline Notifications

#### Slack Integration
```yaml
- name: Notify Slack on build failure
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "❌ Build Failed: auth-service",
        "blocks": [
          {
            "type": "header",
            "text": {
              "type": "plain_text",
              "text": "❌ Build Failed"
            }
          },
          {
            "type": "section",
            "fields": [
              {
                "type": "mrkdwn",
                "text": "*Service:*\nauth-service"
              },
              {
                "type": "mrkdwn",
                "text": "*Branch:*\n${{ github.ref_name }}"
              },
              {
                "type": "mrkdwn",
                "text": "*Commit:*\n${{ github.sha }}"
              },
              {
                "type": "mrkdwn",
                "text": "*Author:*\n${{ github.actor }}"
              }
            ]
          },
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Failed Stage:* ${{ env.FAILED_STAGE }}"
            }
          },
          {
            "type": "actions",
            "elements": [
              {
                "type": "button",
                "text": {
                  "type": "plain_text",
                  "text": "View Build Logs"
                },
                "url": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
              }
            ]
          }
        ]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_ALERTS }}

- name: Notify Slack on successful deployment
  if: success() && github.ref == 'refs/heads/main'
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "✅ Deployed to Production: auth-service",
        "blocks": [
          {
            "type": "header",
            "text": {
              "type": "plain_text",
              "text": "✅ Production Deployment Successful"
            }
          },
          {
            "type": "section",
            "fields": [
              {
                "type": "mrkdwn",
                "text": "*Service:*\nauth-service"
              },
              {
                "type": "mrkdwn",
                "text": "*Version:*\n${{ github.sha }}"
              },
              {
                "type": "mrkdwn",
                "text": "*Deployed by:*\n${{ github.actor }}"
              },
              {
                "type": "mrkdwn",
                "text": "*Duration:*\n${{ env.DEPLOY_DURATION }}"
              }
            ]
          },
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "View deployment: https://auth.sumafinance.com"
            }
          }
        ]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_DEPLOYMENTS }}
```

#### PagerDuty Integration (Production Incidents)
```yaml
- name: Trigger PagerDuty incident on rollback
  if: failure() && github.ref == 'refs/heads/main'
  run: |
    curl -X POST "https://api.pagerduty.com/incidents" \
      -H "Authorization: Token token=${{ secrets.PAGERDUTY_API_KEY }}" \
      -H "Content-Type: application/json" \
      -d @- <<EOF
    {
      "incident": {
        "type": "incident",
        "title": "Production deployment failed: auth-service",
        "service": {
          "id": "${{ secrets.PAGERDUTY_SERVICE_ID }}",
          "type": "service_reference"
        },
        "urgency": "high",
        "body": {
          "type": "incident_body",
          "details": "Deployment of auth-service version ${{ github.sha }} failed. Automatic rollback triggered."
        }
      }
    }
    EOF
```

### Deployment Tracking

#### Datadog Deployment Markers
```yaml
- name: Create Datadog deployment event
  run: |
    curl -X POST "https://api.datadoghq.com/api/v1/events" \
      -H "Content-Type: application/json" \
      -H "DD-API-KEY: ${{ secrets.DATADOG_API_KEY }}" \
      -d @- <<EOF
    {
      "title": "Deployed auth-service to ${{ env.ENVIRONMENT }}",
      "text": "Version ${{ github.sha }} deployed by ${{ github.actor }}",
      "tags": [
        "service:auth-service",
        "environment:${{ env.ENVIRONMENT }}",
        "version:${{ github.sha }}"
      ],
      "alert_type": "info",
      "source_type_name": "github"
    }
    EOF
```

#### Sentry Release Tracking
```yaml
- name: Create Sentry release
  run: |
    sentry-cli releases new ${{ github.sha }} --project auth-service
    sentry-cli releases set-commits ${{ github.sha }} --auto
    sentry-cli releases finalize ${{ github.sha }}
    sentry-cli releases deploys ${{ github.sha }} new -e ${{ env.ENVIRONMENT }}
  env:
    SENTRY_AUTH_TOKEN: ${{ secrets.SENTRY_AUTH_TOKEN }}
    SENTRY_ORG: suma-finance
```

---

## 12. Quality Gates

### Build Quality Gates

```yaml
quality-gates:
  # Gate 1: Code Style
  linting:
    enabled: true
    tools:
      - golangci-lint (Go)
      - ESLint (JavaScript/TypeScript)
      - Prettier (formatting)
    failure_action: block_merge

  # Gate 2: Test Coverage
  coverage:
    enabled: true
    thresholds:
      line_coverage: 80%
      branch_coverage: 75%
      function_coverage: 85%
    failure_action: block_merge

  # Gate 3: Security Vulnerabilities
  security:
    enabled: true
    severity_thresholds:
      critical: 0  # Zero tolerance
      high: 0      # Zero tolerance
      medium: 5    # Max 5 allowed (with justification)
    failure_action: block_merge

  # Gate 4: License Compliance
  licenses:
    enabled: true
    allowed:
      - MIT
      - Apache-2.0
      - BSD-2-Clause
      - BSD-3-Clause
      - ISC
    prohibited:
      - GPL
      - AGPL
      - Unknown
    failure_action: block_merge

  # Gate 5: Performance Regression
  performance:
    enabled: true
    thresholds:
      api_latency_p95: 200ms
      api_latency_p99: 500ms
      throughput: 1000 req/s
    failure_action: warn  # Don't block, but alert

  # Gate 6: GDPR Compliance
  gdpr:
    enabled: true
    checks:
      - data_retention_policy
      - consent_management
      - data_subject_rights
      - audit_logging
    failure_action: block_merge
```

### Implementation

```yaml
# Quality gate enforcement
- name: Run quality gates
  run: |
    # Gate 1: Linting
    echo "✓ Gate 1: Linting"
    golangci-lint run --config .golangci.yml
    npm run lint
    
    # Gate 2: Coverage
    echo "✓ Gate 2: Test Coverage"
    ./scripts/check_coverage_threshold.sh 80
    
    # Gate 3: Security
    echo "✓ Gate 3: Security Scan"
    ./scripts/check_vulnerabilities.sh --severity high,critical --max-count 0
    
    # Gate 4: Licenses
    echo "✓ Gate 4: License Compliance"
    ./scripts/check_licenses.sh
    
    # Gate 5: Performance (warning only)
    echo "✓ Gate 5: Performance Check"
    ./scripts/check_performance.sh || echo "⚠️ Performance degradation detected"
    
    # Gate 6: GDPR Compliance
    echo "✓ Gate 6: GDPR Compliance"
    ./scripts/check_gdpr_compliance.sh
    
    echo "✅ All quality gates passed"
```

### Branch Protection Rules

```yaml
# GitHub branch protection settings
branch_protection:
  main:
    required_status_checks:
      strict: true
      contexts:
        - build-backend
        - build-frontend
        - security-sast
        - security-dependencies
        - integration-tests
        - quality-gates
    required_pull_request_reviews:
      required_approving_review_count: 2
      dismiss_stale_reviews: true
      require_code_owner_reviews: true
    enforce_admins: true
    required_linear_history: true
    allow_force_pushes: false
    allow_deletions: false

  develop:
    required_status_checks:
      strict: true
      contexts:
        - build-backend
        - build-frontend
        - unit-tests
    required_pull_request_reviews:
      required_approving_review_count: 1
```

---

## 13. Rollback Procedures

### Automatic Rollback Triggers

```yaml
# Datadog monitor for automatic rollback
resource "datadog_monitor" "auth_service_error_rate" {
  name    = "Auth Service Error Rate (Automatic Rollback)"
  type    = "metric alert"
  message = <<-EOT
    ⚠️ Error rate exceeded threshold. Triggering automatic rollback.
    
    @webhook-rollback-trigger
    @slack-alerts
    @pagerduty-oncall
  EOT

  query = "avg(last_5m):sum:auth.service.errors{environment:production} / sum:auth.service.requests{environment:production} > 0.05"

  thresholds = {
    critical          = 0.05  # 5% error rate
    critical_recovery = 0.01
  }

  notify_no_data    = false
  notify_audit      = true
  require_full_window = false
  renotify_interval = 0

  tags = ["service:auth-service", "environment:production", "auto-rollback:true"]
}

# Webhook receiver for rollback trigger
resource "aws_lambda_function" "rollback_trigger" {
  filename      = "rollback_trigger.zip"
  function_name = "auth-service-rollback-trigger"
  role          = aws_iam_role.lambda_rollback.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 300

  environment {
    variables = {
      ECS_CLUSTER = "suma-finance-production"
      ECS_SERVICE = "auth-service-production"
      SNS_TOPIC   = aws_sns_topic.rollback_notifications.arn
    }
  }
}
```

### Manual Rollback Workflow

```yaml
# .github/workflows/rollback-production.yml
name: Rollback Production

on:
  workflow_dispatch:
    inputs:
      target_version:
        description: 'Version to rollback to (commit SHA or tag)'
        required: true
      reason:
        description: 'Reason for rollback'
        required: true
      notify_pagerduty:
        description: 'Create PagerDuty incident'
        type: boolean
        default: true

jobs:
  rollback:
    name: Rollback to ${{ github.event.inputs.target_version }}
    runs-on: ubuntu-latest
    environment:
      name: production-rollback

    steps:
      - name: Validate rollback target
        run: |
          # Verify target version exists in ECR
          aws ecr describe-images \
            --repository-name suma-finance/auth-service \
            --image-ids imageTag=${{ github.event.inputs.target_version }} \
            || (echo "❌ Target version not found in ECR" && exit 1)

      - name: Get current version
        id: current
        run: |
          CURRENT=$(aws ecs describe-services \
            --cluster suma-finance-production \
            --services auth-service-production \
            --query 'services[0].taskDefinition' \
            --output text)
          echo "task_definition=$CURRENT" >> $GITHUB_OUTPUT

      - name: Create rollback backup
        run: |
          # Save current task definition for potential rollback-of-rollback
          aws ecs describe-task-definition \
            --task-definition ${{ steps.current.outputs.task_definition }} \
            --query taskDefinition > /tmp/rollback-backup.json
          
          aws s3 cp /tmp/rollback-backup.json \
            s3://suma-finance-rollback-backups/$(date +%Y%m%d-%H%M%S)-${{ github.sha }}.json

      - name: Execute rollback
        run: |
          # Update ECS service to target version
          aws ecs update-service \
            --cluster suma-finance-production \
            --service auth-service-production \
            --task-definition auth-service-production:${{ github.event.inputs.target_version }} \
            --force-new-deployment

          # Wait for service to stabilize
          aws ecs wait services-stable \
            --cluster suma-finance-production \
            --services auth-service-production

      - name: Verify rollback
        run: |
          # Run smoke tests
          ./scripts/smoke_tests.sh https://auth.sumafinance.com
          
          # Check error rate
          sleep 60  # Wait for metrics
          ERROR_RATE=$(./scripts/get_error_rate.sh)
          if (( $(echo "$ERROR_RATE > 1.0" | bc -l) )); then
            echo "❌ Error rate still high after rollback: $ERROR_RATE%"
            exit 1
          fi

      - name: Create rollback event
        run: |
          # Datadog event
          curl -X POST "https://api.datadoghq.com/api/v1/events" \
            -H "DD-API-KEY: ${{ secrets.DATADOG_API_KEY }}" \
            -d @- <<EOF
          {
            "title": "🔄 Rolled back auth-service to ${{ github.event.inputs.target_version }}",
            "text": "Reason: ${{ github.event.inputs.reason }}\nTriggered by: ${{ github.actor }}",
            "tags": ["service:auth-service", "environment:production", "event:rollback"],
            "alert_type": "warning"
          }
          EOF

          # Sentry event
          sentry-cli releases deploys ${{ github.event.inputs.target_version }} rollback -e production

      - name: Notify team
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "🔄 Production Rollback Completed",
              "blocks": [
                {
                  "type": "header",
                  "text": {
                    "type": "plain_text",
                    "text": "🔄 Production Rollback Completed"
                  }
                },
                {
                  "type": "section",
                  "fields": [
                    {
                      "type": "mrkdwn",
                      "text": "*Service:*\nauth-service"
                    },
                    {
                      "type": "mrkdwn",
                      "text": "*Rolled back to:*\n${{ github.event.inputs.target_version }}"
                    },
                    {
                      "type": "mrkdwn",
                      "text": "*Reason:*\n${{ github.event.inputs.reason }}"
                    },
                    {
                      "type": "mrkdwn",
                      "text": "*Triggered by:*\n${{ github.actor }}"
                    }
                  ]
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_ALERTS }}

      - name: Create PagerDuty incident
        if: github.event.inputs.notify_pagerduty == 'true'
        run: |
          curl -X POST "https://api.pagerduty.com/incidents" \
            -H "Authorization: Token token=${{ secrets.PAGERDUTY_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d @- <<EOF
          {
            "incident": {
              "type": "incident",
              "title": "Production rollback: auth-service",
              "service": {
                "id": "${{ secrets.PAGERDUTY_SERVICE_ID }}",
                "type": "service_reference"
              },
              "urgency": "high",
              "body": {
                "type": "incident_body",
                "details": "Rolled back to ${{ github.event.inputs.target_version }}. Reason: ${{ github.event.inputs.reason }}"
              }
            }
          }
          EOF
```

### Database Rollback Strategy

```sql
-- Migration versioning with rollback support
-- migrations/000001_create_users_table.up.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- migrations/000001_create_users_table.down.sql
DROP TABLE users;

-- Safe rollback procedure
BEGIN;
  -- Check if any data will be lost
  SELECT COUNT(*) FROM users_new_column;
  
  -- If count = 0, safe to rollback
  -- Otherwise, manual intervention required
COMMIT;
```

**Database Rollback Policy**:
- **Backward-compatible migrations only** in production
- **Additive changes**: Add columns with defaults, don't drop
- **Multi-phase migrations**: Add → Backfill → Cleanup (separate deploys)
- **Zero-downtime**: Use techniques like dual writes during schema changes

---

## 14. Multi-Environment Pipeline

```yaml
# Complete pipeline flow
┌─────────────────────────────────────────────────────────────────┐
│ COMMIT STAGE (All branches)                                      │
├─────────────────────────────────────────────────────────────────┤
│ 1. Checkout code                                                 │
│ 2. Build backend (Go)                                            │
│ 3. Build frontend (React)                                        │
│ 4. Run unit tests (80% coverage required)                       │
│ 5. Static security scan (SAST)                                   │
│ 6. Dependency scan (SCA)                                         │
│ 7. License compliance check                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ ACCEPTANCE STAGE (develop branch only)                           │
├─────────────────────────────────────────────────────────────────┤
│ 1. Build Docker image                                            │
│ 2. Container security scan (Trivy, Grype)                        │
│ 3. Run integration tests (with Postgres, Redis)                 │
│ 4. Deploy to Development environment                             │
│    → Auto-deploy on push                                         │
│    → URL: https://dev-auth.sumafinance.com                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ STAGING STAGE (develop branch only)                              │
├─────────────────────────────────────────────────────────────────┤
│ 1. Deploy to Staging environment                                 │
│    → Auto-deploy on push                                         │
│    → URL: https://staging-auth.sumafinance.com                   │
│ 2. Run smoke tests                                               │
│ 3. Run E2E tests (Playwright)                                    │
│ 4. GDPR compliance validation                                    │
│ 5. Performance testing (optional)                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ PRODUCTION STAGE (main branch only)                              │
├─────────────────────────────────────────────────────────────────┤
│ 1. Manual approval required (2 reviewers)                        │
│ 2. Deploy canary (10% traffic)                                   │
│    → Monitor error rate, latency for 5 minutes                   │
│    → Auto-rollback if thresholds breached                        │
│ 3. Increase to 50% traffic                                       │
│    → Monitor for 10 minutes                                      │
│ 4. Full rollout (100% traffic)                                   │
│    → URL: https://auth.sumafinance.com                           │
│ 5. Post-deployment validation                                    │
│ 6. Notify stakeholders (Slack, Datadog)                          │
└─────────────────────────────────────────────────────────────────┘
```

### Environment Promotion Strategy

```yaml
# Promotion gates between environments
promotion_gates:
  dev_to_staging:
    automatic: true
    conditions:
      - unit_tests: passed
      - integration_tests: passed
      - security_scans: passed
    
  staging_to_production:
    automatic: false
    conditions:
      - smoke_tests: passed
      - e2e_tests: passed
      - compliance_checks: passed
      - manual_approval: required (2 reviewers)
      - change_window: Tue-Thu 10:00-16:00 UTC
```

---

## 15. Performance Optimization

### Build Caching Strategy

```yaml
# Layer caching for Docker builds
- name: Build Docker image with multi-stage caching
  uses: docker/build-push-action@v5
  with:
    context: services/auth
    file: services/auth/Dockerfile
    push: true
    tags: ${{ env.IMAGE_TAG }}
    cache-from: |
      type=registry,ref=${{ env.ECR_REGISTRY }}/auth-service:buildcache
      type=gha
    cache-to: |
      type=registry,ref=${{ env.ECR_REGISTRY }}/auth-service:buildcache,mode=max
      type=gha,mode=max
    build-args: |
      BUILDKIT_INLINE_CACHE=1

# Optimized Dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app

# Cache dependencies separately from source code
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 go build -o bin/auth-service ./cmd/server

# Minimal runtime image
FROM alpine:3.18
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/bin/auth-service /usr/local/bin/
CMD ["auth-service"]
```

**Cache Hit Ratios** (Target):
- Go dependencies: 95%
- npm dependencies: 90%
- Docker layers: 85%
- GitHub Actions cache: 80%

### Parallel Execution

```yaml
# Matrix strategy for parallel tests
test-backend:
  strategy:
    matrix:
      go-version: [1.20, 1.21]
      os: [ubuntu-latest]
      test-group: [unit, integration, e2e]
    fail-fast: false  # Run all combinations even if one fails

  steps:
    - name: Run ${{ matrix.test-group }} tests
      run: go test -v ./tests/${{ matrix.test-group }}/...

# Parallel service builds
build:
  strategy:
    matrix:
      service: [auth, payment, notification]
  steps:
    - name: Build ${{ matrix.service }} service
      run: ./scripts/build_service.sh ${{ matrix.service }}
```

### Resource Optimization

```yaml
# Self-hosted runners for cost savings
jobs:
  build-heavy:
    runs-on: [self-hosted, linux, x64, spot]
    # Runs on AWS EC2 Spot instances (70% cost savings)

# Resource limits for GitHub-hosted runners
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 15  # Prevent runaway builds
    concurrency:
      group: build-${{ github.ref }}
      cancel-in-progress: true  # Cancel outdated builds
```

**Cost Optimization**:
- **GitHub-hosted runners**: Free tier (2,000 min/month)
- **Self-hosted runners**: AWS EC2 Spot instances for heavy builds (70% cheaper)
- **Build caching**: Reduces build time by 60% (5 min → 2 min)
- **Concurrent build limits**: Max 5 concurrent builds per repository

---

## 16. Compliance & Audit

### Audit Logging

```yaml
# CloudTrail for AWS API calls
resource "aws_cloudtrail" "pipeline_audit" {
  name                          = "suma-finance-pipeline-audit"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type = "All"
    data_resource {
      type   = "AWS::ECS::Service"
      values = ["arn:aws:ecs:*:*:service/suma-finance-*/*"]
    }
  }

  event_selector {
    read_write_type = "All"
    data_resource {
      type   = "AWS::ECR::Repository"
      values = ["arn:aws:ecr:*:*:repository/suma-finance/*"]
    }
  }
}

# GitHub Actions audit log
- name: Log deployment event
  run: |
    echo "DEPLOYMENT_AUDIT_LOG" >> $GITHUB_STEP_SUMMARY
    echo "- **Timestamp**: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> $GITHUB_STEP_SUMMARY
    echo "- **User**: ${{ github.actor }}" >> $GITHUB_STEP_SUMMARY
    echo "- **Version**: ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
    echo "- **Environment**: production" >> $GITHUB_STEP_SUMMARY
    echo "- **Approved By**: ${{ github.event.review.user.login }}" >> $GITHUB_STEP_SUMMARY
```

### Compliance Requirements

#### SOC 2 Type II
```yaml
soc2_controls:
  CC6.1_Logical_Access:
    - GitHub branch protection (2 reviewers required)
    - AWS IAM role-based access control
    - Secrets management with AWS Secrets Manager
    - Audit logging for all deployments

  CC6.6_Segregation_of_Duties:
    - Developers cannot approve own PRs
    - Separate roles for deploy (DevOps) and approve (Tech Leads)
    - Production deployment requires manual approval

  CC7.2_System_Monitoring:
    - Real-time monitoring with Datadog
    - Security scanning in CI/CD pipeline
    - Automated alerts for anomalies

  CC8.1_Change_Management:
    - All changes via Git version control
    - Automated deployment pipeline (no manual changes)
    - Rollback capability with audit trail
```

#### GDPR Compliance
```yaml
- name: GDPR compliance checks
  run: |
    # Verify data retention policies
    ./scripts/check_gdpr_retention.sh
    
    # Validate consent management endpoints
    curl -f https://staging-auth.sumafinance.com/api/gdpr/consent || exit 1
    
    # Check data subject rights endpoints
    curl -f https://staging-auth.sumafinance.com/api/gdpr/export || exit 1
    curl -f https://staging-auth.sumafinance.com/api/gdpr/delete || exit 1
    
    # Verify audit logging
    aws logs filter-log-events \
      --log-group-name /aws/ecs/auth-service-staging \
      --filter-pattern "{ $.event = \"gdpr_request\" }" \
      --start-time $(date -d '1 hour ago' +%s)000 | jq '.events | length' | grep -v '^0$' || exit 1
```

### Change Management

```yaml
# JIRA integration for change tickets
- name: Create change ticket
  if: github.ref == 'refs/heads/main'
  run: |
    CHANGE_TICKET=$(curl -X POST "https://sumafinance.atlassian.net/rest/api/3/issue" \
      -H "Authorization: Bearer ${{ secrets.JIRA_API_TOKEN }}" \
      -H "Content-Type: application/json" \
      -d @- <<EOF
    {
      "fields": {
        "project": { "key": "CHANGE" },
        "summary": "Deploy auth-service ${{ github.sha }} to production",
        "description": "Automated deployment via CI/CD pipeline\n\nCommit: ${{ github.sha }}\nAuthor: ${{ github.actor }}\nBranch: ${{ github.ref }}",
        "issuetype": { "name": "Change Request" },
        "customfield_10001": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      }
    }
    EOF
    )
    
    echo "CHANGE_TICKET_ID=$(echo $CHANGE_TICKET | jq -r .key)" >> $GITHUB_ENV

- name: Update change ticket on completion
  if: always()
  run: |
    curl -X PUT "https://sumafinance.atlassian.net/rest/api/3/issue/${{ env.CHANGE_TICKET_ID }}" \
      -H "Authorization: Bearer ${{ secrets.JIRA_API_TOKEN }}" \
      -H "Content-Type: application/json" \
      -d @- <<EOF
    {
      "fields": {
        "status": { "name": "${{ job.status == 'success' && 'Completed' || 'Failed' }}" }
      }
    }
    EOF
```

---

## 17. Disaster Recovery

### Pipeline Configuration Backup

```yaml
# All pipeline configuration in Git
.github/
├── workflows/
│   ├── auth-service-pipeline.yml
│   ├── rollback-production.yml
│   └── scheduled-security-scan.yml
├── actions/
│   ├── setup-auth-env/
│   └── deploy-to-ecs/
└── environments/
    ├── production.yml
    └── staging.yml

# Terraform for infrastructure
terraform/
├── ecr.tf
├── ecs.tf
├── iam.tf
└── secrets.tf
```

**Recovery Procedure**:
1. Clone repository: `git clone https://github.com/suma-finance/auth-service`
2. Restore secrets: `./scripts/restore_secrets.sh`
3. Apply Terraform: `terraform apply`
4. Trigger pipeline: `git push origin main`

**Recovery Time Objective (RTO)**: 30 minutes
**Recovery Point Objective (RPO)**: 0 (Git commits)

### Environment Rebuild

```bash
#!/bin/bash
# scripts/rebuild_environment.sh

ENVIRONMENT=$1  # production, staging, development

echo "Rebuilding $ENVIRONMENT environment..."

# 1. Restore infrastructure with Terraform
cd terraform/
terraform workspace select $ENVIRONMENT
terraform apply -auto-approve

# 2. Restore secrets
aws secretsmanager restore-secret \
  --secret-id suma-finance/$ENVIRONMENT/auth-service

# 3. Deploy latest stable version
LATEST_STABLE=$(aws ecr describe-images \
  --repository-name suma-finance/auth-service \
  --query 'sort_by(imageDetails,& imagePushedAt)[-1].imageTags[0]' \
  --output text)

aws ecs update-service \
  --cluster suma-finance-$ENVIRONMENT \
  --service auth-service-$ENVIRONMENT \
  --task-definition auth-service-$ENVIRONMENT:$LATEST_STABLE \
  --force-new-deployment

# 4. Verify service health
./scripts/health_check.sh https://$ENVIRONMENT-auth.sumafinance.com

echo "✅ Environment rebuilt successfully"
```

---

## 18. Testing Strategy

### Pipeline Configuration Testing

```yaml
# Test pipeline changes before merge
- name: Validate workflow syntax
  run: |
    # Install actionlint
    wget https://github.com/rhysd/actionlint/releases/download/v1.6.26/actionlint_1.6.26_linux_amd64.tar.gz
    tar xzf actionlint_1.6.26_linux_amd64.tar.gz
    
    # Validate all workflows
    ./actionlint .github/workflows/*.yml

# Test Docker builds locally
- name: Test Docker build
  run: |
    docker build -t auth-service:test services/auth/
    docker run --rm auth-service:test --version
```

### Smoke Tests

```javascript
// tests/e2e/smoke_tests.spec.js
const { test, expect } = require('@playwright/test');

test.describe('Authentication Service Smoke Tests', () => {
  test('health check endpoint responds', async ({ request }) => {
    const response = await request.get('/health');
    expect(response.status()).toBe(200);
    
    const body = await response.json();
    expect(body.status).toBe('healthy');
  });

  test('user can register and login', async ({ page, request }) => {
    // Register
    const email = `test-${Date.now()}@sumafinance.com`;
    const password = 'Test@Password123';
    
    await page.goto('/register');
    await page.fill('[name="email"]', email);
    await page.fill('[name="password"]', password);
    await page.click('button[type="submit"]');
    
    await expect(page.locator('.success-message')).toBeVisible();
    
    // Login
    await page.goto('/login');
    await page.fill('[name="email"]', email);
    await page.fill('[name="password"]', password);
    await page.click('button[type="submit"]');
    
    await expect(page).toHaveURL('/dashboard');
  });

  test('rate limiting works', async ({ request }) => {
    const attempts = [];
    for (let i = 0; i < 6; i++) {
      attempts.push(
        request.post('/api/auth/login', {
          data: { email: 'test@test.com', password: 'wrong' }
        })
      );
    }
    
    const responses = await Promise.all(attempts);
    const rateLimited = responses.filter(r => r.status() === 429);
    
    expect(rateLimited.length).toBeGreaterThan(0);
  });
});
```

### Canary Validation Tests

```javascript
// tests/canary/validation.spec.js
const { test, expect } = require('@playwright/test');

test.describe('Canary Deployment Validation', () => {
  test('canary version has acceptable error rate', async () => {
    // Query Datadog for canary error rate
    const errorRate = await getCanaryErrorRate();
    expect(errorRate).toBeLessThan(0.5); // <0.5%
  });

  test('canary version meets latency SLA', async () => {
    const p95Latency = await getCanaryLatencyP95();
    expect(p95Latency).toBeLessThan(200); // <200ms
  });

  test('critical user flows work on canary', async ({ page }) => {
    // Force canary routing via header
    await page.setExtraHTTPHeaders({
      'X-Canary-Route': 'true'
    });

    // Test login flow
    await page.goto('/login');
    await page.fill('[name="email"]', process.env.TEST_EMAIL);
    await page.fill('[name="password"]', process.env.TEST_PASSWORD);
    await page.click('button[type="submit"]');
    
    await expect(page).toHaveURL('/dashboard');
  });
});
```

### Chaos Testing

```yaml
# Scheduled chaos testing (weekly)
name: Chaos Engineering Tests

on:
  schedule:
    - cron: '0 2 * * 1'  # Monday 2 AM UTC
  workflow_dispatch:

jobs:
  chaos-test:
    runs-on: ubuntu-latest
    environment: staging

    steps:
      - name: Inject random pod failures
        run: |
          # Kill random pods to test resilience
          kubectl delete pod \
            -n staging \
            -l app=auth-service \
            --random \
            --wait=false

      - name: Monitor recovery
        run: |
          # Wait for auto-recovery
          kubectl wait --for=condition=ready pod \
            -n staging \
            -l app=auth-service \
            --timeout=180s

      - name: Verify service availability
        run: |
          ./scripts/smoke_tests.sh https://staging-auth.sumafinance.com
```

---

**Document Status**: ✅ Architecture Design Complete
**Ready for Implementation**: Yes
**Based on**: Gate 0 Requirements, Pre-Gate 0 Research
**Compliance**: GDPR, PCI-DSS, SOC2, ISO 27001
**Security**: OWASP Top 10 2021, Shift-Left Security
