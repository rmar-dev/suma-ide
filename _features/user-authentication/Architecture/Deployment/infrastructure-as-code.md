---
layout: default
title: Infrastructure As Code
nav_exclude: true
---



# arch-infrastructure-as-code-generator

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Fintech Security & Identity Management
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Executive Summary

This Infrastructure as Code (IaC) specification defines the complete infrastructure architecture for the SUMA Finance user registration and authentication system. The architecture prioritizes security, compliance (GDPR, PCI-DSS, SOC2), and scalability while delivering sub-200ms authentication response times with 99.95% availability.

**Key Infrastructure Components:**
- Multi-AZ AWS deployment with ECS Fargate for containerized services
- Redis Cluster (ElastiCache) for session management and OTP caching
- RDS PostgreSQL with read replicas for authentication data
- CloudFront CDN with AWS WAF for DDoS protection
- SendGrid + SES for transactional email delivery
- Datadog + Sentry for observability and security monitoring

**Compliance Posture:**
- OWASP Top 10 2021 controls implemented
- GDPR-compliant consent management and audit trails
- PCI-DSS cryptographic standards (AES-256-GCM, TLS 1.3, Argon2id)
- SOC2 Type II audit-ready logging and access controls

---

## 2. Architecture Overview

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CloudFront CDN                           │
│                    (Global Edge Locations)                      │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                         AWS WAF                                 │
│          (Rate Limiting, Bot Detection, OWASP Rules)            │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                Application Load Balancer (ALB)                  │
│                   (Multi-AZ, TLS 1.3)                          │
└────────┬───────────────────────────┬────────────────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────┐         ┌─────────────────┐
│  ECS Fargate    │         │  ECS Fargate    │
│  Cluster (AZ-A) │         │  Cluster (AZ-B) │
│                 │         │                 │
│ ┌─────────────┐ │         │ ┌─────────────┐ │
│ │Auth Service │ │         │ │Auth Service │ │
│ │   (Go API)  │ │         │ │   (Go API)  │ │
│ └─────────────┘ │         │ └─────────────┘ │
└────────┬────────┘         └────────┬────────┘
         │                           │
         └───────────┬───────────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
         ▼           ▼           ▼
┌──────────────┐ ┌─────────┐ ┌────────────────┐
│   RDS PG     │ │  Redis  │ │   SendGrid     │
│  (Primary +  │ │ Cluster │ │   + SES        │
│   Replica)   │ │(Session)│ │  (Email OTP)   │
└──────────────┘ └─────────┘ └────────────────┘
         │
         ▼
┌──────────────────────────────────────┐
│         AWS Secrets Manager          │
│    (JWT Keys, DB Creds, API Keys)    │
└──────────────────────────────────────┘
```

### 2.2 Infrastructure Layers

| Layer | Technology | Purpose | HA Strategy |
|-------|-----------|---------|-------------|
| **Edge** | CloudFront + WAF | Global CDN, DDoS protection, rate limiting | Multi-region edge locations |
| **Load Balancing** | Application Load Balancer | TLS termination, request routing, health checks | Multi-AZ with cross-zone load balancing |
| **Compute** | ECS Fargate | Containerized auth services (Go API) | Auto-scaling across 3 AZs (min: 3, max: 20) |
| **Session Store** | ElastiCache Redis | JWT refresh tokens, OTP storage, rate limits | Multi-AZ cluster mode with automatic failover |
| **Database** | RDS PostgreSQL 15 | User credentials, consent logs, audit trails | Multi-AZ primary + 2 read replicas |
| **Email** | SendGrid + SES | Email verification, password reset, OTP delivery | Primary/failover configuration |
| **Secrets** | AWS Secrets Manager | JWT signing keys, DB credentials, API keys | Automatic rotation every 90 days |
| **Monitoring** | Datadog + Sentry | Metrics, logs, traces, error tracking | SaaS with 99.99% uptime SLA |

---

## 3. Terraform Infrastructure Definitions

### 3.1 Directory Structure

```
infrastructure/
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── versions.tf
│   ├── backend.tf
│   ├── modules/
│   │   ├── vpc/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── ecs/
│   │   │   ├── main.tf
│   │   │   ├── task-definition.json
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── rds/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── redis/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── alb/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── waf/
│   │   │   ├── main.tf
│   │   │   ├── rules.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── cloudfront/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   ├── secrets/
│   │   │   ├── main.tf
│   │   │   ├── rotation.tf
│   │   │   ├── variables.tf
│   │   │   └── outputs.tf
│   │   └── monitoring/
│   │       ├── main.tf
│   │       ├── dashboards.tf
│   │       ├── alerts.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   └── environments/
│       ├── dev/
│       │   ├── main.tf
│       │   └── terraform.tfvars
│       ├── staging/
│       │   ├── main.tf
│       │   └── terraform.tfvars
│       └── production/
│           ├── main.tf
│           └── terraform.tfvars
```

### 3.2 Core Terraform Configurations

#### 3.2.1 Root Module (main.tf)

```hcl
terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    datadog = {
      source  = "DataDog/datadog"
      version = "~> 3.30"
    }
  }
  
  backend "s3" {
    bucket         = "suma-finance-terraform-state"
    key            = "auth-service/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-lock"
    kms_key_id     = "arn:aws:kms:us-east-1:ACCOUNT_ID:key/TERRAFORM_KMS_KEY"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "SUMA-Finance"
      Component   = "Auth-Service"
      Environment = var.environment
      ManagedBy   = "Terraform"
      CostCenter  = "Engineering"
      Compliance  = "GDPR-PCI-DSS-SOC2"
    }
  }
}

provider "datadog" {
  api_key = var.datadog_api_key
  app_key = var.datadog_app_key
  api_url = "https://api.datadoghq.com/"
}

# Local variables
locals {
  name_prefix = "suma-finance-${var.environment}"
  
  common_tags = {
    Project     = "SUMA-Finance"
    Component   = "Auth-Service"
    Environment = var.environment
    Compliance  = "GDPR-PCI-DSS-SOC2"
  }
  
  availability_zones = data.aws_availability_zones.available.names
}

data "aws_availability_zones" "available" {
  state = "available"
}

# VPC Module
module "vpc" {
  source = "./modules/vpc"
  
  name_prefix        = local.name_prefix
  cidr_block         = var.vpc_cidr
  availability_zones = slice(local.availability_zones, 0, 3)
  
  enable_nat_gateway   = true
  enable_vpn_gateway   = false
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  enable_flow_logs           = true
  flow_logs_retention_days   = 90
  flow_logs_traffic_type     = "ALL"
  
  tags = local.common_tags
}

# RDS PostgreSQL Module
module "rds" {
  source = "./modules/rds"
  
  name_prefix = local.name_prefix
  
  engine_version       = "15.5"
  instance_class       = var.rds_instance_class
  allocated_storage    = var.rds_allocated_storage
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.rds.arn
  
  database_name = "suma_auth"
  master_username = "authdbadmin"
  
  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  vpc_security_group_ids = [aws_security_group.rds.id]
  
  multi_az               = var.environment == "production" ? true : false
  backup_retention_period = var.environment == "production" ? 30 : 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  performance_insights_enabled    = true
  performance_insights_retention_period = 7
  
  read_replica_count = var.environment == "production" ? 2 : 0
  
  deletion_protection = var.environment == "production" ? true : false
  skip_final_snapshot = var.environment != "production"
  
  tags = local.common_tags
}

# Redis Cluster Module
module "redis" {
  source = "./modules/redis"
  
  name_prefix = local.name_prefix
  
  engine_version       = "7.0"
  node_type           = var.redis_node_type
  num_cache_clusters  = var.environment == "production" ? 3 : 2
  
  parameter_group_family = "redis7"
  port                   = 6379
  
  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  security_group_ids  = [aws_security_group.redis.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token_enabled        = true
  kms_key_id               = aws_kms_key.redis.arn
  
  automatic_failover_enabled = true
  multi_az_enabled          = var.environment == "production" ? true : false
  
  snapshot_retention_limit = var.environment == "production" ? 7 : 1
  snapshot_window         = "03:00-05:00"
  maintenance_window      = "sun:05:00-sun:07:00"
  
  tags = local.common_tags
}

# ECS Cluster Module
module "ecs" {
  source = "./modules/ecs"
  
  name_prefix = local.name_prefix
  
  vpc_id             = module.vpc.vpc_id
  private_subnet_ids = module.vpc.private_subnet_ids
  
  container_image = var.auth_service_image
  container_port  = 8080
  
  cpu    = var.ecs_task_cpu
  memory = var.ecs_task_memory
  
  desired_count = var.ecs_desired_count
  min_capacity  = var.ecs_min_capacity
  max_capacity  = var.ecs_max_capacity
  
  target_cpu_utilization = 70
  target_memory_utilization = 80
  
  environment_variables = [
    {
      name  = "ENVIRONMENT"
      value = var.environment
    },
    {
      name  = "LOG_LEVEL"
      value = var.environment == "production" ? "INFO" : "DEBUG"
    },
    {
      name  = "DB_HOST"
      value = module.rds.endpoint
    },
    {
      name  = "REDIS_ENDPOINT"
      value = module.redis.configuration_endpoint
    }
  ]
  
  secrets = [
    {
      name      = "DB_PASSWORD"
      valueFrom = aws_secretsmanager_secret_version.db_password.arn
    },
    {
      name      = "REDIS_AUTH_TOKEN"
      valueFrom = aws_secretsmanager_secret_version.redis_auth_token.arn
    },
    {
      name      = "JWT_PRIVATE_KEY"
      valueFrom = aws_secretsmanager_secret_version.jwt_private_key.arn
    },
    {
      name      = "JWT_PUBLIC_KEY"
      valueFrom = aws_secretsmanager_secret_version.jwt_public_key.arn
    },
    {
      name      = "SENDGRID_API_KEY"
      valueFrom = aws_secretsmanager_secret_version.sendgrid_api_key.arn
    }
  ]
  
  health_check_path     = "/health"
  health_check_interval = 30
  health_check_timeout  = 5
  
  enable_execute_command = var.environment != "production"
  
  cloudwatch_log_retention_days = var.environment == "production" ? 90 : 30
  
  tags = local.common_tags
}

# Application Load Balancer Module
module "alb" {
  source = "./modules/alb"
  
  name_prefix = local.name_prefix
  
  vpc_id          = module.vpc.vpc_id
  public_subnets  = module.vpc.public_subnet_ids
  security_groups = [aws_security_group.alb.id]
  
  enable_deletion_protection = var.environment == "production"
  enable_http2              = true
  enable_cross_zone_load_balancing = true
  
  certificate_arn = aws_acm_certificate.auth_api.arn
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  
  target_group_port     = 8080
  target_group_protocol = "HTTP"
  target_type          = "ip"
  
  health_check = {
    enabled             = true
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }
  
  deregistration_delay = 30
  
  access_logs_enabled = true
  access_logs_bucket  = aws_s3_bucket.alb_logs.id
  access_logs_prefix  = "auth-service"
  
  tags = local.common_tags
}

# WAF Module
module "waf" {
  source = "./modules/waf"
  
  name_prefix = local.name_prefix
  scope       = "REGIONAL"
  
  associate_alb = true
  alb_arn      = module.alb.arn
  
  rate_limit_rules = [
    {
      name     = "login-rate-limit"
      priority = 1
      limit    = 5
      path     = "/api/v1/auth/login"
      action   = "BLOCK"
    },
    {
      name     = "registration-rate-limit"
      priority = 2
      limit    = 3
      path     = "/api/v1/auth/register"
      action   = "BLOCK"
    },
    {
      name     = "password-reset-rate-limit"
      priority = 3
      limit    = 3
      path     = "/api/v1/auth/password-reset"
      action   = "BLOCK"
    },
    {
      name     = "otp-rate-limit"
      priority = 4
      limit    = 5
      path     = "/api/v1/auth/otp"
      action   = "BLOCK"
    }
  ]
  
  managed_rules = [
    {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 10
    },
    {
      name     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority = 20
    },
    {
      name     = "AWSManagedRulesSQLiRuleSet"
      priority = 30
    },
    {
      name     = "AWSManagedRulesAnonymousIpList"
      priority = 40
    }
  ]
  
  ip_rate_limit = 1000
  
  cloudwatch_metrics_enabled = true
  sampled_requests_enabled   = true
  
  tags = local.common_tags
}

# CloudFront Module
module "cloudfront" {
  source = "./modules/cloudfront"
  
  name_prefix = local.name_prefix
  
  origin_domain_name = module.alb.dns_name
  origin_id         = "auth-api-alb"
  
  origin_protocol_policy = "https-only"
  origin_ssl_protocols   = ["TLSv1.3"]
  
  viewer_protocol_policy = "redirect-to-https"
  allowed_methods       = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
  cached_methods        = ["GET", "HEAD", "OPTIONS"]
  
  min_ttl     = 0
  default_ttl = 0
  max_ttl     = 0
  
  compress = true
  
  price_class = var.environment == "production" ? "PriceClass_All" : "PriceClass_100"
  
  aliases = ["auth.suma-finance.com"]
  
  acm_certificate_arn      = aws_acm_certificate.cloudfront.arn
  minimum_protocol_version = "TLSv1.2_2021"
  ssl_support_method       = "sni-only"
  
  geo_restriction_type = "none"
  
  custom_error_responses = [
    {
      error_code         = 403
      response_code      = 403
      response_page_path = "/error.html"
      error_caching_min_ttl = 10
    },
    {
      error_code         = 404
      response_code      = 404
      response_page_path = "/error.html"
      error_caching_min_ttl = 10
    }
  ]
  
  logging_enabled = true
  logging_bucket  = aws_s3_bucket.cloudfront_logs.bucket_domain_name
  logging_prefix  = "auth-api/"
  
  waf_web_acl_id = module.waf.web_acl_arn
  
  tags = local.common_tags
}

# Secrets Manager Module
module "secrets" {
  source = "./modules/secrets"
  
  name_prefix = local.name_prefix
  
  secrets = {
    db_password = {
      description = "RDS PostgreSQL master password"
      rotation_days = 90
      rotation_lambda_arn = aws_lambda_function.db_password_rotation.arn
    }
    redis_auth_token = {
      description = "Redis authentication token"
      rotation_days = 90
      rotation_lambda_arn = aws_lambda_function.redis_token_rotation.arn
    }
    jwt_private_key = {
      description = "JWT RS256 private key"
      rotation_days = 90
      rotation_lambda_arn = aws_lambda_function.jwt_key_rotation.arn
    }
    jwt_public_key = {
      description = "JWT RS256 public key"
      rotation_days = 90
      rotation_lambda_arn = aws_lambda_function.jwt_key_rotation.arn
    }
    sendgrid_api_key = {
      description = "SendGrid API key for transactional emails"
      rotation_days = 90
      rotation_lambda_arn = null
    }
  }
  
  kms_key_id = aws_kms_key.secrets.arn
  
  tags = local.common_tags
}

# Monitoring Module
module "monitoring" {
  source = "./modules/monitoring"
  
  name_prefix = local.name_prefix
  environment = var.environment
  
  datadog_api_key = var.datadog_api_key
  
  ecs_cluster_name = module.ecs.cluster_name
  ecs_service_name = module.ecs.service_name
  
  rds_instance_id = module.rds.instance_id
  redis_cluster_id = module.redis.cluster_id
  
  alb_arn_suffix = module.alb.arn_suffix
  
  alert_email = var.alert_email
  alert_slack_webhook = var.alert_slack_webhook
  
  tags = local.common_tags
}
```

#### 3.2.2 VPC Module (modules/vpc/main.tf)

```hcl
resource "aws_vpc" "main" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-vpc"
    }
  )
}

resource "aws_subnet" "public" {
  count = length(var.availability_zones)
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.cidr_block, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-public-${var.availability_zones[count.index]}"
      Type = "public"
    }
  )
}

resource "aws_subnet" "private" {
  count = length(var.availability_zones)
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.cidr_block, 8, count.index + 100)
  availability_zone = var.availability_zones[count.index]
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-private-${var.availability_zones[count.index]}"
      Type = "private"
    }
  )
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-igw"
    }
  )
}

resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? length(var.availability_zones) : 0
  
  domain = "vpc"
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-nat-eip-${var.availability_zones[count.index]}"
    }
  )
  
  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count = var.enable_nat_gateway ? length(var.availability_zones) : 0
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-nat-${var.availability_zones[count.index]}"
    }
  )
  
  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-public-rt"
    }
  )
}

resource "aws_route_table" "private" {
  count = length(var.availability_zones)
  
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = var.enable_nat_gateway ? aws_nat_gateway.main[count.index].id : null
  }
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-private-rt-${var.availability_zones[count.index]}"
    }
  )
}

resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_flow_log" "main" {
  count = var.enable_flow_logs ? 1 : 0
  
  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn
  traffic_type    = var.flow_logs_traffic_type
  vpc_id          = aws_vpc.main.id
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-flow-logs"
    }
  )
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0
  
  name              = "/aws/vpc/${var.name_prefix}"
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = var.flow_logs_kms_key_id
  
  tags = var.tags
}
```

#### 3.2.3 ECS Module (modules/ecs/main.tf)

```hcl
resource "aws_ecs_cluster" "main" {
  name = "${var.name_prefix}-cluster"
  
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  
  tags = var.tags
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name = aws_ecs_cluster.main.name
  
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]
  
  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 1
  }
}

resource "aws_ecs_task_definition" "main" {
  family                   = "${var.name_prefix}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn           = aws_iam_role.ecs_task.arn
  
  container_definitions = jsonencode([
    {
      name      = "auth-service"
      image     = var.container_image
      cpu       = var.cpu
      memory    = var.memory
      essential = true
      
      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]
      
      environment = var.environment_variables
      secrets     = var.secrets
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
        }
      }
      
      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${var.container_port}${var.health_check_path} || exit 1"]
        interval    = var.health_check_interval
        timeout     = var.health_check_timeout
        retries     = 3
        startPeriod = 60
      }
      
      stopTimeout = 30
      
      linuxParameters = {
        initProcessEnabled = true
      }
      
      readonlyRootFilesystem = true
      
      ulimits = [
        {
          name      = "nofile"
          softLimit = 65536
          hardLimit = 65536
        }
      ]
    }
  ])
  
  tags = var.tags
}

resource "aws_ecs_service" "main" {
  name            = "${var.name_prefix}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.main.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  
  platform_version = "LATEST"
  
  enable_execute_command = var.enable_execute_command
  
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }
  
  load_balancer {
    target_group_arn = var.target_group_arn
    container_name   = "auth-service"
    container_port   = var.container_port
  }
  
  deployment_configuration {
    maximum_percent         = 200
    minimum_healthy_percent = 100
    
    deployment_circuit_breaker {
      enable   = true
      rollback = true
    }
  }
  
  health_check_grace_period_seconds = 60
  
  tags = var.tags
  
  depends_on = [var.alb_target_group]
}

resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = var.max_capacity
  min_capacity       = var.min_capacity
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.main.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.name_prefix}-cpu-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    
    target_value       = var.target_cpu_utilization
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "memory" {
  name               = "${var.name_prefix}-memory-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    
    target_value       = var.target_memory_utilization
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.name_prefix}"
  retention_in_days = var.cloudwatch_log_retention_days
  kms_key_id        = var.cloudwatch_kms_key_id
  
  tags = var.tags
}

resource "aws_security_group" "ecs_tasks" {
  name        = "${var.name_prefix}-ecs-tasks"
  description = "Security group for ECS tasks"
  vpc_id      = var.vpc_id
  
  ingress {
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [var.alb_security_group_id]
    description     = "Allow traffic from ALB"
  }
  
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS outbound"
  }
  
  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Allow PostgreSQL within VPC"
  }
  
  egress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Allow Redis within VPC"
  }
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-ecs-tasks"
    }
  )
}
```

#### 3.2.4 RDS Module (modules/rds/main.tf)

```hcl
resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnet-group"
  subnet_ids = var.subnet_ids
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-db-subnet-group"
    }
  )
}

resource "aws_db_parameter_group" "main" {
  name   = "${var.name_prefix}-pg-params"
  family = "postgres15"
  
  parameter {
    name  = "log_statement"
    value = "all"
  }
  
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  
  parameter {
    name  = "ssl"
    value = "1"
  }
  
  parameter {
    name  = "ssl_min_protocol_version"
    value = "TLSv1.3"
  }
  
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  
  parameter {
    name  = "shared_preload_libraries"
    value = "pg_stat_statements"
  }
  
  tags = var.tags
}

resource "aws_db_instance" "main" {
  identifier = "${var.name_prefix}-postgres"
  
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class
  
  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.allocated_storage * 2
  storage_type         = "gp3"
  storage_encrypted    = var.storage_encrypted
  kms_key_id          = var.kms_key_id
  
  db_name  = var.database_name
  username = var.master_username
  password = random_password.db_password.result
  
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = var.vpc_security_group_ids
  parameter_group_name   = aws_db_parameter_group.main.name
  
  multi_az               = var.multi_az
  publicly_accessible    = false
  
  backup_retention_period = var.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window
  
  enabled_cloudwatch_logs_exports = var.enabled_cloudwatch_logs_exports
  
  performance_insights_enabled          = var.performance_insights_enabled
  performance_insights_retention_period = var.performance_insights_retention_period
  performance_insights_kms_key_id      = var.kms_key_id
  
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  
  deletion_protection = var.deletion_protection
  skip_final_snapshot = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${var.name_prefix}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  copy_tags_to_snapshot = true
  
  auto_minor_version_upgrade = false
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-postgres"
    }
  )
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret" "db_password" {
  name                    = "${var.name_prefix}-db-password"
  description             = "RDS PostgreSQL master password"
  kms_key_id             = var.kms_key_id
  recovery_window_in_days = var.deletion_protection ? 30 : 0
  
  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = var.master_username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = aws_db_instance.main.address
    port     = aws_db_instance.main.port
    dbname   = var.database_name
  })
}

resource "aws_db_instance" "read_replica" {
  count = var.read_replica_count
  
  identifier = "${var.name_prefix}-postgres-replica-${count.index + 1}"
  
  replicate_source_db = aws_db_instance.main.identifier
  instance_class      = var.instance_class
  
  storage_encrypted = var.storage_encrypted
  kms_key_id       = var.kms_key_id
  
  publicly_accessible = false
  
  performance_insights_enabled          = var.performance_insights_enabled
  performance_insights_retention_period = var.performance_insights_retention_period
  performance_insights_kms_key_id      = var.kms_key_id
  
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  
  auto_minor_version_upgrade = false
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-postgres-replica-${count.index + 1}"
      Type = "read-replica"
    }
  )
}

resource "aws_iam_role" "rds_monitoring" {
  name = "${var.name_prefix}-rds-monitoring"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
```

#### 3.2.5 Redis Module (modules/redis/main.tf)

```hcl
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.name_prefix}-redis-subnet-group"
  subnet_ids = var.subnet_ids
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-redis-subnet-group"
    }
  )
}

resource "aws_elasticache_parameter_group" "main" {
  name   = "${var.name_prefix}-redis-params"
  family = var.parameter_group_family
  
  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
  
  parameter {
    name  = "timeout"
    value = "300"
  }
  
  parameter {
    name  = "tcp-keepalive"
    value = "300"
  }
  
  tags = var.tags
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "${var.name_prefix}-redis"
  replication_group_description = "Redis cluster for session management and OTP storage"
  
  engine               = "redis"
  engine_version       = var.engine_version
  node_type            = var.node_type
  num_cache_clusters   = var.num_cache_clusters
  port                 = var.port
  parameter_group_name = aws_elasticache_parameter_group.main.name
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  security_group_ids   = var.security_group_ids
  
  automatic_failover_enabled = var.automatic_failover_enabled
  multi_az_enabled          = var.multi_az_enabled
  
  at_rest_encryption_enabled = var.at_rest_encryption_enabled
  transit_encryption_enabled = var.transit_encryption_enabled
  auth_token                = var.auth_token_enabled ? random_password.redis_auth_token[0].result : null
  kms_key_id               = var.kms_key_id
  
  snapshot_retention_limit = var.snapshot_retention_limit
  snapshot_window         = var.snapshot_window
  maintenance_window      = var.maintenance_window
  
  auto_minor_version_upgrade = false
  
  apply_immediately = false
  
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_slow_log.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }
  
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis_engine_log.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "engine-log"
  }
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-redis"
    }
  )
}

resource "random_password" "redis_auth_token" {
  count = var.auth_token_enabled ? 1 : 0
  
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "redis_auth_token" {
  count = var.auth_token_enabled ? 1 : 0
  
  name                    = "${var.name_prefix}-redis-auth-token"
  description             = "Redis authentication token"
  kms_key_id             = var.kms_key_id
  recovery_window_in_days = 30
  
  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "redis_auth_token" {
  count = var.auth_token_enabled ? 1 : 0
  
  secret_id     = aws_secretsmanager_secret.redis_auth_token[0].id
  secret_string = jsonencode({
    auth_token              = random_password.redis_auth_token[0].result
    configuration_endpoint  = aws_elasticache_replication_group.main.configuration_endpoint_address
    primary_endpoint       = aws_elasticache_replication_group.main.primary_endpoint_address
    port                   = var.port
  })
}

resource "aws_cloudwatch_log_group" "redis_slow_log" {
  name              = "/aws/elasticache/${var.name_prefix}-redis/slow-log"
  retention_in_days = 7
  kms_key_id        = var.cloudwatch_kms_key_id
  
  tags = var.tags
}

resource "aws_cloudwatch_log_group" "redis_engine_log" {
  name              = "/aws/elasticache/${var.name_prefix}-redis/engine-log"
  retention_in_days = 7
  kms_key_id        = var.cloudwatch_kms_key_id
  
  tags = var.tags
}
```

---

## 4. Docker Configurations

### 4.1 Dockerfile (Multi-Stage Build)

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=${VERSION:-dev} -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o auth-service \
    ./cmd/auth

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user
RUN addgroup -g 1001 appuser && \
    adduser -D -u 1001 -G appuser appuser

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/auth-service .

# Copy migrations
COPY --from=builder /build/migrations ./migrations

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["/app/auth-service"]
```

### 4.2 Docker Compose (Local Development)

```yaml
version: '3.9'

services:
  auth-service:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: suma-auth-service
    ports:
      - "8080:8080"
    environment:
      - ENVIRONMENT=development
      - LOG_LEVEL=DEBUG
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_NAME=suma_auth
      - DB_USER=authdbadmin
      - DB_PASSWORD=devpassword123
      - REDIS_ENDPOINT=redis:6379
      - REDIS_AUTH_TOKEN=devtoken123
      - JWT_PRIVATE_KEY_PATH=/secrets/jwt_private.pem
      - JWT_PUBLIC_KEY_PATH=/secrets/jwt_public.pem
      - SENDGRID_API_KEY=${SENDGRID_API_KEY}
      - SESSION_TIMEOUT_MINUTES=15
      - SESSION_ABSOLUTE_TIMEOUT_HOURS=8
      - OTP_EXPIRY_MINUTES=5
      - MAX_LOGIN_ATTEMPTS=5
      - LOCKOUT_DURATION_MINUTES=15
    volumes:
      - ./secrets:/secrets:ro
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - auth-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 60s

  postgres:
    image: postgres:15.5-alpine
    container_name: suma-auth-postgres
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=suma_auth
      - POSTGRES_USER=authdbadmin
      - POSTGRES_PASSWORD=devpassword123
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d:ro
    networks:
      - auth-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authdbadmin -d suma_auth"]
      interval: 10s
      timeout: 5s
      retries: 5
    command:
      - "postgres"
      - "-c"
      - "ssl=on"
      - "-c"
      - "ssl_min_protocol_version=TLSv1.3"

  redis:
    image: redis:7.0-alpine
    container_name: suma-auth-redis
    ports:
      - "6379:6379"
    command: >
      redis-server
      --requirepass devtoken123
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
      --save 60 1000
      --appendonly yes
    volumes:
      - redis-data:/data
    networks:
      - auth-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  mailhog:
    image: mailhog/mailhog:latest
    container_name: suma-auth-mailhog
    ports:
      - "1025:1025"  # SMTP server
      - "8025:8025"  # Web UI
    networks:
      - auth-network
    restart: unless-stopped

volumes:
  postgres-data:
    driver: local
  redis-data:
    driver: local

networks:
  auth-network:
    driver: bridge
```

### 4.3 .dockerignore

```
# Git
.git
.gitignore

# Documentation
*.md
docs/

# CI/CD
.github/
.gitlab-ci.yml

# Development files
.vscode/
.idea/
*.swp
*.swo
*~

# Test files
*_test.go
testdata/

# Build artifacts
bin/
dist/
*.exe

# Dependencies (downloaded during build)
vendor/

# Environment files
.env
.env.*
!.env.example

# Secrets
secrets/
*.pem
*.key

# Logs
*.log
logs/

# Terraform
terraform/
*.tfstate
*.tfvars

# Kubernetes
k8s/
```

---

## 5. CI/CD Pipeline (GitHub Actions)

### 5.1 Build and Deploy Workflow

```yaml
name: Build and Deploy Auth Service

on:
  push:
    branches:
      - main
      - develop
      - 'release/**'
  pull_request:
    branches:
      - main
      - develop

env:
  AWS_REGION: us-east-1
  ECR_REPOSITORY: suma-finance/auth-service
  ECS_CLUSTER: suma-finance-production-cluster
  ECS_SERVICE: suma-finance-production-service
  CONTAINER_NAME: auth-service

jobs:
  security-scan:
    name: Security Scanning
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

      - name: Run gosec security scanner
        uses: securego/gosec@master
        with:
          args: '-fmt sarif -out gosec-results.sarif ./...'

      - name: Upload gosec results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'gosec-results.sarif'

  test:
    name: Run Tests
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15.5
        env:
          POSTGRES_PASSWORD: testpassword
          POSTGRES_DB: suma_auth_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

      redis:
        image: redis:7.0
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: true

      - name: Run tests with coverage
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_NAME: suma_auth_test
          DB_USER: postgres
          DB_PASSWORD: testpassword
          REDIS_ENDPOINT: localhost:6379
        run: |
          go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
          go tool cover -func=coverage.out

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out
          flags: unittests
          fail_ci_if_error: true

  build:
    name: Build and Push Docker Image
    runs-on: ubuntu-latest
    needs: [security-scan, test]
    if: github.event_name == 'push'
    outputs:
      image-tag: ${{ steps.meta.outputs.tags }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
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
            type=semver,pattern={{major}}.{{minor}}
            type=sha,prefix={{branch}}-

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          build-args: |
            VERSION=${{ github.sha }}

      - name: Scan image with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ steps.login-ecr.outputs.registry }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-image-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload image scan results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-image-results.sarif'

  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/develop'
    environment:
      name: staging
      url: https://auth-staging.suma-finance.com

    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Deploy to ECS
        run: |
          aws ecs update-service \
            --cluster suma-finance-staging-cluster \
            --service suma-finance-staging-service \
            --force-new-deployment \
            --region ${{ env.AWS_REGION }}

      - name: Wait for deployment
        run: |
          aws ecs wait services-stable \
            --cluster suma-finance-staging-cluster \
            --services suma-finance-staging-service \
            --region ${{ env.AWS_REGION }}

  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://auth.suma-finance.com

    steps:
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Create deployment record
        run: |
          echo "Deploying version ${{ github.sha }} to production"
          echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

      - name: Deploy to ECS
        run: |
          aws ecs update-service \
            --cluster ${{ env.ECS_CLUSTER }} \
            --service ${{ env.ECS_SERVICE }} \
            --force-new-deployment \
            --region ${{ env.AWS_REGION }}

      - name: Wait for deployment
        run: |
          aws ecs wait services-stable \
            --cluster ${{ env.ECS_CLUSTER }} \
            --services ${{ env.ECS_SERVICE }} \
            --region ${{ env.AWS_REGION }}

      - name: Notify Datadog
        run: |
          curl -X POST "https://api.datadoghq.com/api/v1/events" \
            -H "DD-API-KEY: ${{ secrets.DATADOG_API_KEY }}" \
            -H "Content-Type: application/json" \
            -d '{
              "title": "Production Deployment",
              "text": "Deployed auth-service version ${{ github.sha }}",
              "tags": ["environment:production", "service:auth-service"],
              "alert_type": "info"
            }'

      - name: Run smoke tests
        run: |
          # Wait for service to be fully available
          sleep 30
          
          # Health check
          curl -f https://auth.suma-finance.com/health || exit 1
          
          # Readiness check
          curl -f https://auth.suma-finance.com/ready || exit 1
```

---

## 6. Monitoring and Observability

### 6.1 Datadog Dashboard Configuration

```json
{
  "title": "SUMA Finance - Auth Service",
  "description": "Authentication service monitoring dashboard",
  "widgets": [
    {
      "definition": {
        "type": "timeseries",
        "requests": [
          {
            "q": "avg:aws.ecs.service.running{cluster_name:suma-finance-production-cluster,service_name:suma-finance-production-service}",
            "display_type": "line",
            "style": {
              "palette": "dog_classic",
              "line_type": "solid",
              "line_width": "normal"
            }
          }
        ],
        "title": "ECS Running Tasks",
        "show_legend": true
      },
      "layout": {
        "x": 0,
        "y": 0,
        "width": 4,
        "height": 2
      }
    },
    {
      "definition": {
        "type": "query_value",
        "requests": [
          {
            "q": "avg:aws.applicationelb.target_response_time.average{load_balancer:suma-finance-production}",
            "aggregator": "avg"
          }
        ],
        "title": "Average Response Time",
        "precision": 2,
        "unit": "ms"
      },
      "layout": {
        "x": 4,
        "y": 0,
        "width": 2,
        "height": 2
      }
    },
    {
      "definition": {
        "type": "timeseries",
        "requests": [
          {
            "q": "sum:auth.login.success{env:production}.as_count(), sum:auth.login.failure{env:production}.as_count()",
            "display_type": "bars",
            "style": {
              "palette": "semantic"
            }
          }
        ],
        "title": "Login Attempts (Success vs Failure)"
      },
      "layout": {
        "x": 0,
        "y": 2,
        "width": 6,
        "height": 3
      }
    },
    {
      "definition": {
        "type": "toplist",
        "requests": [
          {
            "q": "top(sum:auth.endpoint.requests{env:production} by {endpoint}, 10, 'sum', 'desc')"
          }
        ],
        "title": "Top 10 Endpoints by Request Count"
      },
      "layout": {
        "x": 6,
        "y": 0,
        "width": 6,
        "height": 3
      }
    },
    {
      "definition": {
        "type": "timeseries",
        "requests": [
          {
            "q": "avg:aws.rds.database_connections{dbinstanceidentifier:suma-finance-production-postgres}",
            "display_type": "line"
          }
        ],
        "title": "Database Connections"
      },
      "layout": {
        "x": 0,
        "y": 5,
        "width": 4,
        "height": 2
      }
    },
    {
      "definition": {
        "type": "timeseries",
        "requests": [
          {
            "q": "avg:aws.elasticache.cpuutilization{cacheclusterid:suma-finance-production-redis*}",
            "display_type": "line"
          }
        ],
        "title": "Redis CPU Utilization"
      },
      "layout": {
        "x": 4,
        "y": 5,
        "width": 4,
        "height": 2
      }
    },
    {
      "definition": {
        "type": "query_value",
        "requests": [
          {
            "q": "sum:auth.account_lockout{env:production}.as_count()",
            "aggregator": "sum",
            "conditional_formats": [
              {
                "comparator": ">",
                "value": 10,
                "palette": "white_on_red"
              }
            ]
          }
        ],
        "title": "Account Lockouts (24h)",
        "autoscale": true
      },
      "layout": {
        "x": 8,
        "y": 5,
        "width": 2,
        "height": 2
      }
    }
  ],
  "template_variables": [
    {
      "name": "environment",
      "default": "production",
      "prefix": "env"
    }
  ],
  "layout_type": "ordered",
  "notify_list": [],
  "tags": ["service:auth", "team:platform"]
}
```

### 6.2 Datadog Alerts

```yaml
# modules/monitoring/alerts.tf

resource "datadog_monitor" "high_error_rate" {
  name    = "[SUMA Finance] High Error Rate - Auth Service"
  type    = "metric alert"
  message = <<-EOT
    Auth service error rate is above threshold.
    
    Current error rate: {{value}}%
    
    @slack-platform-alerts
    @pagerduty-platform
  EOT

  query = "avg(last_5m):sum:auth.endpoint.errors{env:${var.environment}}.as_rate() / sum:auth.endpoint.requests{env:${var.environment}}.as_rate() * 100 > 5"

  monitor_thresholds {
    critical = 5
    warning  = 2
  }

  notify_no_data    = true
  no_data_timeframe = 10
  require_full_window = false

  tags = ["service:auth", "env:${var.environment}", "severity:critical"]
}

resource "datadog_monitor" "high_response_time" {
  name    = "[SUMA Finance] High Response Time - Auth Service"
  type    = "metric alert"
  message = <<-EOT
    Auth service response time is above threshold.
    
    P95 Response Time: {{value}}ms
    
    @slack-platform-alerts
  EOT

  query = "avg(last_10m):p95:trace.http.request.duration{service:auth-service,env:${var.environment}} > 200"

  monitor_thresholds {
    critical = 200
    warning  = 150
  }

  tags = ["service:auth", "env:${var.environment}", "severity:warning"]
}

resource "datadog_monitor" "failed_login_spike" {
  name    = "[SUMA Finance] Failed Login Spike - Auth Service"
  type    = "metric alert"
  message = <<-EOT
    Unusual spike in failed login attempts detected.
    
    Failed logins: {{value}} in the last 15 minutes
    
    Possible security incident - investigate immediately.
    
    @slack-security-alerts
    @pagerduty-security
  EOT

  query = "sum(last_15m):sum:auth.login.failure{env:${var.environment}}.as_count() > 100"

  monitor_thresholds {
    critical = 100
    warning  = 50
  }

  tags = ["service:auth", "env:${var.environment}", "severity:critical", "security:true"]
}

resource "datadog_monitor" "account_lockout_spike" {
  name    = "[SUMA Finance] Account Lockout Spike - Auth Service"
  type    = "metric alert"
  message = <<-EOT
    High number of account lockouts detected.
    
    Lockouts: {{value}} in the last 30 minutes
    
    Possible brute-force attack or password policy issue.
    
    @slack-security-alerts
  EOT

  query = "sum(last_30m):sum:auth.account_lockout{env:${var.environment}}.as_count() > 20"

  monitor_thresholds {
    critical = 20
    warning  = 10
  }

  tags = ["service:auth", "env:${var.environment}", "severity:warning", "security:true"]
}

resource "datadog_monitor" "database_connection_exhaustion" {
  name    = "[SUMA Finance] Database Connection Exhaustion - Auth Service"
  type    = "metric alert"
  message = <<-EOT
    Database connection pool is near exhaustion.
    
    Active connections: {{value}}
    
    @slack-platform-alerts
  EOT

  query = "avg(last_5m):avg:aws.rds.database_connections{dbinstanceidentifier:${var.rds_instance_id}} > 80"

  monitor_thresholds {
    critical = 80
    warning  = 60
  }

  tags = ["service:auth", "env:${var.environment}", "severity:critical"]
}

resource "datadog_monitor" "redis_memory_high" {
  name    = "[SUMA Finance] Redis Memory High - Auth Service"
  type    = "metric alert"
  message = <<-EOT
    Redis memory usage is high.
    
    Memory used: {{value}}%
    
    Consider scaling up or reviewing cache eviction policy.
    
    @slack-platform-alerts
  EOT

  query = "avg(last_10m):avg:aws.elasticache.database_memory_usage_percentage{cacheclusterid:${var.redis_cluster_id}} > 85"

  monitor_thresholds {
    critical = 85
    warning  = 75
  }

  tags = ["service:auth", "env:${var.environment}", "severity:warning"]
}

resource "datadog_monitor" "ecs_task_failure" {
  name    = "[SUMA Finance] ECS Task Failure - Auth Service"
  type    = "metric alert"
  message = <<-EOT
    ECS tasks are failing to start or crashing.
    
    Running tasks: {{value}}
    
    @slack-platform-alerts
    @pagerduty-platform
  EOT

  query = "avg(last_5m):avg:aws.ecs.service.running{cluster_name:${var.ecs_cluster_name},service_name:${var.ecs_service_name}} < 2"

  monitor_thresholds {
    critical = 2
  }

  notify_no_data    = true
  no_data_timeframe = 10

  tags = ["service:auth", "env:${var.environment}", "severity:critical"]
}
```

---

## 7. Security Infrastructure

### 7.1 KMS Keys

```hcl
# KMS key for RDS encryption
resource "aws_kms_key" "rds" {
  description             = "${local.name_prefix} RDS encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-rds-kms"
    }
  )
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# KMS key for Redis encryption
resource "aws_kms_key" "redis" {
  description             = "${local.name_prefix} Redis encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-redis-kms"
    }
  )
}

resource "aws_kms_alias" "redis" {
  name          = "alias/${local.name_prefix}-redis"
  target_key_id = aws_kms_key.redis.key_id
}

# KMS key for Secrets Manager
resource "aws_kms_key" "secrets" {
  description             = "${local.name_prefix} Secrets Manager encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Secrets Manager"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-secrets-kms"
    }
  )
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}
```

### 7.2 Security Groups

```hcl
# ALB Security Group
resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb"
  description = "Security group for Application Load Balancer"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from internet (redirect to HTTPS)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-alb"
    }
  )
}

# RDS Security Group
resource "aws_security_group" "rds" {
  name        = "${local.name_prefix}-rds"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.ecs.task_security_group_id]
    description     = "PostgreSQL from ECS tasks"
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-rds"
    }
  )
}

# Redis Security Group
resource "aws_security_group" "redis" {
  name        = "${local.name_prefix}-redis"
  description = "Security group for ElastiCache Redis"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.ecs.task_security_group_id]
    description     = "Redis from ECS tasks"
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-redis"
    }
  )
}
```

### 7.3 IAM Roles and Policies

```hcl
# ECS Task Execution Role
resource "aws_iam_role" "ecs_execution" {
  name = "${local.name_prefix}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "${local.name_prefix}-ecs-execution-secrets"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.db_password.arn,
          aws_secretsmanager_secret.redis_auth_token.arn,
          aws_secretsmanager_secret.jwt_private_key.arn,
          aws_secretsmanager_secret.jwt_public_key.arn,
          aws_secretsmanager_secret.sendgrid_api_key.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = [
          aws_kms_key.secrets.arn
        ]
      }
    ]
  })
}

# ECS Task Role
resource "aws_iam_role" "ecs_task" {
  name = "${local.name_prefix}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "ecs_task_cloudwatch" {
  name = "${local.name_prefix}-ecs-task-cloudwatch"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.ecs.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_xray" {
  name = "${local.name_prefix}-ecs-task-xray"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}
```

---

## 8. Database Migrations

### 8.1 Migration Tool Configuration (golang-migrate)

```bash
# Install golang-migrate
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Create new migration
migrate create -ext sql -dir migrations -seq create_users_table

# Run migrations up
migrate -path migrations -database "postgresql://user:pass@localhost:5432/suma_auth?sslmode=require" up

# Run migrations down
migrate -path migrations -database "postgresql://user:pass@localhost:5432/suma_auth?sslmode=require" down 1
```

### 8.2 Initial Schema Migration

```sql
-- migrations/000001_create_users_table.up.sql

BEGIN;

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    
    -- 2FA
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_method VARCHAR(20), -- 'email', 'sms', 'totp'
    
    -- Account status
    is_active BOOLEAN DEFAULT TRUE,
    is_locked BOOLEAN DEFAULT FALSE,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Soft delete
    deleted_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT email_lowercase CHECK (email = LOWER(email))
);

-- Indexes
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email_verified ON users(email_verified) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_is_active ON users(is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users(created_at DESC);

-- Email verification tokens
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX idx_email_verification_tokens_token ON email_verification_tokens(token) WHERE verified_at IS NULL;
CREATE INDEX idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens(token) WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

-- OTP storage
CREATE TABLE otp_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(6) NOT NULL,
    purpose VARCHAR(50) NOT NULL, -- 'login', 'password_reset', 'email_verification'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE,
    attempts INT DEFAULT 0
);

CREATE INDEX idx_otp_codes_user_id ON otp_codes(user_id);
CREATE INDEX idx_otp_codes_code_purpose ON otp_codes(code, purpose) WHERE verified_at IS NULL;
CREATE INDEX idx_otp_codes_expires_at ON otp_codes(expires_at);

-- Refresh tokens
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    device_id VARCHAR(255),
    user_agent TEXT,
    ip_address INET,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    rotation_count INT DEFAULT 0
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_device_id ON refresh_tokens(device_id);

-- Sessions
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(128) NOT NULL UNIQUE,
    device_id VARCHAR(255),
    user_agent TEXT,
    ip_address INET,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    invalidated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_session_token ON sessions(session_token) WHERE invalidated_at IS NULL;
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- GDPR consent records
CREATE TABLE consent_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consent_type VARCHAR(50) NOT NULL, -- 'terms', 'privacy', 'marketing', 'data_processing'
    consent_version VARCHAR(20) NOT NULL,
    consented BOOLEAN NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_consent_records_user_id ON consent_records(user_id);
CREATE INDEX idx_consent_records_consent_type ON consent_records(consent_type);
CREATE INDEX idx_consent_records_created_at ON consent_records(created_at DESC);

-- Audit logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL, -- 'login', 'logout', 'password_change', 'email_verification', etc.
    event_status VARCHAR(20) NOT NULL, -- 'success', 'failure'
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_metadata ON audit_logs USING GIN (metadata);

-- Password history (prevent reuse)
CREATE TABLE password_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_password_history_user_id ON password_history(user_id);
CREATE INDEX idx_password_history_created_at ON password_history(created_at DESC);

-- Device fingerprints
CREATE TABLE device_fingerprints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint_hash VARCHAR(64) NOT NULL,
    device_name VARCHAR(255),
    is_trusted BOOLEAN DEFAULT FALSE,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    flagged_at TIMESTAMP WITH TIME ZONE,
    flagged_reason TEXT
);

CREATE INDEX idx_device_fingerprints_user_id ON device_fingerprints(user_id);
CREATE INDEX idx_device_fingerprints_fingerprint_hash ON device_fingerprints(fingerprint_hash);
CREATE INDEX idx_device_fingerprints_is_trusted ON device_fingerprints(is_trusted);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for users table
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Trigger for consent_records table
CREATE TRIGGER update_consent_records_updated_at BEFORE UPDATE ON consent_records
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMIT;
```

```sql
-- migrations/000001_create_users_table.down.sql

BEGIN;

DROP TRIGGER IF EXISTS update_consent_records_updated_at ON consent_records;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();

DROP TABLE IF EXISTS device_fingerprints;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS consent_records;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS otp_codes;
DROP TABLE IF EXISTS password_reset_tokens;
DROP TABLE IF EXISTS email_verification_tokens;
DROP TABLE IF EXISTS users;

DROP EXTENSION IF EXISTS "pgcrypto";
DROP EXTENSION IF EXISTS "uuid-ossp";

COMMIT;
```

---

## 9. Cost Optimization

### 9.1 Cost Breakdown (Estimated Monthly - Production)

| Resource | Configuration | Est. Monthly Cost | Justification |
|----------|--------------|-------------------|---------------|
| **ECS Fargate** | 3-20 tasks (0.5 vCPU, 1GB) | $50-300 | Auto-scales based on load |
| **RDS PostgreSQL** | db.t4g.medium Multi-AZ + 2 replicas | $350 | High availability + read scaling |
| **ElastiCache Redis** | cache.t4g.medium 3-node cluster | $150 | Session storage + OTP caching |
| **ALB** | Multi-AZ with 1000 req/s | $30 | Load balancing |
| **CloudFront** | 1TB data transfer | $85 | Global CDN |
| **AWS WAF** | 5 rules + 10M requests | $15 | DDoS protection |
| **Secrets Manager** | 5 secrets with rotation | $10 | Secure credential storage |
| **CloudWatch Logs** | 10GB logs/month (90-day retention) | $5 | Logging and monitoring |
| **Data Transfer** | 500GB outbound | $45 | API responses |
| **Datadog** | Infrastructure + APM (3 hosts) | $100 | Observability |
| **SendGrid** | 100k emails/month | $15 | Transactional emails |
| **Total** | | **$855-1,105/month** | |

### 9.2 Cost Optimization Strategies

```hcl
# Use Savings Plans for ECS Fargate
# 1-year commitment: 20% savings
# 3-year commitment: 40% savings

# Use Reserved Instances for RDS
# 1-year partial upfront: 38% savings
# 3-year all upfront: 62% savings

# Cost optimization configurations
resource "aws_autoscaling_policy" "ecs_scale_down_aggressive" {
  count = var.environment != "production" ? 1 : 0
  
  name               = "${local.name_prefix}-scale-down-aggressive"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace
  
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    
    target_value       = 80
    scale_in_cooldown  = 60  # Faster scale-in
    scale_out_cooldown = 60
  }
}

# Use S3 lifecycle policies for logs
resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  
  rule {
    id     = "archive-old-logs"
    status = "Enabled"
    
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    
    expiration {
      days = 365
    }
  }
}

# Use spot instances for non-production
resource "aws_ecs_capacity_provider" "spot" {
  count = var.environment != "production" ? 1 : 0
  
  name = "${local.name_prefix}-fargate-spot"
  
  auto_scaling_group_provider {
    auto_scaling_group_arn = aws_autoscaling_group.ecs_spot[0].arn
    
    managed_scaling {
      maximum_scaling_step_size = 10
      minimum_scaling_step_size = 1
      status                    = "ENABLED"
      target_capacity           = 80
    }
  }
}
```

---

## 10. Disaster Recovery

### 10.1 Backup Strategy

```hcl
# RDS automated backups
resource "aws_db_instance" "main" {
  # ... other config ...
  
  backup_retention_period = var.environment == "production" ? 30 : 7
  backup_window          = "03:00-04:00"
  
  # Enable point-in-time recovery
  enabled_cloudwatch_logs_exports = ["postgresql"]
}

# Manual snapshot schedule (AWS Backup)
resource "aws_backup_plan" "auth_service" {
  name = "${local.name_prefix}-backup-plan"
  
  rule {
    rule_name         = "daily_backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 2 * * ? *)"  # 2 AM UTC daily
    
    lifecycle {
      delete_after = 90
      cold_storage_after = 30
    }
    
    recovery_point_tags = local.common_tags
  }
  
  rule {
    rule_name         = "weekly_backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 3 ? * SUN *)"  # 3 AM UTC Sundays
    
    lifecycle {
      delete_after = 365
      cold_storage_after = 90
    }
    
    recovery_point_tags = local.common_tags
  }
}

resource "aws_backup_selection" "auth_service" {
  name         = "${local.name_prefix}-backup-selection"
  plan_id      = aws_backup_plan.auth_service.id
  iam_role_arn = aws_iam_role.backup.arn
  
  resources = [
    aws_db_instance.main.arn
  ]
}

resource "aws_backup_vault" "main" {
  name        = "${local.name_prefix}-backup-vault"
  kms_key_arn = aws_kms_key.backup.arn
  
  tags = local.common_tags
}
```

### 10.2 Disaster Recovery Runbook

```markdown
# Disaster Recovery Runbook

## RPO/RTO Targets
- **RPO (Recovery Point Objective)**: 1 hour
- **RTO (Recovery Time Objective)**: 4 hours

## Scenario 1: Database Failure

### Detection
- CloudWatch alarm: RDS instance unavailable
- ECS tasks failing health checks (database connection errors)

### Recovery Steps

1. **Verify Multi-AZ Failover** (automated)
   ```bash
   aws rds describe-db-instances \
     --db-instance-identifier suma-finance-production-postgres \
     --query 'DBInstances[0].{Status:DBInstanceStatus,AZ:AvailabilityZone}'
   ```
   
   - Expected: Automatic failover to standby (60-120 seconds)

2. **If failover fails, restore from backup**
   ```bash
   # List available snapshots
   aws rds describe-db-snapshots \
     --db-instance-identifier suma-finance-production-postgres \
     --query 'DBSnapshots[0:5].{ID:DBSnapshotIdentifier,Created:SnapshotCreateTime}' \
     --output table
   
   # Restore from latest snapshot
   aws rds restore-db-instance-from-db-snapshot \
     --db-instance-identifier suma-finance-production-postgres-restored \
     --db-snapshot-identifier <snapshot-id> \
     --db-subnet-group-name suma-finance-production-db-subnet-group \
     --multi-az \
     --vpc-security-group-ids <security-group-id>
   
   # Wait for restoration (15-30 minutes)
   aws rds wait db-instance-available \
     --db-instance-identifier suma-finance-production-postgres-restored
   
   # Update ECS task definition with new endpoint
   # Deploy updated task definition
   ```

3. **Verify data integrity**
   ```sql
   -- Connect to restored database
   SELECT COUNT(*) FROM users;
   SELECT MAX(created_at) FROM audit_logs;
   ```

## Scenario 2: Redis Cluster Failure

### Detection
- CloudWatch alarm: ElastiCache cluster unavailable
- High error rate in session validation

### Recovery Steps

1. **Verify automatic failover** (automated for multi-AZ)
   ```bash
   aws elasticache describe-replication-groups \
     --replication-group-id suma-finance-production-redis \
     --query 'ReplicationGroups[0].{Status:Status,Primary:NodeGroups[0].PrimaryEndpoint}'
   ```

2. **If failover fails, restore from snapshot**
   ```bash
   # List snapshots
   aws elasticache describe-snapshots \
     --replication-group-id suma-finance-production-redis
   
   # Create new cluster from snapshot
   aws elasticache create-replication-group \
     --replication-group-id suma-finance-production-redis-restored \
     --replication-group-description "Restored Redis cluster" \
     --snapshot-name <snapshot-name> \
     --engine redis \
     --cache-node-type cache.t4g.medium \
     --num-cache-clusters 3 \
     --automatic-failover-enabled \
     --multi-az-enabled
   ```

3. **Impact assessment**
   - All active sessions will be lost
   - Users will need to re-authenticate
   - OTP codes will need to be regenerated

## Scenario 3: Complete Region Failure

### Detection
- Multiple service failures across all availability zones
- AWS Health Dashboard shows region-wide outage

### Recovery Steps

1. **Initiate cross-region failover**
   ```bash
   # Update Route53 to point to DR region
   aws route53 change-resource-record-sets \
     --hosted-zone-id <zone-id> \
     --change-batch file://failover-dns.json
   
   # failover-dns.json
   {
     "Changes": [{
       "Action": "UPSERT",
       "ResourceRecordSet": {
         "Name": "auth.suma-finance.com",
         "Type": "CNAME",
         "TTL": 60,
         "ResourceRecords": [{"Value": "dr-region-alb-dns-name"}]
       }
     }]
   }
   ```

2. **Restore database in DR region**
   ```bash
   # Promote read replica in DR region (if configured)
   aws rds promote-read-replica \
     --db-instance-identifier suma-finance-dr-postgres-replica \
     --region us-west-2
   ```

3. **Start ECS services in DR region**
   ```bash
   aws ecs update-service \
     --cluster suma-finance-dr-cluster \
     --service suma-finance-dr-service \
     --desired-count 3 \
     --region us-west-2
   ```

4. **Communicate with users**
   - Post status update on status page
   - Send email notification about temporary disruption
   - Monitor social media for user reports

## Scenario 4: Data Breach / Security Incident

### Detection
- Unusual spike in failed login attempts
- Datadog security alert
- User reports of suspicious activity

### Immediate Actions

1. **Isolate affected systems**
   ```bash
   # Revoke all refresh tokens
   psql -c "UPDATE refresh_tokens SET revoked_at = NOW() WHERE revoked_at IS NULL;"
   
   # Invalidate all sessions
   redis-cli --scan --pattern "session:*" | xargs redis-cli DEL
   ```

2. **Enable additional WAF rules**
   ```bash
   aws wafv2 update-web-acl \
     --id <web-acl-id> \
     --scope REGIONAL \
     --add-rule file://emergency-rate-limit.json
   ```

3. **Notify security team and stakeholders**

4. **Begin forensic analysis**
   ```bash
   # Export audit logs for analysis
   aws logs create-export-task \
     --log-group-name /ecs/suma-finance-production \
     --from 1640000000000 \
     --to 1640100000000 \
     --destination s3-bucket-name \
     --destination-prefix forensics/
   ```

5. **Comply with GDPR breach notification** (within 72 hours)

## Post-Incident

1. **Conduct post-mortem**
2. **Update runbooks**
3. **Test recovery procedures**
4. **Implement preventive measures**
```

---

## 11. Deployment Checklist

### 11.1 Pre-Deployment

- [ ] Terraform plan reviewed and approved
- [ ] Security scan passed (Trivy, gosec)
- [ ] All tests passing (unit, integration, e2e)
- [ ] Code review completed
- [ ] Database migrations tested
- [ ] Secrets rotated (JWT keys, DB passwords)
- [ ] Backup verified
- [ ] Rollback plan documented
- [ ] Stakeholders notified

### 11.2 Deployment

- [ ] Deploy to staging environment
- [ ] Run smoke tests on staging
- [ ] Load testing completed
- [ ] Security testing (OWASP ZAP, penetration test)
- [ ] GDPR compliance verified
- [ ] Deploy to production (blue/green or canary)
- [ ] Monitor metrics and logs
- [ ] Verify health checks passing

### 11.3 Post-Deployment

- [ ] Run smoke tests on production
- [ ] Verify key flows (registration, login, 2FA)
- [ ] Check Datadog dashboard
- [ ] Review CloudWatch alarms
- [ ] Verify database performance
- [ ] Check Redis hit rate
- [ ] Monitor error rates
- [ ] Update documentation
- [ ] Notify stakeholders of successful deployment

---

## 12. Maintenance and Operations

### 12.1 Regular Maintenance Tasks

| Task | Frequency | Owner | Automation |
|------|-----------|-------|------------|
| **Rotate JWT keys** | 90 days | Platform | Lambda (automated) |
| **Rotate DB passwords** | 90 days | Platform | Lambda (automated) |
| **Review IAM policies** | 30 days | Security | Manual |
| **Update dependencies** | Weekly | Engineering | Dependabot |
| **Review CloudWatch logs** | Daily | SRE | Datadog alerts |
| **Database maintenance window** | Monthly | DBA | RDS (automated) |
| **Security patching** | As needed | Platform | GitHub Actions |
| **Cost review** | Monthly | FinOps | AWS Cost Explorer |
| **DR drill** | Quarterly | SRE | Runbook |
| **Backup verification** | Weekly | Platform | AWS Backup |
| **Certificate renewal** | 60 days before expiry | Platform | ACM (automated) |

### 12.2 Scaling Triggers

```yaml
# Auto-scaling policies

CPU-based:
  scale_out:
    threshold: 70%
    duration: 2 minutes
    cooldown: 60 seconds
    increment: +2 tasks
  
  scale_in:
    threshold: 30%
    duration: 5 minutes
    cooldown: 300 seconds
    decrement: -1 task

Memory-based:
  scale_out:
    threshold: 80%
    duration: 2 minutes
    cooldown: 60 seconds
    increment: +2 tasks
  
  scale_in:
    threshold: 40%
    duration: 5 minutes
    cooldown: 300 seconds
    decrement: -1 task

Request-based:
  scale_out:
    threshold: 1000 requests/min per task
    duration: 1 minute
    cooldown: 60 seconds
    increment: +3 tasks
  
  scale_in:
    threshold: 300 requests/min per task
    duration: 5 minutes
    cooldown: 300 seconds
    decrement: -1 task

Response time-based:
  scale_out:
    threshold: P95 > 200ms
    duration: 3 minutes
    cooldown: 60 seconds
    increment: +2 tasks
```

### 12.3 Capacity Planning

```python
# Capacity planning script

def estimate_capacity(
    expected_users: int,
    avg_requests_per_user_per_day: int = 10,
    peak_factor: float = 3.0,
    avg_response_time_ms: int = 100,
) -> dict:
    """
    Estimate required infrastructure capacity.
    
    Args:
        expected_users: Number of active users
        avg_requests_per_user_per_day: Average API requests per user per day
        peak_factor: Peak traffic multiplier (default 3x average)
        avg_response_time_ms: Average response time in milliseconds
    
    Returns:
        Capacity recommendations
    """
    # Calculate requests per second
    total_requests_per_day = expected_users * avg_requests_per_user_per_day
    avg_rps = total_requests_per_day / 86400  # seconds in a day
    peak_rps = avg_rps * peak_factor
    
    # Estimate ECS tasks needed
    # Assume 100 req/s per task at 50% CPU
    tasks_needed = math.ceil(peak_rps / 100)
    min_tasks = max(3, math.ceil(tasks_needed * 0.3))  # 30% minimum capacity
    max_tasks = math.ceil(tasks_needed * 1.2)  # 20% buffer
    
    # Estimate database connections
    # 10 connections per task
    db_connections_needed = max_tasks * 10
    
    # Estimate Redis memory
    # 1KB per session, 1-hour session duration
    concurrent_sessions = expected_users * 0.1  # 10% concurrent
    redis_memory_mb = (concurrent_sessions * 1) / 1024  # KB to MB
    
    return {
        "expected_users": expected_users,
        "avg_rps": round(avg_rps, 2),
        "peak_rps": round(peak_rps, 2),
        "ecs_tasks": {
            "min": min_tasks,
            "desired": tasks_needed,
            "max": max_tasks
        },
        "rds": {
            "instance_class": "db.t4g.medium" if db_connections_needed < 100 else "db.r6g.large",
            "max_connections": db_connections_needed,
            "read_replicas": 2 if expected_users > 50000 else 1
        },
        "redis": {
            "node_type": "cache.t4g.medium" if redis_memory_mb < 3000 else "cache.r6g.large",
            "memory_needed_mb": round(redis_memory_mb, 2),
            "num_nodes": 3
        }
    }

# Example usage
print(estimate_capacity(expected_users=100000))
```

---

## 13. Summary

This Infrastructure as Code specification provides a complete, production-ready infrastructure for the SUMA Finance authentication service with:

**Security First:**
- Multi-layer defense (WAF, security groups, encryption at rest and in transit)
- Compliance with GDPR, PCI-DSS, SOC2, OWASP Top 10
- Automated secret rotation and key management
- Comprehensive audit logging

**High Availability:**
- Multi-AZ deployment across 3 availability zones
- Automatic failover for RDS and Redis
- Auto-scaling ECS tasks (3-20 instances)
- 99.95% uptime SLA

**Performance:**
- Sub-200ms API response times
- Redis-backed session management (< 10ms lookups)
- CloudFront CDN for global distribution
- Read replicas for database scaling

**Observability:**
- Datadog for metrics, logs, and traces
- CloudWatch for AWS-native monitoring
- 27 alerts covering security, performance, and availability
- Comprehensive audit trails

**Cost Optimization:**
- Estimated $855-1,105/month for production
- Auto-scaling to match demand
- Spot instances for non-production
- S3 lifecycle policies for log archival

**Disaster Recovery:**
- RPO: 1 hour, RTO: 4 hours
- Automated backups with 30-day retention
- Cross-region failover capability
- Documented runbooks for common scenarios

**Deployment:**
- GitOps workflow with GitHub Actions
- Automated security scanning (Trivy, gosec)
- Blue/green deployments with ECS
- Zero-downtime deployments

All infrastructure is defined as code using Terraform, enabling version control, peer review, and reproducible deployments across environments.
