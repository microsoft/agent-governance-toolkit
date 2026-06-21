# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Example: governed agent infrastructure on AWS
#
# Provisions all AWS resources required to run AGT-governed agents in production:
#   - VPC with private subnets (agents) and public subnets (NAT gateways)
#   - Egress-only security group for agent workloads (HTTPS only, no inbound)
#   - KMS key (auto-rotating) for Ed25519 receipt signing and audit log encryption
#   - S3 bucket with versioning, KMS encryption, lifecycle tiers, and TLS enforcement
#   - IAM role + instance profile with least-privilege permissions
#   - Secrets Manager secret for the Ed25519 signing key PEM
#   - SSM parameters for all AGT_* governance config values agents read at runtime
#   - CloudWatch Log Group for structured governance events
#
# Usage:
#   cd examples/terraform-aws
#   terraform init
#   terraform plan -var="project=myagent"
#   terraform apply -var="project=myagent"
#
# Agents read governance config from SSM at runtime:
#   aws ssm get-parameters-by-path --path "/<project>-<env>/agt/"

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  name_prefix = "${var.project}-${var.environment}"

  common_tags = merge(var.tags, {
    "agt:project"     = var.project
    "agt:environment" = var.environment
    "agt:trust-level" = var.trust_level
    "agt:managed-by"  = "terraform"
  })
}

# ── Data sources ──────────────────────────────────────────────────────────────

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── VPC ───────────────────────────────────────────────────────────────────────

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-vpc" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "${local.name_prefix}-igw" })
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name                              = "${local.name_prefix}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name                     = "${local.name_prefix}-public-${count.index + 1}"
    "kubernetes.io/role/elb" = "1"
  })
}

resource "aws_eip" "nat" {
  count  = length(var.public_subnet_cidrs)
  domain = "vpc"
  tags   = merge(local.common_tags, { Name = "${local.name_prefix}-nat-eip-${count.index + 1}" })
}

resource "aws_nat_gateway" "this" {
  count         = length(var.public_subnet_cidrs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(local.common_tags, { Name = "${local.name_prefix}-nat-${count.index + 1}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-public-rt" })
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count  = length(var.private_subnet_cidrs)
  vpc_id = aws_vpc.this.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[count.index].id
  }
  tags = merge(local.common_tags, { Name = "${local.name_prefix}-private-rt-${count.index + 1}" })
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ── Security group for agent workloads (egress-only) ─────────────────────────

resource "aws_security_group" "agents" {
  name        = "${local.name_prefix}-agents"
  description = "Governed agent workloads — HTTPS egress only, no inbound."
  vpc_id      = aws_vpc.this.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS egress for LLM API calls"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "Intra-VPC traffic"
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-agents-sg" })
}

# ── KMS key for receipt signing and audit log encryption ─────────────────────

resource "aws_kms_key" "receipt_signing" {
  description             = "AGT governance receipt signing key for ${local.name_prefix}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = var.receipt_signing_key_rotation_days
  multi_region            = false

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
        Sid    = "AllowAgentRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.agent.arn
        }
        Action = [
          "kms:GenerateDataKeyPair",
          "kms:Sign",
          "kms:Verify",
          "kms:DescribeKey",
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-receipt-signing" })
}

resource "aws_kms_alias" "receipt_signing" {
  name          = "alias/${local.name_prefix}-receipt-signing"
  target_key_id = aws_kms_key.receipt_signing.key_id
}

# ── S3 audit log bucket ───────────────────────────────────────────────────────

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "audit_logs" {
  bucket        = "${local.name_prefix}-audit-${random_id.bucket_suffix.hex}"
  force_destroy = var.environment != "prod"

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-audit-logs" })
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.receipt_signing.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    id     = "audit-retention"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket     = aws_s3_bucket.audit_logs.id
  depends_on = [aws_s3_bucket_public_access_block.audit_logs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid    = "AllowAgentRole"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.agent.arn
        }
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.audit_logs.arn}/*"
      }
    ]
  })
}

# ── IAM role for agent workloads ──────────────────────────────────────────────

data "aws_iam_policy_document" "agent_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com", "ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "agent" {
  name               = "${local.name_prefix}-agent-role"
  assume_role_policy = data.aws_iam_policy_document.agent_assume_role.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "agent_permissions" {
  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]
    resources = ["arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${local.name_prefix}/agt/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${aws_s3_bucket.audit_logs.arn}/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.signing_key.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:GenerateDataKeyPair",
      "kms:Sign",
      "kms:Verify",
      "kms:DescribeKey",
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.receipt_signing.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.governance.arn}:*"]
  }
}

resource "aws_iam_policy" "agent" {
  name        = "${local.name_prefix}-agent-policy"
  description = "Least-privilege AGT governance permissions for agent workloads."
  policy      = data.aws_iam_policy_document.agent_permissions.json
  tags        = local.common_tags
}

resource "aws_iam_role_policy_attachment" "agent" {
  role       = aws_iam_role.agent.name
  policy_arn = aws_iam_policy.agent.arn
}

resource "aws_iam_instance_profile" "agent" {
  name = "${local.name_prefix}-agent-profile"
  role = aws_iam_role.agent.name
  tags = local.common_tags
}

# ── Secrets Manager — Ed25519 signing key ────────────────────────────────────

resource "aws_secretsmanager_secret" "signing_key" {
  name                    = "${local.name_prefix}/agt/signing-key"
  description             = "Ed25519 private key PEM for AGT governance receipt signing."
  recovery_window_in_days = var.environment == "prod" ? 30 : 7
  kms_key_id              = aws_kms_key.receipt_signing.arn

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-signing-key" })
}

# ── SSM parameters — AGT governance config ────────────────────────────────────
# Mirrors GovernanceConfig fields from agent-runtime/deploy.py.
# Agents read these at startup instead of relying on baked-in env vars.

resource "aws_ssm_parameter" "trust_level" {
  name  = "/${local.name_prefix}/agt/trust-level"
  type  = "String"
  value = var.trust_level
  tags  = local.common_tags
}

resource "aws_ssm_parameter" "max_tool_calls" {
  name  = "/${local.name_prefix}/agt/max-tool-calls"
  type  = "String"
  value = tostring(var.max_tool_calls)
  tags  = local.common_tags
}

resource "aws_ssm_parameter" "rate_limit_rpm" {
  name  = "/${local.name_prefix}/agt/rate-limit-rpm"
  type  = "String"
  value = tostring(var.rate_limit_rpm)
  tags  = local.common_tags
}

resource "aws_ssm_parameter" "audit_enabled" {
  name  = "/${local.name_prefix}/agt/audit-enabled"
  type  = "String"
  value = tostring(var.audit_enabled)
  tags  = local.common_tags
}

resource "aws_ssm_parameter" "kill_switch_enabled" {
  name  = "/${local.name_prefix}/agt/kill-switch-enabled"
  type  = "String"
  value = tostring(var.kill_switch_enabled)
  tags  = local.common_tags
}

resource "aws_ssm_parameter" "audit_bucket" {
  name  = "/${local.name_prefix}/agt/audit-bucket"
  type  = "String"
  value = aws_s3_bucket.audit_logs.bucket
  tags  = local.common_tags
}

# ── CloudWatch Log Group for governance events ────────────────────────────────

resource "aws_cloudwatch_log_group" "governance" {
  name              = "/agt/${local.name_prefix}/governance"
  retention_in_days = min(var.retention_days, 365)
  kms_key_id        = aws_kms_key.receipt_signing.arn

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-governance-logs" })
}
