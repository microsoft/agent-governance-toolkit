# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

variable "project" {
  description = "Project name used as a prefix for all resource names."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{3,24}$", var.project))
    error_message = "project must be 3-24 lowercase alphanumeric characters or hyphens."
  }
}

variable "environment" {
  description = "Deployment environment: dev, staging, or prod."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

# ── Governance config (mirrors GovernanceConfig in agent-runtime/deploy.py) ──

variable "trust_level" {
  description = "AGT trust tier injected into agent containers via AGT_TRUST_LEVEL."
  type        = string
  default     = "standard"

  validation {
    condition     = contains(["unclassified", "basic", "standard", "elevated", "critical"], var.trust_level)
    error_message = "trust_level must be one of: unclassified, basic, standard, elevated, critical."
  }
}

variable "max_tool_calls" {
  description = "Maximum tool calls per agent session (AGT_MAX_TOOL_CALLS)."
  type        = number
  default     = 100
}

variable "rate_limit_rpm" {
  description = "Agent request rate cap in requests per minute (AGT_RATE_LIMIT_RPM)."
  type        = number
  default     = 60
}

variable "audit_enabled" {
  description = "Whether to enable AGT audit logging (AGT_AUDIT_ENABLED)."
  type        = bool
  default     = true
}

variable "kill_switch_enabled" {
  description = "Whether to enable the AGT kill switch (AGT_KILL_SWITCH)."
  type        = bool
  default     = true
}

variable "retention_days" {
  description = "Days to retain audit logs in S3 (AGT_RETENTION_DAYS). Must be >= 180."
  type        = number
  default     = 180

  validation {
    condition     = var.retention_days >= 180
    error_message = "retention_days must be at least 180 for compliance."
  }
}

# ── Networking ────────────────────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "CIDR block for the agent governance VPC."
  type        = string
  default     = "10.10.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ). Agent workloads run here."
  type        = list(string)
  default     = ["10.10.1.0/24", "10.10.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets hosting NAT gateways."
  type        = list(string)
  default     = ["10.10.101.0/24", "10.10.102.0/24"]
}

# ── Receipt signing ───────────────────────────────────────────────────────────

variable "receipt_signing_key_rotation_days" {
  description = "Automatic KMS key rotation period in days for governance receipt signing."
  type        = number
  default     = 365
}

# ── Tags ──────────────────────────────────────────────────────────────────────

variable "tags" {
  description = "Additional tags applied to all resources."
  type        = map(string)
  default     = {}
}
