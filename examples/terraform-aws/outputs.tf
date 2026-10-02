# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

output "vpc_id" {
  description = "ID of the agent governance VPC."
  value       = aws_vpc.this.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets where agent workloads run."
  value       = aws_subnet.private[*].id
}

output "agent_security_group_id" {
  description = "Security group ID for agent workloads (egress-only)."
  value       = aws_security_group.agents.id
}

output "kms_key_arn" {
  description = "ARN of the non-exportable Ed25519 KMS key used for receipt signatures."
  value       = aws_kms_key.receipt_signing.arn
}

output "kms_encryption_key_arn" {
  description = "ARN of the auto-rotating symmetric KMS key used to encrypt audit logs."
  value       = aws_kms_key.encryption.arn
}

output "kms_key_alias" {
  description = "Alias of the KMS receipt signing key."
  value       = aws_kms_alias.receipt_signing.name
}

output "audit_log_bucket" {
  description = "Name of the S3 bucket storing governance audit logs."
  value       = aws_s3_bucket.audit_logs.bucket
}

output "audit_log_bucket_arn" {
  description = "ARN of the audit log S3 bucket."
  value       = aws_s3_bucket.audit_logs.arn
}

output "agent_iam_role_arn" {
  description = "ARN of the IAM role for agent ECS tasks / EC2 instances."
  value       = aws_iam_role.agent.arn
}

output "agent_instance_profile_arn" {
  description = "ARN of the EC2 instance profile for agent workloads."
  value       = aws_iam_instance_profile.agent.arn
}

output "cloudwatch_log_group" {
  description = "Name of the CloudWatch Log Group for governance events."
  value       = aws_cloudwatch_log_group.governance.name
}

output "ssm_parameter_prefix" {
  description = "SSM parameter path prefix. Agents read AGT_* config from <prefix>/<param>."
  value       = "/${var.project}-${var.environment}/agt"
}
