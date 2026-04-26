package com.agentos.plugin.agents

import java.time.LocalDateTime
import java.util.UUID

/**
 * Represents an AgentOS agent with its configuration and state.
 */
data class Agent(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val description: String = "",
    val language: AgentLanguage = AgentLanguage.JAVA,
    val trigger: AgentTrigger = AgentTrigger.MANUAL,
    val schedule: String? = null,
    val policies: List<String> = emptyList(),
    val approvalMode: ApprovalMode = ApprovalMode.NONE,
    val status: AgentStatus = AgentStatus.STOPPED,
    val createdAt: LocalDateTime = LocalDateTime.now(),
    val lastRunAt: LocalDateTime? = null,
    val configPath: String? = null
)

/**
 * Supported programming languages for agents.
 */
enum class AgentLanguage(val displayName: String, val fileExtension: String) {
    JAVA("Java", "java"),
    KOTLIN("Kotlin", "kt"),
    PYTHON("Python", "py"),
    JAVASCRIPT("JavaScript", "js"),
    TYPESCRIPT("TypeScript", "ts"),
    GO("Go", "go"),
    PHP("PHP", "php"),
    RUBY("Ruby", "rb"),
    CSHARP("C#", "cs")
}

/**
 * Agent trigger types.
 */
enum class AgentTrigger(val displayName: String) {
    MANUAL("Manual"),
    ON_FILE_SAVE("On file save"),
    ON_COMMIT("Git pre-commit"),
    SCHEDULED("Scheduled (cron)"),
    EVENT("Event-driven"),
    API("API webhook")
}

/**
 * Approval modes for agent actions.
 */
enum class ApprovalMode(val displayName: String) {
    NONE("No approval required"),
    SINGLE("Single approval"),
    MULTI("Multi-person approval"),
    AUTO("Auto-approve if safe")
}

/**
 * Agent runtime status.
 */
enum class AgentStatus(val displayName: String, val icon: String) {
    RUNNING("Running", "🟢"),
    PAUSED("Paused", "🟡"),
    STOPPED("Stopped", "⚪"),
    ERROR("Error", "🔴"),
    PENDING_APPROVAL("Pending Approval", "🟠")
}

/**
 * Agent template for quick creation.
 */
data class AgentTemplate(
    val id: String,
    val name: String,
    val description: String,
    val category: TemplateCategory,
    val defaultLanguage: AgentLanguage,
    val defaultTrigger: AgentTrigger,
    val recommendedPolicies: List<String>,
    val icon: String
)

/**
 * Template categories.
 */
enum class TemplateCategory(val displayName: String, val icon: String) {
    DATA_PROCESSING("Data Processing", "🔄"),
    API_INTEGRATION("API Integration", "🌐"),
    TESTING("Testing & Quality", "🧪"),
    DEPLOYMENT("Deployment", "📦"),
    CODE_REVIEW("Code Review", "🔍"),
    SECURITY("Security", "🛡️"),
    DOCUMENTATION("Documentation", "📝"),
    CUSTOM("Custom", "⚙️")
}

/**
 * Audit log entry for agent actions.
 */
data class AuditLogEntry(
    val id: String = UUID.randomUUID().toString(),
    val agentId: String,
    val agentName: String,
    val action: String,
    val result: AuditResult,
    val details: String,
    val timestamp: LocalDateTime = LocalDateTime.now(),
    val policyViolations: List<String> = emptyList()
)

/**
 * Audit result types.
 */
enum class AuditResult(val displayName: String, val icon: String) {
    SUCCESS("Success", "✅"),
    BLOCKED("Blocked", "🚫"),
    WARNING("Warning", "⚠️"),
    APPROVED("Approved", "👍"),
    DENIED("Denied", "👎")
}

/**
 * Policy definition.
 */
data class Policy(
    val id: String,
    val name: String,
    val description: String,
    val rules: List<PolicyRule>,
    val enabled: Boolean = true,
    val builtIn: Boolean = false
)

/**
 * Individual policy rule.
 */
data class PolicyRule(
    val id: String,
    val name: String,
    val condition: String,
    val action: PolicyAction,
    val severity: PolicySeverity
)

/**
 * Policy actions.
 */
enum class PolicyAction(val displayName: String) {
    ALLOW("Allow"),
    BLOCK("Block"),
    REQUIRE_APPROVAL("Require Approval"),
    LOG("Log Only"),
    THROTTLE("Rate Limit")
}

/**
 * Policy severity levels.
 */
enum class PolicySeverity(val displayName: String, val color: String) {
    INFO("Info", "#2196F3"),
    WARNING("Warning", "#FF9800"),
    ERROR("Error", "#F44336"),
    CRITICAL("Critical", "#9C27B0")
}
