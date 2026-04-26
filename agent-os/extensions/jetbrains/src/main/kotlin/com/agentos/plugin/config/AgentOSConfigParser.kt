package com.agentos.plugin.config

import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import org.yaml.snakeyaml.Yaml
import java.io.StringReader

/**
 * Parser for .agentos.yml project configuration files.
 * 
 * Example configuration:
 * ```yaml
 * organization: acme-corp
 * policies:
 *   - production-safety
 *   - pci-dss-compliance
 * 
 * agents:
 *   order-processor:
 *     language: java
 *     trigger: order_created_event
 *     policies:
 *       - payment-processing
 *     approval: single
 * ```
 */
class AgentOSConfigParser {
    
    private val logger = Logger.getInstance(AgentOSConfigParser::class.java)
    
    /**
     * Parse .agentos.yml content into a configuration object.
     */
    fun parse(content: String): AgentOSConfig? {
        return try {
            val yaml = Yaml()
            val data = yaml.load<Map<String, Any>>(StringReader(content))
            parseConfig(data)
        } catch (e: Exception) {
            logger.warn("Failed to parse .agentos.yml: ${e.message}")
            null
        }
    }
    
    /**
     * Parse configuration from a VirtualFile.
     */
    fun parse(file: VirtualFile): AgentOSConfig? {
        return try {
            val content = String(file.contentsToByteArray())
            parse(content)
        } catch (e: Exception) {
            logger.warn("Failed to read .agentos.yml: ${e.message}")
            null
        }
    }
    
    /**
     * Find and parse .agentos.yml in a project.
     */
    fun findAndParse(project: Project): AgentOSConfig? {
        val baseDir = project.baseDir ?: return null
        val configFile = baseDir.findChild(".agentos.yml") 
            ?: baseDir.findChild(".agentos.yaml")
            ?: return null
        return parse(configFile)
    }
    
    private fun parseConfig(data: Map<String, Any>): AgentOSConfig {
        val organization = data["organization"] as? String ?: ""
        val policies = (data["policies"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
        
        val agentsData = data["agents"] as? Map<*, *> ?: emptyMap<String, Any>()
        val agents = agentsData.mapNotNull { (key, value) ->
            val name = key as? String ?: return@mapNotNull null
            val agentData = value as? Map<*, *> ?: return@mapNotNull null
            parseAgentConfig(name, agentData)
        }
        
        return AgentOSConfig(
            organization = organization,
            policies = policies,
            agents = agents,
            settings = parseSettings(data["settings"] as? Map<*, *>)
        )
    }
    
    private fun parseAgentConfig(name: String, data: Map<*, *>): AgentConfigEntry {
        return AgentConfigEntry(
            name = name,
            language = data["language"] as? String ?: "java",
            trigger = data["trigger"] as? String ?: "manual",
            schedule = data["schedule"] as? String,
            policies = (data["policies"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList(),
            approval = data["approval"] as? String ?: "none",
            description = data["description"] as? String ?: "",
            environment = (data["environment"] as? Map<*, *>)?.mapNotNull { (k, v) -> 
                val key = k as? String ?: return@mapNotNull null
                val value = v as? String ?: return@mapNotNull null
                key to value
            }?.toMap() ?: emptyMap()
        )
    }
    
    private fun parseSettings(data: Map<*, *>?): ConfigSettings {
        if (data == null) return ConfigSettings()
        
        return ConfigSettings(
            autoSync = data["auto_sync"] as? Boolean ?: true,
            notifyOnBlock = data["notify_on_block"] as? Boolean ?: true,
            auditRetentionDays = (data["audit_retention_days"] as? Number)?.toInt() ?: 7,
            cmvkEnabled = data["cmvk_enabled"] as? Boolean ?: false,
            cmvkModels = (data["cmvk_models"] as? List<*>)?.mapNotNull { it as? String } ?: emptyList()
        )
    }
    
    /**
     * Validate a configuration.
     */
    fun validate(config: AgentOSConfig): List<ConfigValidationError> {
        val errors = mutableListOf<ConfigValidationError>()
        
        // Validate agents
        for (agent in config.agents) {
            if (agent.name.isBlank()) {
                errors.add(ConfigValidationError("Agent name cannot be empty", "agents"))
            }
            
            if (agent.trigger == "scheduled" && agent.schedule.isNullOrBlank()) {
                errors.add(ConfigValidationError("Scheduled agent '${agent.name}' requires a schedule", "agents.${agent.name}.schedule"))
            }
            
            val validLanguages = listOf("java", "kotlin", "python", "javascript", "typescript", "go", "php", "ruby", "csharp")
            if (agent.language !in validLanguages) {
                errors.add(ConfigValidationError("Invalid language '${agent.language}' for agent '${agent.name}'", "agents.${agent.name}.language"))
            }
            
            val validApprovals = listOf("none", "single", "multi", "auto")
            if (agent.approval !in validApprovals) {
                errors.add(ConfigValidationError("Invalid approval mode '${agent.approval}' for agent '${agent.name}'", "agents.${agent.name}.approval"))
            }
        }
        
        return errors
    }
    
    /**
     * Generate a default .agentos.yml template.
     */
    fun generateTemplate(projectName: String = "my-project"): String {
        return """
            # AgentOS Configuration
            # Documentation: https://docs.agent-os.dev/config
            
            organization: my-org
            
            # Global policies applied to all agents
            policies:
              - production-safety
              - secret-exposure
            
            # Agent definitions
            agents:
              code-reviewer:
                description: Reviews pull requests for code quality
                language: kotlin
                trigger: git_push
                policies:
                  - code-quality
                  - security-scan
                approval: auto
            
              test-generator:
                description: Generates unit tests for new code
                language: java
                trigger: on_file_save
                policies:
                  - test-coverage
                approval: none
            
              dependency-updater:
                description: Keeps dependencies up to date
                language: kotlin
                trigger: scheduled
                schedule: "0 0 * * 1"  # Weekly on Monday
                policies:
                  - dependency-security
                approval: single
            
            # Optional settings
            settings:
              auto_sync: true
              notify_on_block: true
              audit_retention_days: 30
              cmvk_enabled: false
        """.trimIndent()
    }
}

/**
 * Represents a parsed .agentos.yml configuration.
 */
data class AgentOSConfig(
    val organization: String,
    val policies: List<String>,
    val agents: List<AgentConfigEntry>,
    val settings: ConfigSettings = ConfigSettings()
)

/**
 * Individual agent configuration from .agentos.yml.
 */
data class AgentConfigEntry(
    val name: String,
    val language: String,
    val trigger: String,
    val schedule: String?,
    val policies: List<String>,
    val approval: String,
    val description: String = "",
    val environment: Map<String, String> = emptyMap()
)

/**
 * Settings section of .agentos.yml.
 */
data class ConfigSettings(
    val autoSync: Boolean = true,
    val notifyOnBlock: Boolean = true,
    val auditRetentionDays: Int = 7,
    val cmvkEnabled: Boolean = false,
    val cmvkModels: List<String> = emptyList()
)

/**
 * Validation error for configuration.
 */
data class ConfigValidationError(
    val message: String,
    val path: String
)
