package com.agentos.plugin.agents

import com.agentos.plugin.services.AgentOSApiService
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.project.Project
import java.time.LocalDateTime
import java.util.concurrent.ConcurrentHashMap

/**
 * Service for managing agents within a project.
 * Provides CRUD operations and state management for agents.
 */
@Service(Service.Level.PROJECT)
class AgentService(private val project: Project) {
    
    private val logger = Logger.getInstance(AgentService::class.java)
    private val apiService = AgentOSApiService.getInstance()
    
    // Local cache of agents
    private val agents = ConcurrentHashMap<String, Agent>()
    
    // Listeners for agent state changes
    private val listeners = mutableListOf<AgentStateListener>()
    
    /**
     * Get all agents for the current project.
     */
    fun getAgents(): List<Agent> = agents.values.toList()
    
    /**
     * Get an agent by ID.
     */
    fun getAgent(id: String): Agent? = agents[id]
    
    /**
     * Create a new agent.
     */
    fun createAgent(
        name: String,
        description: String = "",
        language: AgentLanguage = AgentLanguage.JAVA,
        trigger: AgentTrigger = AgentTrigger.MANUAL,
        schedule: String? = null,
        policies: List<String> = emptyList(),
        approvalMode: ApprovalMode = ApprovalMode.NONE
    ): Agent {
        val agent = Agent(
            name = name,
            description = description,
            language = language,
            trigger = trigger,
            schedule = schedule,
            policies = policies,
            approvalMode = approvalMode,
            status = AgentStatus.STOPPED
        )
        
        agents[agent.id] = agent
        notifyAgentCreated(agent)
        
        // Sync with backend
        apiService.createAgent(agent).thenAccept { syncedAgent ->
            agents[syncedAgent.id] = syncedAgent
            logger.info("Agent ${agent.name} synced with backend")
        }
        
        return agent
    }
    
    /**
     * Create an agent from a template.
     */
    fun createAgentFromTemplate(template: AgentTemplate, name: String): Agent {
        return createAgent(
            name = name,
            description = "Created from ${template.name} template",
            language = template.defaultLanguage,
            trigger = template.defaultTrigger,
            policies = template.recommendedPolicies
        )
    }
    
    /**
     * Update an existing agent.
     */
    fun updateAgent(id: String, updates: (Agent) -> Agent): Agent? {
        val existing = agents[id] ?: return null
        val updated = updates(existing)
        agents[id] = updated
        notifyAgentUpdated(updated)
        return updated
    }
    
    /**
     * Delete an agent.
     */
    fun deleteAgent(id: String): Boolean {
        val agent = agents.remove(id)
        if (agent != null) {
            notifyAgentDeleted(agent)
            return true
        }
        return false
    }
    
    /**
     * Start an agent.
     */
    fun startAgent(id: String) {
        updateAgent(id) { agent ->
            agent.copy(
                status = AgentStatus.RUNNING,
                lastRunAt = LocalDateTime.now()
            )
        }
        apiService.startAgent(id)
    }
    
    /**
     * Stop an agent.
     */
    fun stopAgent(id: String) {
        updateAgent(id) { agent ->
            agent.copy(status = AgentStatus.STOPPED)
        }
        apiService.stopAgent(id)
    }
    
    /**
     * Pause an agent.
     */
    fun pauseAgent(id: String) {
        updateAgent(id) { agent ->
            agent.copy(status = AgentStatus.PAUSED)
        }
        apiService.pauseAgent(id)
    }
    
    /**
     * Resume a paused agent.
     */
    fun resumeAgent(id: String) {
        updateAgent(id) { agent ->
            agent.copy(
                status = AgentStatus.RUNNING,
                lastRunAt = LocalDateTime.now()
            )
        }
        apiService.startAgent(id)
    }
    
    /**
     * Load agents from backend.
     */
    fun refreshAgents() {
        apiService.listAgents().thenAccept { remoteAgents ->
            agents.clear()
            remoteAgents.forEach { agent ->
                agents[agent.id] = agent
            }
            notifyAgentsRefreshed()
        }
    }
    
    /**
     * Get available agent templates.
     */
    fun getTemplates(): List<AgentTemplate> = listOf(
        AgentTemplate(
            id = "data-processing",
            name = "Data Processing Agent",
            description = "Process data files, streams, or databases",
            category = TemplateCategory.DATA_PROCESSING,
            defaultLanguage = AgentLanguage.PYTHON,
            defaultTrigger = AgentTrigger.SCHEDULED,
            recommendedPolicies = listOf("rate-limiting", "error-handling"),
            icon = "🔄"
        ),
        AgentTemplate(
            id = "api-integration",
            name = "API Integration Agent",
            description = "Connect to external REST or GraphQL APIs",
            category = TemplateCategory.API_INTEGRATION,
            defaultLanguage = AgentLanguage.TYPESCRIPT,
            defaultTrigger = AgentTrigger.EVENT,
            recommendedPolicies = listOf("rate-limiting", "secret-exposure"),
            icon = "🌐"
        ),
        AgentTemplate(
            id = "test-generator",
            name = "Test Generator Agent",
            description = "Automatically generate unit and integration tests",
            category = TemplateCategory.TESTING,
            defaultLanguage = AgentLanguage.JAVA,
            defaultTrigger = AgentTrigger.ON_FILE_SAVE,
            recommendedPolicies = listOf("code-quality"),
            icon = "🧪"
        ),
        AgentTemplate(
            id = "code-reviewer",
            name = "Code Review Agent",
            description = "Review pull requests and suggest improvements",
            category = TemplateCategory.CODE_REVIEW,
            defaultLanguage = AgentLanguage.KOTLIN,
            defaultTrigger = AgentTrigger.ON_COMMIT,
            recommendedPolicies = listOf("code-quality", "security-scan"),
            icon = "🔍"
        ),
        AgentTemplate(
            id = "deployment",
            name = "Deployment Agent",
            description = "Automate CI/CD and release workflows",
            category = TemplateCategory.DEPLOYMENT,
            defaultLanguage = AgentLanguage.KOTLIN,
            defaultTrigger = AgentTrigger.EVENT,
            recommendedPolicies = listOf("approval-required", "production-safety"),
            icon = "📦"
        ),
        AgentTemplate(
            id = "security-scanner",
            name = "Security Scanner Agent",
            description = "Scan code for vulnerabilities and compliance",
            category = TemplateCategory.SECURITY,
            defaultLanguage = AgentLanguage.PYTHON,
            defaultTrigger = AgentTrigger.ON_COMMIT,
            recommendedPolicies = listOf("secret-exposure", "destructive-sql"),
            icon = "🛡️"
        ),
        AgentTemplate(
            id = "doc-generator",
            name = "Documentation Agent",
            description = "Generate and update documentation from code",
            category = TemplateCategory.DOCUMENTATION,
            defaultLanguage = AgentLanguage.TYPESCRIPT,
            defaultTrigger = AgentTrigger.ON_FILE_SAVE,
            recommendedPolicies = listOf("code-quality"),
            icon = "📝"
        ),
        AgentTemplate(
            id = "custom",
            name = "Custom Agent",
            description = "Start from scratch with a blank agent",
            category = TemplateCategory.CUSTOM,
            defaultLanguage = AgentLanguage.JAVA,
            defaultTrigger = AgentTrigger.MANUAL,
            recommendedPolicies = emptyList(),
            icon = "⚙️"
        )
    )
    
    // Listener management
    
    fun addListener(listener: AgentStateListener) {
        listeners.add(listener)
    }
    
    fun removeListener(listener: AgentStateListener) {
        listeners.remove(listener)
    }
    
    private fun notifyAgentCreated(agent: Agent) {
        listeners.forEach { it.onAgentCreated(agent) }
    }
    
    private fun notifyAgentUpdated(agent: Agent) {
        listeners.forEach { it.onAgentUpdated(agent) }
    }
    
    private fun notifyAgentDeleted(agent: Agent) {
        listeners.forEach { it.onAgentDeleted(agent) }
    }
    
    private fun notifyAgentsRefreshed() {
        listeners.forEach { it.onAgentsRefreshed(agents.values.toList()) }
    }
    
    companion object {
        fun getInstance(project: Project): AgentService = project.service()
    }
}

/**
 * Listener for agent state changes.
 */
interface AgentStateListener {
    fun onAgentCreated(agent: Agent) {}
    fun onAgentUpdated(agent: Agent) {}
    fun onAgentDeleted(agent: Agent) {}
    fun onAgentsRefreshed(agents: List<Agent>) {}
}
