package com.agentos.plugin.runconfig

import com.agentos.plugin.agents.Agent
import com.agentos.plugin.agents.AgentService
import com.intellij.execution.ExecutionException
import com.intellij.execution.Executor
import com.intellij.execution.configurations.*
import com.intellij.execution.process.ProcessHandler
import com.intellij.execution.runners.ExecutionEnvironment
import com.intellij.openapi.options.SettingsEditor
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.JDOMExternalizerUtil
import com.intellij.ui.components.JBTextField
import com.intellij.ui.dsl.builder.panel
import org.jdom.Element
import javax.swing.JComponent

/**
 * Run configuration type for AgentOS agents.
 */
class AgentRunConfigurationType : ConfigurationType {
    override fun getDisplayName() = "AgentOS Agent"
    override fun getConfigurationTypeDescription() = "Run an AgentOS agent"
    override fun getIcon() = com.intellij.icons.AllIcons.Actions.Execute
    override fun getId() = "AgentOSAgentRunConfiguration"
    override fun getConfigurationFactories(): Array<ConfigurationFactory> = arrayOf(AgentRunConfigurationFactory(this))
}

/**
 * Factory for creating agent run configurations.
 */
class AgentRunConfigurationFactory(type: ConfigurationType) : ConfigurationFactory(type) {
    override fun createTemplateConfiguration(project: Project): RunConfiguration {
        return AgentRunConfiguration(project, this, "Agent")
    }
    
    override fun getId() = "AgentOSAgentRunConfigurationFactory"
    override fun getName() = "AgentOS Agent"
}

/**
 * Run configuration for an AgentOS agent.
 */
class AgentRunConfiguration(
    project: Project,
    factory: ConfigurationFactory,
    name: String
) : RunConfigurationBase<AgentRunConfigurationOptions>(project, factory, name) {
    
    var agentId: String = ""
    var agentName: String = ""
    var environment: String = "development"
    var validatePolicies: Boolean = true
    var customPolicies: List<String> = emptyList()
    
    override fun getConfigurationEditor(): SettingsEditor<out RunConfiguration> {
        return AgentRunConfigurationEditor(project)
    }
    
    override fun getState(executor: Executor, environment: ExecutionEnvironment): RunProfileState {
        return AgentRunProfileState(this, environment)
    }
    
    override fun readExternal(element: Element) {
        super.readExternal(element)
        agentId = JDOMExternalizerUtil.readField(element, "agentId") ?: ""
        agentName = JDOMExternalizerUtil.readField(element, "agentName") ?: ""
        this.environment = JDOMExternalizerUtil.readField(element, "environment") ?: "development"
        validatePolicies = JDOMExternalizerUtil.readField(element, "validatePolicies")?.toBoolean() ?: true
    }
    
    override fun writeExternal(element: Element) {
        super.writeExternal(element)
        JDOMExternalizerUtil.writeField(element, "agentId", agentId)
        JDOMExternalizerUtil.writeField(element, "agentName", agentName)
        JDOMExternalizerUtil.writeField(element, "environment", environment)
        JDOMExternalizerUtil.writeField(element, "validatePolicies", validatePolicies.toString())
    }
}

/**
 * Options holder for run configuration.
 */
class AgentRunConfigurationOptions : RunConfigurationOptions()

/**
 * Settings editor UI for agent run configuration.
 */
class AgentRunConfigurationEditor(private val project: Project) : SettingsEditor<AgentRunConfiguration>() {
    
    private val agentIdField = JBTextField()
    private val agentNameField = JBTextField()
    private val environmentField = JBTextField()
    private var validatePoliciesCheckbox: javax.swing.JCheckBox? = null
    
    override fun createEditor(): JComponent {
        return panel {
            row("Agent ID:") {
                cell(agentIdField).resizableColumn()
            }
            row("Agent Name:") {
                cell(agentNameField).resizableColumn()
            }
            row("Environment:") {
                cell(environmentField).resizableColumn()
                    .comment("development, staging, production")
            }
            row {
                checkBox("Validate policies before run")
                    .also { validatePoliciesCheckbox = it.component }
            }
            
            group("Available Agents") {
                val agents = AgentService.getInstance(project).getAgents()
                if (agents.isEmpty()) {
                    row {
                        label("No agents configured. Create one in the AgentOS tool window.")
                    }
                } else {
                    for (agent in agents) {
                        row {
                            button("${agent.status.icon} ${agent.name}") {
                                agentIdField.text = agent.id
                                agentNameField.text = agent.name
                            }
                        }
                    }
                }
            }
        }
    }
    
    override fun applyEditorTo(s: AgentRunConfiguration) {
        s.agentId = agentIdField.text
        s.agentName = agentNameField.text
        s.environment = environmentField.text
        s.validatePolicies = validatePoliciesCheckbox?.isSelected ?: true
    }
    
    override fun resetEditorFrom(s: AgentRunConfiguration) {
        agentIdField.text = s.agentId
        agentNameField.text = s.agentName
        environmentField.text = s.environment
        validatePoliciesCheckbox?.isSelected = s.validatePolicies
    }
}

/**
 * Run profile state that executes the agent.
 */
class AgentRunProfileState(
    private val configuration: AgentRunConfiguration,
    private val environment: ExecutionEnvironment
) : RunProfileState {
    
    override fun execute(executor: Executor?, runner: com.intellij.execution.runners.ProgramRunner<*>): com.intellij.execution.ExecutionResult? {
        val project = environment.project
        val agentService = AgentService.getInstance(project)
        
        // Find the agent
        val agent = agentService.getAgent(configuration.agentId)
            ?: throw ExecutionException("Agent not found: ${configuration.agentId}")
        
        // Validate policies if enabled
        if (configuration.validatePolicies) {
            // TODO: Implement policy validation
        }
        
        // Start the agent
        agentService.startAgent(agent.id)
        
        // Create a simple process handler that shows agent status
        val processHandler = AgentProcessHandler(agent, agentService)
        
        return com.intellij.execution.DefaultExecutionResult(
            com.intellij.execution.ui.ConsoleViewImpl(project, true),
            processHandler
        )
    }
}

/**
 * Process handler for running agents.
 */
class AgentProcessHandler(
    private val agent: Agent,
    private val agentService: AgentService
) : ProcessHandler() {
    
    init {
        notifyTextAvailable("Starting agent: ${agent.name}\n", com.intellij.execution.process.ProcessOutputTypes.SYSTEM)
        notifyTextAvailable("Language: ${agent.language.displayName}\n", com.intellij.execution.process.ProcessOutputTypes.STDOUT)
        notifyTextAvailable("Trigger: ${agent.trigger.displayName}\n", com.intellij.execution.process.ProcessOutputTypes.STDOUT)
        notifyTextAvailable("Policies: ${agent.policies.joinToString(", ").ifEmpty { "None" }}\n", com.intellij.execution.process.ProcessOutputTypes.STDOUT)
        notifyTextAvailable("\nAgent is now running...\n", com.intellij.execution.process.ProcessOutputTypes.SYSTEM)
    }
    
    override fun destroyProcessImpl() {
        agentService.stopAgent(agent.id)
        notifyTextAvailable("\nAgent stopped.\n", com.intellij.execution.process.ProcessOutputTypes.SYSTEM)
        notifyProcessTerminated(0)
    }
    
    override fun detachProcessImpl() {
        notifyProcessDetached()
    }
    
    override fun detachIsDefault() = false
    
    override fun getProcessInput() = null
}
