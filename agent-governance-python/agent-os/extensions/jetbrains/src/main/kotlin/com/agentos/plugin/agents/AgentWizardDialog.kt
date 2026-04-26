package com.agentos.plugin.agents

import com.agentos.plugin.settings.AgentOSSettings
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.JBColor
import com.intellij.ui.components.*
import com.intellij.ui.dsl.builder.*
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Dimension
import javax.swing.*

/**
 * Multi-step wizard dialog for creating new agents.
 */
class AgentWizardDialog(private val project: Project) : DialogWrapper(project) {
    
    private val agentService = AgentService.getInstance(project)
    private val cardLayout = CardLayout()
    private val cardPanel = JPanel(cardLayout)
    
    private var currentStep = 0
    private val totalSteps = 3
    
    // Step 1: Template selection
    private var selectedTemplate: AgentTemplate? = null
    private val templateList = JBList<AgentTemplate>()
    
    // Step 2: Agent configuration
    private var agentName = ""
    private var agentDescription = ""
    private var selectedLanguage = AgentLanguage.JAVA
    private var selectedTrigger = AgentTrigger.MANUAL
    private var cronSchedule = ""
    
    // Step 3: Policy selection
    private val selectedPolicies = mutableSetOf<String>()
    private var approvalMode = ApprovalMode.NONE
    
    init {
        title = "Create New Agent"
        setSize(600, 500)
        init()
    }
    
    override fun createCenterPanel(): JComponent {
        // Step 1: Template Selection
        cardPanel.add(createTemplatePanel(), "step1")
        
        // Step 2: Agent Configuration
        cardPanel.add(createConfigurationPanel(), "step2")
        
        // Step 3: Policy Selection
        cardPanel.add(createPolicyPanel(), "step3")
        
        updateButtons()
        return cardPanel
    }
    
    private fun createTemplatePanel(): JPanel {
        val panel = JPanel(BorderLayout(0, 10))
        panel.border = JBUI.Borders.empty(10)
        
        // Header
        val headerLabel = JBLabel("<html><h2>Choose a Template</h2><p>Select a template to get started quickly, or choose Custom for a blank agent.</p></html>")
        panel.add(headerLabel, BorderLayout.NORTH)
        
        // Template list
        val templates = agentService.getTemplates()
        templateList.setListData(templates.toTypedArray())
        templateList.cellRenderer = TemplateListCellRenderer()
        templateList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        templateList.selectedIndex = 0
        selectedTemplate = templates.firstOrNull()
        
        templateList.addListSelectionListener {
            selectedTemplate = templateList.selectedValue
        }
        
        val scrollPane = JBScrollPane(templateList)
        scrollPane.preferredSize = Dimension(550, 350)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        return panel
    }
    
    private fun createConfigurationPanel(): JPanel {
        return panel {
            row {
                label("<html><h2>Configure Agent</h2></html>")
            }
            
            row("Name:") {
                textField()
                    .columns(30)
                    .bindText(::agentName)
                    .focused()
                    .validationOnApply {
                        if (it.text.isBlank()) ValidationInfo("Name is required", it)
                        else null
                    }
            }
            
            row("Description:") {
                textArea()
                    .rows(3)
                    .columns(30)
                    .bindText(::agentDescription)
            }
            
            row("Language:") {
                comboBox(AgentLanguage.entries.toList())
                    .bindItem({ selectedLanguage }, { selectedLanguage = it ?: AgentLanguage.JAVA })
            }
            
            row("Trigger:") {
                comboBox(AgentTrigger.entries.toList())
                    .bindItem({ selectedTrigger }, { selectedTrigger = it ?: AgentTrigger.MANUAL })
                    .onChanged {
                        // Show/hide schedule field based on trigger type
                    }
            }
            
            row("Schedule (cron):") {
                textField()
                    .columns(20)
                    .bindText(::cronSchedule)
                    .comment("e.g., 0 */6 * * * (every 6 hours)")
                    .enabledIf(object : ComponentPredicate() {
                        override fun invoke() = selectedTrigger == AgentTrigger.SCHEDULED
                        override fun addListener(listener: (Boolean) -> Unit) {}
                    })
            }
        }.apply {
            border = JBUI.Borders.empty(10)
        }
    }
    
    private fun createPolicyPanel(): JPanel {
        return panel {
            row {
                label("<html><h2>Select Policies</h2><p>Choose which safety policies to apply to this agent.</p></html>")
            }
            
            group("Recommended Policies") {
                row {
                    checkBox("Block Destructive SQL")
                        .onChanged { selectedPolicies.toggle("destructive-sql", it.isSelected) }
                        .apply { component.isSelected = true }
                }
                row {
                    checkBox("Block Secret Exposure")
                        .onChanged { selectedPolicies.toggle("secret-exposure", it.isSelected) }
                        .apply { component.isSelected = true }
                }
                row {
                    checkBox("Block Dangerous File Operations")
                        .onChanged { selectedPolicies.toggle("dangerous-file-ops", it.isSelected) }
                }
                row {
                    checkBox("Rate Limiting (100 calls/min)")
                        .onChanged { selectedPolicies.toggle("rate-limiting", it.isSelected) }
                }
            }
            
            group("Approval Mode") {
                buttonsGroup {
                    row {
                        radioButton("No approval required", ApprovalMode.NONE)
                    }
                    row {
                        radioButton("Single approval", ApprovalMode.SINGLE)
                    }
                    row {
                        radioButton("Multi-person approval", ApprovalMode.MULTI)
                    }
                    row {
                        radioButton("Auto-approve if safe", ApprovalMode.AUTO)
                    }
                }.bind(::approvalMode)
            }
        }.apply {
            border = JBUI.Borders.empty(10)
        }
    }
    
    private fun MutableSet<String>.toggle(value: String, selected: Boolean) {
        if (selected) add(value) else remove(value)
    }
    
    override fun createSouthPanel(): JComponent {
        val panel = JPanel(BorderLayout())
        
        val buttonPanel = JPanel()
        val backButton = JButton("< Back").apply {
            addActionListener { previousStep() }
        }
        val nextButton = JButton("Next >").apply {
            addActionListener { nextStep() }
        }
        val createButton = JButton("Create Agent").apply {
            addActionListener { createAgent() }
        }
        val cancelButton = JButton("Cancel").apply {
            addActionListener { close(CANCEL_EXIT_CODE) }
        }
        
        buttonPanel.add(cancelButton)
        buttonPanel.add(backButton)
        buttonPanel.add(nextButton)
        buttonPanel.add(createButton)
        
        // Store buttons for updating
        this.backButton = backButton
        this.nextButton = nextButton
        this.createButton = createButton
        
        panel.add(buttonPanel, BorderLayout.EAST)
        
        // Step indicator
        val stepLabel = JBLabel("Step ${currentStep + 1} of $totalSteps")
        panel.add(stepLabel, BorderLayout.WEST)
        this.stepLabel = stepLabel
        
        return panel
    }
    
    private var backButton: JButton? = null
    private var nextButton: JButton? = null
    private var createButton: JButton? = null
    private var stepLabel: JBLabel? = null
    
    private fun updateButtons() {
        backButton?.isEnabled = currentStep > 0
        nextButton?.isVisible = currentStep < totalSteps - 1
        createButton?.isVisible = currentStep == totalSteps - 1
        stepLabel?.text = "Step ${currentStep + 1} of $totalSteps"
    }
    
    private fun previousStep() {
        if (currentStep > 0) {
            currentStep--
            cardLayout.show(cardPanel, "step${currentStep + 1}")
            updateButtons()
        }
    }
    
    private fun nextStep() {
        if (validateCurrentStep()) {
            // Apply template defaults when moving from step 1 to step 2
            if (currentStep == 0 && selectedTemplate != null) {
                val template = selectedTemplate!!
                if (agentName.isBlank()) {
                    agentName = "My ${template.name}"
                }
                selectedLanguage = template.defaultLanguage
                selectedTrigger = template.defaultTrigger
                selectedPolicies.addAll(template.recommendedPolicies)
            }
            
            currentStep++
            cardLayout.show(cardPanel, "step${currentStep + 1}")
            updateButtons()
        }
    }
    
    private fun validateCurrentStep(): Boolean {
        return when (currentStep) {
            0 -> selectedTemplate != null
            1 -> agentName.isNotBlank()
            else -> true
        }
    }
    
    private fun createAgent() {
        if (!validateCurrentStep()) return
        
        val agent = agentService.createAgent(
            name = agentName,
            description = agentDescription,
            language = selectedLanguage,
            trigger = selectedTrigger,
            schedule = if (selectedTrigger == AgentTrigger.SCHEDULED) cronSchedule else null,
            policies = selectedPolicies.toList(),
            approvalMode = approvalMode
        )
        
        close(OK_EXIT_CODE)
    }
    
    /**
     * Custom renderer for template list items.
     */
    private inner class TemplateListCellRenderer : DefaultListCellRenderer() {
        override fun getListCellRendererComponent(
            list: JList<*>?,
            value: Any?,
            index: Int,
            isSelected: Boolean,
            cellHasFocus: Boolean
        ): java.awt.Component {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
            
            if (value is AgentTemplate) {
                text = "<html><b>${value.icon} ${value.name}</b><br><small>${value.description}</small></html>"
                border = JBUI.Borders.empty(8)
            }
            
            return this
        }
    }
}

/**
 * Show the agent creation wizard and return the created agent.
 */
fun showAgentWizard(project: Project): Agent? {
    val dialog = AgentWizardDialog(project)
    return if (dialog.showAndGet()) {
        AgentService.getInstance(project).getAgents().lastOrNull()
    } else {
        null
    }
}
