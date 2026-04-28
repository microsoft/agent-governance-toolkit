package com.agentos.plugin.toolwindow

import com.agentos.plugin.agents.*
import com.agentos.plugin.settings.AgentOSSettings
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.JBColor
import com.intellij.ui.components.*
import com.intellij.ui.content.ContentFactory
import com.intellij.util.ui.JBUI
import java.awt.*
import java.time.format.DateTimeFormatter
import javax.swing.*

/**
 * Factory for the Agent OS tool window.
 */
class AgentOSToolWindowFactory : ToolWindowFactory {
    
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = AgentOSToolWindowPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "", false)
        toolWindow.contentManager.addContent(content)
    }
}

/**
 * Main panel for the Agent OS tool window with tabbed interface.
 */
class AgentOSToolWindowPanel(private val project: Project) : JPanel(BorderLayout()) {
    
    private val agentService = AgentService.getInstance(project)
    private val agentListModel = DefaultListModel<Agent>()
    private val agentList = JBList(agentListModel)
    private val auditListModel = DefaultListModel<String>()
    
    init {
        val settings = AgentOSSettings.getInstance().state
        
        // Header with status and actions
        add(createHeaderPanel(settings), BorderLayout.NORTH)
        
        // Tabbed pane for Agents, Audit Log, Policies
        val tabbedPane = JBTabbedPane()
        tabbedPane.addTab("Agents", createAgentsPanel())
        tabbedPane.addTab("Audit Log", createAuditLogPanel(settings))
        tabbedPane.addTab("Policies", createPoliciesPanel(settings))
        add(tabbedPane, BorderLayout.CENTER)
        
        // Footer with stats
        add(createFooterPanel(), BorderLayout.SOUTH)
        
        // Listen for agent changes
        agentService.addListener(object : AgentStateListener {
            override fun onAgentCreated(agent: Agent) {
                SwingUtilities.invokeLater { refreshAgentList() }
            }
            override fun onAgentUpdated(agent: Agent) {
                SwingUtilities.invokeLater { refreshAgentList() }
            }
            override fun onAgentDeleted(agent: Agent) {
                SwingUtilities.invokeLater { refreshAgentList() }
            }
            override fun onAgentsRefreshed(agents: List<Agent>) {
                SwingUtilities.invokeLater { refreshAgentList() }
            }
        })
        
        // Initial load
        refreshAgentList()
    }
    
    private fun createHeaderPanel(settings: AgentOSSettings.State): JPanel {
        val panel = JPanel(BorderLayout())
        panel.border = JBUI.Borders.empty(8, 12)
        panel.background = if (settings.enabled) JBColor(0xECFDF5, 0x064E3B) else JBColor(0xFEF2F2, 0x7F1D1D)
        
        val statusLabel = JBLabel(
            if (settings.enabled) "🛡️ Agent OS: Active" else "⚠️ Agent OS: Disabled"
        )
        statusLabel.font = statusLabel.font.deriveFont(Font.BOLD)
        panel.add(statusLabel, BorderLayout.WEST)
        
        val actionsPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
        actionsPanel.isOpaque = false
        
        val createButton = JButton("+ Create Agent")
        createButton.addActionListener {
            showAgentWizard(project)
        }
        actionsPanel.add(createButton)
        
        val refreshButton = JButton("↻")
        refreshButton.toolTipText = "Refresh agents"
        refreshButton.addActionListener {
            agentService.refreshAgents()
        }
        actionsPanel.add(refreshButton)
        
        panel.add(actionsPanel, BorderLayout.EAST)
        
        return panel
    }
    
    private fun createAgentsPanel(): JComponent {
        val panel = JPanel(BorderLayout())
        
        agentList.cellRenderer = AgentListCellRenderer()
        agentList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        
        // Double-click to show agent details
        agentList.addMouseListener(object : java.awt.event.MouseAdapter() {
            override fun mouseClicked(e: java.awt.event.MouseEvent) {
                if (e.clickCount == 2) {
                    val agent = agentList.selectedValue
                    if (agent != null) {
                        showAgentDetails(agent)
                    }
                }
            }
        })
        
        panel.add(JBScrollPane(agentList), BorderLayout.CENTER)
        
        // Agent action buttons
        val buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        val startButton = JButton("▶ Start")
        startButton.addActionListener {
            agentList.selectedValue?.let { agent ->
                agentService.startAgent(agent.id)
            }
        }
        buttonPanel.add(startButton)
        
        val stopButton = JButton("⏹ Stop")
        stopButton.addActionListener {
            agentList.selectedValue?.let { agent ->
                agentService.stopAgent(agent.id)
            }
        }
        buttonPanel.add(stopButton)
        
        val pauseButton = JButton("⏸ Pause")
        pauseButton.addActionListener {
            agentList.selectedValue?.let { agent ->
                if (agent.status == AgentStatus.PAUSED) {
                    agentService.resumeAgent(agent.id)
                } else {
                    agentService.pauseAgent(agent.id)
                }
            }
        }
        buttonPanel.add(pauseButton)
        
        val logsButton = JButton("📋 Logs")
        logsButton.addActionListener {
            agentList.selectedValue?.let { agent ->
                showAgentLogs(agent)
            }
        }
        buttonPanel.add(logsButton)
        
        panel.add(buttonPanel, BorderLayout.SOUTH)
        
        return panel
    }
    
    private fun createAuditLogPanel(settings: AgentOSSettings.State): JComponent {
        val panel = JPanel(BorderLayout())
        
        // Add initial log entries
        auditListModel.addElement("✅ Project opened - ${java.time.LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"))}")
        auditListModel.addElement("🔍 Scanning enabled files...")
        
        if (settings.blockDestructiveSQL) {
            auditListModel.addElement("📋 Policy: Destructive SQL blocking enabled")
        }
        if (settings.blockSecretExposure) {
            auditListModel.addElement("📋 Policy: Secret exposure blocking enabled")
        }
        if (settings.blockFileDeletes) {
            auditListModel.addElement("📋 Policy: Dangerous file ops blocking enabled")
        }
        
        val auditList = JBList(auditListModel)
        panel.add(JBScrollPane(auditList), BorderLayout.CENTER)
        
        // Filter/clear buttons
        val filterPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        filterPanel.add(JButton("Clear Log").apply {
            addActionListener { auditListModel.clear() }
        })
        filterPanel.add(JButton("Export").apply {
            addActionListener { exportAuditLog() }
        })
        panel.add(filterPanel, BorderLayout.SOUTH)
        
        return panel
    }
    
    private fun createPoliciesPanel(settings: AgentOSSettings.State): JComponent {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.border = JBUI.Borders.empty(8)
        
        val policies = listOf(
            Triple("Block Destructive SQL", settings.blockDestructiveSQL, "Prevents DROP, DELETE, TRUNCATE"),
            Triple("Block Secret Exposure", settings.blockSecretExposure, "Detects hardcoded API keys and passwords"),
            Triple("Block Dangerous File Ops", settings.blockFileDeletes, "Prevents rm -rf and similar commands"),
            Triple("Block Privilege Escalation", settings.blockPrivilegeEscalation, "Detects sudo, chmod 777, etc."),
            Triple("Block Unsafe Network Calls", settings.blockUnsafeNetworkCalls, "Monitors external API calls")
        )
        
        for ((name, enabled, description) in policies) {
            val policyPanel = JPanel(BorderLayout())
            policyPanel.border = JBUI.Borders.empty(8)
            policyPanel.maximumSize = Dimension(Int.MAX_VALUE, 60)
            
            val infoPanel = JPanel()
            infoPanel.layout = BoxLayout(infoPanel, BoxLayout.Y_AXIS)
            infoPanel.add(JBLabel(name).apply { font = font.deriveFont(Font.BOLD) })
            infoPanel.add(JBLabel(description).apply { 
                foreground = JBColor.GRAY 
                font = font.deriveFont(11f)
            })
            
            policyPanel.add(infoPanel, BorderLayout.CENTER)
            policyPanel.add(JBLabel(if (enabled) "✅ Enabled" else "❌ Disabled"), BorderLayout.EAST)
            
            panel.add(policyPanel)
        }
        
        return JBScrollPane(panel)
    }
    
    private fun createFooterPanel(): JPanel {
        val panel = JPanel(BorderLayout())
        panel.border = JBUI.Borders.empty(4, 12)
        
        val agents = agentService.getAgents()
        val running = agents.count { it.status == AgentStatus.RUNNING }
        val paused = agents.count { it.status == AgentStatus.PAUSED }
        val errors = agents.count { it.status == AgentStatus.ERROR }
        
        val statsLabel = JBLabel("Running: $running | Paused: $paused | Errors: $errors")
        statsLabel.foreground = JBColor.GRAY
        panel.add(statsLabel, BorderLayout.WEST)
        
        return panel
    }
    
    private fun refreshAgentList() {
        agentListModel.clear()
        agentService.getAgents().forEach { agent ->
            agentListModel.addElement(agent)
        }
    }
    
    private fun showAgentDetails(agent: Agent) {
        // Show agent details dialog
        val message = """
            Name: ${agent.name}
            Status: ${agent.status.displayName}
            Language: ${agent.language.displayName}
            Trigger: ${agent.trigger.displayName}
            Policies: ${agent.policies.joinToString(", ").ifEmpty { "None" }}
            Created: ${agent.createdAt}
            Last Run: ${agent.lastRunAt ?: "Never"}
        """.trimIndent()
        
        JOptionPane.showMessageDialog(this, message, "Agent Details", JOptionPane.INFORMATION_MESSAGE)
    }
    
    private fun showAgentLogs(agent: Agent) {
        // Show agent logs in a dialog
        JOptionPane.showMessageDialog(this, "Logs for ${agent.name}\n\n(Log viewer coming soon)", "Agent Logs", JOptionPane.INFORMATION_MESSAGE)
    }
    
    private fun exportAuditLog() {
        // Export audit log functionality
        JOptionPane.showMessageDialog(this, "Export functionality coming soon", "Export Audit Log", JOptionPane.INFORMATION_MESSAGE)
    }
}

/**
 * Custom renderer for agent list items.
 */
private class AgentListCellRenderer : DefaultListCellRenderer() {
    override fun getListCellRendererComponent(
        list: JList<*>?,
        value: Any?,
        index: Int,
        isSelected: Boolean,
        cellHasFocus: Boolean
    ): java.awt.Component {
        super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus)
        
        if (value is Agent) {
            text = "<html><b>${value.status.icon} ${value.name}</b><br>" +
                   "<small style='color:gray'>${value.language.displayName} • ${value.trigger.displayName}</small></html>"
            border = JBUI.Borders.empty(6, 8)
        }
        
        return this
    }
}
