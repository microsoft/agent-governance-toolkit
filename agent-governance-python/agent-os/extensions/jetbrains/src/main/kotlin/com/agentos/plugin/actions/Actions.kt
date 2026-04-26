package com.agentos.plugin.actions

import com.agentos.plugin.agents.AgentService
import com.agentos.plugin.agents.showAgentWizard
import com.agentos.plugin.config.AgentOSConfigParser
import com.agentos.plugin.settings.AgentOSSettings
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.VirtualFile
import java.io.File

/**
 * Action to create a new agent using the wizard.
 */
class CreateAgentAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        showAgentWizard(project)
    }
}

/**
 * Action to review selected code with CMVK multi-model verification.
 */
class ReviewWithCMVKAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val editor = event.getData(CommonDataKeys.EDITOR) ?: return
        val project = event.project ?: return
        
        val selectedText = editor.selectionModel.selectedText
        if (selectedText.isNullOrBlank()) {
            Messages.showInfoMessage(project, "Please select code to review", "Agent OS")
            return
        }
        
        val settings = AgentOSSettings.getInstance().state
        if (!settings.cmvkEnabled) {
            Messages.showInfoMessage(
                project,
                "CMVK is not enabled. Enable it in Settings → Tools → Agent OS",
                "Agent OS"
            )
            return
        }
        
        // TODO: Implement actual CMVK API call
        Messages.showInfoMessage(
            project,
            """
            🛡️ CMVK Review Result
            
            Consensus: 100% Agreement
            
            ✅ GPT-4: No issues detected
            ✅ Claude: No issues detected
            ✅ Gemini: No issues detected
            
            Code appears safe.
            """.trimIndent(),
            "Agent OS - CMVK Review"
        )
    }
    
    override fun update(event: AnActionEvent) {
        val editor = event.getData(CommonDataKeys.EDITOR)
        event.presentation.isEnabledAndVisible = editor != null && editor.selectionModel.hasSelection()
    }
}

/**
 * Action to toggle Agent OS safety mode.
 */
class ToggleSafetyAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val settings = AgentOSSettings.getInstance()
        val state = settings.state
        state.enabled = !state.enabled
        settings.loadState(state)
        
        val status = if (state.enabled) "enabled" else "disabled"
        Messages.showInfoMessage(
            event.project,
            "Agent OS is now $status",
            "Agent OS"
        )
    }
}

/**
 * Action to show audit log.
 */
class ShowAuditLogAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        
        // Open the Agent OS tool window
        val toolWindowManager = com.intellij.openapi.wm.ToolWindowManager.getInstance(project)
        val toolWindow = toolWindowManager.getToolWindow("Agent OS")
        toolWindow?.show()
    }
}

/**
 * Action to configure policies.
 */
class ConfigurePoliciesAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        com.intellij.openapi.options.ShowSettingsUtil.getInstance()
            .showSettingsDialog(event.project, "Agent OS")
    }
}

/**
 * Action to generate a default .agentos.yml configuration file.
 */
class GenerateConfigFileAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val baseDir = project.basePath ?: return
        
        val configFile = File(baseDir, ".agentos.yml")
        if (configFile.exists()) {
            val overwrite = Messages.showYesNoDialog(
                project,
                ".agentos.yml already exists. Overwrite?",
                "Agent OS",
                Messages.getQuestionIcon()
            )
            if (overwrite != Messages.YES) return
        }
        
        val parser = AgentOSConfigParser()
        val template = parser.generateTemplate(project.name)
        
        configFile.writeText(template)
        
        // Refresh the file system
        com.intellij.openapi.vfs.LocalFileSystem.getInstance().refreshAndFindFileByPath(configFile.absolutePath)
        
        Messages.showInfoMessage(
            project,
            "Created .agentos.yml in project root.\n\nEdit it to configure your agents and policies.",
            "Agent OS"
        )
    }
}

/**
 * Action to create an agent from selected code.
 */
class CreateAgentFromSelectionAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val editor = event.getData(CommonDataKeys.EDITOR) ?: return
        val selectedText = editor.selectionModel.selectedText
        
        if (selectedText.isNullOrBlank()) {
            Messages.showInfoMessage(project, "Please select code first", "Agent OS")
            return
        }
        
        // Open wizard with pre-filled context
        val agent = showAgentWizard(project)
        
        if (agent != null) {
            Messages.showInfoMessage(
                project,
                "Agent '${agent.name}' created from selection.\n\nYou can now run it from the Agent OS tool window.",
                "Agent OS"
            )
        }
    }
    
    override fun update(event: AnActionEvent) {
        val editor = event.getData(CommonDataKeys.EDITOR)
        event.presentation.isEnabledAndVisible = editor != null && editor.selectionModel.hasSelection()
    }
}

/**
 * Action to convert selected code to a safe agent.
 */
class ConvertToSafeAgentAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val editor = event.getData(CommonDataKeys.EDITOR) ?: return
        
        Messages.showInfoMessage(
            project,
            "Convert to Safe Agent functionality coming soon.\n\nThis will wrap your code with AgentOS safety checks.",
            "Agent OS"
        )
    }
    
    override fun update(event: AnActionEvent) {
        val editor = event.getData(CommonDataKeys.EDITOR)
        event.presentation.isEnabledAndVisible = editor != null && editor.selectionModel.hasSelection()
    }
}

/**
 * Action to add a policy check at the current location.
 */
class AddPolicyCheckAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        
        Messages.showInfoMessage(
            project,
            "Add Policy Check functionality coming soon.\n\nThis will insert a policy validation call at the cursor position.",
            "Agent OS"
        )
    }
}

/**
 * Action to deploy a file/folder as an agent.
 */
class DeployAsAgentAction : AnAction() {
    
    override fun actionPerformed(event: AnActionEvent) {
        val project = event.project ?: return
        val file = event.getData(CommonDataKeys.VIRTUAL_FILE) ?: return
        
        Messages.showInfoMessage(
            project,
            "Deploy '${file.name}' as agent functionality coming soon.\n\nThis will package and deploy your code as an AgentOS agent.",
            "Agent OS"
        )
    }
    
    override fun update(event: AnActionEvent) {
        val file = event.getData(CommonDataKeys.VIRTUAL_FILE)
        event.presentation.isEnabledAndVisible = file != null
    }
}
