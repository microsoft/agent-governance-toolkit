package com.agentos.plugin.statusbar

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory
import com.intellij.util.Consumer
import com.agentos.plugin.settings.AgentOSSettings
import java.awt.event.MouseEvent

/**
 * Factory for the status bar widget.
 */
class AgentOSStatusBarWidgetFactory : StatusBarWidgetFactory {
    
    override fun getId(): String = "AgentOSStatusBar"
    
    override fun getDisplayName(): String = "Agent OS Status"
    
    override fun isAvailable(project: Project): Boolean = true
    
    override fun createWidget(project: Project): StatusBarWidget {
        return AgentOSStatusBarWidget(project)
    }
    
    override fun disposeWidget(widget: StatusBarWidget) {}
    
    override fun canBeEnabledOn(statusBar: StatusBar): Boolean = true
}

/**
 * Status bar widget showing Agent OS status.
 */
class AgentOSStatusBarWidget(private val project: Project) : StatusBarWidget, StatusBarWidget.TextPresentation {
    
    override fun ID(): String = "AgentOSStatusBar"
    
    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this
    
    override fun install(statusBar: StatusBar) {}
    
    override fun dispose() {}
    
    override fun getText(): String {
        val settings = AgentOSSettings.getInstance().state
        return if (settings.enabled) "🛡️ Agent OS" else "⚠️ Agent OS (off)"
    }
    
    override fun getAlignment(): Float = 0f
    
    override fun getTooltipText(): String {
        val settings = AgentOSSettings.getInstance().state
        return if (settings.enabled) {
            "Agent OS: Protecting your code"
        } else {
            "Agent OS: Disabled - click to enable"
        }
    }
    
    override fun getClickConsumer(): Consumer<MouseEvent>? {
        return Consumer {
            val settings = AgentOSSettings.getInstance()
            val state = settings.state
            state.enabled = !state.enabled
            settings.loadState(state)
        }
    }
}
