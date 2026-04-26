package com.agentos.plugin

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.StartupActivity
import com.agentos.plugin.settings.AgentOSSettings

/**
 * Startup activity that runs when a project is opened.
 */
class AgentOSStartupActivity : StartupActivity {
    
    override fun runActivity(project: Project) {
        val settings = AgentOSSettings.getInstance().state
        
        if (settings.enabled) {
            NotificationGroupManager.getInstance()
                .getNotificationGroup("Agent OS Notifications")
                .createNotification(
                    "Agent OS Active",
                    "Kernel-level safety is protecting your code. " +
                    "${countActivePolicies(settings)} policies enabled.",
                    NotificationType.INFORMATION
                )
                .notify(project)
        }
    }
    
    private fun countActivePolicies(settings: AgentOSSettings.State): Int {
        var count = 0
        if (settings.blockDestructiveSQL) count++
        if (settings.blockFileDeletes) count++
        if (settings.blockSecretExposure) count++
        if (settings.blockPrivilegeEscalation) count++
        if (settings.blockUnsafeNetworkCalls) count++
        return count
    }
}
