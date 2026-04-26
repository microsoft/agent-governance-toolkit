package com.agentos.plugin.inspections

import com.intellij.codeInspection.*
import com.intellij.psi.PsiFile
import com.agentos.plugin.settings.AgentOSSettings

/**
 * Inspection that detects destructive SQL operations.
 */
class DestructiveSQLInspection : LocalInspectionTool() {
    
    private val destructivePatterns = listOf(
        Regex("""(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\b"""),
        Regex("""(?i)\bDELETE\s+FROM\b"""),
        Regex("""(?i)\bTRUNCATE\s+(TABLE)?\b"""),
    )
    
    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val settings = AgentOSSettings.getInstance().state
        if (!settings.enabled || !settings.blockDestructiveSQL) return null
        
        return findProblems(file, manager, isOnTheFly, destructivePatterns, 
            "Agent OS: Destructive SQL operation detected", ProblemHighlightType.ERROR)
    }
}

/**
 * Inspection that detects hardcoded secrets.
 */
class HardcodedSecretsInspection : LocalInspectionTool() {
    
    private val secretPatterns = listOf(
        Regex("""(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][^"']{20,}["']"""),
        Regex("""(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']"""),
        Regex("""(?i)ghp_[A-Za-z0-9]{36}"""),
        Regex("""(?i)sk-[A-Za-z0-9]{48}"""),
    )
    
    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val settings = AgentOSSettings.getInstance().state
        if (!settings.enabled || !settings.blockSecretExposure) return null
        
        return findProblems(file, manager, isOnTheFly, secretPatterns,
            "Agent OS: Hardcoded secret detected", ProblemHighlightType.ERROR)
    }
}

/**
 * Inspection that detects dangerous file operations.
 */
class DangerousFileOpsInspection : LocalInspectionTool() {
    
    private val dangerousPatterns = listOf(
        Regex("""(?i)\brm\s+-rf?\s"""),
        Regex("""(?i)shutil\.rmtree\s*\("""),
        Regex("""(?i)os\.remove\s*\("""),
        Regex("""(?i)fs\.rmSync\s*\("""),
    )
    
    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val settings = AgentOSSettings.getInstance().state
        if (!settings.enabled || !settings.blockFileDeletes) return null
        
        return findProblems(file, manager, isOnTheFly, dangerousPatterns,
            "Agent OS: Dangerous file operation detected", ProblemHighlightType.ERROR)
    }
}

/**
 * Inspection that detects privilege escalation.
 */
class PrivilegeEscalationInspection : LocalInspectionTool() {
    
    private val escalationPatterns = listOf(
        Regex("""(?i)\bsudo\s"""),
        Regex("""(?i)chmod\s+777\b"""),
    )
    
    override fun checkFile(file: PsiFile, manager: InspectionManager, isOnTheFly: Boolean): Array<ProblemDescriptor>? {
        val settings = AgentOSSettings.getInstance().state
        if (!settings.enabled || !settings.blockPrivilegeEscalation) return null
        
        return findProblems(file, manager, isOnTheFly, escalationPatterns,
            "Agent OS: Privilege escalation detected", ProblemHighlightType.WARNING)
    }
}

private fun findProblems(
    file: PsiFile,
    manager: InspectionManager,
    isOnTheFly: Boolean,
    patterns: List<Regex>,
    message: String,
    highlightType: ProblemHighlightType
): Array<ProblemDescriptor>? {
    val problems = mutableListOf<ProblemDescriptor>()
    val text = file.text
    
    for (pattern in patterns) {
        for (match in pattern.findAll(text)) {
            val element = file.findElementAt(match.range.first)
            if (element != null) {
                problems.add(manager.createProblemDescriptor(
                    element, "$message - '${match.value.take(50)}'",
                    true, highlightType, isOnTheFly
                ))
            }
        }
    }
    
    return if (problems.isNotEmpty()) problems.toTypedArray() else null
}
