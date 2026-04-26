package com.agentos.plugin.services

import com.agentos.plugin.agents.*
import com.agentos.plugin.settings.AgentOSSettings
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.diagnostic.Logger
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.time.LocalDateTime
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Service for communicating with the AgentOS backend API.
 */
@Service
class AgentOSApiService {
    
    private val logger = Logger.getInstance(AgentOSApiService::class.java)
    private val gson: Gson = GsonBuilder()
        .setPrettyPrinting()
        .create()
    
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()
    
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()
    
    private val baseUrl: String
        get() = AgentOSSettings.getInstance().state.apiEndpoint.ifBlank { 
            "https://api.agent-os.dev/v1" 
        }
    
    private val apiKey: String
        get() = AgentOSSettings.getInstance().state.apiKey
    
    /**
     * Create a new agent.
     */
    fun createAgent(agent: Agent): CompletableFuture<Agent> {
        val future = CompletableFuture<Agent>()
        
        val request = Request.Builder()
            .url("$baseUrl/agents")
            .addHeader("Authorization", "Bearer $apiKey")
            .addHeader("Content-Type", "application/json")
            .post(gson.toJson(agent).toRequestBody(jsonMediaType))
            .build()
        
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                logger.warn("Failed to create agent: ${e.message}")
                // Return the local agent on API failure (offline mode)
                future.complete(agent)
            }
            
            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (it.isSuccessful) {
                        val body = it.body?.string()
                        val createdAgent = gson.fromJson(body, Agent::class.java)
                        future.complete(createdAgent)
                    } else {
                        logger.warn("API error creating agent: ${it.code}")
                        future.complete(agent)
                    }
                }
            }
        })
        
        return future
    }
    
    /**
     * List all agents for the current organization.
     */
    fun listAgents(): CompletableFuture<List<Agent>> {
        val future = CompletableFuture<List<Agent>>()
        
        val request = Request.Builder()
            .url("$baseUrl/agents")
            .addHeader("Authorization", "Bearer $apiKey")
            .get()
            .build()
        
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                logger.warn("Failed to list agents: ${e.message}")
                future.complete(emptyList())
            }
            
            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (it.isSuccessful) {
                        val body = it.body?.string()
                        val agents = gson.fromJson(body, Array<Agent>::class.java).toList()
                        future.complete(agents)
                    } else {
                        logger.warn("API error listing agents: ${it.code}")
                        future.complete(emptyList())
                    }
                }
            }
        })
        
        return future
    }
    
    /**
     * Start an agent.
     */
    fun startAgent(agentId: String): CompletableFuture<Boolean> {
        return updateAgentStatus(agentId, "start")
    }
    
    /**
     * Stop an agent.
     */
    fun stopAgent(agentId: String): CompletableFuture<Boolean> {
        return updateAgentStatus(agentId, "stop")
    }
    
    /**
     * Pause an agent.
     */
    fun pauseAgent(agentId: String): CompletableFuture<Boolean> {
        return updateAgentStatus(agentId, "pause")
    }
    
    private fun updateAgentStatus(agentId: String, action: String): CompletableFuture<Boolean> {
        val future = CompletableFuture<Boolean>()
        
        val request = Request.Builder()
            .url("$baseUrl/agents/$agentId/$action")
            .addHeader("Authorization", "Bearer $apiKey")
            .post("".toRequestBody(jsonMediaType))
            .build()
        
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                logger.warn("Failed to $action agent: ${e.message}")
                future.complete(false)
            }
            
            override fun onResponse(call: Call, response: Response) {
                response.use {
                    future.complete(it.isSuccessful)
                }
            }
        })
        
        return future
    }
    
    /**
     * Perform CMVK (Verification Kernel) review on code.
     */
    fun reviewWithCMVK(code: String, language: String): CompletableFuture<CMVKResult> {
        val future = CompletableFuture<CMVKResult>()
        
        val payload = mapOf(
            "code" to code,
            "language" to language,
            "models" to listOf("gpt-4", "claude-3", "gemini-pro")
        )
        
        val request = Request.Builder()
            .url("$baseUrl/cmvk/review")
            .addHeader("Authorization", "Bearer $apiKey")
            .addHeader("Content-Type", "application/json")
            .post(gson.toJson(payload).toRequestBody(jsonMediaType))
            .build()
        
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                logger.warn("CMVK review failed: ${e.message}")
                future.complete(CMVKResult.offline())
            }
            
            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (it.isSuccessful) {
                        val body = it.body?.string()
                        val result = gson.fromJson(body, CMVKResult::class.java)
                        future.complete(result)
                    } else {
                        logger.warn("CMVK API error: ${it.code}")
                        future.complete(CMVKResult.error("API error: ${it.code}"))
                    }
                }
            }
        })
        
        return future
    }
    
    /**
     * Get available policies.
     */
    fun listPolicies(): CompletableFuture<List<Policy>> {
        val future = CompletableFuture<List<Policy>>()
        
        val request = Request.Builder()
            .url("$baseUrl/policies")
            .addHeader("Authorization", "Bearer $apiKey")
            .get()
            .build()
        
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                logger.warn("Failed to list policies: ${e.message}")
                future.complete(getDefaultPolicies())
            }
            
            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (it.isSuccessful) {
                        val body = it.body?.string()
                        val policies = gson.fromJson(body, Array<Policy>::class.java).toList()
                        future.complete(policies)
                    } else {
                        future.complete(getDefaultPolicies())
                    }
                }
            }
        })
        
        return future
    }
    
    /**
     * Get audit log entries.
     */
    fun getAuditLog(agentId: String? = null, limit: Int = 100): CompletableFuture<List<AuditLogEntry>> {
        val future = CompletableFuture<List<AuditLogEntry>>()
        
        val url = if (agentId != null) {
            "$baseUrl/audit?agentId=$agentId&limit=$limit"
        } else {
            "$baseUrl/audit?limit=$limit"
        }
        
        val request = Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer $apiKey")
            .get()
            .build()
        
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                logger.warn("Failed to get audit log: ${e.message}")
                future.complete(emptyList())
            }
            
            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (it.isSuccessful) {
                        val body = it.body?.string()
                        val entries = gson.fromJson(body, Array<AuditLogEntry>::class.java).toList()
                        future.complete(entries)
                    } else {
                        future.complete(emptyList())
                    }
                }
            }
        })
        
        return future
    }
    
    /**
     * Default policies when API is unavailable.
     */
    private fun getDefaultPolicies(): List<Policy> = listOf(
        Policy(
            id = "destructive-sql",
            name = "Block Destructive SQL",
            description = "Prevents DROP, DELETE without WHERE, TRUNCATE statements",
            rules = listOf(
                PolicyRule("sql-drop", "Block DROP", "sql.contains('DROP')", PolicyAction.BLOCK, PolicySeverity.CRITICAL),
                PolicyRule("sql-truncate", "Block TRUNCATE", "sql.contains('TRUNCATE')", PolicyAction.BLOCK, PolicySeverity.CRITICAL)
            ),
            builtIn = true
        ),
        Policy(
            id = "secret-exposure",
            name = "Block Secret Exposure",
            description = "Detects hardcoded API keys, passwords, and secrets",
            rules = listOf(
                PolicyRule("api-key", "Detect API Keys", "code.matches('.*api[_-]?key.*=.*[\"\\'][a-zA-Z0-9]{20,}[\"\\'].*')", PolicyAction.BLOCK, PolicySeverity.ERROR)
            ),
            builtIn = true
        ),
        Policy(
            id = "dangerous-file-ops",
            name = "Block Dangerous File Operations",
            description = "Prevents rm -rf, format, and destructive file commands",
            rules = listOf(
                PolicyRule("rm-rf", "Block rm -rf", "command.contains('rm -rf')", PolicyAction.BLOCK, PolicySeverity.CRITICAL)
            ),
            builtIn = true
        ),
        Policy(
            id = "rate-limiting",
            name = "Rate Limiting",
            description = "Limits API calls to prevent abuse",
            rules = listOf(
                PolicyRule("rate-limit", "Max 100 calls/min", "calls_per_minute > 100", PolicyAction.THROTTLE, PolicySeverity.WARNING)
            ),
            builtIn = true
        )
    )
    
    companion object {
        fun getInstance(): AgentOSApiService = service()
    }
}

/**
 * Result of CMVK multi-model code review.
 */
data class CMVKResult(
    val consensus: Double,
    val modelResults: List<ModelResult>,
    val overallSafe: Boolean,
    val issues: List<String>,
    val suggestions: List<String>
) {
    companion object {
        fun offline() = CMVKResult(
            consensus = 0.0,
            modelResults = emptyList(),
            overallSafe = true,
            issues = listOf("Offline mode - unable to perform CMVK review"),
            suggestions = emptyList()
        )
        
        fun error(message: String) = CMVKResult(
            consensus = 0.0,
            modelResults = emptyList(),
            overallSafe = false,
            issues = listOf(message),
            suggestions = emptyList()
        )
    }
}

/**
 * Individual model result in CMVK review.
 */
data class ModelResult(
    val model: String,
    val safe: Boolean,
    val confidence: Double,
    val issues: List<String>
)
