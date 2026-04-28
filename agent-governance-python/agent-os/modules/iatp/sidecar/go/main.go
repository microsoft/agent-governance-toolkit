package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TrustLevel represents agent trust levels
type TrustLevel string

const (
	VerifiedPartner TrustLevel = "verified_partner"
	Trusted         TrustLevel = "trusted"
	Standard        TrustLevel = "standard"
	Unknown         TrustLevel = "unknown"
	Untrusted       TrustLevel = "untrusted"
)

// ReversibilityLevel represents reversibility capabilities
type ReversibilityLevel string

const (
	Full    ReversibilityLevel = "full"
	Partial ReversibilityLevel = "partial"
	None    ReversibilityLevel = "none"
)

// RetentionPolicy represents data retention policies
type RetentionPolicy string

const (
	Ephemeral RetentionPolicy = "ephemeral"
	Temporary RetentionPolicy = "temporary"
	Permanent RetentionPolicy = "permanent"
)

// CapabilityManifest represents the agent's capabilities
type CapabilityManifest struct {
	Identity struct {
		AgentID         string `json:"agent_id"`
		VerificationKey string `json:"verification_key,omitempty"`
		Owner           string `json:"owner,omitempty"`
	} `json:"identity"`
	TrustLevel   TrustLevel `json:"trust_level"`
	Capabilities struct {
		Idempotency      bool `json:"idempotency"`
		ConcurrencyLimit int  `json:"concurrency_limit"`
		SLALatencyMs     int  `json:"sla_latency_ms"`
	} `json:"capabilities"`
	Reversibility struct {
		Level                ReversibilityLevel `json:"level"`
		UndoWindowSeconds    int                `json:"undo_window_seconds,omitempty"`
		CompensationMethod   string             `json:"compensation_method,omitempty"`
	} `json:"reversibility"`
	Privacy struct {
		RetentionPolicy  RetentionPolicy `json:"retention_policy"`
		HumanInLoop      bool            `json:"human_in_loop"`
		TrainingConsent  bool            `json:"training_consent"`
	} `json:"privacy"`
}

// Sidecar represents the IATP sidecar
type Sidecar struct {
	AgentURL string
	Manifest CapabilityManifest
	Port     int
}

// FlightRecordEntry represents a log entry
type FlightRecordEntry struct {
	Type      string                 `json:"type"`
	TraceID   string                 `json:"trace_id"`
	Timestamp string                 `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

var flightRecorder []FlightRecordEntry

// calculateTrustScore calculates the trust score based on the manifest
func (s *Sidecar) calculateTrustScore() int {
	score := 0

	// Base score from trust level
	switch s.Manifest.TrustLevel {
	case VerifiedPartner:
		score = 10
	case Trusted:
		score = 7
	case Standard:
		score = 5
	case Unknown:
		score = 2
	case Untrusted:
		score = 0
	}

	// Adjust based on reversibility
	if s.Manifest.Reversibility.Level != None {
		score += 2
	}

	// Adjust based on retention policy
	switch s.Manifest.Privacy.RetentionPolicy {
	case Ephemeral:
		score += 1
	case Permanent:
		score -= 1
	}

	// Adjust based on human in loop
	if s.Manifest.Privacy.HumanInLoop {
		score -= 2
	}

	// Adjust based on training consent
	if s.Manifest.Privacy.TrainingConsent {
		score -= 1
	}

	// Ensure score is in range [0, 10]
	if score < 0 {
		score = 0
	}
	if score > 10 {
		score = 10
	}

	return score
}

// detectSensitiveData checks for credit cards and SSNs
func detectSensitiveData(data string) map[string]bool {
	result := map[string]bool{
		"credit_card": false,
		"ssn":         false,
	}

	// Credit card detection (Luhn algorithm)
	ccPattern := regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)
	if matches := ccPattern.FindAllString(data, -1); len(matches) > 0 {
		for _, match := range matches {
			cleaned := strings.ReplaceAll(strings.ReplaceAll(match, "-", ""), " ", "")
			if luhnCheck(cleaned) {
				result["credit_card"] = true
				break
			}
		}
	}

	// SSN detection
	ssnPattern := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	if ssnPattern.MatchString(data) {
		result["ssn"] = true
	}

	return result
}

// luhnCheck implements the Luhn algorithm for credit card validation
func luhnCheck(cardNumber string) bool {
	if len(cardNumber) < 13 || len(cardNumber) > 19 {
		return false
	}

	sum := 0
	alternate := false

	for i := len(cardNumber) - 1; i >= 0; i-- {
		digit, err := strconv.Atoi(string(cardNumber[i]))
		if err != nil {
			return false
		}

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

// scrubSensitiveData removes sensitive data from logs
func scrubSensitiveData(data string) string {
	// Scrub credit cards
	ccPattern := regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)
	data = ccPattern.ReplaceAllString(data, "****-****-****-****")

	// Scrub SSNs
	ssnPattern := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	data = ssnPattern.ReplaceAllString(data, "***-**-****")

	return data
}

// logFlightRecord logs an entry to the flight recorder
func logFlightRecord(entry FlightRecordEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	flightRecorder = append(flightRecorder, entry)
	
	// Also log to stdout
	jsonData, _ := json.Marshal(entry)
	log.Printf("FLIGHT_RECORDER: %s\n", string(jsonData))
}

// NewSidecar creates a new sidecar instance
func NewSidecar(agentURL string, manifest CapabilityManifest, port int) *Sidecar {
	return &Sidecar{
		AgentURL: agentURL,
		Manifest: manifest,
		Port:     port,
	}
}

// Run starts the sidecar server
func (s *Sidecar) Run() error {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Capability manifest endpoint
	router.GET("/capabilities", func(c *gin.Context) {
		c.JSON(200, s.Manifest)
	})

	// Proxy endpoint
	router.POST("/proxy", func(c *gin.Context) {
		traceID := uuid.New().String()
		c.Header("X-Agent-Trace-ID", traceID)

		// Read request body
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			logFlightRecord(FlightRecordEntry{
				Type:    "error",
				TraceID: traceID,
				Details: map[string]interface{}{"error": "Failed to read request body"},
			})
			c.JSON(500, gin.H{"error": "Failed to read request body"})
			return
		}

		// Parse JSON
		var payload map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			logFlightRecord(FlightRecordEntry{
				Type:    "error",
				TraceID: traceID,
				Details: map[string]interface{}{"error": "Invalid JSON"},
			})
			c.JSON(400, gin.H{"error": "Invalid JSON"})
			return
		}

		// Convert to string for sensitive data detection
		payloadStr := string(bodyBytes)
		sensitive := detectSensitiveData(payloadStr)

		// Log request (with scrubbing)
		logFlightRecord(FlightRecordEntry{
			Type:    "request",
			TraceID: traceID,
			Details: map[string]interface{}{
				"payload":   scrubSensitiveData(payloadStr),
				"sensitive": sensitive,
			},
		})

		// Calculate trust score
		trustScore := s.calculateTrustScore()

		// Check for blocking conditions (credit card to permanent storage)
		if sensitive["credit_card"] && s.Manifest.Privacy.RetentionPolicy == Permanent {
			logFlightRecord(FlightRecordEntry{
				Type:    "blocked",
				TraceID: traceID,
				Details: map[string]interface{}{
					"reason": "Privacy Violation: Credit card data cannot be sent to agents with permanent retention",
				},
			})
			c.JSON(403, gin.H{
				"error":   "Privacy Violation: Credit card data cannot be sent to agents with permanent retention",
				"blocked": true,
			})
			return
		}

		// Check for blocking conditions (SSN to non-ephemeral storage)
		if sensitive["ssn"] && s.Manifest.Privacy.RetentionPolicy != Ephemeral {
			logFlightRecord(FlightRecordEntry{
				Type:    "blocked",
				TraceID: traceID,
				Details: map[string]interface{}{
					"reason": "Privacy Violation: SSN data can only be sent to agents with ephemeral retention",
				},
			})
			c.JSON(403, gin.H{
				"error":   "Privacy Violation: SSN data can only be sent to agents with ephemeral retention",
				"blocked": true,
			})
			return
		}

		// Check for warning conditions (low trust score)
		if trustScore < 7 {
			// Check for user override
			userOverride := c.GetHeader("X-User-Override")
			if userOverride != "true" {
				warning := fmt.Sprintf("⚠️ WARNING:\n  • Low trust score (%d/10)", trustScore)
				if s.Manifest.Reversibility.Level == None {
					warning += "\n  • No reversibility"
				}
				if s.Manifest.Privacy.RetentionPolicy == Permanent {
					warning += "\n  • Data stored permanently"
				}
				if s.Manifest.Privacy.HumanInLoop {
					warning += "\n  • Human review enabled"
				}

				logFlightRecord(FlightRecordEntry{
					Type:    "warning",
					TraceID: traceID,
					Details: map[string]interface{}{
						"warning":     warning,
						"trust_score": trustScore,
					},
				})

				c.JSON(449, gin.H{
					"warning":          warning,
					"requires_override": true,
					"trust_score":      trustScore,
				})
				return
			}

			// User overrode warning
			logFlightRecord(FlightRecordEntry{
				Type:    "quarantine",
				TraceID: traceID,
				Details: map[string]interface{}{
					"reason":      "low_trust_override",
					"trust_score": trustScore,
				},
			})
		}

		// Forward request to backend agent
		startTime := time.Now()
		resp, err := http.Post(
			s.AgentURL,
			"application/json",
			bytes.NewBuffer(bodyBytes),
		)
		if err != nil {
			logFlightRecord(FlightRecordEntry{
				Type:    "error",
				TraceID: traceID,
				Details: map[string]interface{}{
					"error": fmt.Sprintf("Failed to reach backend agent: %v", err),
				},
			})
			c.JSON(502, gin.H{"error": "Failed to reach backend agent"})
			return
		}
		defer resp.Body.Close()

		// Read response
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			logFlightRecord(FlightRecordEntry{
				Type:    "error",
				TraceID: traceID,
				Details: map[string]interface{}{
					"error": "Failed to read response from backend agent",
				},
			})
			c.JSON(500, gin.H{"error": "Failed to read response from backend agent"})
			return
		}

		// Log response
		latency := time.Since(startTime).Milliseconds()
		logFlightRecord(FlightRecordEntry{
			Type:    "response",
			TraceID: traceID,
			Details: map[string]interface{}{
				"latency_ms":  latency,
				"status_code": resp.StatusCode,
				"response":    scrubSensitiveData(string(respBody)),
			},
		})

		// Forward response
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
	})

	// Flight recorder trace endpoint
	router.GET("/trace/:trace_id", func(c *gin.Context) {
		traceID := c.Param("trace_id")
		var traces []FlightRecordEntry
		for _, entry := range flightRecorder {
			if entry.TraceID == traceID {
				traces = append(traces, entry)
			}
		}
		c.JSON(200, traces)
	})

	addr := fmt.Sprintf(":%d", s.Port)
	log.Printf("Starting IATP Sidecar on %s", addr)
	log.Printf("Backend Agent URL: %s", s.AgentURL)
	log.Printf("Trust Score: %d/10", s.calculateTrustScore())
	return router.Run(addr)
}

func main() {
	// Get configuration from environment variables
	agentURL := os.Getenv("IATP_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8000"
	}

	portStr := os.Getenv("IATP_PORT")
	port := 8001
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	trustLevelStr := os.Getenv("IATP_TRUST_LEVEL")
	if trustLevelStr == "" {
		trustLevelStr = "standard"
	}

	// Create default manifest (can be overridden via config file)
	manifest := CapabilityManifest{}
	manifest.Identity.AgentID = os.Getenv("IATP_AGENT_ID")
	if manifest.Identity.AgentID == "" {
		manifest.Identity.AgentID = "default-agent"
	}
	
	manifest.TrustLevel = TrustLevel(trustLevelStr)
	manifest.Capabilities.Idempotency = true
	manifest.Capabilities.ConcurrencyLimit = 100
	manifest.Capabilities.SLALatencyMs = 2000
	
	manifest.Reversibility.Level = ReversibilityLevel(os.Getenv("IATP_REVERSIBILITY"))
	if manifest.Reversibility.Level == "" {
		manifest.Reversibility.Level = Partial
	}
	manifest.Reversibility.UndoWindowSeconds = 3600
	
	manifest.Privacy.RetentionPolicy = RetentionPolicy(os.Getenv("IATP_RETENTION"))
	if manifest.Privacy.RetentionPolicy == "" {
		manifest.Privacy.RetentionPolicy = Temporary
	}
	manifest.Privacy.HumanInLoop = os.Getenv("IATP_HUMAN_IN_LOOP") == "true"
	manifest.Privacy.TrainingConsent = os.Getenv("IATP_TRAINING_CONSENT") == "true"

	// Create and run sidecar
	sidecar := NewSidecar(agentURL, manifest, port)
	if err := sidecar.Run(); err != nil {
		log.Fatalf("Failed to start sidecar: %v", err)
	}
}
