# Security Policy

## Supported Versions

We take security seriously and actively maintain the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We appreciate your efforts to responsibly disclose security vulnerabilities. Please follow these guidelines:

### 🔒 Private Disclosure (Recommended)

For serious security vulnerabilities, please use one of these private channels:

1. **GitHub Security Advisories** (preferred)
   - Go to [Security Advisories](https://github.com/microsoft/agent-governance-toolkit/security/advisories/new)
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Direct Contact**
   - Create a draft security advisory on GitHub
   - We will respond within 48 hours

### 📢 Public Disclosure

For low-severity issues or security improvements, you may:
- Create a public issue using the [Security Vulnerability template](https://github.com/microsoft/agent-governance-toolkit/issues/new?template=security_vulnerability.yml)
- Be aware that this will be publicly visible immediately

## What to Include in Your Report

Please provide the following information:

1. **Vulnerability Description**: Clear explanation of the issue
2. **Affected Versions**: Which versions are vulnerable
3. **Impact Assessment**: What could an attacker do with this vulnerability?
4. **Reproduction Steps**: Detailed steps to reproduce the issue
5. **Proof of Concept**: Code or commands demonstrating the vulnerability (if applicable)
6. **Suggested Fix**: If you have ideas for remediation (optional)
7. **CVE Information**: If a CVE has been assigned (optional)

## Our Commitment

When you report a vulnerability, we commit to:

- **Acknowledge** your report within **48 hours**
- **Provide an initial assessment** within **5 business days**
- **Keep you informed** about our progress toward a fix
- **Credit you** in the security advisory (if desired)
- **Follow coordinated disclosure** practices

## Security Best Practices for Users

When using Agent Control Plane in production:

### 1. Access Control
```python
# Always use strict permission policies
control_plane = ControlPlane(
    agent_id="production-agent",
    allowed_tools=["search", "read_only"],  # Minimal permissions
    denied_tools=["execute_code", "file_write"],  # Explicitly deny dangerous tools
)
```

### 2. Rate Limiting
```python
# Configure appropriate rate limits
control_plane.policy_engine.configure_rate_limit(
    max_requests=100,
    time_window=60  # per minute
)
```

### 3. Audit Logging
```python
# Enable comprehensive audit logs
control_plane.enable_audit_logging()

# Regularly review audit logs
audit_trail = control_plane.get_audit_trail()
```

### 4. Constraint Graphs
```python
# Use constraint graphs to enforce safety boundaries
from agent_control_plane import DataConstraint, PolicyConstraint

control_plane.add_constraint(
    DataConstraint(allowed_data_types=["public"])
)
control_plane.add_constraint(
    PolicyConstraint(require_approval=True)
)
```

### 5. Shadow Mode Testing
```python
# Test agent behavior in shadow mode first
control_plane.enable_shadow_mode()
# Validate behavior before enabling real execution
control_plane.disable_shadow_mode()
```

### 6. Supervisor Agents
```python
# Use supervisor agents for high-risk operations
from agent_control_plane import SupervisorAgent

supervisor = SupervisorAgent(
    agent_id="supervisor",
    supervised_agents=["agent-1", "agent-2"],
    anomaly_detection=True
)
```

### 7. Regular Updates
- Keep Agent Control Plane updated to the latest version
- Subscribe to security advisories via GitHub Watch
- Review CHANGELOG.md for security-related updates

### 8. Environment Isolation
- Run agents in sandboxed environments (Docker containers, VMs)
- Use network segmentation
- Apply principle of least privilege

### 9. Input Validation
```python
# Always validate and sanitize inputs
from agent_control_plane import JailbreakDetector

detector = JailbreakDetector()
if detector.is_jailbreak_attempt(user_input):
    # Reject the request
    raise SecurityError("Potential jailbreak detected")
```

### 10. Compliance Frameworks
```python
# Enable relevant compliance frameworks
from agent_control_plane import ComplianceEngine

compliance = ComplianceEngine()
compliance.enable_framework("eu_ai_act")
compliance.enable_framework("soc2")
```

## Known Security Considerations

### 1. LLM-Specific Risks
- **Prompt Injection**: Use JailbreakDetector and input validation
- **Data Exfiltration**: Enforce data constraints and output monitoring
- **Model Manipulation**: Use constitutional AI principles

### 2. Multi-Agent Risks
- **Privilege Escalation**: Supervisor agents monitor for anomalies
- **Agent Collusion**: Isolation boundaries enforced by kernel
- **Resource Exhaustion**: Rate limiting and quotas enforced

### 3. Integration Risks
- **Third-Party APIs**: Validate all external inputs/outputs
- **Dependency Chain**: Regular security audits of dependencies
- **Configuration Errors**: Use provided secure defaults

## Security Features

Agent Control Plane provides multiple layers of security:

1. **Deterministic Enforcement**: Policy violations blocked at kernel level
2. **Jailbreak Detection**: 60+ attack pattern recognition
3. **Anomaly Detection**: Behavioral analysis of agent actions
4. **Audit Trail**: Complete SQLite-based action logging
5. **Compliance Engine**: EU AI Act, SOC 2, GDPR support
6. **Constitutional AI**: Value alignment framework
7. **Multimodal Safety**: Content moderation for vision/audio
8. **Zero-Trust Architecture**: Default deny, explicit allow

## Security Research and Bug Bounty

We currently do not have a formal bug bounty program, but we:
- Welcome security research on the project
- Credit security researchers in advisories (with permission)
- Consider significant contributions for acknowledgment
- Follow responsible disclosure practices

## CVE Process

For vulnerabilities assigned CVEs:
1. We will work with you on coordinated disclosure
2. A security advisory will be published on GitHub
3. Affected versions will be documented
4. Fixed versions will be released promptly
5. Users will be notified through multiple channels

## Questions?

For general security questions (non-vulnerability):
- Open a [discussion](https://github.com/microsoft/agent-governance-toolkit/discussions)
- Create a question issue
- Review the [security documentation](docs/)

---

**Thank you for helping keep Agent Control Plane secure!**
