# Frequently Asked Questions (FAQ)

## 1. What is AI agent governance and why does it matter?
AI agent governance refers to the safety, trust, control, and reliability mechanisms required to run AI agents in production environments. The Agent Governance stack provides a unified platform that includes policy enforcement, zero-trust communication, runtime supervision, and reliability engineering.
It matters because deploying AI agents without governance can lead to security risks, uncontrolled resource usage, lack of auditability, and silent failures. This stack ensures production-grade protection across multiple layers.
## 2. How does Agent OS differ from LangChain/CrewAI?
Agent OS is focused on governance rather than orchestration. While frameworks like LangChain or CrewAI focus on building agent workflows and coordination logic, Agent OS provides policy enforcement, capability-based security, audit logging, and syscall abstraction for production safety and control.
## 3. Can I use this with my existing AI agents?
Yes. Each component of the Agent Governance ecosystem can work independently and can be integrated into existing AI agent systems. Developers can install only the core kernel or selectively add the runtime and SRE layers based on their production requirements.
## 4. What frameworks are supported?
The governance stack is framework-agnostic. It focuses on enforcing security, trust, runtime control, and reliability at the system level rather than being tied to a specific AI orchestration framework.
## 5. How much latency does governance add?
The system is designed to provide governance while remaining suitable for production use. For performance-specific details, refer to individual component repositories.
## 6. Is this production-ready?
Yes. The project is explicitly designed for production AI agents. It provides capability-based security, zero-trust identity, runtime supervision, and reliability engineering, all integrated through a version-compatible meta-package.
## 7. What compliance standards are supported?
The stack includes immutable audit logs and decision lineage tracking to support compliance and accountability. The project also follows a responsible disclosure security policy with coordinated vulnerability reporting and supported version guidelines.
## 8. How do I contribute?
Contributions are welcome. Contributors should refer to the individual component repositories (Agent OS, AgentMesh, Agent Runtime, and Agent SRE) for detailed contribution guidelines.
## 9. What is the license?
This project is licensed under the MIT License. See the LICENSE file for more details.
## 10. What is the roadmap?
The project is structured around expanding and integrating four governance layers: policy enforcement (Agent OS), zero-trust communication (AgentMesh), runtime supervision (Agent Runtime), and reliability engineering (Agent SRE). 

