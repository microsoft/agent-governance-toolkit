# GDPR-Compliant Customer Service Agents at VelvetCart Commerce
_Disclaimer: This document presents a hypothetical use case intended to guide architecture and compliance planning. No real-world company data or metrics are included. This case study references AGT version 3.1.0. Component names and capabilities may differ in newer versions. Refer to the current documentation for the latest features. AGT is a tool to assist with compliance but does not guarantee compliance. Compliance depends on proper implementation and operational practices._
**AGT Version**: 3.1.0

## Case Study Metadata

**Title**: GDPR-Compliant Customer Service Agents at VelvetCart Commerce

**Organization**: VelvetCart Commerce (VCC)

**Industry**: E-Commerce / Retail

**Primary Use Case**: Autonomous customer service automation with intelligent escalation, refund processing, and real-time privacy compliance for global e-commerce platform

**AGT Components Deployed**: Agent OS, AgentMesh, Agent Runtime, Agent SRE, Agent Compliance

**Timeline**: 12 months — 2-month pilot, 8-month rollout, 2-month optimization

**Deployment Scale**: 8 autonomous customer service agents, 45,000 tickets/day, 3 production environments (staging, prod, disaster recovery) across 4 GCP regions

---

## 1. Executive Summary

VelvetCart Commerce, an online fashion retailer with $2.1B annual GMV serving 8.2M customers across North America and Europe, faced a customer service crisis. A 180-person support team cost $12M annually, average response times of 18–24 hours placed CSAT in the 32nd percentile, and inconsistent policy application drove $3.8M in erroneous refunds during 2023. With $45 customer acquisition costs, 22% annual churn cost an estimated $31M in lost lifetime value.

Deploying autonomous AI agents without governance posed severe risks: GDPR fines up to €20M or 4% of global revenue, PCI-DSS failures suspending payment processing, unauthorized refund fraud, and brand-damaging viral incidents. A single agent mishandling a data deletion request could trigger regulatory investigation.

VCC deployed the Agent Governance Toolkit (AGT) to enable safe production deployment of 8 agents with Ed25519 cryptographic identity, sub-millisecond policy enforcement (<0.06ms average), and Merkle-chained append-only audit trails meeting GDPR Article 30 requirements. Results over 12 months: 99.9% faster response time (18–24 hours to 90 seconds), 83% support cost reduction ($12M to $2.1M), zero GDPR violations across 16.4M interactions, and 99.96% availability. CSAT improved from 32nd to 78th percentile.

---

## 2. Industry Context and Challenge

### 2.1 Business Problem

VCC's 180-person team handled ~35,000 tickets daily during normal periods, with seasonal spikes exceeding 60,000. Support costs totaled $12M/year plus $1.8M in seasonal hiring. Staff turnover hit 35%, and inconsistent policy application led to $3.8M in policy-violating refunds in 2023.

The triggering event: in April 2024 a support agent exported 12,000 customer records to a personal Google Drive, triggering GDPR Article 32 breach notification to the Irish Data Protection Commission. The DPC's remediation order mandated comprehensive access controls, real-time data monitoring, and cryptographic audit trails.

### 2.2 Regulatory and Compliance Landscape

GDPR governs VCC's EU operations: Article 5 (data minimization), Article 15 (right of access), Article 17 (right to erasure), Article 30 (processing records), Article 32 (security measures), and Articles 33–34 (breach notification within 72 hours). Non-compliance carries fines up to €20M or 4% of turnover — $84M exposure for VCC.

PCI-DSS Requirement 7 restricts cardholder data access; Requirement 10 mandates comprehensive logging. Non-compliance risks $5,000–$100,000/month fines or loss of card processing. CCPA grants California residents data rights with penalties up to $7,500 per intentional violation.

Before AGT, VCC used shared service accounts for automation, making individual attribution impossible. Application logs in GCP Cloud Logging lacked tamper-proof integrity, and data access controls existed only at the UI level with no policy-layer enforcement.

### 2.3 The Governance Gap

VCC's 90-day pilot in March 2024 used Microsoft Agent Framework without a governance layer, integrating Zendesk, Shopify, and Stripe. Controlled testing with 50 curated tickets showed 94% accuracy. Production exposed critical failures:

**Refund Exploit**: A customer discovered that mentioning "rash" bypassed the final-sale policy. The phrase spread through social media, generating $890 in fraudulent refunds within four days. Shared service accounts meant no attribution — no way to trace which logic triggered the override.

**GDPR Deletion Disaster**: A German customer requested to stop marketing emails. The automation misinterpreted this as a full erasure request and deleted the customer's profile while three orders (€840) were in transit, causing packages to ship to null recipients. The customer filed a DPC complaint citing both incomplete deletion and GDPR Article 6(1)(b) violation.

**Viral Hallucination**: An order-status agent fabricated a "Nevada weather delay" when tracking data was unavailable. The customer — a former VCC warehouse employee — posted the exchange to Twitter, generating 50,000+ negative impressions.

Post-pilot analysis revealed: shared identity preventing accountability, unrestricted data access violating minimization principles, mutable logs failing GDPR Article 30, no hallucination detection, and customer-facing failure modes with viral blast radius.

---

## 3. Agent Architecture and Roles

### 3.1 Agent Personas and Capabilities

**inquiry-routing-agent** (DID: `did:agentmesh:inquiry-route:7c4a9f2e`) — Ring 1, Trust 830. Triages incoming tickets, classifies intent, extracts entities, routes to specialists. Can read ticket content and customer emails; cannot access profiles, order histories, or payment data. Escalates on high-severity issues, ambiguous intent (confidence <0.75), or VIP customers (LTV >$5,000).

**order-status-agent** (DID: `did:agentmesh:order-status:3b8e2a7d`) — Ring 2, Trust 760. Retrieves tracking from Shopify and carrier APIs. Can read specific order shipping details only. Cannot access payment methods, full order histories, or initiate refunds. Escalates lost packages, address mismatches, and high-value orders (>$1,000).

**returns-and-refund-agent** (DID: `did:agentmesh:returns-refund:9e5f3c1b`) — Ring 1, Trust 720. Evaluates return eligibility and issues refunds up to $200 autonomously. Cannot access full credit card numbers or full order history. Escalates high-value refunds (>$200), final-sale exceptions, suspected fraud (>3 refunds in 90 days), and out-of-window returns.

**product-question-agent** (DID: `did:agentmesh:product-qa:6d2c8f4a`) — Ring 2, Trust 790. Answers product questions using vector database of catalog, reviews, and FAQs. Cannot access customer PII, purchase history, or financial data. Escalates safety concerns and low-confidence answers (<0.8).

**sentiment-analysis-agent** (DID: `did:agentmesh:sentiment:4a7b9e3f`) — Ring 1, Trust 810. Monitors all messages in real-time for frustration, anger, and viral risk. Operates on linguistic analysis only — no access to PII, orders, or financial data. Flags high-anger sentiment, at-risk VIP customers, and viral threats via IATP.

**fraud-detection-agent** (DID: `did:agentmesh:fraud-detect:8c3e5a9b`) — Ring 1, Trust 840. Monitors refund abuse, account takeover, and payment fraud via graph analysis. Can read order patterns and account metadata; cannot access full card numbers or issue refunds. Flags accounts for human review within 4 hours.

**escalation-coordinator-agent** (DID: `did:agentmesh:escalation:5f8b2c4d`) — Ring 1, Trust 800. Routes escalations to appropriate human queues based on urgency and complexity. Cannot access customer PII or modify tickets directly.

**gdpr-compliance-agent** (DID: `did:agentmesh:gdpr-compliance:2e9a7f6c`) — Ring 1, Trust 860. Handles Article 15/17/20 requests. Generates deletion plans across 11 systems, calculates legal retention, and creates approval workflows. Cannot execute deletions without multi-factor human approval — bypass attempts trigger the kill switch.

### 3.2 System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CUSTOMER-FACING CHANNELS                          │
│                                                                      │
│  Website Chat    Email    Twitter/X    Instagram DM                  │
│  SMS Support    Phone → Transcription    TikTok Mentions             │
│                                                                      │
│  [Live customers typing, screenshotting, posting publicly]           │
└──────────────────────────┬───────────────────────────────────────────┘
                           │ Real-time, high-volume, emotional
                           ▼
        ┌──────────────────────────────────────────────┐
        │      Zendesk Omnichannel Ticketing Hub       │
        │                                              │
        │  • 45K tickets/day from all channels         │
        │  • Customer history & purchase context       │
        │  • SLA tracking (90-sec target response)     │
        │  • Social media mentions monitoring          │
        └──────────────────┬───────────────────────────┘
                           │
                           ▼
        ┌─────────────────────────────────────────────────────┐
        │            AGT GOVERNANCE LAYER                     │
        │    (The firewall between agents and customer data)  │
        │                                                     │
        │  ┌────────────────────┐  ┌─────────────────────┐    │
        │  │   Agent OS         │  │   AgentMesh         │    │
        │  │   Policy Engine    │  │   Identity & Trust  │    │
        │  │   • Data access    │  │   • Ed25519 crypto  │    │
        │  │   • Refund limits  │  │   • Per-agent DID   │    │
        │  │   • GDPR controls  │  │   • Trust decay     │    │
        │  │   <0.06ms latency  │  │   • Viral risk flags│    │
        │  └────────────────────┘  └─────────────────────┘    │
        │                                                     │
        │  ┌─────────────────────────────────────────────┐    │
        │  │   Agent Runtime - Execution Sandboxes       │    │
        │  │   Ring 0: System    Ring 1: Trusted ($$)    │    │
        │  │   Ring 2: Standard  Ring 3: Untrusted       │    │
        │  │   [Containers isolated by privilege level]  │    │
        │  └─────────────────────────────────────────────┘    │
        └─────────────────────┬───────────────────────────────┘
                              │
        ┌─────────────────┬───┴─────────────┬───────────────┐
        │                 │                 │               │
        ▼                 ▼                 ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Sentiment    │  │ Inquiry      │  │ Fraud        │  │ GDPR         │
│ Analysis     │  │ Routing      │  │ Detection    │  │ Compliance   │
│ Agent        │  │ Agent        │  │ Agent        │  │ Agent        │
│              │  │              │  │              │  │              │
│ Ring 1       │  │ Ring 1       │  │ Ring 1       │  │ Ring 1       │
│ Trust: 810   │  │ Trust: 830   │  │ Trust: 840   │  │ Trust: 860   │
│              │  │              │  │              │  │              │
│ • Anger      │  │ • Categorize │  │ • Refund     │  │ • Art. 15    │
│   detection  │  │   tickets    │  │   abuse      │  │   data access│
│ • Profanity  │  │ • VIP flags  │  │ • Wardrobing │  │ • Art. 17    │
│ • Viral risk │  │ • Multi-lang │  │ • Fraud rings│  │   deletion   │
│ • Social     │  │ • Confidence │  │ • Graph      │  │ • Multi-sys  │
│   influence  │  │   scoring    │  │   analysis   │  │   tracking   │
└──────┬───────┘  └───────┬──────┘  └──────┬───────┘  └──────┬───────┘
       │(monitors all)    │                │(monitors all)   │
       │                  │                │                 │
       └──────────────────┼────────────────┘                 │
                          │                                  │
                          ▼                                  │
        ┌─────────────────────────────────────────┐          │
        │   SPECIALIST CUSTOMER SERVICE AGENTS    │          │
        │                                         │          │
        │  ┌──────────┐  ┌──────────┐  ┌────────┴┐           │
        │  │ Order    │  │ Returns &│  │ Product │           │
        │  │ Status   │  │ Refunds  │  │ Q&A     │           │
        │  │          │  │          │  │         │           │
        │  │ Ring 2   │  │ Ring 1   │  │ Ring 2  │           │
        │  │ Trust:760│  │ Trust:720│  │ Trust:790           │
        │  │          │  │          │  │         │           │
        │  │ • Track  │  │ • $200   │  │ • Sizing│           │
        │  │   orders │  │   limit  │  │ • Care  │           │
        │  │ • Carrier│  │ • Policy │  │ • No PII│           │
        │  │   APIs   │  │   enforce│  │   needed│           │
        │  │ • ETA    │  │ • Human  │  │ • Catalog           │
        │  │   calcs  │  │   >$200  │  │   only  │           │
        │  └────┬─────┘  └────┬─────┘  └────┬────┘           │
        └───────┼─────────────┼─────────────┼────────────────┘
                │             │             │
                └─────────────┼─────────────┘
                              ▼
        ┌────────────────────────────────────────────────────┐
        │         E-COMMERCE PLATFORM INTEGRATIONS           │
        │                                                    │
        │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │
        │  │   Shopify    │  │    Stripe    │  │ Shipping │  │
        │  │              │  │              │  │ Carriers │  │
        │  │ • Orders     │  │ • Payments   │  │          │  │
        │  │ • Customers  │  │ • Refunds    │  │ • UPS    │  │
        │  │ • Products   │  │ • Last 4 only│  │ • FedEx  │  │
        │  │ • Fulfillment│  │ • PCI scope  │  │ • USPS   │  │
        │  └──────┬───────┘  └──────┬───────┘  └────┬─────┘  │
        │         │                 │               │        │
        │  ┌──────┴─────────────────┴───────────────┴─────┐  │
        │  │        Customer Data & Analytics             │  │
        │  │  • SendGrid (email)  • Klaviyo (marketing)   │  │
        │  │  • Segment (events)  • Google Analytics      │  │
        │  │  [GDPR deletion must cover all these]        │  │
        │  └──────────────────────────────────────────────┘  │
        └─────────────────────┬──────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────────────────┐
        │            AUDIT & SOCIAL LISTENING                 │
        │                                                     │
        │  Merkle-chained append-only logs (GDPR Art. 30)     │
        │  GCP WORM storage (6-year retention)                │
        │  Customer interaction transcripts                   │
        │  Social media monitoring (Twitter, TikTok, IG)      │
        │  Viral risk alerts (follower count, sentiment)      │
        │  CSAT tracking per agent (quality feedback loop)    │
        └─────────────────────────────────────────────────────┘
```

*Figure 1: VCC's customer service agent architecture. Inbound tickets from six channels (chat, email, Twitter/X, Instagram, SMS, phone) funnel through Zendesk into the AGT governance layer, which acts as a firewall between agents and customer data. Agent OS (<0.06ms policy evaluation), AgentMesh (Ed25519 identity, per-agent DID, trust decay), and Agent Runtime (Ring 1–2 execution sandboxes on GCP) intercept every action before it reaches the eight agents. Monitoring agents (sentiment-analysis, fraud-detection) observe all traffic in parallel; specialist agents (order-status, returns-and-refund, product-question) handle resolution. All agent actions flow to e-commerce platform integrations (Shopify, Stripe, shipping carriers) with GDPR deletion required to cover all downstream data stores. Merkle-chained audit logs stream to GCP WORM storage with 6-year retention per GDPR Article 30.*

YAML policies are stored in a version-controlled GitHub repository with mandatory 2-person review, evaluated at 0.05–0.06ms latency before every agent action. AgentMesh provides Ed25519 cryptographic identity per agent stored in GCP Secret Manager with Cloud HSM protection. Trust scores adjust dynamically based on CSAT, policy compliance, and business outcomes. Agent Runtime executes each agent in dedicated GCP Cloud Run containers with ring-based resource limits. Agent Compliance generates Merkle-chained append-only audit trails streamed to GCP Cloud Storage in WORM mode with 6-year retention.

### 3.3 Inter-Agent Communication and Governance

**Viral Risk Escalation Flow**: When an influencer with 42K followers DM'd about a defective product, the sentiment-analysis-agent flagged VIRAL-RISK-CRITICAL within 100ms. The fraud-detection-agent verified legitimacy in parallel (0.6s). The escalation-coordinator-agent bypassed normal queues and created a VIP crisis ticket. A VP responded within 5 minutes, arranging same-day courier delivery. The customer posted positive testimonial reaching 38K viewers. Total agent coordination overhead: <1 second across 3 agents.

**GDPR Deletion Workflow**: The gdpr-compliance-agent scans 11 systems, checks for active orders and legal retention requirements, generates a deletion plan, and routes to human privacy team for cryptographic approval. Agent OS blocks execution without human signature. During 12 months, 127 GDPR requests were processed with 100% compliance and zero order fulfillment failures.

**Fraud Ring Detection**: The fraud-detection-agent maintains a graph database linking customers by shared addresses, payment methods, and return patterns. In Month 8, it detected 5 coordinated wardrobing returns in Boston — individual risk scores were low (0.15–0.25), but graph analysis showed 0.87 fraud probability. All 5 refunds were blocked, preventing $1,900 in losses.

### 3.4 Agent Runtime Sandboxing

VCC deploys all 8 agents on Google Kubernetes Engine (GKE) across 4 GCP regions (us-central1, us-east1, europe-west1, asia-east1), running on Container-Optimized OS (COS). The 90-second response SLA is the most lenient of the three case studies, which enables a meaningful Layer 3 isolation choice: gVisor is deployed for Ring 2 agents where the ~10μs/syscall overhead is acceptable, while Ring 1 agents use standard runc for lower latency.

#### Execution Isolation Primitives

| Mechanism | Layer | What It Enforces | Escape Risk Mitigated |
|-----------|-------|------------------|-----------------------|
| **Linux cgroups v2** | OS kernel | GKE resource limits per pod by ring: Ring 1 → 1.0 vCPU / 1 GiB; Ring 2 → 0.5 vCPU / 512 MiB | Runaway sentiment-analysis-agent (processing viral spikes) starving gdpr-compliance-agent during an active deletion workflow |
| **Linux namespaces** (PID, network, mount, IPC) | OS kernel | Each pod has an isolated network stack; Ring 2 agents have no route to Shopify payment or refund APIs | product-question-agent or order-status-agent reaching payment endpoints they are explicitly denied under PCI-DSS Req. 7 |
| **seccomp-BPF** | OS kernel | GKE default seccomp profile + VCC extensions blocking `ptrace`, `process_vm_readv`, and raw socket creation | Exploiting a kernel syscall to read another agent's in-memory customer PII or Shopify session tokens |
| **AppArmor** | OS mandatory access control | Container-Optimized OS default AppArmor profile restricts filesystem paths and mount operations | Defense-in-depth if the seccomp profile is bypassed; prevents host filesystem path traversal |
| **gVisor (`runsc`) — GKE Sandbox** | User-space kernel | Deployed for Ring 2 agents (order-status-agent, product-question-agent): user-space kernel intercepts all syscalls; host kernel never directly exposed | Kernel-level container escape in lower-trust agents handling untrusted customer-supplied product queries; 90-second SLA absorbs the ~10μs overhead |

#### Privilege Ring → Resource Limit Mapping

| Agent | Ring | Trust Score | vCPU | Memory | Network Access | Runtime |
|-------|------|-------------|------|--------|----------------|---------|
| gdpr-compliance-agent | Ring 1 | 860 | 1.0 | 1 GiB | GCP Secret Manager, internal deletion APIs only | runc |
| fraud-detection-agent | Ring 1 | 840 | 1.0 | 1 GiB | Shopify order/account metadata (read-only) | runc |
| inquiry-routing-agent | Ring 1 | 830 | 1.0 | 1 GiB | Zendesk ticket API (read/write) | runc |
| sentiment-analysis-agent | Ring 1 | 810 | 1.0 | 1 GiB | Social media monitoring feeds (read-only) | runc |
| escalation-coordinator-agent | Ring 1 | 800 | 1.0 | 1 GiB | Zendesk escalation queues | runc |
| returns-and-refund-agent | Ring 1 | 720 | 1.0 | 1 GiB | Shopify refund API (write, capped at $200) | runc |
| product-question-agent | Ring 2 | 790 | 0.5 | 512 MiB | Vector DB (catalog/FAQs) — no customer data endpoints | gVisor |
| order-status-agent | Ring 2 | 760 | 0.5 | 512 MiB | Shopify shipping read + carrier tracking APIs | gVisor |

`AgentRateLimiter`: Ring 1 → 1,000 calls/min; Ring 2 → 100 calls/min. Trust decay below 700 triggers mandatory human oversight mode — returns-and-refund-agent (trust 720) is monitored closest to this threshold.

#### VFS Namespace Isolation

Each agent's session context and customer data extracts are scoped to a per-DID `SessionVFS` namespace:
- gdpr-compliance-agent's deletion plan (listing all 11 systems and legal retention exceptions) cannot be read or modified by any other agent — this prevents a compromised inquiry-routing-agent from interfering with a live GDPR workflow
- returns-and-refund-agent cannot read fraud-detection-agent's risk scores before they are explicitly communicated via IATP — preventing an agent from gaming its own fraud assessment
- All agents use **Snapshot isolation**: at 45K tickets/day with independent per-customer sessions, Serializable isolation overhead is unnecessary

#### Breach Detection and Emergency Response

- **`RingBreachDetector`**: WARNING (1-ring gap, e.g., order-status-agent attempting a Ring 1 refund API call), HIGH (2-ring gap), CRITICAL (3-ring gap). HIGH and CRITICAL trigger automatic kill
- **`KillSwitch`**: automatic triggers for `RING_BREACH` (HIGH/CRITICAL), `RATE_LIMIT`, and `BEHAVIORAL_DRIFT`. **GDPR deferral exception**: if gdpr-compliance-agent holds an active Article 17 deletion in progress (deletion plan approved, execution underway), kill is deferred up to 120 seconds — a mid-execution kill would leave customer data partially erased across 11 systems with no saga compensation path, creating a GDPR Article 17 violation worse than the breach itself. The deletion completes, then the agent is terminated and the privacy team is notified.
- **`QuarantineManager`**: preferred response for returns-and-refund-agent anomalies (trust 720, closest to the 700 human-oversight threshold) — isolates the agent while in-flight refund sagas are handed to human reviewers

#### Side-Channel Attack Mitigations

VCC's customer data (PII, purchase history, GDPR deletion plans) is sensitive to timing inference — an adversary observing fraud-detection-agent response latency could determine whether a specific refund pattern triggered a fraud ring match, enabling systematic evasion. GDPR Article 32 requires "appropriate technical measures" to protect personal data, which VCC interprets to include side-channel mitigations at each isolation layer:

**CPU cache and timing attacks**:
- GKE's Container-Optimized OS runs on Google-managed infrastructure; VCC does not control SMT/hyper-threading settings at the host level — this is a known limitation, documented in VCC's GDPR Article 32 risk register with Google's shared-responsibility model cited as the compensating control
- gVisor (GKE Sandbox), deployed for Ring 2 agents (order-status-agent, product-question-agent), provides user-space kernel isolation that also limits the syscall surface available for timing-based host inference; gVisor intercepts all syscalls through a user-space kernel, preventing Ring 2 agents from observing host CPU timing signals directly
- CPU pinning is not enforced on GKE pods — GKE's scheduler does not guarantee exclusive core assignment; VCC mitigates this by ensuring Ring 2 agents (lower trust, handling untrusted customer-supplied product queries) run in gVisor-isolated pods, and Ring 1 agents are deployed in a dedicated GKE node pool with no Ring 2 co-tenancy

**Shared memory**:
- IPC namespace isolation (Layer 2) enforced on all GKE pods — no shared memory segments, message queues, or semaphore sets across agent containers
- No shared-memory inter-agent paths exist in VCC's deployment; all customer data exchange between agents (e.g., fraud score from fraud-detection-agent to returns-and-refund-agent) passes through IATP-signed messages rather than shared buffers — this was an explicit architectural decision to support GDPR data minimization (each agent receives only the fields it needs)

**Memory access pattern leakage**:
- Fraud-detection-agent's graph analysis (linking customers by shared address, payment method, return patterns) uses constant-time comparisons for fraud score thresholds — variable-time comparison would leak whether a specific account crossed the fraud ring detection boundary, enabling coordinated wardrobing at scores just below the threshold
- GDPR deletion plan generation in gdpr-compliance-agent involves checking legal retention holds across 11 systems; these lookups use constant-time existence checks to prevent timing inference of whether a customer has active orders or legal holds that block full erasure
- Ed25519 signing operations execute inside GCP Cloud HSM (FIPS 140-2 Level 2); constant-time guarantees are provided by the HSM hardware

**Known limitations and trade-offs**:
- VCC does not control GKE host-level SMT configuration; Google's infrastructure-level mitigations (GCP applies Spectre/Meltdown patches at the hypervisor layer across all GKE hosts) are the primary defense against cross-VM cache-timing attacks — VCC accepts this dependency as part of the GCP shared-responsibility model documented in its GDPR Data Processing Agreement with Google
- Ring 1 agents use standard runc (not gVisor) for performance; they are protected by Layer 2 OS controls and the dedicated node pool separation but lack Layer 3 hypervisor isolation — VCC's threat model accepts this for Ring 1 agents given their higher trust scores and tighter capability restrictions
- Review cadence: VCC security team reviews side-channel mitigations annually and after any GCP infrastructure CVE disclosure affecting GKE or Container-Optimized OS

#### Defense-in-Depth Composition

```
Layer 1 — Application (AGT)
  Agent OS: capability allow/deny, ring enforcement, <0.06ms latency
  CapabilityGuardMiddleware: blocks Ring 2 agents from payment and refund APIs
  SessionVFS: per-agent customer data namespace, Snapshot isolation

Layer 2 — OS Kernel (GKE, Container-Optimized OS)
  cgroups v2: Ring 1 → 1.0 vCPU / 1 GiB; Ring 2 → 0.5 vCPU / 512 MiB
  Linux namespaces: PID, network, mount, IPC — Ring 2 agents have no route to payment endpoints
  seccomp-BPF: GKE default profile + VCC extensions (blocks ptrace, raw sockets)
  AppArmor: COS default profile restricts filesystem and mount operations

Layer 3 — Hypervisor (GKE Sandbox — gVisor)
  Deployed for Ring 2 agents (order-status-agent, product-question-agent)
  Host kernel never directly exposed for lower-trust workloads handling customer queries
  Ring 1 agents use standard runc; 90-second SLA makes gVisor overhead acceptable for Ring 2
```

A policy bypass at Layer 1 for a Ring 2 agent is contained by network namespace isolation at Layer 2 (no route to payment APIs) and by gVisor at Layer 3 (host kernel unreachable). Ring 1 agents rely on Layers 1 and 2; the threat model accepts that Ring 1 agents are sufficiently trusted that gVisor's overhead is not justified.

---

## 4. Governance Policies Applied

### 4.1 OWASP ASI Risk Coverage

| OWASP Risk | Description | AGT Controls Applied |
|------------|-------------|---------------------|
| **ASI-01: Agent Goal Hijacking** | Attackers manipulate agent objectives via prompt injection in customer messages | Agent OS policy engine intercepts all actions before execution; unauthorized actions blocked in <0.06ms. Input sanitization detects injection patterns. Customer messages never modify agent policies. |
| **ASI-02: Excessive Capabilities** | Agent's authorized tools abused for fraud or data theft | Capability model enforces least-privilege per agent. Returns agent can issue refunds up to $200 only for active tickets. Rate limiting: max 10 refunds/hour per agent. |
| **ASI-03: Identity & Privilege Abuse** | Agents escalate privileges by abusing identities or inheriting excessive permissions | Ed25519 cryptographic identity per agent in GCP Secret Manager HSM; trust scoring (0–1000) with dynamic adjustment; delegation chains enforce monotonic capability narrowing. Shared service accounts prohibited. |
| **ASI-04: Uncontrolled Code Execution** | Agents trigger unintended actions through code execution or injection | Agent Runtime execution rings (0–3) with resource limits; kill switch for instant termination (<100ms); agents cannot execute shell commands; all database access via parameterized queries; container network policies block unapproved egress. |
| **ASI-05: Insecure Output Handling** | Agent outputs contain fabricated or harmful content | Content policies validate all outputs; confidence thresholding prevents hallucination; agents must respond "I don't know" when certainty is low rather than fabricating explanations. |
| **ASI-06: Memory Poisoning** | Persistent memory poisoned with malicious instructions from customer messages | Agent OS VFS makes policy files read-only; agents cannot modify own refund limits; customer messages sanitized before processing; RAG vector databases require authentication with version control. |
| **ASI-07: Unsafe Inter-Agent Communication** | Agents collaborate without adequate authentication | IATP with mutual TLS 1.3; all messages carry Ed25519 signatures; trust score verification before accepting delegated tasks; encrypted channels for sensitive data in transit. |
| **ASI-08: Cascading Failures** | Single agent error triggers compound failures halting service | Agent SRE circuit breakers trip after 5 consecutive API failures; SLO enforcement (99.9% response rate); graceful degradation routes to human agents when systems degrade. |
| **ASI-09: Human-Agent Trust Deficit** | Attackers leverage trust in automated responses to approve fraudulent requests | Full audit trails and flight recorder; approval workflows for high-risk actions (>$200 refunds, GDPR deletions); risk assessment classifies all tickets. |
| **ASI-10: Rogue Agents** | Agents operating outside scope via bugs or adversarial behavior | Kill switch terminates containers exhibiting fraud patterns; ring isolation prevents privilege escalation; trust decay on violations; Merkle audit trails detect tampering; behavioral anomaly detection. |

Additional security measures include AI-BOM tracking LLM model provenance and training data lineage, SBOM for Python dependencies scanned daily with Dependabot, mutual TLS for all API connections to Zendesk/Shopify/Stripe, secrets management via GCP Secret Manager with 90-day credential rotation, and PII encryption at rest using AES-256-GCM.

### 4.2 Key Governance Policies

  This section details the mission-critical governance policies that prevented 3,847 violations worth $142K+ in potential exposure over 12 months of
  production operation. The policies below represent the minimum viable governance layer required to safely deploy autonomous agents in e-commerce
  environments under GDPR and PCI-DSS. Each policy maps to specific regulatory requirements, demonstrates sub-millisecond enforcement
  latency, and includes real production examples showing AGT controls in action.

  **Most Critical Policies at a Glance:**

  | Policy Name | Regulatory Driver | Prevented Risk | Impact |
  |-------------|-------------------|----------------|--------|
  | Viral Social Media Escalation | GDPR Art. 5(1)(f), brand risk management | Reputational damage and negative viral events | 23 interventions over 12 months, 100% success rate, 0 negative viral incidents |
  | Refund Fraud Ring Detection | PCI-DSS Req. 6.4 | Coordinated refund fraud and wardrobing | Blocked 628 fraud patterns (347 individual, 281 rings), prevented $142K in losses |
  | GDPR Deletion with Order-Safety Checks | GDPR Art. 17 (right to erasure) | Incomplete deletion causing DPC complaints and order fulfillment failures | 127 requests processed, 100% compliance, zero regulatory complaints |
  | GDPR Data Minimization | GDPR Art. 5(1)(c) | Unauthorized PII access by agents outside their permitted scope | Blocked 892 data minimization violations, €0 in GDPR fines |

**Viral Social Media Escalation**: Combines sentiment analysis with social media context. When high-anger keywords and influencer indicators are detected, normal routing is overridden for VIP escalation. During 12 months, 23 viral-risk interventions achieved 100% success rate preventing negative viral events, with 2.3% false positive rate.

**Refund Fraud Ring Detection**: Graph-based detection linking customers by shared addresses, payment methods, IP ranges, and timing patterns. Catches coordinated abuse that individual transaction analysis misses. Detected 628 fraud patterns (347 individual abusers, 281 rings), preventing $142K in losses.

**GDPR Deletion with Order-Safety Checks**: Multi-phase validation before any deletion — checks active orders, pending refunds, legal holds, and retention requirements. Deletions execute in transactional batches with rollback on partial failure. Mandatory human verification with cryptographic signature. Processed 127 requests with zero incidents.

**GDPR Data Minimization**: Restricts data access based on agent role and ticket context. Order-status-agent can access only the specific order in the current ticket. Product-question-agent operates with zero customer PII. Policy engine evaluates before every Shopify/Stripe API call.

### 4.3 Compliance Alignment

**GDPR Article 30**: Agent Compliance logs every action with agent DID, timestamp, pseudonymized customer ID, data categories accessed, legal basis, and purpose. Logs stored in GCP Cloud Storage WORM mode with 6-year retention. DPC audit of 2.7M interactions confirmed full Article 30 compliance.

**GDPR Article 17**: Multi-stage erasure workflow with human approval. 94 successful deletions, 33 deferred for active orders. Zero regulatory complaints.

**PCI-DSS Requirement 7**: Policy engine intercepts Stripe API calls, filtering responses to remove full PANs — agents see only last 4 digits and card brand. QSA audit confirmed zero vulnerabilities.

**Governance Reporting**: Weekly auto-generated reports covering ticket volume by agent, compliance rates (99.97% over 12 months), trust score distributions, escalation rates, and OWASP ASI posture. Delivered to CPO, VP Customer Experience, and available to regulators.

### 4.4 Cryptographic Controls and Key Management

This section documents cryptographic operations, key management practices, and verification mechanisms implemented to address OWASP ASI-03 (Identity & Privilege Abuse) and ASI-07 (Insecure Inter-Agent Communication) in VCC's GDPR- and PCI-DSS-regulated customer service environment.

#### 4.4.1 Cryptographic Operations

| Operation | Algorithm | What Is Signed | Verification Point |
|-----------|-----------|----------------|--------------------|
| Agent identity signing | Ed25519 | `{agentDID, actionType, resourceURI, timestamp_ms, policyDecision}` | AgentMesh DID registry; Zendesk, Shopify, and Stripe API calls include signed JWT validated against DID registry on every request |
| IATP trust attestation | Ed25519 | `{delegatorDID, delegateeDID, capabilitySet, effectiveTrustScore, issuedAt, expiresAt, nonce}` | Receiving agent verifies signature against delegator's public key in DID registry before accepting task delegation |
| Inter-agent message integrity | Ed25519 + SHA-256 | Full message payload signed at each delegation hop | Each downstream agent re-verifies; monotonic capability narrowing enforced on capability set at each hop |
| GDPR deletion approval | Ed25519 (human-signed) | `{deletionPlanID, agentDID, affectedSystems[], retentionExceptions[], approverID, timestamp_ms}` | gdpr-compliance-agent verifies human approver's Ed25519 signature before executing any erasure action across 11 systems; Agent OS blocks execution without valid signature |
| Audit trail integrity | SHA-256 Merkle chain | Each log entry: `{prev_hash, agentDID, timestamp_ms, actionType, pseudonymizedCustomerID, dataCategory, legalBasis, policyDecision}` | Hash chains verified in GCP Cloud Storage WORM mode; DPC audit confirmed 100% integrity across 2.7M interactions |
| Transport | TLS 1.3 (mTLS) | N/A — channel-level encryption | Mutual certificate validation on all Zendesk, Shopify, and Stripe API connections and inter-agent channels; required cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| PII at rest | AES-256-GCM | Customer PII, cardholder data, ticket content | GCP Cloud HSM-managed keys scoped per agent; PCI-DSS Requirement 3 compliance; agents outside PCI scope never receive decrypted PANs |

#### 4.4.2 Key Management Practices

- **Key generation**: Ed25519 keypairs generated inside GCP Cloud HSM (FIPS 140-2 Level 2) at agent provisioning time. Private keys never leave the HSM — all signing operations execute within Cloud HSM via GCP Secret Manager API. Entropy source: hardware RNG within GCP Cloud HSM.
- **Key storage**: GCP Secret Manager with per-agent service accounts. Each agent's secret has an IAM binding scoped exclusively to that agent's service account — no shared credentials, no cross-agent access. Separation of duty enforced: Secret Manager administrators cannot access secret values; agents cannot modify their own IAM bindings. All secret access logged to GCP Cloud Audit Logs for GDPR Article 30 and PCI-DSS Requirement 10 compliance.
- **Key rotation**: Ed25519 identity keys rotate every 90 days via automated GCP Secret Manager rotation policy. On rotation, AgentMesh publishes the updated public key to the DID registry. In-flight Shopify and Stripe API calls complete under the prior key (short JWT expiry ensures natural cutover); new requests use tokens signed with the new key. Zero downtime — no agent restart or customer ticket interruption required.
- **Key revocation**: Triggers: (a) trust score drops below 600 following fraud pattern detection or GDPR policy violations, (b) gdpr-compliance-agent attempts to bypass human approval signature — immediately activates kill switch, (c) Agent SRE detects anomalous behavior (e.g., returns-and-refund-agent issuing refunds beyond $200 cap), (d) manual security incident declaration. On trigger: GCP Secret Manager disables the secret version within <2 seconds; AgentMesh marks DID `deactivated`; all active IATP sessions from the revoked agent invalidated within one heartbeat cycle (5 seconds). In-flight customer tickets are routed to the human escalation queue — no customer request is silently dropped.
- **DID lifecycle**:
  - *Creation*: On agent provisioning — Cloud HSM generates keypair, AgentMesh registers `did:agentmesh:{agentId}:{fingerprint}` with public key, privilege ring, and initial trust score.
  - *Update*: On 90-day key rotation (new public key) or ring change (trust score threshold crossed, e.g., fraud-detection-agent trust decay). DID document version incremented; prior versions retained for GDPR Article 30 audit integrity.
  - *Deactivation*: On agent decommission or revocation. DID marked `deactivated` — not deleted. Historical signatures remain verifiable for the 6-year GDPR Article 30 retention period.

**Key Compromise and Recovery**

A compromised Ed25519 private key at VCC carries two distinct risks: forged GDPR deletion approvals (triggering unauthorized erasure across 11 systems) and forged Shopify refund authorizations (enabling fraud above the $200 autonomous cap). VCC's response targets containment within 5 minutes of detection:

Detection mechanisms:
- **GCP Security Command Center + Cloud Audit Logs**: unexpected Secret Manager secret access outside the agent's service account, API calls from unrecognized identities, or audit log gaps that may indicate secret extraction; alerts routed to VCC security operations via GCP Cloud Monitoring within 60 seconds
- **Trust score anomaly**: an unexpected spike in GDPR deletion requests or refund approvals from an agent — particularly gdpr-compliance-agent or returns-and-refund-agent — correlated with signing activity may indicate key misuse before formal compromise is confirmed; trust decay below 700 already triggers mandatory human oversight, providing an early warning signal
- **GDPR workflow anomaly**: deletion plan executions without a corresponding human approval signature in the Merkle audit trail trigger an immediate alert — Agent OS blocks unsigned deletions, so a forged approval signature appearing in the trail without a corresponding human action is a strong compromise indicator

Immediate mitigation steps (target: <5 minutes from detection to containment):
1. Disable the GCP Secret Manager secret version for the affected agent — propagates to all agents holding a cached public key within <2 seconds via Secret Manager event notification
2. Quarantine the affected agent via `QuarantineManager` — preferred over kill switch for GDPR continuity: if compromise is detected during an active Article 17 deletion, quarantine preserves in-flight saga state for human review rather than leaving data partially erased across 11 systems
3. Issue a DID deactivation event in AgentMesh — all peer agents reject delegations from the deactivated DID within one heartbeat cycle (~5 seconds); pending customer tickets routed to human escalation queue automatically
4. Provision a new Ed25519 keypair in GCP Cloud HSM, generate a new DID, and re-register the agent — requires privacy team lead and security officer dual approval; if gdpr-compliance-agent is the affected agent, assess whether any in-progress GDPR deletion was compromised and notify affected customers under GDPR Article 33 (72-hour DPA breach notification window)

Propagation timeline and impact on dependent agents:
- Key revocation: <2 seconds (Secret Manager) → <5 seconds (IATP session invalidation) → <30 seconds (full cache invalidation across all 8 agents across all 4 GCP regions)
- IATP attestations signed by the compromised key: invalid immediately after DID deactivation; VCC's 10-minute nonce TTL cache is flushed on deactivation — the longest TTL across the three deployments, making this flush especially important to close the residual replay window
- In-flight GDPR deletions: if an active Article 17 deletion was in progress under the compromised key, the saga is suspended and escalated to the privacy team; no erasure step is executed or reversed without explicit re-authorization from a human approver using a new, verified key
- Incident recorded in the Merkle audit trail with agent DID, timestamp, revocation reason, and approving identities — retained for 6 years per GDPR Article 30; GDPR Article 33 assessment initiated immediately to determine whether the incident constitutes a personal data breach requiring DPA notification within 72 hours

#### 4.4.3 Verification Mechanisms

- **Peer identity verification before inter-agent calls**: Before accepting any IATP delegation, the receiving agent: (1) resolves the delegating agent's DID from AgentMesh registry, (2) checks status — rejects immediately if `deactivated`, (3) verifies the Ed25519 signature on the attestation payload, (4) confirms the effective trust score meets the minimum threshold for the requested capability. Total verification overhead: <1ms per call — negligible against the 90-second customer response SLA.
- **Trust score threshold at connection time**: Agents with trust score below 600 cannot initiate delegations for financial or privacy-sensitive actions (refund issuance, GDPR data access, customer PII retrieval). Agents scoring 600–699 may delegate only to human escalation queues, not to peer agents. Agents at 700+ may delegate within their approved capability set. The returns-and-refund-agent (trust 720) and gdpr-compliance-agent (trust 860) are specifically monitored — any trust decay below 700 for either triggers mandatory human oversight for all subsequent actions.
- **Replay attack prevention**: All IATP attestations include a cryptographically random 128-bit nonce and an `issuedAt` timestamp (millisecond precision, NTP-synchronized). Key details:
  - **Nonce reuse detection**: each receiving agent maintains a per-sender-DID nonce cache (10-minute TTL — the longest across all three deployments, chosen to cover async GDPR deletion workflows that may span multiple agent interactions over several minutes); a duplicate nonce from the same sender DID is rejected immediately and logged to the Merkle audit trail as a potential replay attempt; this is especially critical for GDPR deletion workflows — a replayed human approval signature could trigger duplicate erasure across all 11 systems (Shopify, Stripe, SendGrid, Klaviyo, Segment, and others) while orders are still in transit, exactly the failure mode that triggered VCC's original DPC complaint
  - **Nonce cache across GKE pod replicas**: VCC runs GKE across 4 regions (us-central1, us-east1, europe-west1, asia-east1) with horizontal pod autoscaling in each; multiple pod replicas of the same agent can exist simultaneously within a region and across regions; nonce caches are per-pod with an accept-on-first-seen policy — a nonce seen by replica A is not automatically known to replica B in the same or a different region; the 10-minute TTL means a replayed nonce remains a risk across pod replicas for the full 10-minute window; the ±60-second timestamp window alone does not close this gap — a replay to a different replica within 60 seconds of original issuance carries a still-valid timestamp; VCC accepts this residual risk given the mandatory human Ed25519 signature requirement for the highest-risk GDPR deletion operations, and mitigates it for lower-risk operations via the trust score threshold check at connection time
  - **Maximum allowable clock drift**: ±60 seconds — the widest window across all three deployments, appropriate for async customer service and GDPR workflows where API responses from Shopify and payer systems may be delayed by tens of seconds; the wider window accepts more clock drift tolerance in exchange for a larger potential replay window, which is mitigated for the highest-risk operations (GDPR deletions) by the mandatory human Ed25519 signature requirement
  - **Clock drift monitoring**: all GKE nodes synchronize to GCP's internal NTP service; Cloud Monitoring alerts VCC operations if NTP sync delta exceeds 10 seconds on any GKE node — a 10-second alert threshold provides a 50-second buffer before approaching the ±60-second rejection boundary, preventing false-positive rejections during normal customer service operations
- **Delegation chain verification**: For the GDPR deletion workflow (gdpr-compliance-agent → human approver → execution across 11 systems), the agent verifies the full chain before executing any erasure: each Ed25519 signature including the human approver's, active order and legal hold checks completed, monotonic capability narrowing at each hop, and no deactivated DID in the chain. For the viral escalation workflow (sentiment-analysis-agent → escalation-coordinator-agent → human VIP queue), the same chain verification applies. Maximum chain depth: 4 hops (Agent OS policy).
- **Failure behavior**: When verification fails (invalid signature, deactivated DID, expired nonce, trust below threshold), the agent: (1) denies the action immediately and logs full chain details with timestamp to the Merkle audit trail (satisfying GDPR Article 30 documentation requirements), (2) never silently fails — customer requests are always routed to a human queue rather than dropped, (3) for GDPR deletion failures, immediately notifies the privacy team with the failure reason to preserve the 30-day GDPR response window, (4) if 3+ failures from the same agent occur within 10 minutes, alerts VCC security operations and initiates trust decay on the suspicious agent.

---

## 5. Outcomes and Metrics

### 5.1 Business Impact

| Metric | Before AGT | After AGT | Improvement |
|--------|-----------|-----------|-------------|
| Average response time | 18-24 hours | 90 seconds | 99.9% faster |
| Daily ticket capacity | 35,000 tickets | 45,000 tickets | 29% increase |
| Support team cost | $12M/year | $2.1M/year | 83% reduction |
| Customer satisfaction (CSAT) | 32nd percentile | 78th percentile | +46 percentile points |
| First-contact resolution rate | 58% | 79% | 36% improvement |
| Customer churn | 22%/year | 14%/year | 36% reduction |

**ROI**: AGT deployment cost $520K over 12 months. Annual savings total $41.4M ($9.9M labor reduction, $1.8M eliminated seasonal hiring, $17M reduced churn, $11M increased LTV, $1.7M fraud prevention). 80x return, break-even at Day 14. The remaining 32-person team shifted to complex escalations and strategic work, with employee NPS improving from -12 to +42.

### 5.2 Technical Performance

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Policy evaluation latency | <0.1ms | 0.058ms avg (p50: 0.05ms, p99: 0.11ms) | Met |
| System availability | 99.9% | 99.96% | Exceeded |
| Agent error rate | <2% | 0.8% | Exceeded |
| Escalation rate | 30-40% | 32% | Met |
| Kill switch false positives | <10/month | 1.2/month avg | Exceeded |
| Average API response time | <200ms | 147ms | Exceeded |

Governance overhead: 0.058ms per action (0.3% of end-to-end latency). Scaled across 4 GCP regions without degradation. Black Friday 2024 peak: 68,000 tickets/day handled with p99 latency under 0.15ms.

### 5.3 Compliance and Security Posture

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Audit trail coverage | 100% | 100% | Met |
| Policy violations (bypasses) | 0 | 0 | Met |
| GDPR regulatory fines | €0 | €0 | Met |
| Data breach incidents | 0 | 0 | Met |
| Blocked unauthorized actions | — | 3,847 over 12 months | — |
| PCI-DSS audit findings | 0 critical | 0 critical, 0 high | Met |
| GDPR Art. 17 compliance rate | >95% | 100% (127/127 requests) | Exceeded |

Irish DPC audit (April 2025) found zero findings across all areas, citing VCC's implementation as a reference model for e-commerce GDPR compliance. PCI-DSS QSA audit confirmed full Requirement 7 compliance. AGT blocked 3,847 violations: 1,247 refund limit breaches, 892 data minimization violations, 523 GDPR violations, 628 fraud pattern refunds, and 557 PCI-DSS violations. Total fraud prevention value: $142,636.

---

## 6. Lessons Learned

### 6.1 What Worked Well

**Escalation Rate Calibration**: The 32% escalation rate was initially seen as underperformance but proved optimal — escalated tickets included VIP service (8%), complex exceptions (12%), fraud investigation (7%), and improvement opportunities (5%). Reducing escalation degraded quality. Benchmark against ticket complexity, not arbitrary targets.

**Transparency Building Trust**: VCC published a "Behind the Scenes: Our AI Customer Service" page explaining governance controls. Customer trust scores improved from 51% to 73%. Privacy-conscious customers became advocates, turning GDPR compliance into a competitive differentiator.

### 6.2 Challenges Encountered

**Black Friday Volume**: 3.2x traffic spikes exposed sentiment model failures on all-caps and emoji-heavy messages, carrier API timeouts causing hallucinations, and emotionally compelling return stories bypassing policy. Resolution: retrained sentiment models on informal text, implemented honest "tracking unavailable" responses, and restricted refund agents to structured decision criteria. Black Friday 2025 CSAT hit 76%, above the annual average.

**Multilingual Drift**: Agents switched languages mid-conversation. Resolution: language preference passed via IATP metadata, LLM temperature reduced to 0.1, language consistency validation blocks mismatched responses.

**Evolving Fraud**: Organized resale rings used VCC as free inventory, exploiting the return window. Resolution: resale platform monitoring cross-referencing customer emails with eBay/Poshmark profiles, delayed refund holds for flagged accounts.

**Gen Z Communication Styles**: Emoji-heavy, hyperbolic language confused sentiment analysis (skull emoji scored as neutral). Resolution: fine-tuned on 5,000 labeled Gen Z customer tickets, improving accuracy from 61% to 89%.

### 6.3 Advice for Similar Implementations

**For E-Commerce Companies**: Start with read-only agents before granting write authority. Engage privacy/legal teams early — GDPR interpretation varies by jurisdiction. Don't underestimate change management; address job-loss fears through transparent communication and redeployment.

**For Customer-Facing Applications**: Optimize for experience, not just cost reduction — the real value was $28M from improved retention, not $9.9M in cost savings. Implement sentiment analysis as a cross-cutting oversight agent providing real-time signals via IATP to all other agents.

**For GDPR-Regulated Environments**: Treat compliance as a product feature, not legal overhead. Document processing purposes at ticket-level granularity. Test right-to-erasure workflows across all systems during pilot — budget 4–6 weeks for deletion workflow development.
