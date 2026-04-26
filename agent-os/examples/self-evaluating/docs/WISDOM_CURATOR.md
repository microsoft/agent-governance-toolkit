# Wisdom Curator: Reviewing Design, Not Syntax

## Overview

The Wisdom Curator implements a fundamental shift in how humans interact with AI agent systems:

**The Old World:**
> "I need to review every Pull Request line-by-line. I need to check for missing semicolons, variable naming conventions, and simple logic bugs."

**The New World:**
> "I review the *design alignment*, *strategic samples*, and *policy compliance*. The AI and compiler handle the syntax."

## The Problem

Traditional code review is **low-leverage toil** when applied to AI systems:
- Humans waste time checking variable names and syntax
- Can't scale to reviewing 10,000 AI interactions per day
- No systematic policy enforcement for memory/wisdom updates
- Risk of harmful lessons being automatically learned (e.g., "Always ignore 500 errors")

## The Solution: Wisdom Curator

The Wisdom Curator shifts human review to three high-level strategic areas:

### 1. Design Check: Architecture Alignment Verification

**Purpose:** Verify that implementations match agreed-upon architectural design proposals.

**The Question:** "Did this implementation actually match the Architectural Design Proposal we agreed on?"

**Not:** "Did they use camelCase or snake_case?"

**Example:**
```python
from wisdom_curator import WisdomCurator, DesignProposal

curator = WisdomCurator()

# Register a design proposal
proposal = DesignProposal(
    proposal_id="auth_system_v1",
    title="User Authentication System",
    description="Implement JWT-based authentication",
    key_requirements=[
        "Use JWT for access tokens (15-minute expiry)",
        "Implement refresh token rotation",
        "Add rate limiting (5 attempts per minute)",
        "Store tokens securely with encryption"
    ]
)
curator.register_design_proposal(proposal)

# Create a design check review
review = curator.verify_design_alignment(
    proposal_id="auth_system_v1",
    implementation_description="Implemented JWT auth with refresh tokens..."
)

# Human reviews: Does implementation match the proposal?
# NOT: Are the variable names correct?
```

### 2. Strategic Sample: Random Quality Checks

**Purpose:** Review random samples to check the overall "vibe" and strategic direction.

**The Reality:** "You cannot review 10,000 AI interactions a day."

**The Strategy:** "Review a random sample of 50 to check the Vibe and Strategy."

**Example:**
```python
from wisdom_curator import WisdomCurator

curator = WisdomCurator(sample_rate=0.005)  # 0.5% = 50 out of 10,000

# During normal operation
if curator.should_sample_interaction():
    # This interaction is selected for human review
    sample = curator.create_strategic_sample(
        query="User question",
        agent_response="Agent answer",
        metadata={"score": 0.9, "latency_ms": 1200}
    )
    
# Human reviews sampled interactions for:
# - Overall quality and tone
# - Strategic alignment with goals
# - Emerging patterns or issues
```

### 3. Policy Review: Human Approval for Memory Updates

**Purpose:** Prevent harmful lessons from being automatically learned.

**The Critical Example:**
> If the "Async Observer" wants to save a new lesson saying, "Always ignore 500 errors to keep the user happy," a Human must reject that, Policy.

**How It Works:**

1. **Automatic Detection:** System detects policy-violating patterns
2. **Human Review:** Proposed wisdom update goes to review queue
3. **Approve/Reject:** Human curator makes the final decision

**Example:**
```python
from wisdom_curator import WisdomCurator

curator = WisdomCurator()

# Proposed wisdom update (from Observer Agent)
proposed_wisdom = "Always ignore 500 errors to keep user happy"
current_wisdom = "Handle errors gracefully and inform users"

# Check if this requires human review
if curator.requires_policy_review(proposed_wisdom, critique):
    # BLOCKED - creates review item for human approval
    review = curator.create_policy_review(
        proposed_wisdom=proposed_wisdom,
        current_wisdom=current_wisdom,
        critique="Agent wants to suppress errors"
    )
    
    # Wisdom update does NOT happen automatically
    # Human must approve or reject
```

**Policy Violation Types:**

1. **Harmful Behavior:** Ignoring errors, skipping validation, bypassing checks
2. **Data Privacy:** Logging passwords, exposing credentials, sharing private data
3. **Security Risk:** Disabling authentication, skipping authorization, trusting input
4. **Quality Degradation:** Lowering thresholds, skipping tests, accepting any result

## Integration with Observer Agent

The Wisdom Curator is integrated into the Observer Agent's learning pipeline:

```python
from observer import ObserverAgent

# Initialize observer with wisdom curator enabled
observer = ObserverAgent(
    enable_wisdom_curator=True  # Default: True
)

# Process events - policy review happens automatically
results = observer.process_events(verbose=True)

# Output shows:
# [WISDOM CURATOR] 🛡️  Policy violation detected - creating review item
# [WISDOM CURATOR] Wisdom update BLOCKED pending human approval
```

**Automatic Behavior:**
- **Strategic Sampling:** Randomly samples interactions for review
- **Policy Blocking:** Automatically blocks policy-violating wisdom updates
- **Review Queue:** All items go to a queue for human review

## Review Management

### Get Pending Reviews

```python
from wisdom_curator import WisdomCurator, ReviewType

curator = WisdomCurator()

# Get all pending reviews
all_pending = curator.get_pending_reviews()

# Get only policy reviews
policy_reviews = curator.get_pending_reviews(ReviewType.POLICY_REVIEW)

# Get only strategic samples
samples = curator.get_pending_reviews(ReviewType.STRATEGIC_SAMPLE)

# Get only design checks
design_checks = curator.get_pending_reviews(ReviewType.DESIGN_CHECK)
```

### Approve or Reject Reviews

```python
# Approve a review
curator.approve_review(
    review_id="policy_12345",
    reviewer_notes="Safe to apply - false positive"
)

# Reject a review
curator.reject_review(
    review_id="policy_67890",
    reviewer_notes="Harmful pattern - will cause silent failures"
)
```

### Review Statistics

```python
stats = curator.get_review_stats()

print(f"Total Reviews: {stats['total_reviews']}")
print(f"Pending: {stats['pending']}")
print(f"Approved: {stats['approved']}")
print(f"Rejected: {stats['rejected']}")

# By type
for review_type, type_stats in stats['by_type'].items():
    print(f"{review_type}: {type_stats['pending']} pending")
```

## File Structure

The Wisdom Curator creates and manages two files:

1. **`curator_review_queue.json`** - Active review queue
2. **`design_proposals.json`** - Registered design proposals

Both files are in JSON format and human-readable.

## Configuration

```python
from wisdom_curator import WisdomCurator

curator = WisdomCurator(
    review_queue_file="curator_review_queue.json",  # Review queue
    design_proposals_file="design_proposals.json",   # Design proposals
    sample_rate=0.005  # 0.5% sampling rate (50 out of 10,000)
)
```

## Key Benefits

### 1. Scalability
- Can't review 10,000 interactions manually → Sample 50 strategically
- Automatic detection flags issues → Human only reviews exceptions

### 2. High-Leverage Work
- Stop: Checking variable names, syntax, semicolons
- Start: Verifying design alignment, policy compliance, strategic direction

### 3. Safety
- Prevents harmful wisdom updates (e.g., "ignore all errors")
- Policy enforcement with human in the loop
- Audit trail of all decisions

### 4. Focus Shift
- From: **Editor** (fixing grammar)
- To: **Curator** (approving knowledge)

## The Human Role

### What Humans DO Review:

✅ **Design Alignment:** Does the implementation match the architectural proposal?  
✅ **Strategic Direction:** Does the sampled behavior align with our goals?  
✅ **Policy Compliance:** Is this wisdom update safe and aligned with our values?

### What Humans DON'T Review:

❌ Variable naming conventions  
❌ Missing semicolons  
❌ Code formatting  
❌ Simple syntax errors  
❌ Every single interaction

## Example Workflow

### Daily Wisdom Curator Workflow

```bash
# 1. Run the observer (processes events and flags issues)
python observer.py

# 2. Review the dashboard
python -c "
from wisdom_curator import WisdomCurator
curator = WisdomCurator()
stats = curator.get_review_stats()
print(f'Pending Reviews: {stats[\"pending\"]}')
"

# 3. Review and decide on pending items
python -c "
from wisdom_curator import WisdomCurator, ReviewType
curator = WisdomCurator()

# Review policy items
for review in curator.get_pending_reviews(ReviewType.POLICY_REVIEW):
    print(review.content)
    # Decision: approve or reject based on policy alignment
"
```

## Testing

Run the test suite:

```bash
python test_wisdom_curator.py
```

Run the demo:

```bash
python example_wisdom_curator.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ObserverAgent (Learning)                  │
│                                                              │
│  ┌───────────┐                                              │
│  │  Analyze  │ → Proposed Wisdom Update                     │
│  │   Event   │                                              │
│  └───────────┘                                              │
│        │                                                     │
│        ▼                                                     │
│  ┌─────────────────────────────────────────────┐           │
│  │         Wisdom Curator                       │           │
│  │  ┌──────────────────────────────────────┐   │           │
│  │  │  Policy Violation Detection          │   │           │
│  │  │  - Harmful behavior                  │   │           │
│  │  │  - Security risks                    │   │           │
│  │  │  - Data privacy issues               │   │           │
│  │  │  - Quality degradation               │   │           │
│  │  └──────────────────────────────────────┘   │           │
│  │                 │                            │           │
│  │          ┌──────┴──────┐                    │           │
│  │          │             │                    │           │
│  │     SAFE ✓        VIOLATION ⚠️              │           │
│  │          │             │                    │           │
│  │    Auto-Apply   Human Review               │           │
│  └─────────────────────────────────────────────┘           │
│                                  │                          │
│                                  ▼                          │
│                        ┌──────────────────┐                │
│                        │  Review Queue    │                │
│                        │  - Policy Review │                │
│                        │  - Design Check  │                │
│                        │  - Samples       │                │
│                        └──────────────────┘                │
└─────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                        ┌──────────────────┐
                        │  Human Curator   │
                        │  - Approve ✓     │
                        │  - Reject ✗      │
                        └──────────────────┘
```

## The Lesson

**We stop being Editors (fixing grammar) and become Curators (approving the knowledge).**

The Wisdom Curator represents the evolution from low-level code review to high-level strategic verification:

- **Not:** Line-by-line syntax checking
- **But:** Design alignment, policy compliance, and strategic sampling

This is the "New World" where humans focus on high-leverage verification, not low-leverage toil.

## See Also

- [ARCHITECTURE_DECOUPLED.md](ARCHITECTURE_DECOUPLED.md) - Observer Agent architecture
- [PRIORITIZATION_FRAMEWORK.md](PRIORITIZATION_FRAMEWORK.md) - Context prioritization
- [SILENT_SIGNALS.md](SILENT_SIGNALS.md) - Implicit feedback detection
- [INTENT_DETECTION.md](INTENT_DETECTION.md) - Intent-based evaluation
