# Multi-Agent Trading Governance Demo

Governed agent pipeline for institutional trading operations, built on
[Agent OS](../../README.md) governance primitives.

## Pipeline Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ ResearchAgent │───▶│  RiskAgent   │───▶│ ComplianceAgent  │───▶│ ExecutionAgent   │
│  (Ring 3)    │    │  (Ring 2)    │    │   (Ring 1)       │    │  (Ring 1 ltd.)   │
│  READ-ONLY   │    │  STANDARD    │    │  PRIVILEGED      │    │  PRIVILEGED      │
└──────────────┘    └──────────────┘    └──────────────────┘    └──────────────────┘
      │                    │                     │                       │
  analyze_market     calculate_var      check_restricted_list     execute_order
  screen_stocks      check_exposure     verify_trading_window     cancel_order
  generate_signal    set_position_limit approve_order             check_fill_status
                                        reject_order
```

Each stage enforces its own `GovernancePolicy` via `PolicyInterceptor`.
A `TradeOrder` flows through all four stages, collecting governance
decisions in an immutable audit trail.

## Agent Privilege Matrix

| Agent           | Ring | Access Level       | Can Execute? | Can Approve? | Human Escalation        |
|-----------------|------|--------------------|--------------|--------------|-------------------------|
| ResearchAgent   | 3    | Read-only          | ✘            | ✘            | —                       |
| RiskAgent       | 2    | Standard           | ✘            | ✘ (flag only)| —                       |
| ComplianceAgent | 1    | Privileged         | ✘            | ✔            | Orders > $1M notional   |
| ExecutionAgent  | 1    | Privileged (limited)| ✔           | ✘            | —                       |

## Governance Controls

- **Tool allow-lists** — each agent can only call its own tools.
  ResearchAgent calling `execute_order` is blocked by the governance layer.
- **Risk gates** — VaR thresholds, position limits, concentration checks.
- **Compliance gates** — restricted lists, trading-window blackouts,
  wash-trading pattern detection.
- **Human escalation** — orders with notional > $1 M are routed to the
  Chief Compliance Officer before execution.
- **Immutable audit trail** — every governance decision is recorded with
  timestamps, agent IDs, and reasons.

## Regulatory Compliance Mapping

| Regulation         | Article / Rule | Coverage in Demo                          |
|--------------------|----------------|-------------------------------------------|
| MiFID II           | Art. 17        | Algorithmic trading governance pipeline   |
| Reg NMS            | Rule 15c3-5    | Pre-trade risk controls (VaR, limits)     |
| MAR                | Art. 12        | Wash trading detection                    |
| SOX                | §302 / §404    | Internal controls, immutable audit trail  |

## Demo Scenarios

1. **Normal trade flow** — AAPL 100 shares passes all four gates and executes.
2. **Risk limit breach** — TSLA 5 000 shares ($1.25 M) exceeds VaR threshold.
3. **Restricted list hit** — INSIDER_CORP blocked by compliance.
4. **Privilege violation** — ResearchAgent (Ring 3) attempts `execute_order`; governance blocks.
5. **Large order escalation** — MSFT $1.17 M triggers human-approval workflow.
6. **Wash trading detection** — AAPL BUY→SELL→BUY pattern detected and rejected.

## Quick Start

```bash
# From the repository root
python examples/trading-governance/demo.py
```

No external dependencies — only the `agent-os` core (`src/agent_os`).

## Sample Output

```
════════════════════════════════════════════════════════════════════════
  Multi-Agent Trading Governance Demo — Agent OS
════════════════════════════════════════════════════════════════════════

  Pipeline: ResearchAgent → RiskAgent → ComplianceAgent → ExecutionAgent

─── Scenario 1: Normal Trade Flow (AAPL 100 shares) ───
    Order: ORD-0001 | BUY 100 AAPL @ $150.00
    Notional: $15,000.00 | Type: LIMIT | Status: NEW

  ▶ ResearchAgent (Ring 3 — READ-ONLY)
    ✔ ALLOWED  | ResearchAgent.analyze_market() (call 1/20)
    ✔ ALLOWED  | ResearchAgent.generate_signal() (call 2/20)
    Signal: BUY AAPL (confidence: 72%)

  ▶ RiskAgent (Ring 2 — STANDARD)
    ✔ ALLOWED  | RiskAgent.calculate_var() (call 1/15)
    VaR (1d 95%): $750.00 (limit: $50,000.00)
    ✔ ALLOWED  | RiskAgent.check_exposure() (call 2/15)
    Exposure: $165,000.00 (concentration: 3.3%)
    ✔ Risk checks passed

  ▶ ComplianceAgent (Ring 1 — PRIVILEGED)
    ✔ ALLOWED  | ComplianceAgent.check_restricted_list() (call 1/20)
    ✔ ALLOWED  | ComplianceAgent.verify_trading_window() (call 2/20)
    ✔ ALLOWED  | ComplianceAgent.approve_order() (call 3/20)
    ✔ Compliance approved

  ▶ ExecutionAgent (Ring 1 — PRIVILEGED)
    ✔ ALLOWED  | ExecutionAgent.execute_order() (call 1/10)
    ✔ EXECUTED: 100 AAPL @ $150.15 on NYSE
  ...
```
