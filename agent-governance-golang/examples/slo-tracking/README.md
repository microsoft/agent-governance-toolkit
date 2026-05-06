# SLO Tracking Example

Run a small AgentMesh SLO engine demo that records sample agent outcomes and prints the current objective status.

```bash
cd agent-governance-golang
go run ./examples/slo-tracking
```

The example creates an availability objective, records five sample events, and prints the actual availability, target, event count, and remaining error budget.
