# Agent Governance Toolkit with Microsoft Agent Framework

These scenarios show native ACS governance for Microsoft Agent Framework
integration patterns in Python and .NET.

## Scenarios

| # | Scenario | Native check |
|---|----------|--------------|
| 01 | [Loan Processing](./01-loan-processing/) | Sensitive identity data |
| 02 | [Customer Service](./02-customer-service/) | Prompt injection |
| 03 | [Healthcare](./03-healthcare/) | Medical record identifiers |
| 04 | [IT Helpdesk](./04-it-helpdesk/) | Destructive shell requests |
| 05 | [DevOps Deploy](./05-devops-deploy/) | Destructive deployment requests |
| 06 | [.NET Extension Validation](./06-dotnet-extension-validation/dotnet/) | Shared .NET extension |

## Python

Each Python folder contains a runnable `main.py`, a native ACS manifest, and a
Rego policy. The script creates `AgtRuntime`, passes it to `MAFKernel`, and
evaluates one allowed and one denied request.

```bash
cd examples/maf-integration/01-loan-processing/python
pip install -r requirements.txt
python main.py
```

In a full MAF application, attach `kernel.as_runtime_middleware()` to the agent
runtime. The runtime owns decisions, transforms, and approvals. MAF middleware
owns framework lifecycle and audit context.

## .NET

The .NET scenarios use native `Microsoft.Agents.AI` middleware. Scenario 06
validates the shared in-repo extension package.

```bash
cd examples/maf-integration/06-dotnet-extension-validation/dotnet
dotnet run
```
