# Slack Compliance Monitor

Real-time compliance monitoring for Slack workspaces that detects and blocks PII, PHI, and sensitive data before it leaves the organization.

## Features

- **PII Detection**: SSN, credit cards, phone numbers, emails, addresses
- **PHI Detection**: Medical record numbers, diagnoses, HIPAA-protected info
- **Financial Data**: Bank accounts, routing numbers, payment details
- **Real-time Blocking**: Stop sensitive messages before they're sent
- **Audit Logging**: Complete compliance trail for SOC 2, GDPR, HIPAA

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export SLACK_BOT_TOKEN=xoxb-your-token
export SLACK_SIGNING_SECRET=your-signing-secret

# Run the monitor
python main.py
```

## Deployment

### Slack App Configuration

1. Create a Slack App at https://api.slack.com/apps
2. Enable Event Subscriptions
3. Subscribe to `message.channels`, `message.groups`, `message.im`
4. Add Bot Token Scopes: `chat:write`, `channels:history`, `groups:history`

### Docker Deployment

```bash
docker build -t slack-compliance .
docker run -e SLACK_BOT_TOKEN=... -e SLACK_SIGNING_SECRET=... slack-compliance
```

## Compliance Frameworks

| Framework | Coverage |
|-----------|----------|
| **GDPR** | PII detection, right to erasure alerts |
| **HIPAA** | PHI detection, audit logging |
| **SOC 2** | Access logging, data classification |
| **PCI-DSS** | Credit card detection, encryption alerts |

## What It Detects

### Personal Identifiable Information (PII)
- Social Security Numbers (XXX-XX-XXXX)
- Credit Card Numbers (with Luhn validation)
- Phone Numbers (US/International formats)
- Email Addresses
- Physical Addresses
- Driver's License Numbers

### Protected Health Information (PHI)
- Medical Record Numbers
- Health conditions/diagnoses
- Treatment information
- Insurance IDs

### Financial Data
- Bank Account Numbers
- Routing Numbers
- Payment Card Data

## Actions

When sensitive data is detected:

1. **Block** (default for critical): Message is prevented from sending
2. **Redact**: Sensitive data is replaced with `[REDACTED]`
3. **Alert**: Compliance team is notified
4. **Log**: Event is recorded for audit trail

## Example Output

```
🚨 Compliance Alert
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Channel: #customer-support
User: @jane.doe
Time: 2024-02-05 14:32:15 UTC

Detected:
  • Credit Card Number (CRITICAL) - BLOCKED
  • Email Address (MEDIUM) - Logged

Action: Message blocked, user notified
Audit ID: CMP-2024-00847
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## Metrics

```
📊 Compliance Dashboard (Last 30 Days)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Messages Scanned:    142,847
PII Detected:           347  🔐
PHI Detected:            23  🏥
Financial Data:          89  💳
Messages Blocked:        12  🚫
Compliance Rate:      99.99%  ✅
```
