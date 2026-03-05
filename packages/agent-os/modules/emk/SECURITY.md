# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in EMK, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email the maintainer directly at: agt@microsoft.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: Next release

### Security Best Practices

When using EMK:

1. **Validate Input**: Always validate episode content before storage
2. **Access Control**: Implement proper access controls at the application layer
3. **Data Sensitivity**: Do not store sensitive information (passwords, tokens) in episodes
4. **File Permissions**: Ensure storage files have appropriate permissions
5. **Dependencies**: Keep EMK and its dependencies updated

## Security Measures in EMK

- **Immutability**: Episodes cannot be modified after creation
- **Content Hashing**: SHA-256 based episode IDs for integrity verification
- **Minimal Dependencies**: Reduced attack surface
- **CodeQL Scanning**: Automated security analysis on all PRs

## Past Security Fixes

### v0.1.0
- Fixed `tempfile.mktemp()` usage vulnerability
- Fixed potential metadata mutation issues
