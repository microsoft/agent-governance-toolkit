# Privacy Policy for AgentMesh Trust Layer Plugin

## Overview

The AgentMesh Trust Layer plugin provides cryptographic identity verification and trust scoring for multi-agent workflows in Dify.

## Data Collection

This plugin does **not** collect, store, or transmit any personal user data. All operations are performed locally within the Dify environment.

### Data Processed

- **Agent DIDs (Decentralized Identifiers)**: Generated locally using Ed25519 cryptography. These are ephemeral and not persisted externally.
- **Trust Scores**: Computed and stored in-memory only. Not transmitted to any external service.
- **Audit Logs**: Stored in-memory during the plugin session. Not persisted to disk or transmitted externally.

### No External Communication

This plugin does not make any network requests or communicate with external services. All cryptographic operations (key generation, signing, verification) are performed locally.

## Data Storage

No data is stored persistently. All trust scores, identity information, and audit logs exist only in-memory during the plugin session and are discarded when the session ends.

## Third-Party Services

This plugin does not use any third-party services or APIs.

## Contact

For privacy-related questions, please open an issue at: https://github.com/imran-siddique/agent-mesh/issues
