// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * E2E encryption primitives for agent-to-agent secure messaging.
 */

export {
  X3DHKeyManager,
  generateX25519KeyPair,
  ed25519ToX25519,
  type X25519KeyPair,
  type PreKeyBundle,
  type X3DHResult,
} from "./x3dh";

export {
  DoubleRatchet,
  type MessageHeader,
  type EncryptedMessage,
  type RatchetState,
} from "./ratchet";

export {
  SecureChannel,
  type ChannelEstablishment,
} from "./channel";

export {
  MeshClient,
  type MeshClientOptions,
  type MeshSession,
  type WebSocketFactory,
} from "./mesh-client";
