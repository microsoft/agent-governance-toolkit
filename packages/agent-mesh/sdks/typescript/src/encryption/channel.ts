// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * SecureChannel — high-level E2E encrypted agent-to-agent messaging.
 *
 * Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 9
 */

import { DoubleRatchet, EncryptedMessage } from "./ratchet";
import { X3DHKeyManager, PreKeyBundle } from "./x3dh";

export interface ChannelEstablishment {
  initiatorIdentityKey: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  usedOneTimeKeyId?: number;
}

export class SecureChannel {
  private ratchet: DoubleRatchet;
  private associatedData: Uint8Array;
  private closed = false;
  private msgCount = 0;
  public readonly localIdentityKey: Uint8Array;
  public readonly remoteIdentityKey: Uint8Array;

  private constructor(
    ratchet: DoubleRatchet,
    associatedData: Uint8Array,
    localIK: Uint8Array,
    remoteIK: Uint8Array,
  ) {
    this.ratchet = ratchet;
    this.associatedData = associatedData;
    this.localIdentityKey = localIK;
    this.remoteIdentityKey = remoteIK;
  }

  static createSender(
    keyManager: X3DHKeyManager,
    peerBundle: PreKeyBundle,
    associatedData: Uint8Array = new Uint8Array(),
  ): [SecureChannel, ChannelEstablishment] {
    const x3dhResult = keyManager.initiate(peerBundle);

    const ratchet = DoubleRatchet.initSender(
      x3dhResult.sharedSecret,
      peerBundle.signedPreKey,
    );

    const ad = new Uint8Array(associatedData.length + x3dhResult.associatedData.length);
    ad.set(associatedData, 0);
    ad.set(x3dhResult.associatedData, associatedData.length);

    const establishment: ChannelEstablishment = {
      initiatorIdentityKey: keyManager.identityKey.publicKey,
      ephemeralPublicKey: x3dhResult.ephemeralPublicKey,
      usedOneTimeKeyId: x3dhResult.usedOneTimeKeyId,
    };

    const channel = new SecureChannel(
      ratchet,
      ad,
      keyManager.identityKey.publicKey,
      peerBundle.identityKey,
    );
    return [channel, establishment];
  }

  static createReceiver(
    keyManager: X3DHKeyManager,
    establishment: ChannelEstablishment,
    associatedData: Uint8Array = new Uint8Array(),
  ): SecureChannel {
    if (!keyManager.signedPreKey) {
      throw new Error("Responder must have a signed pre-key.");
    }

    const x3dhResult = keyManager.respond(
      establishment.initiatorIdentityKey,
      establishment.ephemeralPublicKey,
      establishment.usedOneTimeKeyId,
    );

    const ratchet = DoubleRatchet.initReceiver(x3dhResult.sharedSecret, {
      privateKey: keyManager.signedPreKey.keyPair.privateKey,
      publicKey: keyManager.signedPreKey.keyPair.publicKey,
    });

    const ad = new Uint8Array(associatedData.length + x3dhResult.associatedData.length);
    ad.set(associatedData, 0);
    ad.set(x3dhResult.associatedData, associatedData.length);

    return new SecureChannel(
      ratchet,
      ad,
      keyManager.identityKey.publicKey,
      establishment.initiatorIdentityKey,
    );
  }

  send(plaintext: Uint8Array): EncryptedMessage {
    if (this.closed) throw new Error("Channel is closed.");
    const msg = this.ratchet.encrypt(plaintext, this.associatedData);
    this.msgCount++;
    return msg;
  }

  receive(message: EncryptedMessage): Uint8Array {
    if (this.closed) throw new Error("Channel is closed.");
    const pt = this.ratchet.decrypt(message, this.associatedData);
    this.msgCount++;
    return pt;
  }

  close(): void {
    this.closed = true;
  }

  get isClosed(): boolean {
    return this.closed;
  }

  get messageCount(): number {
    return this.msgCount;
  }
}
