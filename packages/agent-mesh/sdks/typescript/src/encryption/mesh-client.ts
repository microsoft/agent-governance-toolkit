// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * AgentMesh transport client — WebSocket connection to relay with
 * plaintext-peer support, KNOCK pending queue, and wsFactory hook.
 *
 * Spec: docs/specs/AGENTMESH-WIRE-1.0.md Sections 9, 10, 12
 *
 * Features added for AzureClaw compatibility:
 * - plaintextPeers: bypass E2E encryption for legacy peers (e.g., Rust controller)
 * - wsFactory: custom WebSocket constructor for HTTPS_PROXY CONNECT tunneling
 * - KNOCK pending queue: handle race between KNOCK and first message
 */

import { SecureChannel, type ChannelEstablishment } from "./channel";
import { X3DHKeyManager, type PreKeyBundle } from "./x3dh";
import { type EncryptedMessage } from "./ratchet";

export type WebSocketFactory = (url: string) => WebSocket;

export interface MeshClientOptions {
  relayUrl: string;
  registryUrl: string;
  keyManager: X3DHKeyManager;
  agentDid: string;
  displayName?: string;
  /** Custom WebSocket constructor (e.g., for HTTPS_PROXY CONNECT tunneling in Node 22) */
  wsFactory?: WebSocketFactory;
  /** AMIDs/DIDs that bypass Signal E2E — use legacy base64(JSON) wire format */
  plaintextPeers?: string[];
  /** Max time (ms) to wait for KNOCK resolution before rejecting a message */
  knockTimeout?: number;
}

export interface MeshSession {
  peerId: string;
  channel: SecureChannel | null; // null for plaintext peers
  isPlaintext: boolean;
  createdAt: Date;
  messageCount: number;
}

type KnockResolver = { resolve: (accepted: boolean) => void; timer: ReturnType<typeof setTimeout> };

/**
 * High-level mesh client for agent-to-agent communication.
 *
 * Manages WebSocket connection to the relay, session establishment
 * (KNOCK + X3DH), and message encryption/decryption. Supports
 * plaintext peers for legacy interop.
 */
export class MeshClient {
  private options: MeshClientOptions;
  private sessions: Map<string, MeshSession> = new Map();
  private plaintextPeers: Set<string>;
  private knockPending: Map<string, KnockResolver> = new Map();
  private knockAccepted: Set<string> = new Set();
  private messageHandlers: Array<(from: string, payload: unknown, isPlaintext: boolean) => void> = [];
  private knockHandlers: Array<(from: string, intent: unknown) => Promise<boolean>> = [];
  private ws: WebSocket | null = null;
  private connected = false;
  private knockTimeout: number;

  constructor(options: MeshClientOptions) {
    this.options = options;
    this.plaintextPeers = new Set(options.plaintextPeers ?? []);
    this.knockTimeout = options.knockTimeout ?? 10_000;
  }

  // ── Plaintext peers ─────────────────────────────────────────────

  addPlaintextPeer(peerId: string): void {
    this.plaintextPeers.add(peerId);
  }

  removePlaintextPeer(peerId: string): void {
    this.plaintextPeers.delete(peerId);
  }

  isPlaintextPeer(peerId: string): boolean {
    return this.plaintextPeers.has(peerId);
  }

  // ── Connection ──────────────────────────────────────────────────

  async connect(): Promise<void> {
    if (this.connected) return;

    const wsUrl = this.options.relayUrl.replace(/^http/, "ws") + "/ws";
    const wsFactory = this.options.wsFactory ?? ((url: string) => new WebSocket(url));
    this.ws = wsFactory(wsUrl);

    await new Promise<void>((resolve, reject) => {
      this.ws!.onopen = () => {
        this.sendFrame({
          v: 1,
          type: "connect",
          from: this.options.agentDid,
        });
        this.connected = true;
        resolve();
      };
      this.ws!.onerror = (e) => reject(new Error(`WebSocket error: ${e}`));
      this.ws!.onmessage = (event) => this.handleFrame(JSON.parse(String(event.data)));
      this.ws!.onclose = () => {
        this.connected = false;
      };
    });
  }

  async disconnect(): Promise<void> {
    if (!this.connected || !this.ws) return;
    this.sendFrame({ v: 1, type: "disconnect", from: this.options.agentDid });
    this.ws.close();
    this.connected = false;
    this.ws = null;
  }

  get isConnected(): boolean {
    return this.connected && this.ws !== null;
  }

  // ── Sending ─────────────────────────────────────────────────────

  async send(peerId: string, payload: unknown): Promise<void> {
    if (!this.isConnected) throw new Error("Not connected to relay");

    const messageId = crypto.randomUUID();

    if (this.isPlaintextPeer(peerId)) {
      // Legacy plaintext path — no encryption
      this.sendFrame({
        v: 1,
        type: "message",
        from: this.options.agentDid,
        to: peerId,
        id: messageId,
        ts: new Date().toISOString(),
        ciphertext: btoa(JSON.stringify(payload)),
        plaintext: true,
      });
      this.incrementSessionCount(peerId, true);
      return;
    }

    // Encrypted path
    let session = this.sessions.get(peerId);
    if (!session || !session.channel) {
      throw new Error(`No encrypted session with ${peerId}. Call establishSession() first.`);
    }

    const encrypted = session.channel.send(
      new TextEncoder().encode(JSON.stringify(payload)),
    );

    this.sendFrame({
      v: 1,
      type: "message",
      from: this.options.agentDid,
      to: peerId,
      id: messageId,
      ts: new Date().toISOString(),
      header: {
        dh: this.uint8ToBase64(encrypted.header.dhPublicKey),
        pn: encrypted.header.previousChainLength,
        n: encrypted.header.messageNumber,
      },
      ciphertext: this.uint8ToBase64(encrypted.ciphertext),
    });

    session.messageCount++;
  }

  // ── Session establishment ───────────────────────────────────────

  async establishSession(
    peerId: string,
    peerBundle: PreKeyBundle,
  ): Promise<MeshSession> {
    // Check for existing session
    const existing = this.sessions.get(peerId);
    if (existing) return existing;

    if (this.isPlaintextPeer(peerId)) {
      const session: MeshSession = {
        peerId,
        channel: null,
        isPlaintext: true,
        createdAt: new Date(),
        messageCount: 0,
      };
      this.sessions.set(peerId, session);
      return session;
    }

    // Send KNOCK
    const knockId = crypto.randomUUID();
    this.sendFrame({
      v: 1,
      type: "knock",
      from: this.options.agentDid,
      to: peerId,
      id: knockId,
      ts: new Date().toISOString(),
      intent: { action: "establish_session" },
    });

    // X3DH + SecureChannel
    const [channel, establishment] = SecureChannel.createSender(
      this.options.keyManager,
      peerBundle,
      new TextEncoder().encode(`${this.options.agentDid}|${peerId}`),
    );

    const session: MeshSession = {
      peerId,
      channel,
      isPlaintext: false,
      createdAt: new Date(),
      messageCount: 0,
    };
    this.sessions.set(peerId, session);

    return session;
  }

  acceptSession(
    peerId: string,
    establishment: ChannelEstablishment,
  ): MeshSession {
    const channel = SecureChannel.createReceiver(
      this.options.keyManager,
      establishment,
      new TextEncoder().encode(`${peerId}|${this.options.agentDid}`),
    );

    const session: MeshSession = {
      peerId,
      channel,
      isPlaintext: false,
      createdAt: new Date(),
      messageCount: 0,
    };
    this.sessions.set(peerId, session);
    this.knockAccepted.add(peerId);

    return session;
  }

  getSession(peerId: string): MeshSession | undefined {
    return this.sessions.get(peerId);
  }

  closeSession(peerId: string): boolean {
    const session = this.sessions.get(peerId);
    if (!session) return false;
    if (session.channel) session.channel.close();
    this.sessions.delete(peerId);
    this.knockAccepted.delete(peerId);
    return true;
  }

  // ── Handlers ────────────────────────────────────────────────────

  onMessage(handler: (from: string, payload: unknown, isPlaintext: boolean) => void): void {
    this.messageHandlers.push(handler);
  }

  onKnock(handler: (from: string, intent: unknown) => Promise<boolean>): void {
    this.knockHandlers.push(handler);
  }

  // ── Heartbeat ───────────────────────────────────────────────────

  sendHeartbeat(): void {
    if (!this.isConnected) return;
    this.sendFrame({
      v: 1,
      type: "heartbeat",
      from: this.options.agentDid,
      ts: new Date().toISOString(),
    });
  }

  // ── Frame handling ──────────────────────────────────────────────

  private async handleFrame(frame: Record<string, unknown>): Promise<void> {
    const type = frame.type as string;
    const from = frame.from as string;

    if (type === "message") {
      await this.handleMessage(frame);
    } else if (type === "knock") {
      await this.handleKnock(frame);
    } else if (type === "knock_accept") {
      this.handleKnockAccept(frame);
    } else if (type === "knock_reject") {
      this.handleKnockReject(frame);
    } else if (type === "ack") {
      // ACK processed — nothing to do
    }
  }

  private async handleMessage(frame: Record<string, unknown>): Promise<void> {
    const from = frame.from as string;

    // Check KNOCK pending queue — wait for resolution if KNOCK is in-flight
    if (!this.knockAccepted.has(from) && !this.isPlaintextPeer(from)) {
      const pending = this.knockPending.get(from);
      if (pending) {
        // Wait for KNOCK resolution
        const accepted = await new Promise<boolean>((resolve) => {
          const originalResolve = pending.resolve;
          pending.resolve = (val: boolean) => {
            originalResolve(val);
            resolve(val);
          };
        });
        if (!accepted) return; // KNOCK rejected — drop message
      }
    }

    let payload: unknown;
    let isPlaintext = false;

    if (frame.plaintext || this.isPlaintextPeer(from)) {
      // Legacy plaintext
      payload = JSON.parse(atob(frame.ciphertext as string));
      isPlaintext = true;
    } else {
      // Encrypted
      const session = this.sessions.get(from);
      if (!session?.channel) return; // No session — drop

      const header = frame.header as Record<string, unknown>;
      const encrypted: EncryptedMessage = {
        header: {
          dhPublicKey: this.base64ToUint8(header.dh as string),
          previousChainLength: header.pn as number,
          messageNumber: header.n as number,
        },
        ciphertext: this.base64ToUint8(frame.ciphertext as string),
      };

      const plaintext = session.channel.receive(encrypted);
      payload = JSON.parse(new TextDecoder().decode(plaintext));
      session.messageCount++;
    }

    // Send ACK
    this.sendFrame({ v: 1, type: "ack", id: frame.id });

    // Notify handlers
    for (const handler of this.messageHandlers) {
      handler(from, payload, isPlaintext);
    }
  }

  private async handleKnock(frame: Record<string, unknown>): Promise<void> {
    const from = frame.from as string;
    const intent = frame.intent;

    // Register as pending
    const pendingPromise = new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        this.knockPending.delete(from);
        resolve(false);
      }, this.knockTimeout);
      this.knockPending.set(from, { resolve, timer });
    });

    // Evaluate via registered handlers
    let accepted = true;
    for (const handler of this.knockHandlers) {
      if (!(await handler(from, intent))) {
        accepted = false;
        break;
      }
    }

    // Resolve pending
    const pending = this.knockPending.get(from);
    if (pending) {
      clearTimeout(pending.timer);
      pending.resolve(accepted);
      this.knockPending.delete(from);
    }

    if (accepted) {
      this.knockAccepted.add(from);
      this.sendFrame({
        v: 1,
        type: "knock_accept",
        from: this.options.agentDid,
        to: from,
        id: crypto.randomUUID(),
        knock_id: frame.id,
        ts: new Date().toISOString(),
      });
    } else {
      this.sendFrame({
        v: 1,
        type: "knock_reject",
        from: this.options.agentDid,
        to: from,
        id: crypto.randomUUID(),
        knock_id: frame.id,
        reason: "policy_denied",
        ts: new Date().toISOString(),
      });
    }
  }

  private handleKnockAccept(frame: Record<string, unknown>): void {
    const from = frame.from as string;
    this.knockAccepted.add(from);
  }

  private handleKnockReject(frame: Record<string, unknown>): void {
    const from = frame.from as string;
    this.closeSession(from);
  }

  // ── Utilities ───────────────────────────────────────────────────

  private sendFrame(frame: Record<string, unknown>): void {
    if (this.ws && this.connected) {
      this.ws.send(JSON.stringify(frame));
    }
  }

  private incrementSessionCount(peerId: string, isPlaintext: boolean): void {
    let session = this.sessions.get(peerId);
    if (!session) {
      session = { peerId, channel: null, isPlaintext, createdAt: new Date(), messageCount: 0 };
      this.sessions.set(peerId, session);
    }
    session.messageCount++;
  }

  private uint8ToBase64(data: Uint8Array): string {
    // Use Buffer in Node.js to avoid stack overflow on large payloads
    if (typeof Buffer !== "undefined") {
      return Buffer.from(data).toString("base64");
    }
    // Browser fallback — loop-based
    let binary = "";
    for (let i = 0; i < data.length; i++) {
      binary += String.fromCharCode(data[i]);
    }
    return btoa(binary);
  }

  private base64ToUint8(b64: string): Uint8Array {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(b64, "base64"));
    }
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}
