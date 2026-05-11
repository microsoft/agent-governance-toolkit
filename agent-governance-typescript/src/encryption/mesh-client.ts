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
import { RegistryClient, type RegistryClientOptions, type DiscoverResult } from "./registry-client";

export type WebSocketFactory = (url: string) => WebSocket;

export interface MeshClientOptions {
  relayUrl: string;
  registryUrl: string;
  keyManager: X3DHKeyManager;
  agentDid: string;
  displayName?: string;
  /** Custom WebSocket constructor (e.g., for HTTPS_PROXY CONNECT tunneling in Node 22) */
  wsFactory?: WebSocketFactory;
  /**
   * Inject a pre-built RegistryClient (overrides registryUrl). Useful for
   * tests, custom auth, or sharing a client across multiple MeshClients.
   */
  registryClient?: RegistryClient;
  /**
   * Extra options forwarded to the auto-built RegistryClient when
   * `registryClient` is not provided. Ignored if registryClient is set.
   */
  registryClientOptions?: Partial<Omit<RegistryClientOptions, "baseUrl">>;
  /**
   * Capabilities to publish at registration time. The displayName is
   * automatically appended (so peers can find this agent via
   * `discover(displayName)`). Default: empty array.
   */
  capabilities?: string[];
  /**
   * Arbitrary metadata to publish at registration. The display_name is
   * automatically merged in if displayName is set.
   */
  registrationMetadata?: Record<string, string>;
  /**
   * Number of one-time pre-keys to generate and upload at connect time.
   * Each successful X3DH initiation by a peer consumes one. Default 20.
   */
  oneTimePrekeyCount?: number;
  /**
   * If false, skip auto-registration on connect even when registryUrl is
   * set (caller will register manually via getRegistry().register()).
   * Default true.
   */
  autoRegister?: boolean;
  /** AMIDs/DIDs that bypass Signal E2E — use legacy base64(JSON) wire format */
  plaintextPeers?: string[];
  /** Max time (ms) to wait for KNOCK resolution before rejecting a message */
  knockTimeout?: number;
  /**
   * Automatically reconnect on non-1000 close events.
   * Defaults to true. Set to false to keep the legacy manual-only behavior.
   */
  autoReconnect?: boolean;
  /** Max reconnect attempts (default: Number.POSITIVE_INFINITY). */
  maxReconnectAttempts?: number;
  /** Base reconnect delay in ms before exponential backoff (default: 1000). */
  reconnectBaseDelayMs?: number;
  /** Max reconnect delay cap in ms (default: 60000). */
  reconnectMaxDelayMs?: number;
  /**
   * Max messages to buffer per peer when an encrypted message arrives before
   * its KNOCK has been processed (out-of-order delivery on the relay).
   * Mirrors vendored agentmesh-sdk patch #16. Default 5. Set to 0 to disable.
   */
  preKnockBufferSize?: number;
  /**
   * TTL in ms for buffered pre-KNOCK messages before they are evicted.
   * Default 3000.
   */
  preKnockBufferTtlMs?: number;
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
  private errorHandlers: Array<(kind: "ws" | "decrypt" | "knock" | "frame" | "session_desync", from: string, detail: string) => void> = [];
  private disconnectHandlers: Array<(reason: "client" | "server" | "ws-error", code?: number) => void> = [];
  private e2eVerifiedHandlers: Array<(peerAmid: string, isFirstPeer: boolean) => void> = [];
  /** Tracks peers whose first encrypted message we've seen — feeds onE2EVerified. */
  private e2eVerifiedSet: Set<string> = new Set();
  private ws: WebSocket | null = null;
  private connected = false;
  private knockTimeout: number;
  private autoReconnect: boolean;
  private maxReconnectAttempts: number;
  private reconnectBaseDelayMs: number;
  private reconnectMaxDelayMs: number;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private clientInitiatedClose = false;
  private preKnockBufferSize: number;
  private preKnockBufferTtlMs: number;
  /**
   * Per-peer buffer for encrypted message frames that arrived before the
   * peer's KNOCK was processed. Drained when the KNOCK is later accepted.
   * Mirrors vendored agentmesh-sdk patch #16.
   */
  private preKnockBuffer: Map<string, Array<{ frame: Record<string, unknown>; timer: ReturnType<typeof setTimeout> }>> = new Map();
  private readonly registry: RegistryClient | null;
  private readonly autoRegister: boolean;
  private readonly oneTimePrekeyCount: number;
  private registered = false;

  constructor(options: MeshClientOptions) {
    this.options = options;
    this.plaintextPeers = new Set(options.plaintextPeers ?? []);
    this.knockTimeout = options.knockTimeout ?? 10_000;
    this.autoReconnect = options.autoReconnect ?? true;
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? Number.POSITIVE_INFINITY;
    this.reconnectBaseDelayMs = options.reconnectBaseDelayMs ?? 1000;
    this.reconnectMaxDelayMs = options.reconnectMaxDelayMs ?? 60_000;
    this.preKnockBufferSize = options.preKnockBufferSize ?? 5;
    this.preKnockBufferTtlMs = options.preKnockBufferTtlMs ?? 3_000;
    this.autoRegister = options.autoRegister ?? true;
    this.oneTimePrekeyCount = options.oneTimePrekeyCount ?? 20;
    if (options.registryClient) {
      this.registry = options.registryClient;
    } else if (options.registryUrl) {
      this.registry = new RegistryClient({
        baseUrl: options.registryUrl,
        ...(options.registryClientOptions ?? {}),
      });
    } else {
      this.registry = null;
    }
  }

  /**
   * Access the RegistryClient (built from registryUrl or injected via
   * registryClient). Returns null only if MeshClient was constructed
   * without a registry URL or client — which means discover/peer lookup
   * features are disabled.
   */
  getRegistry(): RegistryClient | null {
    return this.registry;
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
        this.connected = true;
        this.sendFrame({
          v: 1,
          type: "connect",
          from: this.options.agentDid,
        });
        // Request any messages queued while offline (inbox replay)
        this.sendFrame({
          v: 1,
          type: "fetch_pending",
          from: this.options.agentDid,
        });
        resolve();
      };
      this.ws!.onerror = (e) => {
        // Surface to AzureClaw-style observers BEFORE rejecting connect.
        // Once connect resolves, subsequent ws errors flow through this same path.
        const errEvent = e as { message?: string; type?: string } | undefined;
        const detail = errEvent?.message ?? errEvent?.type ?? "ws-error";
        for (const h of this.errorHandlers) {
          try { h("ws", this.options.agentDid, detail); } catch { /* swallow handler errors */ }
        }
        if (!this.connected) reject(new Error(`WebSocket error: ${e}`));
      };
      this.ws!.onmessage = (event) => {
        // Guard against malformed frames (upstream #1998) — combines with
        // our additive event-hook handler.
        let frame: Record<string, unknown>;
        try {
          frame = JSON.parse(String(event.data));
        } catch (err) {
          console.warn(`MeshClient: dropping malformed frame (JSON parse): ${err}`);
          return;
        }
        this.handleFrame(frame).catch((err) => {
          console.warn(`MeshClient: handler error for frame type=${String(frame.type)}: ${err}`);
        });
      };
      this.ws!.onclose = (event) => {
        const wasConnected = this.connected;
        this.connected = false;
        if (wasConnected) {
          // Distinguish client-initiated disconnect (1000 Normal Closure) from server / network drops.
          const code = (event as CloseEvent | undefined)?.code;
          const isClientInitiated = code === 1000 || this.clientInitiatedClose;
          const reason: "client" | "server" | "ws-error" = isClientInitiated ? "client" : "server";
          for (const h of this.disconnectHandlers) {
            try { h(reason, code); } catch { /* swallow handler errors */ }
          }
          // Auto-reconnect on non-client closures (network drops, relay restart).
          // Mirrors vendored agentmesh-sdk patch #9: never give up by default,
          // exponential backoff capped at 60s. Caller can opt out via
          // autoReconnect: false in MeshClientOptions.
          if (!isClientInitiated && this.autoReconnect) {
            this.scheduleReconnect();
          }
        }
        this.clientInitiatedClose = false;
      };
    });
    // Successful connect — reset reconnect counter.
    this.reconnectAttempts = 0;

    // Auto-register the agent in the registry on first successful connect.
    // Idempotent: a re-connect after a relay restart skips this. The
    // registry POST is idempotent on its end too (409 = already present).
    if (this.autoRegister && this.registry && !this.registered) {
      await this.registerSelf();
    }
  }

  /**
   * Publish this agent in the registry and upload an X3DH pre-key bundle.
   *
   * - Generates a signed pre-key and `oneTimePrekeyCount` one-time
   *   pre-keys via `keyManager.generateSignedPreKey()` /
   *   `generateOneTimePreKeys()`.
   * - Capabilities are `[displayName?, ...options.capabilities]` so peers
   *   can find this agent via `registry.discover(displayName)`.
   * - Throws RegistryError on transport / 4xx (other than 409) / 5xx
   *   failure. Callers that want best-effort registration should catch.
   *
   * Safe to call directly when `autoRegister: false` was used.
   */
  async registerSelf(): Promise<void> {
    if (!this.registry) {
      throw new Error("MeshClient.registerSelf: no registry configured");
    }
    const km = this.options.keyManager;
    // identityKey is the long-term X25519 public key derived from the
    // Ed25519 signing key in the X3DHKeyManager constructor.
    // identityKeyEd is the Ed25519 public key — peers MUST receive it
    // to verify the signed pre-key signature (see x3dh.ts verifyBundle).
    const identityKey = km.identityKey.publicKey;
    const identityKeyEd = km.identityKeyEd;
    const signedPreKey = km.generateSignedPreKey();
    const oneTimePreKeys = km.generateOneTimePreKeys(this.oneTimePrekeyCount);

    // Capabilities: include displayName so name-based discover() works.
    const caps: string[] = [];
    const dn = this.options.displayName;
    if (dn) caps.push(dn);
    for (const c of this.options.capabilities ?? []) {
      if (c && !caps.includes(c)) caps.push(c);
    }

    const metadata: Record<string, string> = { ...(this.options.registrationMetadata ?? {}) };
    if (dn && metadata.display_name === undefined) metadata.display_name = dn;

    await this.registry.register(this.options.agentDid, identityKey, caps, metadata);
    await this.registry.uploadPrekeys(
      this.options.agentDid,
      identityKey,
      identityKeyEd,
      signedPreKey,
      oneTimePreKeys,
    );
    this.registered = true;
  }

  /**
   * Discover peers advertising a given capability. Returns [] if no
   * registry is configured.
   */
  async discover(capability: string, limit = 50): Promise<DiscoverResult[]> {
    if (!this.registry) return [];
    return this.registry.discover(capability, limit);
  }

  /**
   * Convenience: fetch a peer's pre-key bundle from the registry, then
   * call `establishSession`. Throws if no registry is configured or no
   * bundle is published for `peerId`.
   */
  async establishSessionWithPeer(peerId: string): Promise<MeshSession> {
    const existing = this.sessions.get(peerId);
    if (existing) return existing;
    if (this.isPlaintextPeer(peerId)) {
      return this.establishSession(peerId, {} as PreKeyBundle);
    }
    if (!this.registry) {
      throw new Error("MeshClient.establishSessionWithPeer: no registry configured");
    }
    const bundle = await this.registry.fetchPrekeys(peerId);
    if (!bundle) {
      throw new Error(`MeshClient.establishSessionWithPeer: no prekey bundle for ${peerId}`);
    }
    return this.establishSession(peerId, bundle);
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return; // already scheduled
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      for (const h of this.errorHandlers) {
        try { h("ws", this.options.agentDid, `auto-reconnect gave up after ${this.reconnectAttempts} attempts`); } catch { /* swallow */ }
      }
      return;
    }
    const exp = Math.min(this.reconnectBaseDelayMs * 2 ** this.reconnectAttempts, this.reconnectMaxDelayMs);
    // Light jitter (±20%) to avoid thundering-herd reconnects across many sandboxes.
    const jitter = exp * (0.8 + Math.random() * 0.4);
    this.reconnectAttempts++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.reconnect().catch((err) => {
        for (const h of this.errorHandlers) {
          try { h("ws", this.options.agentDid, `reconnect failed: ${err instanceof Error ? err.message : String(err)}`); } catch { /* swallow */ }
        }
        // Schedule next attempt — onclose may not fire if connect() rejected before ws.onopen.
        this.scheduleReconnect();
      });
    }, Math.round(jitter));
  }

  async disconnect(): Promise<void> {
    // Cancel any pending reconnect — caller asked to stay disconnected.
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.reconnectAttempts = 0;
    // Drop any buffered pre-KNOCK frames + their eviction timers.
    for (const peer of [...this.preKnockBuffer.keys()]) {
      this.dropPreKnockBuffer(peer);
    }
    if (!this.connected || !this.ws) return;
    this.clientInitiatedClose = true;
    this.sendFrame({ v: 1, type: "disconnect", from: this.options.agentDid });
    this.ws.close(1000, "client disconnect");
    this.connected = false;
    this.ws = null;
  }

  /**
   * Disconnect and reconnect to the relay.
   *
   * Resets the WebSocket connection and sends a fresh connect +
   * fetch_pending sequence, triggering inbox replay for any messages
   * queued while offline.
   */
  async reconnect(): Promise<void> {
    this.connected = false;
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        /* ignore close errors */
      }
      this.ws = null;
    }
    await this.connect();
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

    // X3DH + SecureChannel — compute establishment FIRST so we can embed it
    // in the KNOCK frame. This lets the receiver auto-bootstrap the responder
    // session before any ciphertext arrives, eliminating the
    // "No encrypted session" race that vendored agentmesh-sdk patch #4b
    // worked around. Backwards-compatible: receivers that don't understand
    // the `establishment` field fall back to manual acceptSession() calls.
    const [channel, establishment] = SecureChannel.createSender(
      this.options.keyManager,
      peerBundle,
      new TextEncoder().encode(`${this.options.agentDid}|${peerId}`),
    );

    this.sendFrame({
      v: 1,
      type: "knock",
      from: this.options.agentDid,
      to: peerId,
      id: knockId,
      ts: new Date().toISOString(),
      intent: { action: "establish_session" },
      establishment: this.serializeEstablishment(establishment),
    });

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

  /**
   * Register a callback for transport-level errors.
   *
   * Fires for: WebSocket errors (handshake, mid-stream), decrypt failures,
   * KNOCK protocol errors, frame validation, and `session_desync` events
   * (recoverable ratchet drift — caller should re-establishSession to that
   * peer; differs from "decrypt" which means no session existed at all).
   * Multiple handlers may be registered; each is invoked in registration
   * order. Handler exceptions are swallowed so one buggy observer cannot
   * break the others.
   */
  onError(handler: (kind: "ws" | "decrypt" | "knock" | "frame" | "session_desync", from: string, detail: string) => void): void {
    this.errorHandlers.push(handler);
  }

  /**
   * Register a callback for transport disconnect events.
   *
   * `reason` is `"client"` for caller-initiated `disconnect()`, `"server"`
   * for relay-side closes (network drop, relay restart), and `"ws-error"`
   * when an error event fires on an already-connected socket.
   */
  onDisconnect(handler: (reason: "client" | "server" | "ws-error", code?: number) => void): void {
    this.disconnectHandlers.push(handler);
  }

  /**
   * Register a callback that fires the first time we successfully decrypt
   * a message from a given peer (i.e. the X3DH+Double-Ratchet session
   * with that peer is fully end-to-end verified).
   *
   * `isFirstPeer` is `true` only for the very first verified peer in the
   * client's lifetime; subsequent peers fire with `false`. This lets
   * orchestrators print "mesh online" once and "+ peer X verified" for
   * the rest.
   */
  onE2EVerified(handler: (peerAmid: string, isFirstPeer: boolean) => void): void {
    this.e2eVerifiedHandlers.push(handler);
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
    } else if (type === "pending_messages") {
      await this.handlePendingMessages(frame);
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
      if (!session?.channel) {
        // Gap-G4 (vendored agentmesh-sdk patch #16): pre-KNOCK message buffer.
        // The relay does not guarantee inter-frame ordering — an encrypted
        // message can land before its KNOCK is processed. Drop-on-floor was
        // the upstream behaviour; instead, buffer the raw frame here and
        // drain it from handleKnock() once the KNOCK is accepted. Capped at
        // preKnockBufferSize entries per peer with preKnockBufferTtlMs TTL.
        if (this.preKnockBufferSize > 0 && !this.isPlaintextPeer(from)) {
          this.bufferPreKnockFrame(from, frame);
        } else {
          for (const h of this.errorHandlers) {
            try { h("decrypt", from, "no session for encrypted message — dropping"); } catch { /* swallow */ }
          }
        }
        return;
      }

      const header = frame.header as Record<string, unknown>;
      const encrypted: EncryptedMessage = {
        header: {
          dhPublicKey: this.base64ToUint8(header.dh as string),
          previousChainLength: header.pn as number,
          messageNumber: header.n as number,
        },
        ciphertext: this.base64ToUint8(frame.ciphertext as string),
      };

      let plaintext: Uint8Array;
      try {
        plaintext = session.channel.receive(encrypted);
      } catch (err) {
        // Gap-G3 (vendored agentmesh-sdk patch #13): on decrypt failure inside
        // an existing session, the ratchet is desynchronised — every
        // subsequent inbound frame will fail the same way. Tear down the
        // broken session so the next establishSession() to this peer runs a
        // fresh X3DH + KNOCK round, and surface a dedicated "session_desync"
        // error kind so callers can distinguish recoverable ratchet drift
        // (re-establish & retry) from genuine tampering (drop & alert).
        const detail = err instanceof Error ? err.message : String(err);
        this.closeSession(from);
        this.knockAccepted.delete(from);
        for (const h of this.errorHandlers) {
          try { h("session_desync", from, detail); } catch { /* swallow */ }
        }
        return;
      }
      payload = JSON.parse(new TextDecoder().decode(plaintext));
      session.messageCount++;

      // First successfully-decrypted message from this peer means E2E
      // is end-to-end verified (KNOCK + X3DH + Double Ratchet all worked).
      // Surface to observers exactly once per peer per process lifetime.
      if (!this.e2eVerifiedSet.has(from)) {
        this.e2eVerifiedSet.add(from);
        const isFirstPeer = this.e2eVerifiedSet.size === 1;
        for (const h of this.e2eVerifiedHandlers) {
          try { h(from, isFirstPeer); } catch { /* swallow handler errors */ }
        }
      }
    }

    // Send ACK
    this.sendFrame({ v: 1, type: "ack", id: frame.id });

    // Notify handlers
    for (const handler of this.messageHandlers) {
      handler(from, payload, isPlaintext);
    }
  }

  /**
   * Handle a batch of pending messages replayed by the relay on reconnect.
   *
   * The relay may respond to a fetch_pending frame with a
   * pending_messages frame containing an array of queued messages.
   * Each message is dispatched through the standard handleMessage path.
   */
  private async handlePendingMessages(frame: Record<string, unknown>): Promise<void> {
    const messages = frame.messages as Array<Record<string, unknown>> | undefined;
    if (!messages || !Array.isArray(messages)) return;

    for (const msg of messages) {
      await this.handleMessage(msg);
    }
  }

  private async handleKnock(frame: Record<string, unknown>): Promise<void> {
    const from = frame.from as string;
    const intent = frame.intent;

    // Register pending entry so concurrent handleMessage calls wait for
    // the verdict. handleMessage may wrap `resolve` to add its own waiter;
    // we look up the (possibly-wrapped) function when we resolve below.
    //
    // The timer is the abort path: if no verdict arrives within
    // knockTimeout, resolve waiters to false and clear the entry. A
    // `timedOut` flag prevents a slow handler from sending knock_accept
    // after the timer has already told waiters the KNOCK was rejected.
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      const entry = this.knockPending.get(from);
      if (entry) {
        this.knockPending.delete(from);
        entry.resolve(false);
      }
    }, this.knockTimeout);
    this.knockPending.set(from, { resolve: () => {}, timer });

    // Evaluate via registered handlers. Use try/finally so the timer is
    // cleared and the pending entry resolved even if a handler throws —
    // otherwise the entry would leak and a re-KNOCK from the same peer
    // would race against stale state.
    let accepted = true;
    try {
      for (const handler of this.knockHandlers) {
        if (!(await handler(from, intent))) {
          accepted = false;
          break;
        }
      }
    } finally {
      clearTimeout(timer);
      if (!timedOut) {
        const entry = this.knockPending.get(from);
        if (entry) {
          this.knockPending.delete(from);
          entry.resolve(accepted);
        }
      }
    }

    // If the timer beat the handler eval, waiters were already told
    // "rejected"; honor that decision when responding to the relay.
    if (timedOut) accepted = false;

    if (accepted) {
      // Auto-bootstrap responder session if establishment data was embedded
      // in the knock. Mirrors vendored agentmesh-sdk patch #4b — receiver no
      // longer needs to call acceptSession() manually before the first
      // encrypted message arrives.
      const est = frame.establishment as Record<string, unknown> | undefined;
      if (est && !this.sessions.has(from)) {
        try {
          const establishment = this.deserializeEstablishment(est);
          this.acceptSession(from, establishment);
        } catch (err) {
          for (const h of this.errorHandlers) {
            try { h("knock", from, `failed to bootstrap responder from KNOCK: ${err instanceof Error ? err.message : String(err)}`); } catch { /* swallow */ }
          }
          accepted = false;
        }
      }
      // Always record acceptance so the encrypted-message gate stops
      // waiting/buffering. (`acceptSession` also sets this, but keep the
      // legacy-peer path covered too.)
      if (accepted) this.knockAccepted.add(from);
    }

    if (accepted) {
      this.sendFrame({
        v: 1,
        type: "knock_accept",
        from: this.options.agentDid,
        to: from,
        id: crypto.randomUUID(),
        knock_id: frame.id,
        ts: new Date().toISOString(),
      });
      // Gap-G4: drain any encrypted frames that arrived for this peer
      // before its KNOCK was processed. The session is now established
      // (via auto-bootstrap above or a prior acceptSession call), so the
      // buffered frames can be replayed through the normal handleMessage
      // path and decrypted against the fresh session.
      await this.drainPreKnockBuffer(from);
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
      // Drop any buffered frames — KNOCK was rejected so we cannot decrypt
      // them anyway. Avoids unbounded buffer growth for hostile peers.
      this.dropPreKnockBuffer(from);
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

  // ── Pre-KNOCK buffer (Gap-G4 / vendored patch #16) ──────────────

  private bufferPreKnockFrame(from: string, frame: Record<string, unknown>): void {
    let entries = this.preKnockBuffer.get(from);
    if (!entries) {
      entries = [];
      this.preKnockBuffer.set(from, entries);
    }
    // Cap: drop oldest when full to keep newest message (sender most likely
    // to retransmit nothing — newer frames carry the most recent ratchet
    // state and have the best chance of being decryptable).
    if (entries.length >= this.preKnockBufferSize) {
      const evicted = entries.shift();
      if (evicted) clearTimeout(evicted.timer);
    }
    const timer = setTimeout(() => {
      const list = this.preKnockBuffer.get(from);
      if (!list) return;
      const idx = list.findIndex((e) => e.frame === frame);
      if (idx >= 0) list.splice(idx, 1);
      if (list.length === 0) this.preKnockBuffer.delete(from);
    }, this.preKnockBufferTtlMs);
    entries.push({ frame, timer });
  }

  private async drainPreKnockBuffer(from: string): Promise<void> {
    const entries = this.preKnockBuffer.get(from);
    if (!entries || entries.length === 0) return;
    this.preKnockBuffer.delete(from);
    for (const entry of entries) {
      clearTimeout(entry.timer);
      try {
        await this.handleMessage(entry.frame);
      } catch (err) {
        for (const h of this.errorHandlers) {
          try { h("decrypt", from, `pre-knock drain failed: ${err instanceof Error ? err.message : String(err)}`); } catch { /* swallow */ }
        }
      }
    }
  }

  private dropPreKnockBuffer(from: string): void {
    const entries = this.preKnockBuffer.get(from);
    if (!entries) return;
    for (const entry of entries) clearTimeout(entry.timer);
    this.preKnockBuffer.delete(from);
  }

  // ── Establishment (de)serialization ─────────────────────────────

  private serializeEstablishment(est: ChannelEstablishment): Record<string, unknown> {
    const out: Record<string, unknown> = {
      ik: this.uint8ToBase64(est.initiatorIdentityKey),
      ek: this.uint8ToBase64(est.ephemeralPublicKey),
    };
    if (typeof est.usedOneTimeKeyId === "number") out.otk = est.usedOneTimeKeyId;
    return out;
  }

  private deserializeEstablishment(obj: Record<string, unknown>): ChannelEstablishment {
    const ik = obj.ik;
    const ek = obj.ek;
    if (typeof ik !== "string" || typeof ek !== "string") {
      throw new Error("malformed establishment: missing ik/ek");
    }
    const result: ChannelEstablishment = {
      initiatorIdentityKey: this.base64ToUint8(ik),
      ephemeralPublicKey: this.base64ToUint8(ek),
    };
    if (typeof obj.otk === "number") result.usedOneTimeKeyId = obj.otk;
    return result;
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
