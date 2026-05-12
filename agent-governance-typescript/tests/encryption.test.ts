// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Tests for E2E encryption modules (X3DH, Double Ratchet, SecureChannel).
 *
 * Implements against: docs/specs/AGENTMESH-WIRE-1.0.md
 */

import { ed25519 } from "@noble/curves/ed25519";
import {
  X3DHKeyManager,
  generateX25519KeyPair,
  ed25519ToX25519,
  DoubleRatchet,
  SecureChannel,
} from "../src/encryption";

function makeManager(): X3DHKeyManager {
  const priv = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(priv);
  return new X3DHKeyManager(priv, pub);
}

function setupPair(): [DoubleRatchet, DoubleRatchet] {
  const alice = makeManager();
  const bob = makeManager();

  bob.generateSignedPreKey();
  bob.generateOneTimePreKeys(1);
  const bobBundle = bob.getPublicBundle(0);

  const aliceResult = alice.initiate(bobBundle);
  const bobResult = bob.respond(
    alice.identityKey.publicKey,
    aliceResult.ephemeralPublicKey,
    aliceResult.usedOneTimeKeyId,
  );

  const aliceRatchet = DoubleRatchet.initSender(
    aliceResult.sharedSecret,
    bobBundle.signedPreKey,
  );
  const bobRatchet = DoubleRatchet.initReceiver(bobResult.sharedSecret, {
    privateKey: bob.signedPreKey!.keyPair.privateKey,
    publicKey: bob.signedPreKey!.keyPair.publicKey,
  });
  return [aliceRatchet, bobRatchet];
}

const enc = new TextEncoder();
const dec = new TextDecoder();

// ── X25519 Key Pair ──

describe("X25519KeyPair", () => {
  test("generate produces 32-byte keys", () => {
    const kp = generateX25519KeyPair();
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
  });

  test("generate produces unique keys", () => {
    const kp1 = generateX25519KeyPair();
    const kp2 = generateX25519KeyPair();
    expect(Buffer.from(kp1.privateKey).equals(Buffer.from(kp2.privateKey))).toBe(false);
  });

  test("ed25519 to x25519 conversion", () => {
    const priv = ed25519.utils.randomSecretKey();
    const pub = ed25519.getPublicKey(priv);
    const kp = ed25519ToX25519(priv, pub);
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
  });
});

// ── X3DH Key Manager ──

describe("X3DHKeyManager", () => {
  test("generate signed pre-key", () => {
    const mgr = makeManager();
    const spk = mgr.generateSignedPreKey();
    expect(spk.publicKey.length).toBe(32);
    expect(spk.signature.length).toBe(64);
  });

  test("generate one-time pre-keys", () => {
    const mgr = makeManager();
    const otks = mgr.generateOneTimePreKeys(5);
    expect(otks.length).toBe(5);
    const ids = new Set(otks.map((k) => k.keyId));
    expect(ids.size).toBe(5);
  });

  test("get bundle requires SPK", () => {
    const mgr = makeManager();
    expect(() => mgr.getPublicBundle()).toThrow("No signed pre-key");
  });

  test("full exchange with OTK", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(5);
    const bobBundle = bob.getPublicBundle(0);

    const aliceResult = alice.initiate(bobBundle);
    const bobResult = bob.respond(
      alice.identityKey.publicKey,
      aliceResult.ephemeralPublicKey,
      aliceResult.usedOneTimeKeyId,
    );

    expect(Buffer.from(aliceResult.sharedSecret).equals(Buffer.from(bobResult.sharedSecret))).toBe(true);
    expect(aliceResult.sharedSecret.length).toBe(32);
  });

  test("exchange without OTK (3-DH)", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bobBundle = bob.getPublicBundle();

    const aliceResult = alice.initiate(bobBundle);
    const bobResult = bob.respond(
      alice.identityKey.publicKey,
      aliceResult.ephemeralPublicKey,
    );

    expect(Buffer.from(aliceResult.sharedSecret).equals(Buffer.from(bobResult.sharedSecret))).toBe(true);
  });

  test("consumed OTK raises", () => {
    const bob = makeManager();
    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(1);
    const bundle = bob.getPublicBundle(0);

    const alice = makeManager();
    const result = alice.initiate(bundle);
    bob.respond(alice.identityKey.publicKey, result.ephemeralPublicKey, 0);

    expect(() =>
      bob.respond(alice.identityKey.publicKey, result.ephemeralPublicKey, 0),
    ).toThrow("not found or already consumed");
  });

  test("bundle includes Ed25519 identity key", () => {
    const mgr = makeManager();
    mgr.generateSignedPreKey();
    const bundle = mgr.getPublicBundle();
    expect(bundle.identityKeyEd).toBeDefined();
    expect(bundle.identityKeyEd!.length).toBe(32);
  });

  test("valid signature passes verification", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();
    expect(() => alice.initiate(bundle)).not.toThrow();
  });

  test("tampered signed pre-key rejected", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();
    const tampered = { ...bundle, signedPreKey: new Uint8Array(bundle.signedPreKey) };
    tampered.signedPreKey[0] ^= 0xff;
    expect(() => alice.initiate(tampered)).toThrow("Signed pre-key signature verification FAILED");
  });

  test("forged identity key rejected", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();
    const attackerPriv = ed25519.utils.randomSecretKey();
    const attackerPub = ed25519.getPublicKey(attackerPriv);
    const forged = { ...bundle, identityKeyEd: attackerPub };
    expect(() => alice.initiate(forged)).toThrow("Signed pre-key signature verification FAILED");
  });

  test("missing identityKeyEd throws (fail-closed)", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();
    delete (bundle as any).identityKeyEd;
    expect(() => alice.initiate(bundle)).toThrow("Missing or invalid Ed25519 identity key (identityKeyEd)");
  });
});

// ── Double Ratchet ──

describe("DoubleRatchet", () => {
  test("single message", () => {
    const [alice, bob] = setupPair();
    const encrypted = alice.encrypt(enc.encode("hello bob"));
    const plaintext = bob.decrypt(encrypted);
    expect(dec.decode(plaintext)).toBe("hello bob");
  });

  test("multiple messages one direction", () => {
    const [alice, bob] = setupPair();
    for (let i = 0; i < 5; i++) {
      const msg = enc.encode(`message ${i}`);
      const encrypted = alice.encrypt(msg);
      expect(dec.decode(bob.decrypt(encrypted))).toBe(`message ${i}`);
    }
  });

  test("bidirectional conversation", () => {
    const [alice, bob] = setupPair();

    let e = alice.encrypt(enc.encode("hello bob"));
    expect(dec.decode(bob.decrypt(e))).toBe("hello bob");

    e = bob.encrypt(enc.encode("hello alice"));
    expect(dec.decode(alice.decrypt(e))).toBe("hello alice");

    e = alice.encrypt(enc.encode("how are you"));
    expect(dec.decode(bob.decrypt(e))).toBe("how are you");
  });

  test("DH ratchet advances on turn change", () => {
    const [alice, bob] = setupPair();
    const e1 = alice.encrypt(enc.encode("a1"));
    bob.decrypt(e1);
    const e2 = bob.encrypt(enc.encode("b1"));
    alice.decrypt(e2);
    const e3 = alice.encrypt(enc.encode("a2"));
    // DH key should have changed
    expect(Buffer.from(e3.header.dhPublicKey).equals(Buffer.from(e1.header.dhPublicKey))).toBe(false);
    expect(dec.decode(bob.decrypt(e3))).toBe("a2");
  });

  test("out-of-order delivery", () => {
    const [alice, bob] = setupPair();
    const e0 = alice.encrypt(enc.encode("msg0"));
    const e1 = alice.encrypt(enc.encode("msg1"));
    const e2 = alice.encrypt(enc.encode("msg2"));

    expect(dec.decode(bob.decrypt(e2))).toBe("msg2");
    expect(dec.decode(bob.decrypt(e0))).toBe("msg0");
    expect(dec.decode(bob.decrypt(e1))).toBe("msg1");
  });

  test("tampered ciphertext rejected", () => {
    const [alice, bob] = setupPair();
    const e = alice.encrypt(enc.encode("secret"));
    const tampered = { ...e, ciphertext: new Uint8Array(e.ciphertext) };
    tampered.ciphertext[tampered.ciphertext.length - 1] ^= 0xff;
    expect(() => bob.decrypt(tampered)).toThrow();
  });

  test("max skip exceeded", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(1);
    const bundle = bob.getPublicBundle(0);
    const ar = alice.initiate(bundle);
    const br = bob.respond(alice.identityKey.publicKey, ar.ephemeralPublicKey, 0);

    const aRatchet = DoubleRatchet.initSender(ar.sharedSecret, bundle.signedPreKey);
    const bRatchet = DoubleRatchet.initReceiver(br.sharedSecret, {
      privateKey: bob.signedPreKey!.keyPair.privateKey,
      publicKey: bob.signedPreKey!.keyPair.publicKey,
    });

    // Override max skip to 2 via fromState
    const state = bRatchet.getState();
    const bLimited = DoubleRatchet.fromState(state, 2);

    aRatchet.encrypt(enc.encode("skip1"));
    aRatchet.encrypt(enc.encode("skip2"));
    aRatchet.encrypt(enc.encode("skip3"));
    const e4 = aRatchet.encrypt(enc.encode("msg4"));

    expect(() => bLimited.decrypt(e4)).toThrow("Too many skipped");
  });

  test("skippedKeys cache is bounded by the aggregate cap", () => {
    // The per-chain cap (maxSkip) bounds a single burst; the global cap
    // bounds the lifetime accumulation across DH ratchet steps. This
    // test forces a single oversized burst within one chain by raising
    // maxSkip well above the global cap and confirms the resulting
    // skippedKeys map never exceeds it (oldest entries are evicted FIFO).
    const MAX_TOTAL = 2000;
    const OVERFLOW = 50;
    const SKIP = MAX_TOTAL + OVERFLOW;

    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(1);
    const bundle = bob.getPublicBundle(0);
    const ar = alice.initiate(bundle);
    const br = bob.respond(alice.identityKey.publicKey, ar.ephemeralPublicKey, 0);

    const aRatchet = DoubleRatchet.initSender(ar.sharedSecret, bundle.signedPreKey);
    const bRatchetRaw = DoubleRatchet.initReceiver(br.sharedSecret, {
      privateKey: bob.signedPreKey!.keyPair.privateKey,
      publicKey: bob.signedPreKey!.keyPair.publicKey,
    });

    // Rebuild bob with a generous per-chain cap so the burst itself is
    // not rejected, leaving the global cap as the only thing protecting
    // memory.
    const bRatchet = DoubleRatchet.fromState(bRatchetRaw.getState(), SKIP + 1);

    // Alice sends SKIP messages that bob will skip, then one we deliver.
    for (let i = 0; i < SKIP; i++) {
      aRatchet.encrypt(enc.encode(`skipped-${i}`));
    }
    const final = aRatchet.encrypt(enc.encode("delivered"));

    expect(dec.decode(bRatchet.decrypt(final))).toBe("delivered");

    // After processing the final message, exactly MAX_TOTAL skipped keys
    // remain cached; the oldest OVERFLOW were evicted.
    const cachedAfter = bRatchet.getState().skippedKeys.size;
    expect(cachedAfter).toBe(MAX_TOTAL);
  });
});

// ── SecureChannel ──

describe("SecureChannel", () => {
  test("full send/receive flow", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(1);
    const bundle = bob.getPublicBundle(0);

    const [aliceCh, est] = SecureChannel.createSender(alice, bundle);
    const bobCh = SecureChannel.createReceiver(bob, est);

    const e = aliceCh.send(enc.encode("hello bob"));
    expect(dec.decode(bobCh.receive(e))).toBe("hello bob");

    const e2 = bobCh.send(enc.encode("hello alice"));
    expect(dec.decode(aliceCh.receive(e2))).toBe("hello alice");
  });

  test("message count", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const bundle = bob.getPublicBundle();
    const [aliceCh, est] = SecureChannel.createSender(alice, bundle);
    const bobCh = SecureChannel.createReceiver(bob, est);

    expect(aliceCh.messageCount).toBe(0);
    const e = aliceCh.send(enc.encode("test"));
    expect(aliceCh.messageCount).toBe(1);
    bobCh.receive(e);
    expect(bobCh.messageCount).toBe(1);
  });

  test("close prevents send", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    const [aliceCh] = SecureChannel.createSender(alice, bob.getPublicBundle());
    aliceCh.close();
    expect(aliceCh.isClosed).toBe(true);
    expect(() => aliceCh.send(enc.encode("nope"))).toThrow("closed");
  });

  test("10-message bidirectional", () => {
    const alice = makeManager();
    const bob = makeManager();
    bob.generateSignedPreKey();
    bob.generateOneTimePreKeys(1);
    const [aliceCh, est] = SecureChannel.createSender(alice, bob.getPublicBundle(0));
    const bobCh = SecureChannel.createReceiver(bob, est);

    for (let i = 0; i < 10; i++) {
      if (i % 2 === 0) {
        const e = aliceCh.send(enc.encode(`alice-${i}`));
        expect(dec.decode(bobCh.receive(e))).toBe(`alice-${i}`);
      } else {
        const e = bobCh.send(enc.encode(`bob-${i}`));
        expect(dec.decode(aliceCh.receive(e))).toBe(`bob-${i}`);
      }
    }
    expect(aliceCh.messageCount).toBe(10);
  });
});
