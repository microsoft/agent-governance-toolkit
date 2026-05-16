# Trust Scoring

Demonstrates the three things that make `TrustManager` non-obvious:

1. **Asymmetric reward/penalty.** A single failure with magnitude `x` moves
   the score down further than a matching-magnitude success moved it up
   (default penalty multiplier is `1.5x`, reward is `1.0x`).
2. **Decay on every interaction.** Each `RecordSuccess`/`RecordFailure`
   call multiplies the previous score by `(1 - DecayRate)` *before*
   applying the reward, so tiny rewards never quite reach the ceiling.
3. **`VerifyPeer` fails closed.** It returns
   `ErrPeerVerificationEvidenceRequired` whenever the caller has only a
   peer's self-attested identity — there is no implicit trust path.

Covers [`trust.go`](../../packages/agentmesh/trust.go) and the
`TrustConfig` / `TrustScore` / `TrustVerificationResult` types in
[`types.go`](../../packages/agentmesh/types.go).

## Run it

```bash
go run .
```

## Expected output

```text
initial:                  overall=0.500 tier=medium
after 5 successes (x0.2): overall=1.000 tier=high
after 1 failure (x0.2):   overall=0.690 tier=medium
after 10 tiny successes:  overall=0.720 tier=medium

VerifyPeer with self-attested identity only:
  Verified=false score=0.720 tier=medium
  err=peer verification requires independent evidence: peer "did:agentmesh:peer-1" only presented self-attested identity data
```

The *shape* is what matters: a single failure of magnitude `0.2` drops
the score by ~0.31 (from 1.000 to 0.690), while a single matching
success of magnitude `0.2` would lift it by only ~0.2 — the penalty
multiplier is `1.5x` to the reward multiplier's `1.0x`. The final 10
tiny rewards converge slowly toward 1.0 but never reach it because
each one is multiplied against the decay first.

## Where to go next

- [`identity-sign-verify/`](../identity-sign-verify/) — generate the
  cryptographic evidence that *would* satisfy `VerifyPeer` in a real
  deployment.
- [`full-stack/`](../full-stack/) — see trust scores feeding into a full
  governance pipeline.
- [`../README.md`](../../README.md) — full SDK overview.
