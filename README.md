# savage-standard — SIA-E2 "One Promotion Standard" + SIA-E1 "The Recomputable Benchmark"

**Ground truth first: [GROUND_TRUTH.md](GROUND_TRUTH.md)** — what this repo
provably does, component by component, including what is NOT true.

The estate mints proof in seven receipt dialects (marketplace delivery
ledger, sia-v6-core benchmark chain, Breakthrough evidence, SIA-v6
benchmark manifest, CEROS promotion receipts, Relay event log, Starr
bounce receipts). Before this repo, each verified only inside its own
repository: **0 of 7 dialects were verifiable by a single independent
tool** (see `BEFORE-MEASUREMENT.md`, taken from the pre-build tree).

This repo is the one standard they converge on:

1. **SRE-1, the common receipt envelope** (`savage_standard/envelope.py`) —
   one minimal envelope (schema `savage/receipt-envelope/1`) that wraps
   any native receipt *verbatim*: claim identity, issuer, subject
   hashes, evidence pointers + hashes, gate verdict, timestamps with an
   explicit trust note, and a hash-chain link. Producers are not
   rewritten; the envelope adds identification and chaining, not trust.
2. **The universal verifier** (`savage-verify`) — one CLI/library that
   takes a receipt in ANY estate dialect, native or envelope-wrapped,
   recomputes its signature/chain/evidence checks from the referenced
   artifacts, and returns **VERIFIED**, **VERIFIED-STRUCTURAL**,
   **REJECTED**, or **UNVERIFIABLE** — never a silent pass.
3. **The claims-gate inventory** (`savage_standard/claims.py`) — the
   estate's public claims enumerated from the site repo and catalogs,
   with the honest BEFORE number: **1 of 12 claim groups (8.3%) are
   gate-issued with outsider-recomputable receipts today.** The register
   target is 100%; this package is the instrument, not the adoption.
4. **SIA-E1 — the external recompute adapter** (`savage_standard/helm.py`,
   CLI subcommand `recompute`) — the standard pointed at a claim Savage
   does NOT own: HELM classic v0.4.0, BoolQ, Mistral v0.1 (7B),
   exact_match on the valid split, published at **0.874**. Before this
   build, **0** external claims were recomputable through the standard —
   an outsider had to trust HELM's published tables. The adapter merges
   HELM's own per-instance statistics (public bucket, no account) with
   HELM's own aggregation rule and mints a receipt
   (`savage/external-benchmark-recompute/1`) that `savage-verify` checks
   like any other dialect: published-vs-recomputed comparison, input
   hash pin, and full re-derivation from the artifact bytes. Recomputed
   value: **0.874** (874.0 / 1,000 unperturbed instances) — delta 0.0,
   MATCH. Coverage is exactly this one claim; see GROUND_TRUTH.md for
   what is NOT covered.
5. **Estate key custody** (`savage_standard/signing.py`,
   `savage_standard/rsa.py`, `savage_standard/key_registry.json`) —
   SRE-1 envelopes can now carry a real issuer signature
   (RSASSA-PKCS1-v1_5 / SHA-256, Savage-original stdlib code,
   cross-checked against OpenSSL). Before this build, envelopes were
   hash-bound only: the verifier emitted zero signature legs, and a
   forged envelope with an honestly recomputed digest still verified
   VERIFIED — an unkeyed hash cannot stop a re-digesting forger. Now
   the forgery is REJECTED on the signature leg, genuine signed
   envelopes verify end to end, and unknown or revoked keys cap the
   verdict at VERIFIED-STRUCTURAL. Custody model: public keys are
   committed in the registry (reviewable, revocable); private keys are
   generated and held by the operator outside any repository and read
   only at signing time. The shipped registry holds one throwaway
   DEMO key (private half destroyed) proving the mechanism — no real
   estate key has been minted yet; that is the operator's act
   (`savage-verify keygen`), and only the public entry gets committed.

## Why a new tiny repo

The verifier must be neutral ground: housing it inside
savage-marketplace would make the marketplace's own receipts
self-verified, defeating the outsider-trust purpose. Precedent:
savage-relay and savage-api-atlas were created the same way for
cross-estate roles. Python 3 standard library only — zero third-party
dependencies — matching the sia-v6-core / Relay house style.

## Use

```sh
python3 -m savage_standard.cli RECEIPT.json [--pair PAIR.json] [--artifacts DIR] [--file ARTIFACT]
python3 -m savage_standard.cli wrap NATIVE.json --claim-id ... (see --help)
python3 -m savage_standard.cli claims
python3 -m savage_standard.cli recompute PER_INSTANCE_STATS.json --metric exact_match --split valid ... (see --help)  # mint an external-benchmark recompute receipt
python3 -m savage_standard.cli keygen --key-id ID --out ~/outside-any-repo/estate.key.json   # operator only: prints the PUBLIC registry entry; the private key never enters a repo
python3 -m savage_standard.cli sign ENVELOPE.json --key-file ~/outside-any-repo/estate.key.json -o SIGNED.json
python3 -m unittest discover -s tests   # 50 tests: genuine + tamper per dialect, incl. the HELM recompute dialect and envelope signatures
```

Exit codes: 0 = VERIFIED / VERIFIED-STRUCTURAL, 1 = REJECTED,
2 = UNVERIFIABLE. A tampered receipt never exits 0.
