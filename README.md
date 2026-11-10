# savage-standard — SIA-E2 "One Promotion Standard"

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
python3 -m unittest discover -s tests   # 27 tests: genuine + tamper per dialect
```

Exit codes: 0 = VERIFIED / VERIFIED-STRUCTURAL, 1 = REJECTED,
2 = UNVERIFIABLE. A tampered receipt never exits 0.
