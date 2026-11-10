# GROUND_TRUTH.md — savage-standard

Code-proven state of this repository, component by component. Verify any
line of it by reading the named file and running the named command.

## What this repo is

The SIA-E2 "One Promotion Standard" build: a common receipt envelope
(SRE-1) plus a universal verifier for the seven receipt dialects minted
across the Savage estate, plus the claims-gate inventory that baselines
SIA-E2's second metric. Python 3 standard library only; zero third-party
dependencies (`pyproject.toml` declares `dependencies = []`).

## Component state

| Component | State | How to verify |
|---|---|---|
| `savage_standard/canonical.py` — JCS (RFC 8785) canonicalizer with ECMAScript number serialization; Python sorted-compact; Starr canonicalJson; fixed-order JS stringify | VERIFIED against producer-minted artifacts | Test suite recomputes real marketplace entry hashes / receipt digests, the sia-v6-core chain hash, Breakthrough record digests, and the Starr receipt hash from fixture bytes and matches them exactly. |
| `savage_standard/envelope.py` — SRE-1 envelope: wrap, digest, structural checks | VERIFIED | `tests/test_savage_standard.py::TestEnvelope` (wrap→verify VERIFIED; tampered native → REJECTED; tampered envelope field → REJECTED). |
| `savage_standard/dialects.py` — seven adapters: marketplace-delivery, siav6core-benchmark, relay-event-log, breakthrough-evidence, siav6-benchmark-manifest, ceros-promotion, starr-bounce | VERIFIED per the coverage table in the PR body | `python3 -m unittest discover -s tests` → 27 tests, all passing: genuine PASS + tamper FAIL per dialect. |
| `savage_standard/verify.py` — dialect detection + verdict assembly (VERIFIED / VERIFIED-STRUCTURAL / REJECTED / UNVERIFIABLE) | VERIFIED | Same suite; garbage input returns UNVERIFIABLE, never a pass. |
| `savage_standard/cli.py` — `savage-verify` CLI (verify / wrap / claims) | VERIFIED | Smoke-run in the PR body; exit codes 0/1/2 by verdict. |
| `savage_standard/claims.py` — claims-gate inventory | VERIFIED as an enumeration | Rows cite their sources (site repo main `4efd6486`, marketplace `catalog.json`, Stripe registry, fix-program results). The BEFORE number is definitional — the definition is printed in the module docstring so it can be argued with. |
| `fixtures/` — real artifacts from the fix program | VERIFIED | `fixtures/PROVENANCE.md` names each artifact's origin. |

## Metrics (Evolution Rule v2)

- BEFORE: receipt dialects verifiable by a single independent tool =
  **0 of 7 (0%)** — measured from the pre-build tree (`BEFORE-MEASUREMENT.md`).
- AFTER: **7 of 7 dialects** covered by the one verifier, each with a
  genuine artifact passing and tamper controls failing loudly in the
  suite. Two dialects return VERIFIED-STRUCTURAL rather than VERIFIED
  for the reasons below — that distinction is the product working as
  designed, not a gap in the build.
- Claims gate: BEFORE **1 of 12 claim groups (8.3%)** gate-issued with
  outsider-recomputable receipts. This build does not move that number —
  it builds the instrument the number is measured with. Adoption
  (routing each line's public claims through the standard) is the
  follow-on work program.

## What is NOT true

- **CEROS signatures are NOT cryptographically verified here.** ML-DSA-87
  (FIPS 204) has no verifier in the Python standard library and the
  zero-dependency law forbids adding one. The adapter recomputes the
  receipt's shape, dimension total, and the exact signed-core byte form,
  and reports the signature leg UNVERIFIABLE (verdict
  VERIFIED-STRUCTURAL). The fixture receipt was confirmed genuine by the
  producer's own `verifyReceipt` at mint time; an outsider who needs the
  cryptographic leg today must run the producer's Node verifier. A
  Savage-original ML-DSA verifier is a named future build.
- **SIA-v6 per-record HMACs are NOT verifiable from artifacts.** The
  producer verifies each record's MAC in-process and persists only the
  `hmac_valid` boolean; the MAC itself is never stored. The adapter
  verifies everything that IS persisted (manifest artifact hashes, the
  certification arithmetic from the suite summary) and reports the
  record-MAC leg UNVERIFIABLE.
- **The envelope adds no signature and no trusted timestamp.** Wrapping
  is hash-bound only; `recorded_at` remains producer-reported. Estate
  key custody for envelope-level signatures is still owed — the same
  defect the delivery-ledger prints on every receipt.
- **No producer was modified.** Every dialect adapter re-implements its
  dialect's checks from the producer's source; producers keep minting
  exactly as before. Convergence of the *gate* (Foundry's arbiter +
  CEROS's engine + Breakthrough's checker as one issuing path) is not
  built here; this repo is the format + verifier foundation the register
  sequences first.
- **The claims BEFORE % is an inventory judgment, not a crawl of the
  whole web.** It enumerates the estate's own public surfaces (site,
  catalogs, registry, published program results) under the stated
  definition. Claims on surfaces not enumerated (e.g. the five
  off-GitHub websites whose domains are not yet recorded) are not
  counted in either direction.
- **The marketplace genuine pair is a measurement-run pair, not a real
  customer sale.** Estate revenue is $0; no production delivery receipt
  exists yet. A scratch pair harvested earlier from a verify-CLI temp
  dir fails the producer's own verifier and was excluded — see
  `fixtures/PROVENANCE.md`.
