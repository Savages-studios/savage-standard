# GROUND_TRUTH.md — savage-standard

Code-proven state of this repository, component by component. Verify any
line of it by reading the named file and running the named command.

## What this repo is

The SIA-E2 "One Promotion Standard" build: a common receipt envelope
(SRE-1) plus a universal verifier for the seven receipt dialects minted
across the Savage estate, plus the claims-gate inventory that baselines
SIA-E2's second metric. Python 3 standard library only; zero third-party
dependencies (`pyproject.toml` declares `dependencies = []`).

SIA-E1 "The Recomputable Benchmark" (this build) adds the first
EXTERNAL dialect: `helm-benchmark`, a recompute adapter for a published
benchmark result from a system Savage does not own — Stanford CRFM's
HELM classic v0.4.0 — with the recompute minter in
`savage_standard/helm.py`. See the SIA-E1 lines in the component table
and Metrics below.

The key-custody build (this build) closes the envelope-signature
defect named in earlier revisions of this file: SRE-1 envelopes can
now carry a real issuer signature, checked by the universal verifier
against a public key registry committed in this repo
(`savage_standard/signing.py`, `savage_standard/rsa.py`,
`savage_standard/key_registry.json`). Private keys are generated and
held by the operator OUTSIDE any repository; only public entries are
committed. See the custody lines in the component table, Metrics, and
"What is NOT true" — in particular: no real estate key has been minted
yet, so no production envelope is signed today.

## Component state

| Component | State | How to verify |
|---|---|---|
| `savage_standard/canonical.py` — JCS (RFC 8785) canonicalizer with ECMAScript number serialization; Python sorted-compact; Starr canonicalJson; fixed-order JS stringify | VERIFIED against producer-minted artifacts | Test suite recomputes real marketplace entry hashes / receipt digests, the sia-v6-core chain hash, Breakthrough record digests, and the Starr receipt hash from fixture bytes and matches them exactly. |
| `savage_standard/envelope.py` — SRE-1 envelope: wrap, digest, structural checks | VERIFIED | `tests/test_savage_standard.py::TestEnvelope` (wrap→verify VERIFIED; tampered native → REJECTED; tampered envelope field → REJECTED). The digest core now also excludes the `signatures` member (the signature is computed over the digest); envelopes without one digest byte-identically to before, which the fixture suite proves on every run. |
| `savage_standard/rsa.py` — RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017): Miller-Rabin key generation, EMSA-PKCS1-v1_5 encoding, sign/verify — Savage-original, stdlib only | VERIFIED, incl. against the reference implementation | `tests/test_signing.py::TestRsa` (EMSA block asserted byte-exact against the RFC 8017 construction; sign/verify round-trip; garbage rejected). Cross-checked against OpenSSL during development in BOTH directions: OpenSSL verified this code's signature, and this code verified OpenSSL's. Classical scheme — NOT post-quantum, not constant-time (see "What is NOT true"). |
| `savage_standard/signing.py` + `savage_standard/key_registry.json` — estate key custody: public registry (committed), operator-side key generation (private key written mode-0600 to an operator-chosen path outside any repo, never copied by this code), envelope signing, and the verifier's signature legs | VERIFIED as a mechanism; NO real estate key exists yet | `tests/test_signing.py` (17 tests: signed envelope VERIFIED end to end; the pre-custody re-digest forgery REJECTED; tampered signature REJECTED; wrong public key REJECTED; unknown/revoked key caps at VERIFIED-STRUCTURAL; unsigned envelopes unchanged; a signed marketplace-delivery envelope verifies with its pair). The shipped registry holds exactly ONE entry — a throwaway DEMO key (usage `demo`) whose private half was destroyed at build time after signing `fixtures/signed-envelope-demo.json`; its leg passes with a detail stating it attests nothing. |
| `savage_standard/dialects.py` — seven estate adapters: marketplace-delivery, siav6core-benchmark, relay-event-log, breakthrough-evidence, siav6-benchmark-manifest, ceros-promotion, starr-bounce | VERIFIED per the coverage table in the PR body | `python3 -m unittest discover -s tests` → genuine PASS + tamper FAIL per dialect. |
| `savage_standard/helm.py` — SIA-E1 recompute minter: HELM per-instance Stat merge + native receipt (`savage/external-benchmark-recompute/1`) | VERIFIED on a real external artifact | `gunzip -dc fixtures/helm-boolq-per-instance-stats.json.gz > /tmp/per_instance_stats.json`, then `savage-verify recompute /tmp/per_instance_stats.json …` reproduces `fixtures/helm-boolq-receipt.json`: 874.0/1000.0 = 0.874. (The fixture is committed gzip-compressed — GitHub's git-blobs API refuses the raw 64.7 MB blob; the decompressed bytes are exactly the SHA-256 pin in the receipt.) |
| `savage_standard/dialects.py::verify_helm` — the eighth dialect, `helm-benchmark`: re-derives the external claim from supplied public artifact bytes | VERIFIED | Suite `TestHelm` (6 tests): genuine VERIFIED native + envelope; no-artifact VERIFIED-STRUCTURAL; edited recomputed value, edited published value, and swapped artifact all REJECTED. |
| `savage_standard/verify.py` — dialect detection + verdict assembly (VERIFIED / VERIFIED-STRUCTURAL / REJECTED / UNVERIFIABLE) | VERIFIED | Same suite; garbage input returns UNVERIFIABLE, never a pass. Envelope path additionally emits an `envelope-signature` leg when a `signatures` member is present (pass / fail / unverifiable per the registry); unsigned envelopes produce no such leg and keep their exact pre-custody verdicts. |
| `savage_standard/cli.py` — `savage-verify` CLI (verify / wrap / recompute / claims / keygen / sign; `--keys` registry override on verify) | VERIFIED | Smoke-run in the PR body; exit codes 0/1/2 by verdict. `tests/test_signing.py::TestDemoAndCustody::test_cli_keygen_sign_verify` drives keygen→sign→verify end to end. |
| `savage_standard/claims.py` — claims-gate inventory | VERIFIED as an enumeration | Rows cite their sources (site repo main `4efd6486`, marketplace `catalog.json`, Stripe registry, fix-program results). The BEFORE number is definitional — the definition is printed in the module docstring so it can be argued with. |
| `fixtures/` — real artifacts from the fix program (and, for SIA-E1, one real external artifact) | VERIFIED | `fixtures/PROVENANCE.md` names each artifact's origin. |

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
- SIA-E1 (external recompute) BEFORE: the chosen external claim —
  HELM classic v0.4.0, BoolQ, Mistral v0.1 (7B), EM = 0.874 — had **0**
  independent recompute paths through the standard: no SRE-1 receipt
  existed for any external claim and `savage-verify` recognized no
  external dialect; an outsider's only options were trusting HELM's
  published tables or re-implementing HELM's aggregation from scratch.
- SIA-E1 AFTER: the claim is recomputed from HELM's own public
  per-instance statistics (pinned by SHA-256 in the receipt) under
  HELM's own Stat-merge rule, read from HELM's source: **recomputed
  0.874 (sum 874.0 / count 1000.0 over the run's 1,000 unperturbed
  valid instances) vs published 0.874 — MATCH, delta 0.0**; the receipt
  verifies **VERIFIED** through `savage-verify` (native and
  envelope-wrapped) with the artifact supplied, and the external-claim
  recomputability for this claim goes **0 → 1**. Suite 27 → 33 tests.
- Key custody BEFORE: envelopes carrying a verifiable signature =
  **0** — the verifier emitted no signature leg at all, and the defect
  was worse than absence: because the envelope digest is an unkeyed
  hash, an attacker who forged an envelope's claim statement, gate
  verdict, and issuer line and then honestly RE-COMPUTED the digest
  still received **VERIFIED** from the pre-custody verifier (measured
  on the pristine tree; the attack is reproduced in
  `tests/test_signing.py` as a regression test). Hash-binding alone
  cannot stop a re-digesting forger.
- Key custody AFTER: the same forgery against a signed envelope is
  **REJECTED** on the signature leg; a genuine signed envelope
  verifies end to end (signature leg pass) through the universal
  verifier; unknown or revoked keys cap the verdict at
  VERIFIED-STRUCTURAL; unsigned envelopes are byte-for-byte and
  verdict-for-verdict unchanged. Verifiable-signature envelopes go
  **0 → 1** (the committed demo fixture, signed by the destroyed demo
  key — mechanism proof, not an attestation) plus every envelope an
  operator signs after minting a real key. Suite 33 → 50 tests.

## What is NOT true

- **SIA-E1 covers exactly ONE external claim, not external benchmarks
  in general.** The adapter speaks one published format (HELM classic
  per-instance statistics) and has been exercised on one claim (BoolQ /
  Mistral v0.1 (7B) / exact_match / valid split, HELM classic v0.4.0).
  The merge code is metric- and scenario-generic *within that format*,
  but no other HELM scenario, release, or leaderboard — and no other
  benchmark family (lm-eval, SWE-bench, WMT, …) — is covered, and no
  other external claim has a receipt. The claims-gate inventory
  (`claims.py`) is unchanged: it enumerates the estate's OWN claims,
  and this external claim is not one of them (the 1/12 number does not
  move).
- **The SIA-E1 recompute verifies HELM's aggregation, not HELM's
  measurements.** It proves the published 0.874 is the correct merge of
  HELM's published per-instance statistics under HELM's published rule.
  Whether those per-instance statistics faithfully record the model's
  raw outputs is HELM's own attestation — the receipt's publisher field
  says so, and the raw request/response artifacts (scenario_state /
  display_predictions) were not independently re-scored in this build.

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
- **No production envelope is signed yet, and no real estate key
  exists.** The custody mechanism is built and proven, but the shipped
  registry's only entry is the throwaway demo key (private half
  destroyed). Minting the real estate key is the operator's remaining
  act: run `savage-verify keygen --key-id <id> --out <path OUTSIDE any
  repo>` on their own machine and commit ONLY the printed public entry
  to `savage_standard/key_registry.json`. Until that entry lands,
  EVO-9 marketplace receipts and all other envelopes remain hash-bound
  exactly as before — this build removes the "custody is owed" defect,
  it does not backdate signatures onto existing receipts.
- **The signature is classical RSA, NOT post-quantum, and the
  implementation is not constant-time.** RSASSA-PKCS1-v1_5/SHA-256 was
  chosen because it is exactly implementable and provable with stdlib
  integer math (and cross-checks against OpenSSL); it does not advance
  the ML-DSA-87 leg named in CEROS receipts, which remains not-built
  for the same stdlib reason as before. Signing runs locally on the
  operator's machine; the private-exponent timing exposure of a local
  offline tool is accepted and stated, not hidden.
- **There is still no trusted timestamp.** A signature binds
  `recorded_at` (it can no longer be edited after signing) but the
  value remains issuer-reported — the signature proves the issuer
  attested that time, nothing more.
- **Producers do not sign at mint time yet.** Signing is an
  envelope-level step (`savage-verify sign`, or `signing.sign_envelope`)
  applied after wrapping; no producer's minting code was modified in
  this build either. Wiring the estate's issuing paths (the EVO-9
  delivery ledger first) to wrap-and-sign at issuance is the named
  follow-on. A `signatures` member can also be stripped by an attacker
  — the result is an unsigned envelope whose missing signature leg is
  visible in the verifier output; whether a given surface REQUIRES
  signed envelopes is a policy for its operator, not something this
  format can enforce on a bare file.
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
