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

PROOF-E1 "The Estate Attestation" (this build) adds the one-command
estate attestation: `savage_standard/estate.py` derives a sealed,
re-derivable attestation artifact for a whole org from a single
snapshot, the CLI gains an `estate` subcommand, and
`savage_standard/estate_fetch.py` collects the snapshot live from the
GitHub API for token holders. See the PROOF-E1 lines in the component
table, Metrics, and "What is NOT true".

The claim-gate build (this build) composes the attestation with the
claim-state linter rule set from Savage-AI-style (EVO-29,
`scripts/claim_linter.py` @ `6a7f65e6`) into one CI-runnable gate:
`savage_standard/gate.py` plus the CLI `gate` subcommand fail a repo
tree whose public documents carry unlabeled or contradicted claims,
with a reusable workflow at `.github/workflows/claim-gate.yml`. The
linter's rule set is composed CLEAN-ROOM from its documented
behavior — no code is imported from Savage-AI-style and this package
has no runtime dependency on that repo. See the claim-gate lines in
the component table, Metrics, and "What is NOT true".

## Component state

| Component | State | How to verify |
|---|---|---|
| `savage_standard/canonical.py` — JCS (RFC 8785) canonicalizer with ECMAScript number serialization; Python sorted-compact; Starr canonicalJson; fixed-order JS stringify | VERIFIED against producer-minted artifacts | Test suite recomputes real marketplace entry hashes / receipt digests, the sia-v6-core chain hash, Breakthrough record digests, and the Starr receipt hash from fixture bytes and matches them exactly. |
| `savage_standard/envelope.py` — SRE-1 envelope: wrap, digest, structural checks | VERIFIED | `tests/test_savage_standard.py::TestEnvelope` (wrap→verify VERIFIED; tampered native → REJECTED; tampered envelope field → REJECTED). The digest core now also excludes the `signatures` member (the signature is computed over the digest); envelopes without one digest byte-identically to before, which the fixture suite proves on every run. |
| `savage_standard/rsa.py` — RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017): Miller-Rabin key generation, EMSA-PKCS1-v1_5 encoding, sign/verify — Savage-original, stdlib only | VERIFIED, incl. against the reference implementation | `tests/test_signing.py::TestRsa` (EMSA block asserted byte-exact against the RFC 8017 construction; sign/verify round-trip; garbage rejected). Cross-checked against OpenSSL during development in BOTH directions: OpenSSL verified this code's signature, and this code verified OpenSSL's. Classical scheme — NOT post-quantum, not constant-time (see "What is NOT true"). |
| `savage_standard/signing.py` + `savage_standard/key_registry.json` — estate key custody: public registry (committed), operator-side key generation (private key written mode-0600 to an operator-chosen path outside any repo, never copied by this code), envelope signing, and the verifier's signature legs | VERIFIED as a mechanism; NO real estate key exists yet | `tests/test_signing.py` (17 tests: signed envelope VERIFIED end to end; the pre-custody re-digest forgery REJECTED; tampered signature REJECTED; wrong public key REJECTED; unknown/revoked key caps at VERIFIED-STRUCTURAL; unsigned envelopes unchanged; a signed marketplace-delivery envelope verifies with its pair passed as a side input — the pair itself travels under the signature only via the `marketplace-delivery-pair` dialect, fix #81). The shipped registry holds exactly ONE entry — a throwaway DEMO key (usage `demo`) whose private half was destroyed at build time after signing `fixtures/signed-envelope-demo.json`; its leg passes with a detail stating it attests nothing. |
| `savage_standard/dialects.py` — seven estate adapters: marketplace-delivery, siav6core-benchmark, relay-event-log, breakthrough-evidence, siav6-benchmark-manifest, ceros-promotion, starr-bounce | VERIFIED per the coverage table in the PR body | `python3 -m unittest discover -s tests` → genuine PASS + tamper FAIL per dialect. |
| `savage_standard/dialects.py::verify_marketplace_pair` + `verify.py` detection — the `marketplace-delivery-pair` dialect: a marketplace delivery-ledger receipt PAIR (payment + delivery) is a first-class native of the verifier, detected by its `savage/delivery-receipt-pair/1` marker or by the ledger's unmarked `receiptsFor()` shape | VERIFIED (fix #81, 2026-11-10) | `tests/test_delivery_pair.py` (12 tests): both committed fixture pairs verify with every binding leg passing (the minted pair reaches VERIFIED with its artifact bytes supplied); a signed envelope over a real pair verifies VERIFIED with the signature leg passing; an edited amount, an honestly-re-digested payment, a member swap, and a malformed member are all REJECTED; an unsigned pair envelope adds no signature leg. See Metrics below. |
| `savage_standard/dialects.py::verify_atlas_call` + `verify.py` envelope routing — the `atlas-call` dialect: savage-api-atlas call receipts verify natively. Envelope-embedded only: detection requires issuer dialect `atlas-call` AND subject native_schema `savage/atlas-call/1`; the adapter recomputes the producer's four dialect legs (gate-verdict-vs-native, body-digest-pointer, body-content, result-consistency) | VERIFIED (fix #82, 2026-11-10) | `tests/test_atlas_call.py` (12 tests) against three genuine landed benchmark receipts (`tests/fixtures/atlas-call-envelopes.json`, copied verbatim from savage-api-atlas `benchmarks/needs-benchmark.json` at atlas main `d9c24a21`): success/refused/failed envelopes verify VERIFIED-STRUCTURAL with the dialect legs passing (body-content unverifiable by the producer's design); claim-flip and native-digest-zeroed REJECTED (Knights' 2026-11-10 controls); honest-redigest status/body/http-status tampers fail their dialect legs; a signed atlas envelope verifies with the signature leg passing and its re-digest forgery REJECTED. The pre-convergence producer source travels at `vendor/atlas_call_v1.py`, pinned by `dialects.ATLAS_CALL_SOURCE_SHA256`. See Metrics below. |
| `savage_standard/helm.py` — SIA-E1 recompute minter: HELM per-instance Stat merge + native receipt (`savage/external-benchmark-recompute/1`) | VERIFIED on a real external artifact | `gunzip -dc fixtures/helm-boolq-per-instance-stats.json.gz > /tmp/per_instance_stats.json`, then `savage-verify recompute /tmp/per_instance_stats.json …` reproduces `fixtures/helm-boolq-receipt.json`: 874.0/1000.0 = 0.874. (The fixture is committed gzip-compressed — GitHub's git-blobs API refuses the raw 64.7 MB blob; the decompressed bytes are exactly the SHA-256 pin in the receipt.) |
| `savage_standard/dialects.py::verify_helm` — the eighth dialect, `helm-benchmark`: re-derives the external claim from supplied public artifact bytes | VERIFIED | Suite `TestHelm` (6 tests): genuine VERIFIED native + envelope; no-artifact VERIFIED-STRUCTURAL; edited recomputed value, edited published value, and swapped artifact all REJECTED. |
| `savage_standard/verify.py` — dialect detection + verdict assembly (VERIFIED / VERIFIED-STRUCTURAL / REJECTED / UNVERIFIABLE) | VERIFIED | Same suite; garbage input returns UNVERIFIABLE, never a pass. Envelope path additionally emits an `envelope-signature` leg when a `signatures` member is present (pass / fail / unverifiable per the registry); unsigned envelopes produce no such leg and keep their exact pre-custody verdicts. |
| `savage_standard/estate.py` — PROOF-E1 attestation core: per-repo record derivation from a snapshot (GT citation extraction + currency, latest-per-workflow CI state, claims-inventory cross-reference by case-sensitive substring of claim/basis text), the sealed `savage.estate_attestation.v1` artifact (snapshot embedded verbatim, SHA-256 over the JCS canonical form), and `verify_artifact` (digest recompute + full re-derivation compare, mismatches naming repo + field) | VERIFIED | `tests/test_estate.py` (22 tests): clean CURRENT repo, DRIFTED + FAILING repo (older success superseded by latest failure), MISSING repo, UNPINNED + NONE_RECORDED repo, canonical-branch citation, short-prefix citation, `**Head:**`-over-canonical preference, claims attachment, exact summary counts, digest verification, and re-digested tamper controls (flipped currency verdict, altered summary count, cleared failure list all REJECTED by re-derivation; snapshot tamper breaks the digest). |
| `savage_standard/estate_fetch.py` — PROOF-E1 snapshot fetcher for token holders: stdlib `urllib` against api.github.com (org repos paginated; per repo default-branch head, GROUND_TRUTH.md via contents API with 404 → null, up to 5 latest default-branch workflow runs) | BUILT; network path NOT exercised by the suite | The suite proves only the CLI's token-missing refusal (exit 2 with `$GITHUB_TOKEN` unset) and never calls the network; the live org-wide fetch is the operator's run (Knights, with the estate credential route). |
| `savage_standard/gate.py` — the estate claim gate: scans a materialized repo tree's public documents (root Markdown + `docs/` tree; apparatus `ARTIFACT_INDEX.md` / `GROUND_TRUTH.md` excluded) for claims under the Savage-AI-style linter's rule set (claim patterns, claim-state vocabulary, label forms, qualification forms, exemptions — re-implemented clean-room from that linter's documented behavior; no import, no runtime dependency), extracts each claim's stated state, and refutes it under four documented mechanical contradiction rules (C1 verified vs attestation GT DRIFTED/MISSING; C2 verified vs attestation CI FAILING; C3 verified vs a tree with no root GROUND_TRUTH.md, only when no attestation record is in play; C4 LIVE vs attestation CI FAILING or GT MISSING), plus the GT-budget rule (DRIFTED/MISSING count for the record in play vs `--gt-budget`, default 0). A supplied attestation is verified via `estate.verify_artifact` before any verdict is taken from it; an unverifying artifact or a missing record is a named failure, never a silent pass | VERIFIED by planted controls | `tests/test_gate.py` (17 tests) incl. fixture trees under `tests/fixtures/gate/`: the BAD fixture (one unlabeled throughput claim + one verified-labeled claim under a DRIFTED attestation) FAILs naming both the UNLABELED and the CONTRADICTED failure; the CLEAN fixture (labeled claims, CURRENT/PASSING attestation) PASSes; C2/C3/C4 each pinned by a dedicated control; a re-digested tampered attestation is an ATTESTATION failure and its verdicts are never used; budget 0 fails / budget 1 passes the same DRIFTED record against clean docs. |
| `.github/workflows/claim-gate.yml` — reusable GitHub Actions workflow (`workflow_call`, plus push/PR/dispatch on this repo) running `savage-verify gate` over the checked-out tree and the full suite in a second job | BUILT; NOT yet run in GitHub Actions | The workflow file is new in this landing — this repo carried no `.github/workflows/` at all before it — so no Actions run of it exists yet; its steps mirror the exact local commands proven in the PR body. |
| `savage_standard/doors.py` — DATA-E1 door registry: derives one record per named asset ("door") from a snapshot composed of landed sources (org repos; commercial payment doors), each section carrying a declared source ({repo, path, as_of}) — a section with entries but no declared source raises; gated entries (asset classes not enumerable from landed sources) carried verbatim with locator null and their reason; the sealed `savage.door_registry.v1` artifact (snapshot embedded verbatim, SHA-256 over the JCS canonical form) and `verify_registry` (digest recompute + full re-derivation compare, mismatches naming door + field). A zero-door snapshot is refused; an inactive commercial door registers WITH a named failure; duplicate (kind, name) names a failure on the later record. Cross-verification (this build): a commercial entry may carry per-source observations (register / registry of record / readback, each declared in `sources` with repo/path/as_of — the registry of record's declaration also carries its file SHA-256); the record's identity fields and its verification verdict are DERIVED from the observations (all sources agreeing on a field → VERIFIED with the sources named; any disagreement → DISAGREEMENT, the record follows the latest-as_of source per field, and a named failure records which sources held which value on which field); entries without observations derive exactly as before (verification null) and a pre-cross-verification artifact re-derives byte-identically under this code | VERIFIED incl. a live cross-verified registry | `tests/test_doors.py` (37 tests): build counts/kinds, verify round-trip, inactive-door and duplicate-name named failures, zero-door and unsourced-section refusals, malformed-entry refusals, re-digested tamper controls (flipped locator, erased failure, dropped gated record all REJECTED), stale-digest and wrong-kind rejection, CLI build + check exits; cross-verification: agreeing sources VERIFIED with sources named, active/amount disagreements following the readback with named failures, agreed-inactive VERIFIED with the not-active failure, unsourced-observation and unknown-billing refusals, legacy entries carrying no verification, and re-digested cross tamper controls (flipped observation, erased disagreement, upgraded verdict, flipped canonical field all REJECTED); asset classes: VERIFIED class carrying a named pull-verification failure, count disagreement following the census with spot/pull failures named, spot-failure-only FAILED verdict, asset-only snapshot registering, unsourced-observation / missing-required-source / malformed-entry refusals, and re-digested asset tamper controls (flipped census count, flipped total_bytes, erased failure, upgraded verdict, flipped manifest digest, dropped asset record all REJECTED). First live registry (2026-11-16): 121 doors, digest `8dbc4385…`, `--check` VERIFIED. Cross-verified live registry (2026-11-16): 121 doors, 75/76 commercial VERIFIED, 1 named disagreement, digest `679dc471…`, `--check` VERIFIED — see Metrics. Asset classes (this build): a snapshot may also carry `asset_classes` — the transfer payload's classes, registered with per-source observations (transfer_manifest / pull_verification / host_census, each declared in `sources`; transfer_manifest and host_census must both be declared); the record's measured fields (file_count, total_bytes, spot_checked, spot_matched, verified_ok, verify_failed) and its verdict are DERIVED from the observations (a measured field disagreed by two or more sources → DISAGREEMENT following the latest observation, named failure per field; a census spot-verification shortfall → FAILED with a named failure; otherwise VERIFIED; a pull verification that failed any file adds a named failure independently of the verdict). Transfer-continuation live registry (2026-11-17): 124 doors, the three transfer classes registered (120,505 files, 19,879,595,632 bytes; 2 VERIFIED, 1 DISAGREEMENT), gated classes 2 → 1 (relay seats only), digest `3be64a0c…`, `--check` VERIFIED — see Metrics. |
| `savage_standard/cli.py` — `savage-verify` CLI (verify / wrap / recompute / claims / keygen / sign / estate / gate / doors; `--keys` registry override on verify) | VERIFIED | Smoke-run in the PR body; exit codes 0/1/2 by verdict. `tests/test_signing.py::TestDemoAndCustody::test_cli_keygen_sign_verify` drives keygen→sign→verify end to end. The `estate` subcommand's exits are pinned by `tests/test_estate.py::TestCli`: build 0 (clean) / 1 (attested WITH named failures, printed to stderr) / 2 (usage/input error, incl. empty repos list and unset `$GITHUB_TOKEN`); `--check` 0 iff the artifact verifies, else 1 with mismatches printed. The `gate` subcommand's exits are pinned by `tests/test_gate.py::TestCli`: 1 on the BAD fixture tree, 0 on the CLEAN fixture tree, 2 on a missing tree. The `doors` subcommand's exits are pinned by `tests/test_doors.py::CliTest`: build 0 (clean) with the artifact written, `--check` 0 on the sealed artifact, 1 on a re-digested tampered artifact. |
| `savage_standard/claims.py` — claims-gate inventory | VERIFIED as an enumeration | Rows cite their sources (site repo main `4efd6486`, marketplace `catalog.json`, Stripe registry, fix-program results). The BEFORE number is definitional — the definition is printed in the module docstring so it can be argued with. |
| `fixtures/` — real artifacts from the fix program (and, for SIA-E1, one real external artifact) | VERIFIED | `fixtures/PROVENANCE.md` names each artifact's origin. |
| `pyproject.toml` + `MANIFEST.in` — packaging: setuptools backend, `savage-verify` console script, `key_registry.json` package-data; the sdist grafts the full evidence tree (`fixtures/`, `tests/`, `vendor/`) plus this file | VERIFIED (fix #85, 2026-11-10) | From a clean venv: `pip install .` in a checkout succeeds; `savage-verify fixtures/signed-envelope-demo.json` from an unrelated cwd prints the same verdict + legs as the from-source run (byte-identical output, measured); the suite passes 74/74 against the INSTALLED package and 74/74 from an extracted sdist. BEFORE fix #85 the sdist shipped the test modules without any of their data (extracted-sdist suite: 56 tests ran, 52 FileNotFoundError errors). The wheel remains runtime-only; the package is installable but NOT published to any index, and no consumer imports it yet (see "What is NOT true"). |

## Metrics (Evolution Rule v2)

- DATA-E1 transfer continuation (2026-11-16; BEFORE measured on the
  EVO-42 tree @ `3d281143`, version 0.9.0): transfer-payload classes
  registered in the door registry = **0 of 3** — Forge outputs, the
  trained Murmuration swarm, and Genesis off-repo artifacts sat in
  one gated entry ("rides the pending ~94 GB transfer"), contents
  unregistered, because the payload lived off-host. The transfer
  completed 2026-11-16 (filing 991): the staged tree is on this host
  at `~/workspace/transfer-pull/knights-transfer/` (120,507 files;
  staged total 19,902,130,356 bytes — NOT ~94 GB; the estimate is
  named as an estimate wherever it survives). AFTER (version
  0.10.0): the three classes are REGISTERED as asset classes, each
  carrying per-source observations measured for this build — the
  transfer manifest (as of 2026-11-08; the manifest file's own
  SHA-256 `3c3776e6…` is declared in the snapshot's source
  declaration), the completed pull's full `sha256sum -c`
  verification (as of 2026-11-16T08:46:20Z; output file SHA-256
  `f7982644…` likewise declared), and a first-hand host census run
  for this build (file counts, byte totals, and spot hash
  verification against the manifest: Forge sampled 8 incl. the
  pull's 2 FAILED files, Genesis 6, the swarm's entire 14-file
  class hashed). Measured contents: **Forge outputs** 43,757 files
  / 4,642,847,820 bytes — verdict DISAGREEMENT (manifest counts
  43,744; the +13 are p22-run files written on the box after the
  manifest was cut; spot matched 6 of 8 and the pull failed the
  same 2 files — `p22-run/build_config.py`, changed post-manifest,
  and `p22-run/phase-a/upload.log`, a live log — each carried as a
  named failure); **Genesis off-repo artifacts** 76,734 files /
  1,447,483,138 bytes — VERIFIED (counts agree, pull 76,734/76,734,
  spot 6/6; the tree also carries 168 pytest-tmp symlinks, not
  counted as files); **trained Murmuration swarm (gpt-oss-20b)**
  14 files / 13,789,264,674 bytes — VERIFIED (counts agree after
  the manifest's `murmuration-cortex-2026-11-05/foundation/`
  path-prefix normalization, declared in the record's
  manifest_prefixes; spot 14/14 — the whole class; the pull's
  checker could not open any of the 14 at their manifest paths, a
  path artifact carried as a named failure). New live registry
  (built 2026-11-17T01:14:09Z): **124 doors** (45 repos + 76
  commercial + 3 asset classes; the repo and commercial sections
  reproduce the cross-verified registry's records exactly, and the
  EVO-39/EVO-42 artifacts still verify byte-identically under this
  code — measured), gated classes **2 → 1** (savage-relay seats
  only), summary gains `asset_classes` / `asset_files` (120,505) /
  `asset_bytes` (19,879,595,632) / `asset_verified` (2) /
  `asset_disagreements` (1) / `asset_failed` (0) only when a
  snapshot carries asset classes. Artifact digest
  `3be64a0cbaa4090a1d97b255a90e8b3a5b25e07a8bd1f30f5eb74daeac15fdea`,
  `savage-verify doors --check` VERIFIED. Tamper controls in
  `tests/test_doors.py` (24 → 37 tests): flipped census count,
  flipped total_bytes, erased failure, upgraded verdict, flipped
  manifest digest in the source declarations, dropped asset record
  — each honestly re-digested — all REJECTED by re-derivation
  naming door + field. Suite 137 → 150, zero regressions.
  Discrepancies against the pre-transfer estimates, named for the
  fix program: Forge outputs measure 4,642,847,820 bytes against
  the ~80 GB estimate carried into the transfer commission
  (≈17× smaller); the swarm measures 13,789,264,674 bytes against
  ~13 GB (consistent); Genesis artifacts measure 1,447,483,138
  bytes against ~0.6 GB (≈2.4× larger). The registry registers the
  measured truth in every case.
- DATA-E1 cross-verification (2026-11-15; BEFORE measured on the
  EVO-39 tree @ `4ffaa4b2`, version 0.8.0): commercial doors
  cross-verified against a second independent source inside the
  registry = **0 of 76** — the first live registry transcribed ONE
  source (savage-marketplace's `stripe-links.json`, as of
  2026-11-08), and the registry of record itself, the original
  `DOOR-REGISTRY.json`, sat inside a gated class, unenumerated.
  AFTER (version 0.9.0): the on-host registry of record was located
  and verified first-hand — `~/workspace/transfer-pull/
  knights-transfer/DOOR-REGISTRY.json` (22,770 bytes, SHA-256
  `69e1358630209b39e93207a992f4aa31a5643c9e88ef2105e4eabdebe8ddb1ac`,
  76 entries; the path savage-hunter's GT cites for it,
  `~/workspace/stripe-rewire-2026-11-04/`, does not exist on this
  host) — and every commercial door now carries three per-source
  observations (marketplace register as of 2026-11-08; registry of
  record as of 2026-11-05 — the file carries no internal date, so
  that as_of is declared from savage-hunter's frozen-extract
  provenance and the capability-truth-registry v2 basis, and the
  snapshot's source declaration says so; Knights' Gen-2 Stripe
  readback as of 2026-11-13, account `acct_1UYG8zCG8Je0vWdb`, 76
  links/products/prices, 75 links active). Three-way join measured
  by the operator before building: register vs registry of record
  **76/76 agree** on every identity field each carries (URL, SKU,
  amount, recurring, product name, active; the registry of record
  carries no currency field and does not vote on it); registry of
  record vs readback **75/76 agree** — the single disagreement is
  `SUB-TOOLDIFF-TEAM-79` on `active` (true in both 2026-11-05/08
  observations, false in the 2026-11-13 readback). New live
  registry (built 2026-11-16T04:47:32Z): **121 doors** (the 45-repo
  section reproduces EVO-39's 45 records exactly), **75 commercial
  doors VERIFIED, 1 DISAGREEMENT** — `SUB-TOOLDIFF-TEAM-79`
  registered `active=false` (following the latest first-hand
  observation) with the named cross-verification failure; summary
  gains `commercial_verified` / `commercial_disagreements` only
  when a snapshot cross-verifies, so the EVO-39 artifact still
  verifies byte-identically under this code (measured). Artifact
  digest `679dc471ca45805b462ce3860e1f729960154d161cc9971423be57952e3ec8c1`,
  `savage-verify doors --check` VERIFIED. The `DOOR-REGISTRY.json`
  asset is un-gated by this landing: it is removed from the gated
  entry's enumeration; the rest of that class (Forge outputs,
  trained Murmuration swarm, Genesis off-repo artifacts) stays
  gated, as does the relay-seats class. Tamper controls in
  `tests/test_doors.py` (13 → 24 tests): flipped observation,
  erased disagreement, upgraded verdict, and flipped canonical
  field — each honestly re-digested — all REJECTED by
  re-derivation naming door + field. Suite 126 → 137, zero
  regressions.
- DATA-E1 door registry (2026-11-15; BEFORE measured on the pristine
  tree @ `4c0ac3ad`, version 0.7.0): named assets under a sealed,
  re-derivable registry = **0** — the org's repos were enumerable
  only inside the attestation's snapshot, the payment doors only in
  savage-marketplace's own register files, and no artifact anywhere
  sealed the estate's doors into one verifiable document. AFTER
  (version 0.8.0): **121 doors registered** in the first live
  registry (built 2026-11-16T04:24:54Z from landed sources: the
  shift-3 estate snapshot's 45 repos @ its 2026-11-16T04:05:18Z
  collection + savage-marketplace `stripe-links.json`'s 76
  commercial doors, as of 2026-11-08, all 76 active in their
  source), 2 gated classes named (the pending transfer's payload;
  savage-relay's live seat state), 0 failures; artifact digest
  `8dbc43852204f9cdcaef5fde586aea958aaaf41d3d424ad8480700aac95ae7b0`,
  `savage-verify doors --check` VERIFIED. Tamper controls in
  `tests/test_doors.py` (13 tests): flipped locator, erased failure,
  and dropped gated record — each honestly re-digested — all
  REJECTED by re-derivation naming door + field; a stale digest and
  a wrong kind are rejected; a zero-door snapshot and an unsourced
  section are refused at build. Suite 113 → 126, zero regressions.
- Claim gate (2026-11-15; BEFORE measured on the pristine tree @
  `e78e75e2`, version 0.6.0): claim gates that fail CI on a
  contradicted or unlabeled claim = **0** — verified by reading the
  CLI (subcommands verify / wrap / recompute / claims / keygen /
  sign / estate; `claims` only prints the inventory, `estate` never
  reads prose) and by the tree carrying no `.github/workflows/`
  directory at all. AFTER (version 0.7.0): **1** landed gate,
  `savage-verify gate`, composing the estate attestation's verdicts
  with the Savage-AI-style linter's label rule set. Planted
  controls: the BAD fixture is caught on both planted failures
  (UNLABELED throughput claim, CONTRADICTED verified claim under a
  DRIFTED attestation — two of two), the CLEAN fixture passes, and
  each contradiction rule C1–C4 has a dedicated test. Self-
  application, run at landing time and reported as measured: the
  gate over this repo's own tree first named exactly two UNLABELED
  claims (the BEFORE metric's percent figure in
  `BEFORE-MEASUREMENT.md` and the claims-inventory percent figure
  in `README.md`); both were honestly labeled from states this file
  already establishes (OBSERVED for the source-read BEFORE
  measurement; VERIFIED as an enumeration for the inventory), after
  which this tree PASSes the gate with no attestation supplied.
  With a self-attestation built from this tree's materialized state
  (head `e78e75e2`, this file's text, no CI runs recorded) the gate
  also PASSes: the record reads GT UNPINNED (this file carries no
  head citation — UNPINNED is not a budget or contradiction
  trigger) and CI NONE_RECORDED. Over the Savage-AI-style tree as
  materialized for this build (its `README.md` plus the apparatus
  `GROUND_TRUTH.md`; the rest of that tree was not materialized)
  the gate PASSes: five claims found, zero failures. Suite
  **96 → 113** tests, all passing.
- PROOF-E1 estate attestation (2026-11-15; BEFORE measured on the
  pristine tree @ `c865a145`, version 0.5.0): `savage-verify estate`
  did not exist — the argument fell through to the receipt path and
  died with FileNotFoundError; repositories attested per run **0**,
  and no artifact format could state an org's GT-citation / CI /
  claims posture in one sealed, re-derivable document. AFTER
  (version 0.6.0): one command attests **every repo in the snapshot**
  (per-repo GT currency, CI state, claims rows, named failures) into
  a digest-sealed artifact whose every verdict re-derives from the
  embedded snapshot under `--check`; the proof suite's 5-repo
  fixture attests 5 repos with summary {gt_present 4, gt_current 2,
  ci_passing 3, claims_rows_attached 1, claims_gated 0} and 5 named
  failures, and re-digested tampering (verdict flip, count edit,
  failure-list erasure) is rejected by re-derivation. Suite
  **74 → 96** tests, all passing. **First live org-wide run
  (operator, 2026-11-16T04:05:18Z snapshot): all 45 Savages-studios
  repos attested in one artifact** (digest `bc17fb661014dd91…`;
  `--check` VERIFIED) with summary {repos_attested 45, gt_present
  42, gt_current 0, ci_passing 24, claims_rows_attached 2,
  claims_gated 1} and **72 failures named per repo, none silent**:
  30 GT DRIFTED, 12 GT UNPINNED, 3 GT MISSING, 7 CI failing, 12 CI
  not passing, 8 with no CI state recorded. The gt_current count of
  0 is the measured estate state under the citation rule — every
  estate GT cites a verification head older than its repo's current
  head — not an attestation error; the artifact's job is to name it.
  The snapshot for this run was collected through the estate
  credential route; `estate_fetch.py`'s own network path remains
  unexercised (see "What is NOT true").
- Fix #85 packaging (2026-11-10; BEFORE measured on the pristine tree
  @ `b12cb607`, version 0.4.0): the wheel path already worked — a clean
  venv `pip install .` succeeded, the `savage-verify` console script
  verified both committed fixtures with output byte-identical to the
  from-source run, a keygen→sign→verify round-trip under a throwaway
  key returned VERIFIED with the signature leg passing, and the suite
  passed 74/74 against the installed package. What was broken was the
  SOURCE distribution: the sdist shipped the four test modules but
  none of their data — no `fixtures/` tree, no
  `tests/fixtures/atlas-call-envelopes.json`, no
  `vendor/atlas_call_v1.py`, not even this file — so the published
  source artifact could not reproduce the repo's own verification:
  extracted-sdist suite **"Ran 56 tests … FAILED (errors=52)"**, every
  error a FileNotFoundError for a missing fixture. AFTER (version
  0.5.0): `MANIFEST.in` grafts the evidence tree into the sdist;
  extracted-sdist suite **74/74 OK**; clean-venv install of the fixed
  tree reproduces the byte-identical fixture verdicts and the 74/74
  against-installed suite; from-source suite unchanged at 74/74. No
  module, digest, or verdict changed — packaging metadata, this file,
  and the README only. Build backend unchanged (setuptools); runtime
  dependencies still `[]`.
- Fix #82 Atlas envelope convergence (2026-11-10; BEFORE measured on
  the pristine trees — savage-standard @ `f551ec40`, savage-api-atlas @
  `d9c24a21`): atlas-call dialect legs executed by this verifier on a
  genuine Atlas receipt **0 → 4** (gate-verdict-vs-native,
  body-digest-pointer, body-content, result-consistency; before, the
  envelope shell verified with dialect None and a single unverifiable
  dialect-detection leg); the 30 landed benchmark receipts keep their
  VERIFIED-STRUCTURAL verdicts, now WITH the dialect legs passing;
  Atlas envelopes signable under the custody stack **no → yes**
  (mechanism proven under a throwaway key; the producer's own digest
  core could not exclude a signatures member, so its verifier could
  never have accepted one); suite **62 → 74** tests, all passing. The
  producer side converged in the same fix: Atlas vendors this package's
  `canonical.py` + `envelope.py` byte-identically under
  `vendor/savage_standard/` (SHA-256-pinned in its suite) and its local
  JCS/digest/wrap implementations are deleted — one envelope
  implementation. What convergence does NOT yet mean: savage-standard
  is not published as an installable package anywhere, so the vendored
  copy is pinned-and-proven rather than imported (packaging state
  since updated by fix #85 — see its Metrics entry above; consumers
  still do not import it); and no production
  Atlas envelope is signed (no real estate key exists — see "What is
  NOT true").
- Fix #81 delivery-pair bridge (2026-11-10; BEFORE measured on the
  pre-bridge tree against a real pair minted by the ledger's own code
  from savage-marketplace main `bfaa3a18`; repro
  `python3 -m pytest tests/ -q` → `tests/test_delivery_pair.py`):
  marketplace receipt pairs natively understood **0 → 1 dialect**
  (`marketplace-delivery-pair`); pair legs executed on a real pair
  **0 → 10**; signed envelopes whose signature covers the
  payment↔delivery binding **0 → mechanism proven** (VERIFIED with the
  signature leg PASS under a throwaway key; the re-digest claim forgery
  REJECTED by the signature leg); suite **50 → 62** tests, all passing.
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

- **The claim gate does not prove a labeled claim true.** It checks
  that claims carry claim-state labels and that two stated states
  (verified, LIVE) are not refuted by the attestation record or by
  a missing root GROUND_TRUTH.md under rules C1–C4. A claim labeled
  UNPROVEN, REPORTED or OBSERVED is never contradicted by the gate
  however wrong the underlying figure is; re-measurement stays with
  each line's own gates and receipts.
- **The gate's linter rule set is a clean-room reimplementation, not
  the Savage-AI-style linter itself.** Label forms, claim patterns
  and exemptions were re-derived from that linter's documented
  behavior and are pinned by this package's own tests; the two
  implementations are not byte-identical code, Savage-AI-style's
  own linter tests do not run in this suite, and a future change to
  the linter's rules does not propagate here automatically — the
  rule sets converge by deliberate re-composition, the same
  discipline as the vendored dialect adapters.
- **The claim-gate workflow has never run in GitHub Actions.**
  `.github/workflows/claim-gate.yml` is new in this landing and
  this repo had no workflows before it; the gate is proven locally
  (suite + CLI runs in the PR body), and the workflow's first real
  Actions run happens only after this landing merges.
- **Self-application coverage is stated exactly, not estate-wide.**
  The claim gate has been run over this repo's full tree and over
  the Savage-AI-style subset materialized for this build (root
  `README.md` + apparatus `GROUND_TRUTH.md` only — that repo's
  `docs/` tree and remaining root documents were not materialized
  and were not gated). No other estate repo's documents have been
  gated yet; adoption is one `--attestation` run per repo, or the
  reusable workflow, per repo.
- **The door registry does not cover the whole door universe
  (DATA-E1).** It registers only doors enumerable from landed
  sources: org repos, the marketplace register's commercial
  doors, and — since the transfer landed (2026-11-16) — the
  transfer payload's three classes (Forge outputs, the trained
  Murmuration swarm, Genesis off-repo artifacts), registered as
  asset classes with measured contents and their disagreements
  and verification failures named in-record (see Metrics). Live
  runtime state (savage-relay's seats) is still carried as a
  GATED entry — named with its reason, locator null — not as a
  registered door; it enters the registry only when a landed
  source (a seats export from the bus) enumerates it. The
  original DOOR-REGISTRY.json is no longer in that gated class:
  its on-host copy was located, hashed, and cross-verified in
  this build (see Metrics), so it is un-gated — as a SOURCE of
  the commercial doors, not as a registered door itself.
- **The transfer payload does not measure ~94 GB (DATA-E1).**
  The gated entry's "~94 GB" was the transfer commission's
  pre-transfer estimate. Measured on host after the completed
  pull: the staged tree totals 19,902,130,356 bytes, of which
  the three registered classes are 19,879,595,632 bytes (Forge
  outputs 4,642,847,820 — against a ~80 GB estimate for that
  class; the trained swarm 13,789,264,674; Genesis artifacts
  1,447,483,138). Nothing in the registry carries the estimate
  as a measurement; where the estimate survives in older text it
  is an estimate, and the class records carry the measured
  counts and bytes with their as-of dates.
- **The door registry carries its sources' facts at their as-of
  dates; it re-observes nothing live (DATA-E1).** The
  cross-verified live registry's commercial doors rest on three
  snapshots at their as-of dates (register 2026-11-08, registry
  of record 2026-11-05, Gen-2 readback 2026-11-13) — it
  cross-verifies those snapshots against each other and names
  the one disagreement they contain (`SUB-TOOLDIFF-TEAM-79`,
  active); it does NOT re-read Stripe or any live system, so a
  door whose live Stripe state changed after 2026-11-13 is
  registered as the readback saw it. The registry of record's
  2026-11-05 as_of is itself declared evidence, not a date the
  file carries: DOOR-REGISTRY.json has no internal date field,
  and the snapshot's source declaration names the provenance
  the date rests on. The asset classes likewise rest on their
  observations' as-of dates (transfer manifest 2026-11-08, pull
  verification 2026-11-16, host census at the registry's
  taken_at): the registry does not re-census the payload, so
  files added to or changed inside the staged tree after the
  census are registered as the census measured them — the Forge
  class's DISAGREEMENT verdict and its named post-manifest files
  are exactly that mechanism working. No fetcher ships;
  snapshots are composed by the operator from landed sources.
- **The estate attestation reports GT citation drift; it does not
  re-verify GT contents (PROOF-E1).** A repo whose GROUND_TRUTH.md
  cites its current head is CURRENT even if every sentence in the
  file is stale or wrong — the attestation checks the citation, the
  presence, and the `Last verified` date's age, never the truth of
  the body. Content verification stays with each repo's own
  code-proven GT process.
- **CI state in an attestation is the latest recorded runs, not a
  re-run of any suite (PROOF-E1).** The snapshot carries what the
  forge last recorded per workflow; the attestation derives state
  from those records (latest per workflow) and runs nothing. A green
  attestation line means "the latest recorded run passed", never
  "the suite passes now".
- **Claims receipt status is carried from the claims inventory, not
  re-adjudicated (PROOF-E1).** Attachment is a mechanical rule (the
  repo's name as a case-sensitive substring of a row's claim or basis
  text) and the attached `gated` flag is the inventory's own verdict,
  copied. Rows whose text does not literally name a repo attach to
  nothing — in the current inventory only `sia-v6-core` is named
  verbatim (in `sia-v6-core-benchmarks`); prose names ("Genesis",
  "Starr", "Relay") do not match the lowercase repo names, so those
  rows attach nowhere until the inventory names repos literally.
- **No live org-wide attestation has been run by this build
  (PROOF-E1).** `estate_fetch.py` is shipped and its refusal paths
  are tested, but the suite never calls the network and no real
  Savages-studios snapshot has been fetched or attested from this
  tree; that run needs the estate credential route and is the
  operator's act. This repo's own GROUND_TRUTH.md, for the record,
  carries no head citation — attested live, this repo would read
  UNPINNED until a citation convention line is added to this file.
- **The package is installable but not published, and consumers still
  do not import it (fix #85).** As of 0.5.0 the package installs
  cleanly from a checkout or sdist of this repo and its sdist can
  reproduce the full suite — but it is on no package index (PyPI or
  otherwise), savage-api-atlas still vendors its pinned byte-identical
  copies of `canonical.py`/`envelope.py` rather than importing, and
  the marketplace's issuance path still resolves the verifier by path
  rather than importing the installed package. Import-based
  convergence in consumers is a separate step, gated on each
  consumer's CI being able to fetch the package.
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
- **Atlas-call chain sequence is not checked here (fix #82).** An
  Atlas envelope's `chain.prev_digest` is bound by the recomputed
  envelope digest, so a rewritten pointer fails `envelope-digest`; but
  whether the pointer equals the PREVIOUS envelope's digest is a
  sequence claim this single-envelope verifier is not shown the inputs
  for — the producer's chain-aware paths (`verify_call_log`, the
  benchmark chain test) own that check. A bare atlas-call native (no
  envelope) is NOT detected as a dialect: the native is not
  self-describing, and convergence is envelope-level by design.
- **Producers do not sign at mint time yet — with one path now built,
  at this layer.** Signing is an envelope-level step (`savage-verify
  sign`, or `signing.sign_envelope`) applied after wrapping. As of fix
  #81 (2026-11-10) the EVO-9 delivery ledger's pair is the first
  issuing path the format fully covers: the pair is a native dialect
  (`marketplace-delivery-pair`), so a fulfillment-side issuance path
  exists end to end — mint the pair, form the pair native
  (`dialects.marketplace_pair_native`), wrap, sign — and is proven with
  throwaway keys in `tests/test_delivery_pair.py`. What does NOT yet
  exist: (a) any PRODUCTION signing key — the registry still holds only
  the destroyed demo key, so no production envelope can be signed until
  the operator mints the real estate key (the named operator act
  above); (b) producer-side wiring — savage-marketplace's deployed
  fulfillment code does not itself call wrap+sign at issuance; the
  marketplace side of fix #81 updates its boundary text only, and the
  ledger's bare receipts remain hash-bound exactly as before (the
  signature lives on the envelope, never on the receipt). A
  `signatures` member can also be stripped by an attacker — the result
  is an unsigned envelope whose missing signature leg is visible in the
  verifier output; whether a given surface REQUIRES signed envelopes
  is a policy for its operator, not something this format can enforce
  on a bare file.
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
