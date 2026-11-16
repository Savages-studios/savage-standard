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
   with the honest BEFORE number (claim state: VERIFIED as an
   enumeration — the inventory itself is the verified record, see
   `GROUND_TRUTH.md`): **1 of 12 claim groups (8.3%) are
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
6. **PROOF-E1 — the estate attestation** (`savage_standard/estate.py`,
   CLI subcommand `estate`) — the estate attested in ONE command.
   From a single snapshot (org, time, and per repo: default-branch
   head, GROUND_TRUTH.md text, latest workflow runs) it derives, per
   repo: the GT citation state (MISSING / UNPINNED / CURRENT /
   DRIFTED against the head, with the `Last verified` date aged
   against the snapshot time), the latest-per-workflow CI state
   (PASSING / FAILING / IN_PROGRESS / NONE_RECORDED — no state is
   ever a silent pass), and the claims-inventory rows whose claim or
   basis text names the repo. The artifact
   (`savage.estate_attestation.v1`) embeds the snapshot verbatim and
   is sealed with a SHA-256 digest over its canonical JSON;
   `savage-verify estate --check` recomputes the digest AND
   re-derives every record from the embedded snapshot, so a tampered
   verdict or count is caught even under an honestly recomputed
   digest. Before this build the CLI had no estate subcommand:
   repositories attested per run = **0**. Operators with a GitHub
   token can collect the snapshot live
   (`savage_standard/estate_fetch.py`, `--org ORG --fetch`, token
   from `$GITHUB_TOKEN`). What the attestation does NOT do: it
   reports GT *citation* drift, it does not re-verify GT contents;
   CI state is the latest *recorded* runs, not a re-run of any
   suite; claims receipt status is carried from the claims
   inventory, not re-adjudicated.
7. **The estate claim gate** (`savage_standard/gate.py`, CLI
   subcommand `gate`) — the two machines above composed into one
   CI-runnable gate. `savage-verify gate REPO_TREE` scans a
   materialized repo's public documents (root Markdown plus the
   `docs/` tree, the documented scope rule) and exits nonzero naming
   every failure: UNLABELED claims (numeric performance figures and
   capability claims carrying none of the claim-state labels the
   Savage-AI-style claim linter requires — its rule set composed
   here clean-room from its documented behavior, with no runtime
   dependency on that repo), CONTRADICTED claims (a stated verified
   or LIVE state refuted by the attestation record under the
   gate's four documented mechanical rules, or a verified label in
   a tree with no GROUND_TRUTH.md at its root), and a GT currency
   of DRIFTED or MISSING beyond `--gt-budget` (default zero) when
   a sealed attestation is supplied with `--attestation` (the
   artifact is verified — digest plus full re-derivation — before
   any verdict is taken from it). Before this build, claim gates
   that fail CI on a contradicted or unlabeled claim numbered
   zero: the inventory only printed, the attestation never read
   prose, and the linter lived in another repo wired to no CI
   here. A reusable workflow ships at
   `.github/workflows/claim-gate.yml`. What the gate does NOT do:
   it checks labels and their agreement with the evidence above;
   it does not re-measure any figure or re-run any suite.
8. **DATA-E1 — the door registry** (`savage_standard/doors.py`, CLI
   subcommand `doors`) — the estate's named assets under one sealed,
   re-derivable registry. From a snapshot composed of landed sources
   (each section declaring its source — repo, path, as-of; there are
   no unsourced doors) it derives one record per door: org
   repositories, commercial payment doors, and gated entries for
   asset classes that cannot be enumerated from landed sources
   today (the pending transfer's payload; live runtime state),
   carried labeled with their reason — present, never fabricated
   into doors. The artifact (`savage.door_registry.v1`) embeds the
   snapshot verbatim and is sealed with the same JCS SHA-256 digest
   as the attestation; `savage-verify doors --check` recomputes the
   digest AND re-derives every record, so a tampered locator or an
   erased failure is caught even under an honestly recomputed
   digest. A snapshot registering zero doors is refused, and a
   commercial door its source marks inactive is registered WITH a
   named failure. Before this build, named assets under a sealed,
   re-derivable registry numbered **0**; the first live registry
   (2026-11-16) registers **121 doors** (45 repos + 76 commercial,
   all 76 active in their source) with 2 gated classes named.
   What the registry does NOT do: it carries its sources' facts at
   their as-of dates — it does not re-observe Stripe, GitHub, or
   any live system; no fetcher ships.

## Why a new tiny repo

The verifier must be neutral ground: housing it inside
savage-marketplace would make the marketplace's own receipts
self-verified, defeating the outsider-trust purpose. Precedent:
savage-relay and savage-api-atlas were created the same way for
cross-estate roles. Python 3 standard library only — zero third-party
dependencies — matching the sia-v6-core / Relay house style.

## Install

The package installs from a checkout of this repo (Python ≥ 3.10,
standard library only — the installed distribution declares zero
third-party dependencies):

```sh
pip install .            # or: pip install /path/to/savage-standard
savage-verify RECEIPT.json [--pair PAIR.json] [--artifacts DIR] [--file ARTIFACT]
```

That puts the `savage-verify` console script on PATH and the
`savage_standard` package (including its shipped `key_registry.json`)
in site-packages. The source distribution (sdist) additionally carries
the full evidence tree — `fixtures/`, `tests/`, `vendor/` — so the
suite below reproduces from an extracted sdist alone; the wheel is
runtime-only and never installs tests or fixtures. The package is not
published to PyPI or any other index, and no estate consumer imports
it yet (see GROUND_TRUTH.md).

For development, `pip install -e .` works the same way against the
live tree. Without installing, every command below also runs from a
checkout via `python3 -m savage_standard.cli`.

## Use

```sh
python3 -m savage_standard.cli RECEIPT.json [--pair PAIR.json] [--artifacts DIR] [--file ARTIFACT]
python3 -m savage_standard.cli wrap NATIVE.json --claim-id ... (see --help)
python3 -m savage_standard.cli claims
python3 -m savage_standard.cli recompute PER_INSTANCE_STATS.json --metric exact_match --split valid ... (see --help)  # mint an external-benchmark recompute receipt
python3 -m savage_standard.cli keygen --key-id ID --out ~/outside-any-repo/estate.key.json   # operator only: prints the PUBLIC registry entry; the private key never enters a repo
python3 -m savage_standard.cli sign ENVELOPE.json --key-file ~/outside-any-repo/estate.key.json -o SIGNED.json
python3 -m savage_standard.cli estate --snapshot SNAPSHOT.json -o ATTESTATION.json   # PROOF-E1: exit 0 = no failures, 1 = attested WITH named failures, 2 = usage/input error
python3 -m savage_standard.cli estate --check ATTESTATION.json                       # verify a sealed attestation (digest + full re-derivation)
python3 -m savage_standard.cli estate --org Savages-studios --fetch -o ATTESTATION.json   # live snapshot via the GitHub API ($GITHUB_TOKEN)
python3 -m savage_standard.cli gate REPO_TREE [--attestation ATTESTATION.json] [--repo NAME] [--gt-budget N]   # the estate claim gate: exit 0 = PASS, 1 = FAIL with every failure named, 2 = usage/input error
python3 -m unittest discover -s tests   # 113 tests: genuine + tamper per dialect, incl. the HELM recompute dialect, envelope signatures, the signed delivery-pair bridge, the atlas-call dialect, the estate attestation, and the claim gate
```

Exit codes: 0 = VERIFIED / VERIFIED-STRUCTURAL, 1 = REJECTED,
2 = UNVERIFIABLE. A tampered receipt never exits 0.
