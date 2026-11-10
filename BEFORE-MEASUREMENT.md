# SIA-E2 — BEFORE measurement (taken from the pre-build tree, 2026-11-10)

Rule v2 discipline: this measurement was taken BEFORE the first line of
savage-standard code was written, from the pre-build trees of each line.

## Dialects in the estate (code-proven inventory, 7)

| # | Dialect | Native schema / form | Native verifier (in-repo only) |
|---|---------|----------------------|-------------------------------|
| 1 | Marketplace delivery-ledger | savage/delivery-ledger/1, savage/delivery-receipt/1 | verifyReceiptPair (TS, in-repo) |
| 2 | sia-v6-core benchmark | sia.benchmark-receipt.v1 | verify_records + scripts/verify_benchmark_receipt.py (in-repo) |
| 3 | Breakthrough evidence | EvidenceRecord digest + checker verdicts | scoring/law-scorer.ts + src/verification/independent-checker.ts (TS, in-repo) |
| 4 | SIA-v6 benchmark | certified_manifest.json + per-record HMAC (MAC not persisted) | benchmark/integrity.py in-process only (in-repo) |
| 5 | CEROS PromotionEngine | PromotionVerdictReceipt, ML-DSA-87 signed core | TriadicPromotionEngine.verifyReceipt (TS, in-repo) |
| 6 | Relay event log | hash-chained JSONL (seq/ts/kind/data/prev/hash) | ChainLog.verify (Python, in-repo server) |
| 7 | Starr bounce | starr.bounce-receipt.v1 | audioQc.ts re-verify (TS, in-repo) |

## BEFORE metric

Receipt dialects verifiable by a SINGLE independent tool (usable by an
outsider, outside the producing repo): **0 of 7 = 0%**.

Every dialect above verifies only through code that lives inside its own
producing repository, in that repository's own runtime. No shared package,
no cross-estate verifier, and no common envelope existed in the pre-build
tree. (Confirmed by reading each producer's source: each verifier imports
or re-implements only its own dialect.)
