# Fixture provenance — every artifact below is real, with its source named

| Fixture | Source |
|---|---|
| `payment.json`, `delivery.json` | A genuine payment/delivery receipt pair issued by the marketplace `@savage/delivery-ledger` package during the EVO-9 delivery-proof measurement run (order `measure-01-tooldiff`, SKU `SUB-TOOLDIFF-STARTER-29`). The pair passes the package's own `verifyReceiptPair`. NOTE: an earlier-harvested pair from a `delivery-verify-*` scratch dir FAILS the producer's own verifier (its delivery entry hash does not recompute) — it was a verify-CLI scratch artifact, not an issued pair, and is deliberately not used. |
| `benchmark-receipts.jsonl` | A real `sia.benchmark-receipt.v1` chain record emitted by sia-v6-core's benchmark harness (EVO-5 scratch run, 2026-11-09). Its acceptance is FAIL — the estate's benchmark gate honestly failing, chain intact. |
| `events.jsonl` | The live Relay bus event log from the EVO-8 run home (19 events: BUS_BOOT, seat registrations, message carries), hash-chained per `relay/server.py`. |
| `certified_manifest.json` + `sia-v6-manifest/` | The SIA-v6 fix-#51 certified manifest (run `035c76ec-696e-44a9-9174-0a1f953ea2ce`, CERTIFIED WITH DEGRADATION) fetched from the repo at main `ee776f7b`, with the six manifest-listed artifact files; every listed sha256 recomputes against the fetched bytes. |
| `breakthrough-book.json` + `breakthrough-artifacts/genuine.ts` | An EvidenceBook sealed by Breakthrough's own `artifact-measurer` + `sealEvidence` (fix #52 code) measuring a real artifact file: candidate GOOD-1, 9 bound laws (C4, C8, C9, G6, S9, C2, M1, M2, E2), all measured pass. `breakthrough-artifact.ts` is a byte-identical copy of the measured file. |
| `ceros-receipt.json` | A PromotionVerdictReceipt minted by CEROS's own `TriadicPromotionEngine.promote()` on the current-main tree (tarball of main after the 2026-11-09 re-land), verdict REJECT (the gate refusing thin evidence — its designed behavior), confirmed genuine by the producer's own `verifyReceipt` (ML-DSA-87) at mint time. |
| `starr-receipt.json` + `bounce_sie2.wav` | A bounce receipt minted by Starr's own `buildBounceReceipt` (EVO-7 code) over a real 1-second WAV produced by the repo's WAV encoder. |
| `*-swapped/` dirs, `bounce_swapped.wav` | Tamper controls: byte-altered counterparts used by the test suite; every one must verify REJECTED. |
