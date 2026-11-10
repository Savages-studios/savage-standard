"""The claims-gate inventory — SIA-E2's second metric baseline.

Enumerated 2026-11-10 from the savageaistudios-site repo (main 4efd6486:
45 product pages + top-level pages), savage-marketplace catalog.json
(11 products with portfolio scores), the Stripe gen-2 registry (76
payment links), and the fix-program's own published results.

Definition used (stated so the number can be argued with): a public
claim is GATED if an outsider can recompute its truth from a receipt
issued by a gate — not merely if machinery exists that could gate it.
Machinery without an issued, reachable receipt does not count.
"""

INVENTORY = [
    # id, class, claim, gated, basis
    {"id": "site-products-45", "class": "offer",
     "claim": "45 product pages on savageaistudios.com (audits, APIs, certificates, monitors, tools)",
     "gated": False,
     "basis": "No sale has occurred (estate revenue $0), so no delivery-ledger receipt exists for any offer; page copy is ungated."},
    {"id": "site-receipt-language-3", "class": "offer-proof-language",
     "claim": "3 pages promise receipt machinery in copy: agent-protocol-settlement and fusion-pre-shot-certification ('signed receipts'), durak-sca-engine ('proof hash per turn')",
     "gated": False,
     "basis": "The promised receipts are product features, not issued receipts; no instance is published or recomputable today."},
    {"id": "marketplace-scores-11", "class": "score",
     "claim": "11 marketplace portfolio scores in catalog.json (weighted 10-criterion model, e.g. ToolDiff 8.11)",
     "gated": False,
     "basis": "Scores are computed by a workspace script (final_portfolio_score.py); no sealed evidence or receipt is published with them."},
    {"id": "stripe-registry-76", "class": "offer",
     "claim": "76 Stripe payment links / products / prices on gen-2 acct_1UYG8zCG8Je0vWdb, all API-active",
     "gated": False,
     "basis": "Registry state is API-verified by Knights, but no claim carries a customer-recomputable receipt."},
    {"id": "sia-v6-benchmark", "class": "certification",
     "claim": "SIA-v6 benchmark: CERTIFIED WITH DEGRADATION, 91.06% certified, mean 97.47 over 1,000,000 observations (fix #51)",
     "gated": True,
     "basis": "certified_manifest.json (run 035c76ec-696e-44a9-9174-0a1f953ea2ce) hashes all six run artifacts; artifact hashes and the certification arithmetic recompute exactly (proven by this package). Caveat: per-record HMACs are not persisted, so record-level integrity is not outsider-recomputable. Not currently published on the site."},
    {"id": "genesis-quality-gates", "class": "score",
     "claim": "Genesis learned-backend quality: PSNR 24.898 / SSIM 0.8624 vs gates >=30 / >=0.90 — FAILED-and-retained, published honestly as failing",
     "gated": False,
     "basis": "Measured by the training harness and reported in PRs/filings; no receipt bundle an outsider can recompute accompanies the claim."},
    {"id": "breakthrough-promotions", "class": "promotion",
     "claim": "Breakthrough discovery promotions (fix #52: 2 promoted, checker-confirmed; sabotage control quarantined)",
     "gated": False,
     "basis": "The sealed EvidenceBook + independent checker gate exists and ran, but its outputs live in crew workspaces/test runs — no receipt is issued in a form an outsider can fetch and recompute. (This package verifies the dialect; the line has not yet issued public receipts.)"},
    {"id": "ceros-promotions", "class": "promotion",
     "claim": "CEROS PromotionEngine verdicts (ML-DSA-87 signed PromotionVerdictReceipts)",
     "gated": False,
     "basis": "The gate exists in code; no PromotionVerdictReceipt instance was found issued in-tree, and the R-1 caller-asserted build attestation remains open debt."},
    {"id": "sia-v6-core-benchmarks", "class": "score",
     "claim": "sia-v6-core benchmark results (hash-chained receipts, EVO-5)",
     "gated": False,
     "basis": "Receipts are produced per run (the fixture chain in this repo verifies), but results are not published as public claims with their receipt bundles attached."},
    {"id": "starr-bounces", "class": "certification",
     "claim": "Starr export QC (EVO-7: every bounce measured across 5 DSP gates with a hash-sealed receipt)",
     "gated": False,
     "basis": "Receipts are minted per bounce in-product; no bounced track + receipt pair is published for outsider recomputation yet."},
    {"id": "relay-carries", "class": "certification",
     "claim": "Relay byte-exact carries (EVO-8: 48/48 legs byte-exact, hash-compared)",
     "gated": False,
     "basis": "The hash-chained event log verifies (this package proves it on the live run log), but the claim is published in filings, not as a receipt bundle."},
    {"id": "site-authority-copy", "class": "assertion",
     "claim": "Site authority copy ('the scope of the work is the credential', 'verified computation', 'evidence-led audits')",
     "gated": False,
     "basis": "Narrative claims; no gate exists for prose and none is claimed here."},
]

TOTAL = len(INVENTORY)
GATED = sum(1 for row in INVENTORY if row["gated"])


def summary_line() -> str:
    pct = 100.0 * GATED / TOTAL if TOTAL else 0.0
    return (f"BEFORE (2026-11-10): {GATED} of {TOTAL} enumerated public-claim "
            f"groups are gate-issued with outsider-recomputable receipts "
            f"= {pct:.1f}%. Target per register SIA-E2: 100%.")


if __name__ == "__main__":
    for row in INVENTORY:
        print(f"{row['id']:<28} gated={row['gated']!s:<5} {row['claim']}")
    print(summary_line())
