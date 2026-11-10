"""SIA-E1 — the recomputable benchmark, external dialect #1: HELM.

Every other dialect in this repo verifies a receipt minted by an estate
producer. This one verifies a receipt about a system Savage does NOT
own: a published benchmark result from Stanford CRFM's HELM classic
v0.4.0 release, recomputed from the per-instance statistics HELM itself
publishes in its public bucket (no account, no payment).

The native receipt (schema ``savage/external-benchmark-recompute/1``)
is minted by THIS repo's recompute tool — the issuer is savage-standard
acting as an independent recompute agent; the claim's publisher is
HELM/CRFM, named in the receipt's ``claim`` block with the exact public
sources of the published value. The receipt pins the public input file
by URL + SHA-256 + byte count, restates the aggregation rule, and
records the recomputed value next to the published one.

The aggregation rule is HELM's own, read from HELM's source
(``src/helm/benchmark/metrics/statistic.py``): each per-instance Stat
carries ``count``/``sum``; merging is ``sum += other.sum``,
``count += other.count``, and the merged mean is ``sum / count``.
``stats.json`` in each run folder is the run-level merge HELM computed
the same way, and the release's group tables (the leaderboard) carry
that value per model. So the recompute is: parse the public
``per_instance_stats.json``, select the stat entries for the claimed
metric name on the claimed split with NO perturbation key, merge them,
and compare against the published value.

The verifier (``dialects.verify_helm``) re-derives everything from the
supplied artifact bytes: it never trusts the receipt's numbers.
"""
from __future__ import annotations

import hashlib
import json

SCHEMA = "savage/external-benchmark-recompute/1"
DIALECT = "helm-benchmark"

RULE = (
    "HELM Stat merge (statistic.py): for every per_instance_stats entry "
    "that is itself unperturbed (no top-level 'perturbation' key — "
    "perturbed variants feed the separate Robustness/Fairness columns), "
    "take the stat whose name.name == metric, name.split == split, and "
    "whose name carries no 'perturbation' key; the recomputed value is "
    "sum(stat.sum) / sum(stat.count) over those entries."
)


def parse_per_instance_stats(data: bytes) -> list:
    """Parse a HELM per_instance_stats.json payload (list of entries)."""
    obj = json.loads(data.decode("utf-8"))
    if not isinstance(obj, list):
        raise ValueError("per_instance_stats payload is not a JSON list")
    return obj


def merge_metric(entries: list, metric: str, split: str) -> dict:
    """Merge one metric over per-instance entries, HELM's way.

    Returns {entries_in_file, instances_with_metric, sum, count, value}.
    ``value`` is None when no entry carries the metric on the split.
    """
    total_sum = 0.0
    total_count = 0.0
    matched = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if "perturbation" in entry:
            continue  # perturbed variant: feeds Robustness/Fairness, not the headline
        for stat in entry.get("stats") or []:
            if not isinstance(stat, dict):
                continue
            name = stat.get("name") or {}
            if name.get("name") != metric or name.get("split") != split:
                continue
            if "perturbation" in name:
                continue
            total_sum += float(stat.get("sum") or 0.0)
            total_count += float(stat.get("count") or 0.0)
            matched += 1
    return {
        "entries_in_file": len(entries),
        "instances_with_metric": matched,
        "sum": total_sum,
        "count": total_count,
        "value": (total_sum / total_count) if total_count else None,
    }


def mint_receipt(per_instance_bytes: bytes, *, benchmark: str, release: str,
                 scenario: str, run: str, model: str, model_display: str,
                 metric: str, metric_label: str, split: str,
                 published_value: float, published_sources: list,
                 source_url: str, source_file: str,
                 recorded_at: str) -> dict:
    """Recompute a published HELM claim from public per-instance bytes
    and mint the native recompute receipt. Raises ValueError when the
    metric is absent from the supplied bytes (nothing to recompute)."""
    entries = parse_per_instance_stats(per_instance_bytes)
    merged = merge_metric(entries, metric, split)
    if merged["value"] is None or merged["instances_with_metric"] == 0:
        raise ValueError(
            f"metric {metric!r} on split {split!r} not present in the "
            "supplied per-instance stats; refusing to mint")
    delta = merged["value"] - float(published_value)
    tolerance = 1e-9
    return {
        "schema": SCHEMA,
        "dialect": DIALECT,
        "claim": {
            "benchmark": benchmark,
            "release": release,
            "scenario": scenario,
            "run": run,
            "model": model,
            "model_display": model_display,
            "metric": metric,
            "metric_label": metric_label,
            "split": split,
            "publisher": "Stanford CRFM — HELM (external; not a Savage system)",
        },
        "published": {
            "value": float(published_value),
            "sources": list(published_sources),
        },
        "inputs": {
            "file": source_file,
            "url": source_url,
            "sha256": hashlib.sha256(per_instance_bytes).hexdigest(),
            "bytes": len(per_instance_bytes),
            "entries": merged["entries_in_file"],
        },
        "recomputation": {
            "rule": RULE,
            "instances_with_metric": merged["instances_with_metric"],
            "sum": merged["sum"],
            "count": merged["count"],
            "value": merged["value"],
            "delta_vs_published": delta,
            "tolerance": tolerance,
            "comparison": "match" if abs(delta) <= tolerance else "delta",
        },
        "recorded_at": recorded_at,
        "recorded_at_trust": "producer-reported; NOT a trusted timestamp",
    }
