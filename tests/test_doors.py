"""DATA-E1 proof suite: the door registry derives every record from
landed sources declared in the snapshot, seals it with a digest, and
catches tampering by re-derivation — including tampering that honestly
re-computes the digest. Fixture snapshots are hand-built; no network
is touched. Stdlib unittest only."""
import copy
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from savage_standard import cli, doors  # noqa: E402

TAKEN_AT = "2026-11-16T00:00:00Z"
HEAD_A = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
HEAD_B = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"

SOURCES = {
    "repos": {"repo": "Savages-studios", "path": "estate snapshot",
              "as_of": "2026-11-16"},
    "commercial_doors": {"repo": "Savages-studios/savage-marketplace",
                         "path": "stripe-links.json",
                         "as_of": "2026-11-08"},
}


def snapshot():
    return {
        "org": "Savages-studios",
        "taken_at": TAKEN_AT,
        "sources": copy.deepcopy(SOURCES),
        "repos": [{"name": "alpha", "head": HEAD_A},
                  {"name": "beta", "head": HEAD_B}],
        "commercial_doors": [
            {"sku": "ALPHA-100", "product_name": "Alpha",
             "url": "https://buy.stripe.com/alpha", "amount_minor": 10000,
             "currency": "usd", "recurring": None, "active": True},
            {"sku": "BETA-200", "product_name": "Beta",
             "url": "https://buy.stripe.com/beta", "amount_minor": 20000,
             "currency": "usd", "recurring": "month", "active": True},
        ],
        "gated": [{"name": "transfer payload assets",
                   "reason": "rides the pending transfer"}],
    }


def redigest(artifact):
    artifact["digest"] = doors.artifact_digest(artifact)
    return artifact


class BuildTest(unittest.TestCase):
    def test_build_counts_and_kinds(self):
        art = doors.build_registry(snapshot())
        self.assertEqual(art["kind"], "savage.door_registry.v1")
        self.assertEqual(art["summary"], {
            "doors_registered": 4, "repos": 2, "commercial_doors": 2,
            "commercial_active": 2, "gated": 1})
        self.assertEqual(art["failures"], [])
        kinds = [r["kind"] for r in art["records"]]
        self.assertEqual(kinds, ["repo", "repo", "commercial",
                                 "commercial", "gated"])
        gated = art["records"][-1]
        self.assertIsNone(gated["locator"])
        self.assertEqual(gated["reason"], "rides the pending transfer")

    def test_verify_round_trip(self):
        art = doors.build_registry(snapshot())
        ok, mismatches = doors.verify_registry(art)
        self.assertTrue(ok, mismatches)

    def test_inactive_door_is_a_named_failure_not_a_crash(self):
        snap = snapshot()
        snap["commercial_doors"][1]["active"] = False
        art = doors.build_registry(snap)
        self.assertEqual(art["summary"]["commercial_active"], 1)
        self.assertEqual(len(art["failures"]), 1)
        self.assertEqual(art["failures"][0]["door"], "BETA-200")
        ok, _ = doors.verify_registry(art)
        self.assertTrue(ok)

    def test_duplicate_door_name_is_a_named_failure(self):
        snap = snapshot()
        snap["repos"].append({"name": "alpha", "head": HEAD_B})
        art = doors.build_registry(snap)
        reasons = [f["reason"] for f in art["failures"]]
        self.assertTrue(any("duplicate" in r for r in reasons))

    def test_zero_doors_refused(self):
        snap = snapshot()
        snap["repos"] = []
        snap["commercial_doors"] = []
        with self.assertRaises(ValueError):
            doors.build_registry(snap)

    def test_unsourced_section_refused(self):
        snap = snapshot()
        del snap["sources"]["commercial_doors"]
        with self.assertRaises(ValueError):
            doors.build_registry(snap)

    def test_malformed_entries_refused(self):
        snap = snapshot()
        del snap["repos"][0]["head"]
        with self.assertRaises(ValueError):
            doors.build_registry(snap)
        snap = snapshot()
        del snap["commercial_doors"][0]["url"]
        with self.assertRaises(ValueError):
            doors.build_registry(snap)


class TamperTest(unittest.TestCase):
    """Planted controls: every tamper shape is rejected, naming the
    door and the field — including tampering that honestly recomputes
    the digest (re-derivation is the real check)."""

    def test_flipped_locator_redigested_rejected(self):
        art = doors.build_registry(snapshot())
        art["records"][2]["locator"] = "https://buy.stripe.com/evil"
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("ALPHA-100" in m and "locator" in m
                            for m in mismatches), mismatches)

    def test_erased_failure_redigested_rejected(self):
        snap = snapshot()
        snap["commercial_doors"][0]["active"] = False
        art = doors.build_registry(snap)
        art["failures"] = []
        art["records"][2]["failures"] = []
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("failures" in m for m in mismatches),
                        mismatches)

    def test_dropped_gated_record_redigested_rejected(self):
        art = doors.build_registry(snapshot())
        art["records"] = [r for r in art["records"]
                          if r["kind"] != "gated"]
        art["summary"]["gated"] = 0
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("records" in m for m in mismatches),
                        mismatches)

    def test_stale_digest_rejected(self):
        art = doors.build_registry(snapshot())
        art["records"][0]["head"] = HEAD_B
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("digest" in m for m in mismatches),
                        mismatches)

    def test_wrong_kind_rejected(self):
        art = doors.build_registry(snapshot())
        art["kind"] = "savage.estate_attestation.v1"
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("kind" in m for m in mismatches), mismatches)


CROSS_SOURCES = {
    "register": {"repo": "Savages-studios/savage-marketplace",
                 "path": "stripe-links.json", "as_of": "2026-11-08"},
    "registry_of_record": {"repo": "on-host (Knights VM)",
                           "path": "~/workspace/transfer-pull/"
                                 "knights-transfer/DOOR-REGISTRY.json",
                           "as_of": "2026-11-05",
                           "sha256": "0" * 64},
    "readback": {"repo": "on-host (Knights VM, first-hand readback)",
                 "path": "~/workspace/hunter-recommission/"
                         "gen2-readback-2026-11-13.json",
                 "as_of": "2026-11-13"},
}


def cross_snapshot():
    snap = snapshot()
    snap["sources"]["commercial_doors"] = copy.deepcopy(CROSS_SOURCES)
    snap["commercial_doors"] = [
        {"sku": "ALPHA-100", "observations": {
            "register": {"product_name": "Alpha",
                         "url": "https://buy.stripe.com/alpha",
                         "amount_minor": 10000, "currency": "usd",
                         "recurring": None, "active": True},
            "registry_of_record": {
                "name": "Alpha", "amount_cents": 10000,
                "billing": "one_time",
                "url": "https://buy.stripe.com/alpha", "active": True,
                "link_metadata": {"sku": "ALPHA-100"}},
            "readback": {"product_name": "Alpha",
                         "url": "https://buy.stripe.com/alpha",
                         "amount_minor": 10000, "currency": "usd",
                         "recurring": None, "active": True}}},
        {"sku": "BETA-200", "observations": {
            "register": {"product_name": "Beta",
                         "url": "https://buy.stripe.com/beta",
                         "amount_minor": 20000, "currency": "usd",
                         "recurring": "month", "active": True},
            "registry_of_record": {
                "name": "Beta", "amount_cents": 20000,
                "billing": "subscription_month",
                "url": "https://buy.stripe.com/beta", "active": True,
                "link_metadata": {"sku": "BETA-200"}},
            "readback": {"product_name": "Beta",
                         "url": "https://buy.stripe.com/beta",
                         "amount_minor": 20000, "currency": "usd",
                         "recurring": "month", "active": False}}},
    ]
    return snap


class CrossVerifyTest(unittest.TestCase):
    def test_agreeing_sources_verify_with_sources_named(self):
        art = doors.build_registry(cross_snapshot())
        alpha = art["records"][2]
        self.assertEqual(alpha["verification"], "VERIFIED")
        self.assertEqual(alpha["verification_sources"],
                         ["register", "registry_of_record", "readback"])
        # Canonical fields derive from the observations: currency is
        # carried only by register + readback, recurring is voted on
        # by the registry of record through its billing vocabulary.
        self.assertEqual(alpha["currency"], "usd")
        self.assertIsNone(alpha["recurring"])
        self.assertEqual(alpha["amount_minor"], 10000)
        self.assertEqual(alpha["sources"]["registry_of_record"]
                         ["sha256"], "0" * 64)
        self.assertEqual(art["summary"]["commercial_verified"], 1)
        ok, mismatches = doors.verify_registry(art)
        self.assertTrue(ok, mismatches)

    def test_disagreement_follows_latest_and_names_failure(self):
        art = doors.build_registry(cross_snapshot())
        beta = art["records"][3]
        self.assertEqual(beta["verification"], "DISAGREEMENT")
        self.assertIs(beta["active"], False)  # readback (2026-11-13)
        self.assertEqual(art["summary"]["commercial_active"], 1)
        self.assertEqual(art["summary"]["commercial_disagreements"], 1)
        self.assertEqual(len(art["failures"]), 1)
        reason = art["failures"][0]["reason"]
        self.assertEqual(art["failures"][0]["door"], "BETA-200")
        self.assertIn("disagreement on active", reason)
        self.assertIn("register=True", reason)
        self.assertIn("registry_of_record=True", reason)
        self.assertIn("readback=False", reason)
        ok, _ = doors.verify_registry(art)
        self.assertTrue(ok)

    def test_disagreement_on_amount_follows_readback(self):
        snap = cross_snapshot()
        snap["commercial_doors"][0]["observations"]["readback"][
            "amount_minor"] = 11000
        art = doors.build_registry(snap)
        alpha = art["records"][2]
        self.assertEqual(alpha["verification"], "DISAGREEMENT")
        self.assertEqual(alpha["amount_minor"], 11000)
        self.assertIn("disagreement on amount_minor",
                      art["failures"][0]["reason"])

    def test_agreed_inactive_is_verified_with_named_failure(self):
        snap = cross_snapshot()
        for obs in snap["commercial_doors"][0]["observations"].values():
            obs["active"] = False
        art = doors.build_registry(snap)
        alpha = art["records"][2]
        self.assertEqual(alpha["verification"], "VERIFIED")
        self.assertIs(alpha["active"], False)
        reasons = [f["reason"] for f in art["failures"]
                   if f["door"] == "ALPHA-100"]
        self.assertEqual(
            reasons,
            ["commercial door not active in its source registry"])

    def test_unsourced_observation_refused(self):
        snap = cross_snapshot()
        del snap["sources"]["commercial_doors"]["readback"]
        with self.assertRaises(ValueError):
            doors.build_registry(snap)

    def test_unknown_billing_refused(self):
        snap = cross_snapshot()
        snap["commercial_doors"][0]["observations"][
            "registry_of_record"]["billing"] = "subscription_week"
        with self.assertRaises(ValueError):
            doors.build_registry(snap)

    def test_legacy_entries_carry_no_verification(self):
        art = doors.build_registry(snapshot())
        rec = art["records"][2]
        self.assertIsNone(rec["verification"])
        self.assertIsNone(rec["observations"])
        self.assertNotIn("commercial_verified", art["summary"])


class CrossTamperTest(unittest.TestCase):
    """Planted controls for cross-verification: the verdict is
    recomputed from the snapshot's embedded observations, so flipping
    an observation in a record, erasing a disagreement, or upgrading
    a verdict — each honestly re-digested — is REJECTED."""

    def test_flipped_observation_redigested_rejected(self):
        art = doors.build_registry(cross_snapshot())
        art["records"][3]["observations"]["readback"]["active"] = True
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("BETA-200" in m and "observations" in m
                            for m in mismatches), mismatches)

    def test_erased_disagreement_redigested_rejected(self):
        art = doors.build_registry(cross_snapshot())
        art["records"][3]["failures"] = []
        art["failures"] = []
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("failures" in m for m in mismatches),
                        mismatches)

    def test_upgraded_verdict_redigested_rejected(self):
        art = doors.build_registry(cross_snapshot())
        art["records"][3]["verification"] = "VERIFIED"
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("BETA-200" in m and "verification" in m
                            for m in mismatches), mismatches)

    def test_flipped_canonical_field_redigested_rejected(self):
        art = doors.build_registry(cross_snapshot())
        art["records"][3]["active"] = True
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("BETA-200" in m and "active" in m
                            for m in mismatches), mismatches)


ASSET_SOURCES = {
    "transfer_manifest": {"repo": "transfer staging",
                          "path": "manifest-2026-11-08.sha256",
                          "as_of": "2026-11-08", "sha256": "f" * 64},
    "pull_verification": {"repo": "transfer pull verification",
                          "path": "sha256-verify.out",
                          "as_of": "2026-11-16T08:46:20Z",
                          "sha256": "e" * 64},
    "host_census": {"repo": "on-host census",
                    "path": "~/workspace/transfer-pull/knights-transfer",
                    "as_of": "2026-11-17T00:00:00Z"},
}


def asset_snapshot():
    snap = snapshot()
    snap["sources"]["asset_classes"] = copy.deepcopy(ASSET_SOURCES)
    snap["asset_classes"] = [
        {"name": "Trained swarm (gpt-oss-20b)",
         "locator": "~/workspace/transfer-pull/knights-transfer/"
                    "gpt-oss-20b",
         "manifest_prefixes": [
             "gpt-oss-20b/",
             "murmuration-cortex-2026-11-05/foundation/gpt-oss-20b/"],
         "observations": {
             "transfer_manifest": {"file_count": 14},
             "pull_verification": {"verified_ok": 0,
                                   "verify_failed": 14},
             "host_census": {"file_count": 14,
                             "total_bytes": 13789264674,
                             "spot_checked": 14, "spot_matched": 14}}},
        {"name": "Forge outputs",
         "locator": "~/workspace/transfer-pull/knights-transfer/"
                    "forge-video-phase2-2026-11-05",
         "manifest_prefixes": ["forge-video-phase2-2026-11-05/"],
         "observations": {
             "transfer_manifest": {"file_count": 43744},
             "pull_verification": {"verified_ok": 43742,
                                   "verify_failed": 2},
             "host_census": {"file_count": 43757,
                             "total_bytes": 4642847820,
                             "spot_checked": 8, "spot_matched": 6}}},
    ]
    return snap


def asset_record(art, name):
    return next(r for r in art["records"] if r["name"] == name)


class AssetClassTest(unittest.TestCase):
    def test_verified_class_with_pull_failure_named(self):
        art = doors.build_registry(asset_snapshot())
        swarm = asset_record(art, "Trained swarm (gpt-oss-20b)")
        self.assertEqual(swarm["kind"], "asset_class")
        self.assertEqual(swarm["verification"], "VERIFIED")
        self.assertEqual(swarm["file_count"], 14)
        self.assertEqual(swarm["total_bytes"], 13789264674)
        self.assertEqual(swarm["verification_sources"],
                         ["transfer_manifest", "pull_verification",
                          "host_census"])
        # The pull's 14 open-or-read failures are carried as a named
        # failure even though the verdict is VERIFIED — the census
        # spot check (14/14, the whole class) is the governing
        # first-hand integrity measurement.
        self.assertEqual(len(swarm["failures"]), 1)
        self.assertIn("failed for 14 of 14", swarm["failures"][0])
        self.assertEqual(art["summary"]["asset_classes"], 2)
        self.assertEqual(art["summary"]["asset_verified"], 1)
        self.assertEqual(art["summary"]["doors_registered"], 6)
        ok, mismatches = doors.verify_registry(art)
        self.assertTrue(ok, mismatches)

    def test_count_disagreement_follows_census(self):
        art = doors.build_registry(asset_snapshot())
        forge = asset_record(art, "Forge outputs")
        self.assertEqual(forge["verification"], "DISAGREEMENT")
        self.assertEqual(forge["file_count"], 43757)  # census governs
        reasons = forge["failures"]
        self.assertTrue(any("disagreement on file_count" in r
                            and "transfer_manifest=43744" in r
                            and "host_census=43757" in r
                            for r in reasons), reasons)
        # The spot mismatch and the pull tallies are also named.
        self.assertTrue(any("matched 6 of 8" in r for r in reasons),
                        reasons)
        self.assertTrue(any("failed for 2 of 43744" in r
                            for r in reasons), reasons)
        self.assertEqual(art["summary"]["asset_disagreements"], 1)
        self.assertEqual(art["summary"]["asset_files"],
                         14 + 43757)
        ok, _ = doors.verify_registry(art)
        self.assertTrue(ok)

    def test_spot_failure_alone_is_failed_verdict(self):
        snap = asset_snapshot()
        forge = snap["asset_classes"][1]
        forge["observations"]["host_census"]["file_count"] = 43744
        forge["observations"]["pull_verification"] = {
            "verified_ok": 43744, "verify_failed": 0}
        art = doors.build_registry(snap)
        forge = asset_record(art, "Forge outputs")
        self.assertEqual(forge["verification"], "FAILED")
        self.assertEqual(len(forge["failures"]), 1)
        self.assertIn("matched 6 of 8", forge["failures"][0])
        self.assertEqual(art["summary"]["asset_failed"], 1)
        ok, _ = doors.verify_registry(art)
        self.assertTrue(ok)

    def test_asset_only_snapshot_registers(self):
        snap = asset_snapshot()
        snap["repos"] = []
        snap["commercial_doors"] = []
        art = doors.build_registry(snap)
        self.assertEqual(art["summary"]["doors_registered"], 2)

    def test_unsourced_observation_refused(self):
        snap = asset_snapshot()
        del snap["sources"]["asset_classes"]["host_census"]
        with self.assertRaises(ValueError):
            doors.build_registry(snap)

    def test_missing_required_source_refused(self):
        snap = asset_snapshot()
        del snap["sources"]["asset_classes"]["transfer_manifest"]
        with self.assertRaises(ValueError):
            doors.build_registry(snap)

    def test_malformed_entries_refused(self):
        snap = asset_snapshot()
        del snap["asset_classes"][0]["locator"]
        with self.assertRaises(ValueError):
            doors.build_registry(snap)
        snap = asset_snapshot()
        snap["asset_classes"][0]["manifest_prefixes"] = []
        with self.assertRaises(ValueError):
            doors.build_registry(snap)
        snap = asset_snapshot()
        snap["asset_classes"][0]["observations"]["host_census"][
            "file_count"] = -1
        with self.assertRaises(ValueError):
            doors.build_registry(snap)
        snap = asset_snapshot()
        snap["asset_classes"][0]["observations"]["host_census"][
            "owner"] = "tights"
        with self.assertRaises(ValueError):
            doors.build_registry(snap)


class AssetTamperTest(unittest.TestCase):
    """Planted controls for asset classes: the verdict and the
    measured fields are recomputed from the snapshot's embedded
    observations and source declarations, so tampering — each time
    honestly re-digested — is REJECTED naming door + field."""

    def test_flipped_census_count_redigested_rejected(self):
        art = doors.build_registry(asset_snapshot())
        asset_record(art, "Forge outputs")["file_count"] = 43744
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("Forge outputs" in m and "file_count" in m
                            for m in mismatches), mismatches)

    def test_flipped_total_bytes_redigested_rejected(self):
        art = doors.build_registry(asset_snapshot())
        asset_record(art, "Trained swarm (gpt-oss-20b)")[
            "total_bytes"] = 1
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("gpt-oss-20b" in m and "total_bytes" in m
                            for m in mismatches), mismatches)

    def test_erased_failure_redigested_rejected(self):
        art = doors.build_registry(asset_snapshot())
        forge = asset_record(art, "Forge outputs")
        forge["failures"] = []
        art["failures"] = [f for f in art["failures"]
                           if f["door"] != "Forge outputs"]
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("failures" in m for m in mismatches),
                        mismatches)

    def test_upgraded_verdict_redigested_rejected(self):
        art = doors.build_registry(asset_snapshot())
        asset_record(art, "Forge outputs")["verification"] = "VERIFIED"
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("Forge outputs" in m
                            and "verification" in m
                            for m in mismatches), mismatches)

    def test_flipped_manifest_digest_redigested_rejected(self):
        art = doors.build_registry(asset_snapshot())
        asset_record(art, "Forge outputs")["sources"][
            "transfer_manifest"]["sha256"] = "0" * 64
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("Forge outputs" in m and "sources" in m
                            for m in mismatches), mismatches)

    def test_dropped_asset_record_redigested_rejected(self):
        art = doors.build_registry(asset_snapshot())
        art["records"] = [r for r in art["records"]
                          if r["kind"] != "asset_class"]
        art["summary"]["doors_registered"] = 4
        for key in [k for k in art["summary"]
                    if k.startswith("asset_")]:
            del art["summary"][key]
        redigest(art)
        ok, mismatches = doors.verify_registry(art)
        self.assertFalse(ok)
        self.assertTrue(any("records" in m or "summary" in m
                            for m in mismatches), mismatches)


class CliTest(unittest.TestCase):
    def _run(self, argv):
        with tempfile.TemporaryDirectory() as td:
            snap_path = os.path.join(td, "snap.json")
            out_path = os.path.join(td, "registry.json")
            with open(snap_path, "w", encoding="utf-8") as fh:
                json.dump(snapshot(), fh)
            rc = cli.main(["doors", "--snapshot", snap_path,
                           "-o", out_path])
            self.assertEqual(rc, 0)
            with open(out_path, encoding="utf-8") as fh:
                art = json.load(fh)
            self.assertEqual(art["summary"]["doors_registered"], 4)
            rc = cli.main(["doors", "--check", out_path])
            self.assertEqual(rc, 0)
            art["records"][0]["locator"] = "repo:elsewhere"
            art["digest"] = doors.artifact_digest(art)
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(art, fh)
            rc = cli.main(["doors", "--check", out_path])
            self.assertEqual(rc, 1)

    def test_cli_build_and_check(self):
        self._run(None)


if __name__ == "__main__":
    unittest.main()
