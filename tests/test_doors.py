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
