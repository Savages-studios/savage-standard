"""PROOF-E1 proof suite: the estate attestation derives every verdict
from the snapshot, seals it with a digest, and catches tampering by
re-derivation — including tampering that honestly re-computes the
digest. Fixture snapshots are hand-built; no network is touched (the
fetcher is exercised only for its token-missing refusal). Stdlib
unittest only."""
import copy
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from savage_standard import cli, estate  # noqa: E402

TAKEN_AT = "2026-11-15T00:00:00Z"
HEAD_A = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
HEAD_B = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
HEAD_C = "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
HEAD_D = "d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
HEAD_SIA = "e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
HEAD_E = "f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1"

CI_OK = [{"workflow": "tests", "status": "completed",
          "conclusion": "success", "updated_at": "2026-11-14T10:00:00Z"}]

GT_A = (f"# GROUND_TRUTH — alpha\n\n"
        f"**Canonical branch:** main @ `{HEAD_A}`\n"
        f"- **Head:** `{HEAD_A}`\n"
        f"**Last verified:** 2026-11-10\n\nbody\n")
GT_B = (f"# GROUND_TRUTH — beta\n\n"
        f"- **Head:** `{HEAD_A}`\n"
        f"**Last verified:** 2026-11-01\n")
GT_D = ("# GROUND_TRUTH — delta\n\nNo head citation anywhere.\n"
        "**Last verified:** 2026-11-12\n")
GT_SIA = (f"# GROUND_TRUTH — sia\n\n"
          f"**Canonical branch:** main @ `{HEAD_SIA}`\n"
          f"**Last verified:** 2026-11-15\n")
GT_E = f"# GROUND_TRUTH — epsilon\n\n- **Head:** `{HEAD_E[:10]}`\n"


def repo_a():
    return {"name": "alpha-clean", "head": HEAD_A,
            "ground_truth": GT_A, "ci": copy.deepcopy(CI_OK)}


def repo_b():
    return {"name": "beta-drifted", "head": HEAD_B, "ground_truth": GT_B,
            "ci": [
                {"workflow": "tests", "status": "completed",
                 "conclusion": "success",
                 "updated_at": "2026-11-13T10:00:00Z"},
                {"workflow": "tests", "status": "completed",
                 "conclusion": "failure",
                 "updated_at": "2026-11-14T10:00:00Z"},
                {"workflow": "lint", "status": "completed",
                 "conclusion": "success",
                 "updated_at": "2026-11-14T09:00:00Z"}]}


def repo_c():
    return {"name": "gamma-missing", "head": HEAD_C,
            "ground_truth": None, "ci": copy.deepcopy(CI_OK)}


def repo_d():
    return {"name": "delta-unpinned", "head": HEAD_D,
            "ground_truth": GT_D, "ci": []}


def repo_sia():
    return {"name": "sia-v6-core", "head": HEAD_SIA,
            "ground_truth": GT_SIA, "ci": copy.deepcopy(CI_OK)}


def repo_e():
    return {"name": "epsilon-progress", "head": HEAD_E,
            "ground_truth": GT_E,
            "ci": [{"workflow": "tests", "status": "in_progress",
                    "conclusion": None,
                    "updated_at": "2026-11-15T01:00:00Z"}]}


def snapshot(repos):
    return {"org": "Savages-studios", "taken_at": TAKEN_AT,
            "repos": repos}


def record_of(artifact, name):
    return next(r for r in artifact["records"] if r["repo"] == name)


class TestDerive(unittest.TestCase):
    def test_repo_a_clean_current(self):
        art = estate.build_attestation(snapshot([repo_a()]))
        rec = record_of(art, "alpha-clean")
        self.assertEqual(rec["gt"]["currency"], "CURRENT")
        self.assertEqual(rec["gt"]["cited_head"], HEAD_A)
        self.assertTrue(rec["gt"]["present"])
        self.assertEqual(rec["gt"]["last_verified"], "2026-11-10")
        self.assertEqual(rec["gt"]["age_days"], 5)
        self.assertEqual(rec["ci"]["state"], "PASSING")
        self.assertEqual(rec["failures"], [])
        self.assertEqual(rec["claims"], [])
        self.assertEqual(art["failures"], [])

    def test_repo_b_drifted_and_failing(self):
        art = estate.build_attestation(snapshot([repo_b()]))
        rec = record_of(art, "beta-drifted")
        self.assertEqual(rec["gt"]["currency"], "DRIFTED")
        self.assertEqual(rec["gt"]["cited_head"], HEAD_A)
        self.assertEqual(rec["ci"]["state"], "FAILING")
        # latest-per-workflow: the older success is superseded
        tests = next(w for w in rec["ci"]["workflows"]
                     if w["workflow"] == "tests")
        self.assertEqual(tests["conclusion"], "failure")
        joined = " | ".join(rec["failures"])
        self.assertIn("drifted", joined)
        self.assertIn("'tests'", joined)
        self.assertIn("failure", joined)

    def test_repo_c_missing(self):
        art = estate.build_attestation(snapshot([repo_c()]))
        rec = record_of(art, "gamma-missing")
        self.assertEqual(rec["gt"]["currency"], "MISSING")
        self.assertFalse(rec["gt"]["present"])
        self.assertIsNone(rec["gt"]["cited_head"])
        self.assertTrue(any("missing" in f for f in rec["failures"]))
        self.assertEqual(rec["ci"]["state"], "PASSING")

    def test_repo_d_unpinned_and_none_recorded(self):
        art = estate.build_attestation(snapshot([repo_d()]))
        rec = record_of(art, "delta-unpinned")
        self.assertEqual(rec["gt"]["currency"], "UNPINNED")
        self.assertEqual(rec["gt"]["last_verified"], "2026-11-12")
        self.assertEqual(rec["gt"]["age_days"], 3)
        self.assertEqual(rec["ci"]["state"], "NONE_RECORDED")
        joined = " | ".join(rec["failures"])
        self.assertIn("unpinned", joined)
        self.assertIn("no CI state recorded", joined)

    def test_canonical_branch_citation(self):
        art = estate.build_attestation(snapshot([repo_sia()]))
        rec = record_of(art, "sia-v6-core")
        self.assertEqual(rec["gt"]["cited_head"], HEAD_SIA)
        self.assertEqual(rec["gt"]["currency"], "CURRENT")
        self.assertEqual(rec["gt"]["age_days"], 0)

    def test_short_prefix_citation_is_current(self):
        art = estate.build_attestation(snapshot([repo_e()]))
        rec = record_of(art, "epsilon-progress")
        self.assertEqual(rec["gt"]["cited_head"], HEAD_E[:10])
        self.assertEqual(rec["gt"]["currency"], "CURRENT")
        self.assertEqual(rec["ci"]["state"], "IN_PROGRESS")

    def test_head_line_preferred_over_canonical(self):
        gt = (f"**Canonical branch:** main @ `{HEAD_B}`\n"
              f"- **Head:** `{HEAD_A}`\n")
        entry = {"name": "alpha-clean", "head": HEAD_A,
                 "ground_truth": gt, "ci": copy.deepcopy(CI_OK)}
        rec = estate.derive_record(entry, TAKEN_AT)
        self.assertEqual(rec["gt"]["cited_head"], HEAD_A)
        self.assertEqual(rec["gt"]["currency"], "CURRENT")

    def test_claims_attachment(self):
        # 'sia-v6-core' appears verbatim in the claim text of exactly
        # one INVENTORY row (sia-v6-core-benchmarks, gated=False);
        # 'alpha-clean' appears in none.
        art = estate.build_attestation(snapshot([repo_sia(), repo_a()]))
        self.assertEqual(record_of(art, "sia-v6-core")["claims"],
                         [{"id": "sia-v6-core-benchmarks",
                           "gated": False}])
        self.assertEqual(record_of(art, "alpha-clean")["claims"], [])


class TestArtifact(unittest.TestCase):
    def setUp(self):
        self.snap = snapshot([repo_a(), repo_b(), repo_c(), repo_d(),
                              repo_sia()])
        self.art = estate.build_attestation(self.snap)

    def test_kind_and_snapshot_embedded_verbatim(self):
        self.assertEqual(self.art["kind"],
                         "savage.estate_attestation.v1")
        self.assertEqual(self.art["snapshot"], self.snap)
        self.assertEqual(self.art["org"], "Savages-studios")
        self.assertEqual(self.art["taken_at"], TAKEN_AT)

    def test_summary_counts(self):
        self.assertEqual(self.art["summary"], {
            "repos_attested": 5, "gt_present": 4, "gt_current": 2,
            "ci_passing": 3, "claims_rows_attached": 1,
            "claims_gated": 0})
        # B: drifted + CI failing; C: missing; D: unpinned + no CI
        self.assertEqual(len(self.art["failures"]), 5)
        self.assertTrue(all(set(f) == {"repo", "reason"}
                            for f in self.art["failures"]))

    def test_digest_verifies(self):
        ok, mismatches = estate.verify_artifact(self.art)
        self.assertTrue(ok, mismatches)
        self.assertEqual(mismatches, [])

    def test_tamper_currency_redigested_rejected(self):
        # The strong attack: flip the verdict AND honestly recompute
        # the digest. Re-derivation from the snapshot must catch it.
        bad = copy.deepcopy(self.art)
        record_of(bad, "beta-drifted")["gt"]["currency"] = "CURRENT"
        bad["digest"] = estate.artifact_digest(bad)
        ok, mismatches = estate.verify_artifact(bad)
        self.assertFalse(ok)
        self.assertTrue(any("beta-drifted" in m and "currency" in m
                            for m in mismatches), mismatches)

    def test_tamper_summary_redigested_rejected(self):
        bad = copy.deepcopy(self.art)
        bad["summary"]["gt_current"] = 5
        bad["digest"] = estate.artifact_digest(bad)
        ok, mismatches = estate.verify_artifact(bad)
        self.assertFalse(ok)
        self.assertTrue(any("summary.gt_current" in m
                            for m in mismatches), mismatches)

    def test_tamper_failures_list_redigested_rejected(self):
        bad = copy.deepcopy(self.art)
        bad["failures"] = []
        bad["digest"] = estate.artifact_digest(bad)
        ok, mismatches = estate.verify_artifact(bad)
        self.assertFalse(ok)
        self.assertTrue(any(m.startswith("failures:")
                            for m in mismatches), mismatches)

    def test_tamper_snapshot_breaks_digest(self):
        bad = copy.deepcopy(self.art)
        bad["snapshot"]["repos"][0]["head"] = HEAD_B
        ok, mismatches = estate.verify_artifact(bad)
        self.assertFalse(ok)
        self.assertTrue(any(m.startswith("digest:")
                            for m in mismatches), mismatches)

    def test_empty_repos_refused(self):
        with self.assertRaises(ValueError):
            estate.build_attestation(snapshot([]))


class TestCli(unittest.TestCase):
    def _write(self, td, name, obj):
        path = os.path.join(td, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return path

    def test_empty_repos_exit_2(self):
        with tempfile.TemporaryDirectory() as td:
            snap = self._write(td, "snap.json", snapshot([]))
            self.assertEqual(
                cli.main(["estate", "--snapshot", snap]), 2)

    def test_missing_snapshot_file_exit_2(self):
        self.assertEqual(
            cli.main(["estate", "--snapshot",
                      "/nonexistent/snap.json"]), 2)

    def test_clean_exit_0_and_check(self):
        with tempfile.TemporaryDirectory() as td:
            snap = self._write(td, "snap.json", snapshot([repo_a()]))
            out = os.path.join(td, "att.json")
            self.assertEqual(
                cli.main(["estate", "--snapshot", snap, "-o", out]), 0)
            with open(out, encoding="utf-8") as fh:
                art = json.load(fh)
            ok, mismatches = estate.verify_artifact(art)
            self.assertTrue(ok, mismatches)
            self.assertEqual(cli.main(["estate", "--check", out]), 0)

    def test_failures_exit_1_but_check_still_verifies(self):
        # Exit 1 means "attested, WITH named failures" — the artifact
        # itself is still a validly sealed attestation, so --check
        # (an integrity verdict, not a cleanliness verdict) exits 0.
        with tempfile.TemporaryDirectory() as td:
            snap = self._write(td, "snap.json",
                               snapshot([repo_a(), repo_b()]))
            out = os.path.join(td, "att.json")
            self.assertEqual(
                cli.main(["estate", "--snapshot", snap, "-o", out]), 1)
            self.assertEqual(cli.main(["estate", "--check", out]), 0)

    def test_check_tampered_exit_1(self):
        with tempfile.TemporaryDirectory() as td:
            snap = self._write(td, "snap.json", snapshot([repo_a()]))
            out = os.path.join(td, "att.json")
            self.assertEqual(
                cli.main(["estate", "--snapshot", snap, "-o", out]), 0)
            with open(out, encoding="utf-8") as fh:
                art = json.load(fh)
            art["summary"]["repos_attested"] = 99
            self._write(td, "att.json", art)
            self.assertEqual(cli.main(["estate", "--check", out]), 1)

    def test_fetch_without_token_exit_2(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("GITHUB_TOKEN", None)
            self.assertEqual(
                cli.main(["estate", "--org", "Savages-studios",
                          "--fetch"]), 2)


if __name__ == "__main__":
    unittest.main()
