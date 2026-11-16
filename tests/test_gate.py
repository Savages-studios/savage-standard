"""Tests for the estate claim gate (savage_standard/gate.py).

Planted controls: the BAD fixture tree carries exactly one unlabeled
claim and one verified-labeled claim that the attestation evidence
refutes (GT DRIFTED) — the gate must FAIL naming both. The CLEAN
fixture carries only labeled claims under a CURRENT / PASSING
attestation — the gate must PASS.
"""
import json
import os
import tempfile
import unittest

from savage_standard import cli, estate, gate

HERE = os.path.dirname(os.path.abspath(__file__))
BAD = os.path.join(HERE, "fixtures", "gate", "bad-repo")
CLEAN = os.path.join(HERE, "fixtures", "gate", "clean-repo")
HEAD_A = "a" * 40
HEAD_B = "b" * 40


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def attestation(name, head, gt_text, conclusion="success"):
    snap = {"org": "Savages-studios", "taken_at": "2026-11-15T00:00:00Z",
            "repos": [{"name": name, "head": head, "ground_truth": gt_text,
                       "ci": [{"workflow": "tests", "status": "completed",
                               "conclusion": conclusion,
                               "updated_at": "2026-11-15T00:00:00Z"}]}]}
    return estate.build_attestation(snap)


def bad_attestation():
    return attestation("bad-repo", HEAD_A, _read(os.path.join(
        BAD, "GROUND_TRUTH.md")))


def clean_attestation():
    return attestation("clean-repo", HEAD_A, _read(os.path.join(
        CLEAN, "GROUND_TRUTH.md")))


class TestPlantedControls(unittest.TestCase):
    def test_bad_fixture_fails_naming_both(self):
        report = gate.gate_tree(BAD, attestation=bad_attestation())
        self.assertEqual(report["verdict"], "FAIL")
        checks = [f["check"] for f in report["failures"]]
        self.assertIn("UNLABELED", checks)
        self.assertIn("CONTRADICTED", checks)
        unlabeled = [f for f in report["failures"]
                     if f["check"] == "UNLABELED"]
        self.assertEqual(len(unlabeled), 1)
        self.assertEqual(unlabeled[0]["kind"], "throughput-figure")
        self.assertEqual(unlabeled[0]["file"], "README.md")
        contradicted = [f for f in report["failures"]
                        if f["check"] == "CONTRADICTED"]
        self.assertEqual(len(contradicted), 1)
        self.assertTrue(contradicted[0]["detail"].startswith("C1:"),
                        contradicted[0]["detail"])
        self.assertIn("DRIFTED", contradicted[0]["detail"])

    def test_clean_fixture_passes(self):
        report = gate.gate_tree(CLEAN, attestation=clean_attestation())
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["verdict"], "PASS")
        self.assertGreaterEqual(report["claims_found"], 2)

    def test_clean_fixture_passes_without_attestation(self):
        report = gate.gate_tree(CLEAN)
        self.assertEqual(report["verdict"], "PASS", report["failures"])


class TestContradictionRules(unittest.TestCase):
    def test_c2_verified_vs_failing_ci(self):
        att = attestation("clean-repo", HEAD_A, _read(os.path.join(
            CLEAN, "GROUND_TRUTH.md")), conclusion="failure")
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "README.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("# x\n\nUptime held at 99.9%. "
                         "Evidence state: VERIFIED.\n")
            with open(os.path.join(td, "GROUND_TRUTH.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("# gt\n")
            report = gate.gate_tree(td, attestation=att)
        contra = [f for f in report["failures"]
                  if f["check"] == "CONTRADICTED"]
        self.assertEqual(len(contra), 1)
        self.assertTrue(contra[0]["detail"].startswith("C2:"),
                        contra[0]["detail"])

    def test_c3_verified_without_local_ground_truth(self):
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "README.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("# x\n\nUptime held at 99.9%. "
                         "Evidence state: VERIFIED.\n")
            report = gate.gate_tree(td)
        contra = [f for f in report["failures"]
                  if f["check"] == "CONTRADICTED"]
        self.assertEqual(len(contra), 1)
        self.assertTrue(contra[0]["detail"].startswith("C3:"),
                        contra[0]["detail"])

    def test_c4_live_vs_failing_ci(self):
        att = attestation("clean-repo", HEAD_A, _read(os.path.join(
            CLEAN, "GROUND_TRUTH.md")), conclusion="failure")
        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "README.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("# x\n\n| Service | Status |\n"
                         "|---|---|\n| api | LIVE |\n")
            report = gate.gate_tree(td, attestation=att)
        contra = [f for f in report["failures"]
                  if f["check"] == "CONTRADICTED"]
        self.assertEqual(len(contra), 1)
        self.assertTrue(contra[0]["detail"].startswith("C4:"),
                        contra[0]["detail"])


class TestGtBudget(unittest.TestCase):
    def test_drifted_beyond_default_budget_fails(self):
        report = gate.gate_tree(CLEAN, attestation=bad_attestation())
        checks = [f["check"] for f in report["failures"]]
        self.assertEqual(checks, ["GT-BUDGET"])

    def test_drifted_within_budget_passes(self):
        report = gate.gate_tree(CLEAN, attestation=bad_attestation(),
                                gt_budget=1)
        self.assertEqual(report["verdict"], "PASS", report["failures"])


class TestAttestationHandling(unittest.TestCase):
    def test_tampered_attestation_is_a_failure_not_evidence(self):
        att = clean_attestation()
        att["records"][0]["gt"]["currency"] = "DRIFTED"
        att["digest"] = estate.artifact_digest(att)  # honest re-digest
        report = gate.gate_tree(CLEAN, attestation=att)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(any(f["check"] == "ATTESTATION"
                            for f in report["failures"]))
        # The tampered DRIFTED verdict is never taken as evidence.
        self.assertFalse(any(f["check"] == "GT-BUDGET"
                             for f in report["failures"]))

    def test_no_matching_record_fails_closed(self):
        report = gate.gate_tree(CLEAN, attestation=clean_attestation(),
                                repo_name="some-other-repo")
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(any(f["check"] == "ATTESTATION"
                            for f in report["failures"]))


class TestLinterSemantics(unittest.TestCase):
    def test_apparatus_documents_are_not_scanned(self):
        claims = gate.scan_document(
            "GROUND_TRUTH.md", "Uptime held at 99.9% with no label.\n",
            set())
        self.assertEqual(claims, [])

    def test_code_fence_and_target_figures_are_not_claims(self):
        text = ("# x\n\n```\nThroughput reached 2.45 M ops/sec.\n```\n\n"
                "Latency target: 5 ms response (target KPI threshold).\n")
        claims = gate.scan_document("README.md", text, set())
        self.assertEqual(claims, [])

    def test_banner_qualifies_whole_file(self):
        text = ("> **Evidence state -- REPORTED, UNVERIFIED** "
                "(qualified 2026-11-11).\n\n"
                "Throughput reached 2.45 M ops/sec in the latest run.\n")
        claims = gate.scan_document("README.md", text, set())
        self.assertEqual(len(claims), 1)
        self.assertTrue(claims[0]["qualified"])
        self.assertIn("reported", claims[0]["states"])

    def test_unlabeled_percent_claim_is_caught(self):
        claims = gate.scan_document(
            "docs/guide.md", "Accuracy improved by 42% last week.\n",
            set())
        self.assertEqual(len(claims), 1)
        self.assertFalse(claims[0]["qualified"])
        self.assertEqual(claims[0]["kind"], "percent-figure")


class TestCli(unittest.TestCase):
    def _write_att(self, td, att):
        path = os.path.join(td, "att.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(att, fh)
        return path

    def test_bad_tree_exit_1_clean_tree_exit_0(self):
        with tempfile.TemporaryDirectory() as td:
            bad_att = self._write_att(td, bad_attestation())
            clean_att = self._write_att(td, clean_attestation())
            self.assertEqual(
                cli.main(["gate", BAD, "--attestation", bad_att]), 1)
            self.assertEqual(
                cli.main(["gate", CLEAN, "--attestation", clean_att]), 0)

    def test_missing_tree_exit_2(self):
        self.assertEqual(cli.main(["gate", "/nonexistent/tree"]), 2)

    def test_json_report(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["gate", CLEAN, "--json"])
        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
