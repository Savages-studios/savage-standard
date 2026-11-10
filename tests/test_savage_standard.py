"""SIA-E2 proof suite: genuine receipts from every estate dialect verify;
every tamper fails loudly; unreachable evidence is UNVERIFIABLE, never a
silent pass. Fixtures are real artifacts produced by the fix program
(see fixtures/PROVENANCE.md). Stdlib unittest only."""
import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from savage_standard import envelope, verify  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
LAWS = ["C4", "C8", "C9", "G6", "S9", "C2", "M1", "M2", "E2"]  # family-1 bindings, per the classifier


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return json.load(fh)


def load_lines(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


class TestMarketplace(unittest.TestCase):
    def setUp(self):
        self.pay = load("payment.json")
        self.dlv = load("delivery.json")

    def test_genuine_pair_verifies(self):
        out = verify.verify(self.dlv, pair=self.pay)
        self.assertEqual(out["dialect"], "marketplace-delivery")
        self.assertEqual(out["verdict"], "VERIFIED-STRUCTURAL")  # artifact bytes not supplied
        fails = [l for l in out["legs"] if l["status"] == "fail"]
        self.assertEqual(fails, [])

    def test_edited_amount_rejected(self):
        bad = copy.deepcopy(self.pay)
        bad["entry"]["payload"]["amountMinor"] += 1
        out = verify.verify(bad)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_swapped_artifact_digest_rejected(self):
        bad = copy.deepcopy(self.dlv)
        bad["entry"]["payload"]["artifacts"][0]["sha256"] = "0" * 64
        out = verify.verify(bad, pair=self.pay)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_broken_pair_binding_rejected(self):
        bad = copy.deepcopy(self.dlv)
        bad["entry"]["payload"]["paymentEntryHash"] = "f" * 64
        out = verify.verify(bad, pair=self.pay)
        self.assertEqual(out["verdict"], "REJECTED")


class TestSiaCore(unittest.TestCase):
    def setUp(self):
        self.records = load_lines("benchmark-receipts.jsonl")

    def test_genuine_chain_verifies(self):
        out = verify.verify(self.records)
        self.assertEqual(out["verdict"], "VERIFIED")
        self.assertEqual(out["claim"]["acceptance"], "FAIL")  # honest failing gate, intact chain

    def test_edited_measurement_rejected(self):
        bad = copy.deepcopy(self.records)
        bad[0]["result"]["ops_per_sec"] = 999999999
        self.assertEqual(verify.verify(bad)["verdict"], "REJECTED")

    def test_broken_chain_link_rejected(self):
        bad = copy.deepcopy(self.records)
        bad[0]["prev_hash"] = "0" * 64
        self.assertEqual(verify.verify(bad)["verdict"], "REJECTED")


class TestRelay(unittest.TestCase):
    def setUp(self):
        self.records = load_lines("events.jsonl")

    def test_genuine_log_verifies(self):
        out = verify.verify(self.records)
        self.assertEqual(out["verdict"], "VERIFIED")
        self.assertEqual(out["claim"]["events"], 19)

    def test_edited_event_rejected(self):
        bad = copy.deepcopy(self.records)
        bad[3]["data"] = {"seat": "mallory"}
        self.assertEqual(verify.verify(bad)["verdict"], "REJECTED")

    def test_swapped_events_rejected(self):
        bad = copy.deepcopy(self.records)
        bad[2], bad[3] = bad[3], bad[2]
        self.assertEqual(verify.verify(bad)["verdict"], "REJECTED")


class TestBreakthrough(unittest.TestCase):
    def setUp(self):
        self.book = load("breakthrough-book.json")
        self.laws = {"GOOD-1": LAWS}
        self.artifacts = os.path.join(FIX, "breakthrough-artifacts")

    def test_genuine_book_verifies(self):
        out = verify.verify(self.book, bound_laws=self.laws, artifact_dir=self.artifacts)
        self.assertEqual(out["verdict"], "VERIFIED")
        score = out["claim"]["candidates"]["GOOD-1"]
        self.assertEqual(score["score"], 1.0)
        self.assertTrue(score["eligible"])

    def test_flipped_outcome_rejected(self):
        bad = copy.deepcopy(self.book)
        bad["GOOD-1"][0]["outcome"] = "fail"  # edited after sealing: digest dies
        out = verify.verify(bad, bound_laws=self.laws)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_self_asserted_evidence_never_promotes(self):
        bad = copy.deepcopy(self.book)
        for rec in bad["GOOD-1"]:
            rec["source"] = "GOOD-1"
            from savage_standard import canonical
            import hashlib
            text = canonical.js_stringify_ordered(
                [(k, rec[k]) for k in ("candidateId", "lawId", "outcome", "source", "method", "observedAt", "payload")])
            rec["digest"] = hashlib.sha256(text.encode()).hexdigest()
        out = verify.verify(bad, bound_laws=self.laws)
        score = out["claim"]["candidates"]["GOOD-1"]
        self.assertEqual(score["score"], 0.0)
        self.assertFalse(score["eligible"])

    def test_swapped_artifact_bytes_rejected(self):
        out = verify.verify(self.book, bound_laws=self.laws,
                            artifact_dir=os.path.join(FIX, "breakthrough-artifacts-swapped"))
        self.assertEqual(out["verdict"], "REJECTED")


class TestSiaV6Manifest(unittest.TestCase):
    def setUp(self):
        self.manifest = load("certified_manifest.json")
        self.dir = os.path.join(FIX, "sia-v6-manifest")

    def test_genuine_manifest_structural(self):
        out = verify.verify(self.manifest, artifact_dir=self.dir)
        # artifacts + certification arithmetic recompute; record MACs unverifiable
        self.assertEqual(out["verdict"], "VERIFIED-STRUCTURAL")
        mac = [l for l in out["legs"] if l["name"] == "record-macs"][0]
        self.assertEqual(mac["status"], "unverifiable")
        arith = [l for l in out["legs"] if l["name"] == "certification-arithmetic"][0]
        self.assertEqual(arith["status"], "pass")

    def test_inflated_status_rejected(self):
        bad = copy.deepcopy(self.manifest)
        bad["certification_status"] = "CERTIFIED"
        out = verify.verify(bad, artifact_dir=self.dir)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_swapped_artifact_rejected(self):
        out = verify.verify(self.manifest,
                            artifact_dir=os.path.join(FIX, "sia-v6-manifest-swapped"))
        self.assertEqual(out["verdict"], "REJECTED")

    def test_no_artifacts_unverifiable_legs(self):
        out = verify.verify(self.manifest)
        self.assertEqual(out["verdict"], "UNVERIFIABLE")


class TestCeros(unittest.TestCase):
    def setUp(self):
        self.receipt = load("ceros-receipt.json")

    def test_genuine_receipt_structural(self):
        out = verify.verify(self.receipt)
        self.assertEqual(out["verdict"], "VERIFIED-STRUCTURAL")
        sig = [l for l in out["legs"] if l["name"] == "mldsa87-signature"][0]
        self.assertEqual(sig["status"], "unverifiable")

    def test_edited_verdict_rejected(self):
        bad = copy.deepcopy(self.receipt)
        bad["verdict"] = "PROMOTE"  # unsigned edit: total no longer matches dims? total unchanged...
        bad["total"] = 30
        out = verify.verify(bad)
        self.assertEqual(out["verdict"], "REJECTED")


class TestStarr(unittest.TestCase):
    def setUp(self):
        self.receipt = load("starr-receipt.json")
        self.wav = os.path.join(FIX, "bounce_sie2.wav")

    def test_genuine_receipt_verifies(self):
        out = verify.verify(self.receipt, artifact_file=self.wav)
        self.assertEqual(out["verdict"], "VERIFIED")

    def test_edited_measurement_rejected(self):
        bad = copy.deepcopy(self.receipt)
        bad["measurements"]["integratedLoudnessLufs"] = -1.0
        out = verify.verify(bad, artifact_file=self.wav)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_swapped_wav_rejected(self):
        out = verify.verify(self.receipt,
                            artifact_file=os.path.join(FIX, "bounce_swapped.wav"))
        self.assertEqual(out["verdict"], "REJECTED")


class TestEnvelope(unittest.TestCase):
    def _wrapped(self):
        native = load("starr-receipt.json")
        return envelope.wrap(
            native, claim_id="starr-bounce-sie2-1", claim_kind="certification",
            statement="bounce measured across the Starr QC gates",
            issuer_line="Starr", issuer_system="star", dialect="starr-bounce",
            native_schema="starr.bounce-receipt.v1", gate_name="audioQc",
            gate_verdict="sealed", recorded_at="2026-11-10T16:32:24.203Z")

    def test_wrap_and_verify(self):
        env = self._wrapped()
        out = verify.verify(env, artifact_file=os.path.join(FIX, "bounce_sie2.wav"))
        self.assertEqual(out["verdict"], "VERIFIED")

    def test_tampered_native_rejected(self):
        env = self._wrapped()
        env["native"]["measurements"]["integratedLoudnessLufs"] = -1.0
        out = verify.verify(env)
        self.assertEqual(out["verdict"], "REJECTED")

    def test_tampered_envelope_digest_rejected(self):
        env = self._wrapped()
        env["gate"]["verdict"] = "passed-everything"
        out = verify.verify(env)
        self.assertEqual(out["verdict"], "REJECTED")


class TestDetection(unittest.TestCase):
    def test_garbage_is_unverifiable_never_pass(self):
        out = verify.verify({"hello": "world"})
        self.assertEqual(out["verdict"], "UNVERIFIABLE")


if __name__ == "__main__":
    unittest.main()
