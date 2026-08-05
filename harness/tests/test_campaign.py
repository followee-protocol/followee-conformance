"""End-to-end campaign tests with scripted fake adapters.

These prove, through the real campaign pipeline (case loading, digest
verification, handshake, execution, comparison, artifact writing), that a
one-byte disagreement, a one-field disagreement, an acceptance
disagreement, and an error-classification disagreement each fail the
campaign and produce a self-contained disagreement artifact.
"""

import contextlib
import hashlib
import io
import json
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from harness import campaign, chained, pins

REPO_ROOT = Path(__file__).resolve().parents[2]
FAKE_SCRIPT = Path(__file__).resolve().parent / "fake_scripted_adapter.py"

ZERO32 = "00" * 32
GOOD_RESULT = {
    "rootPublicKeyHex": "aa" * 32,
    "revocationPublicKeyHex": "bb" * 32,
    "revocationPublicKeyCborHex": "a20032015820" + "bb" * 32,
    "revocationCommitmentHex": "cc" * 32,
    "authorityDescriptorCborHex": "a300",
    "authorityDescriptorDigestHex": "dd" * 32,
    "did": "did:flw:z1111",
}


CHAIN_ID = chained.SCENARIOS[0]["id"]
CHAIN_DID = "did:flw:z1111"
CHAIN_ENVELOPE = "d200"


def chain_author_result() -> dict:
    return {
        "did": CHAIN_DID,
        "recordBodyCborHex": "a600",
        "recordBodyDigestHex": "11" * 32,
        "sigStructureHex": "8400",
        "signatureHex": "22" * 64,
        "envelopeHex": CHAIN_ENVELOPE,
    }


def chain_verify_result(stale: bool) -> dict:
    return {
        "envelopeHex": CHAIN_ENVELOPE,
        "recordBodyCborHex": "a600",
        "recordBodyDigestHex": "11" * 32,
        "id": CHAIN_DID,
        "timestampMs": chained.AUTHOR_TIMESTAMP_MS,
        "authority": "root",
        "validUntilMs": chained.VALID_UNTIL_MS,
        "premature": False,
        "stale": stale,
        "record": {
            "protocolVersion": "1",
            "id": CHAIN_DID,
            "timestampMs": chained.AUTHOR_TIMESTAMP_MS,
            "authority": "root",
            "authorityDescriptor": {
                "descriptorVersion": "1",
                "rootKey": {"suite": "-19", "publicKeyHex": "aa" * 32},
                "revocationCommitmentHex": "cc" * 32,
            },
            "revocationKey": None,
            "validUntilMs": chained.VALID_UNTIL_MS,
            "contact": {
                "displayName": None,
                "summary": None,
                "avatar": None,
                "alsoKnownAs": [],
                "services": [],
                "migration": None,
                "extensions": {},
            },
            "extensions": {},
        },
    }


def chained_responses(after_horizon_stale: bool = True):
    def build() -> dict:
        return {
            f"{CHAIN_ID}-author": {
                "status": "accepted",
                "result": chain_author_result(),
            },
            f"{CHAIN_ID}-verify-at-horizon": {
                "status": "accepted",
                "result": chain_verify_result(False),
            },
            f"{CHAIN_ID}-verify-after-horizon": {
                "status": "accepted",
                "result": chain_verify_result(after_horizon_stale),
            },
        }

    return build(), build()


def hello_result(pin: pins.AdapterPin) -> dict:
    return {
        "adapter": pin.adapter,
        "adapterVersion": "1",
        "implementationRepository": pin.repository_url,
        "implementationCommit": pin.implementation_commit,
        "specificationCommit": pins.SPECIFICATION_COMMIT,
        "runnerProtocols": ["1"],
        "operations": list(pins.SUPPORTED_OPERATIONS),
    }


def case_manifest(case_id: str, expected: dict) -> dict:
    return {
        "id": case_id,
        "runnerProtocol": "1",
        "operation": "deriveIdentity",
        "specificationCommit": pins.SPECIFICATION_COMMIT,
        "specificationSections": ["Appendix B.2"],
        "derivationStatus": "specification",
        "faultProfile": "none" if expected["outcome"] == "accepted" else "single",
        "expected": expected,
        "input": {"rootSeedHex": ZERO32, "revocationSeedHex": ZERO32},
    }


class CampaignEndToEndTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="followee-campaign-test-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.cases_dir = self.tmp / "cases"
        self.report_dir = self.tmp / "reports"
        self.cases_dir.mkdir()

    def write_cases(self, manifests: list[dict]) -> None:
        files = {f"{m['id']}.json": json.dumps(m, indent=2) + "\n" for m in manifests}
        for name, content in files.items():
            (self.cases_dir / name).write_text(content)
        digest_lines = [
            f"{hashlib.sha256(content.encode()).hexdigest()}  {name}"
            for name, content in sorted(files.items())
        ]
        (self.cases_dir / "DIGESTS.sha256").write_text("\n".join(digest_lines) + "\n")

    def write_adapter(self, name: str, pin: pins.AdapterPin, responses: dict) -> Path:
        script = self.tmp / f"{name}.py"
        shutil.copy(FAKE_SCRIPT, script)
        (self.tmp / f"{name}.responses.json").write_text(
            json.dumps({"hello": hello_result(pin), "cases": responses})
        )
        return script

    def run_campaign(
        self,
        rust_responses: dict,
        python_responses: dict,
        only: str | None = None,
    ):
        rust_script = self.write_adapter(
            "fake-rust", pins.RUST_ADAPTER_PIN, rust_responses
        )
        python_script = self.write_adapter(
            "fake-python", pins.PYTHON_ADAPTER_PIN, python_responses
        )
        wrapper = self.tmp / "fake-rust"
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" -B "{rust_script}" "$@"\n'
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = campaign.main(
                [
                    "--repo-root",
                    str(REPO_ROOT),
                    "--cases",
                    str(self.cases_dir),
                    "--report-dir",
                    str(self.report_dir),
                    "--rust-adapter",
                    str(wrapper),
                    "--python-adapter",
                    str(python_script),
                ]
                + (["--only", only] if only else [])
            )
        return code, stdout.getvalue(), stderr.getvalue()

    def artifact(self, case_id: str) -> dict:
        path = self.report_dir / f"disagreement-{case_id}.json"
        self.assertTrue(path.is_file(), f"artifact for {case_id} written")
        return json.loads(path.read_text())

    def test_agreement_passes(self):
        self.write_cases([case_manifest("agree-1", {"outcome": "accepted"})])
        accepted = {"status": "accepted", "result": GOOD_RESULT}
        code, out, err = self.run_campaign(
            {"agree-1": accepted}, {"agree-1": accepted}, only="agree-1"
        )
        self.assertEqual(code, 0, err)
        self.assertIn("campaign PASSED", out)

    def test_one_byte_disagreement_fails_with_artifact(self):
        self.write_cases([case_manifest("byte-1", {"outcome": "accepted"})])
        mutated = dict(GOOD_RESULT)
        mutated["rootPublicKeyHex"] = "ab" + GOOD_RESULT["rootPublicKeyHex"][2:]
        code, _, err = self.run_campaign(
            {"byte-1": {"status": "accepted", "result": GOOD_RESULT}},
            {"byte-1": {"status": "accepted", "result": mutated}},
            only="byte-1",
        )
        self.assertEqual(code, 3)
        self.assertIn("resultEquality", err)
        artifact = self.artifact("byte-1")
        self.assertEqual(artifact["failedRules"][0]["path"], "rootPublicKeyHex")
        self.assertIn("reproduceCommand", artifact)
        self.assertIn("environment", artifact)

    def test_one_field_disagreement_fails(self):
        self.write_cases([case_manifest("field-1", {"outcome": "accepted"})])
        mutated = dict(GOOD_RESULT)
        mutated["did"] = "did:flw:z2222"
        code, _, _ = self.run_campaign(
            {"field-1": {"status": "accepted", "result": GOOD_RESULT}},
            {"field-1": {"status": "accepted", "result": mutated}},
            only="field-1",
        )
        self.assertEqual(code, 3)
        self.assertEqual(self.artifact("field-1")["failedRules"][0]["path"], "did")

    def test_acceptance_disagreement_fails(self):
        self.write_cases([case_manifest("accept-1", {"outcome": "accepted"})])
        code, _, _ = self.run_campaign(
            {"accept-1": {"status": "accepted", "result": GOOD_RESULT}},
            {"accept-1": {"status": "rejected", "error": "invalidDid"}},
            only="accept-1",
        )
        self.assertEqual(code, 3)
        self.assertEqual(
            self.artifact("accept-1")["failedRules"][0]["rule"], "acceptance"
        )

    def test_error_classification_disagreement_fails_under_exact(self):
        self.write_cases(
            [
                case_manifest(
                    "error-1",
                    {
                        "outcome": "rejected",
                        "errorAssertion": "exact",
                        "error": "invalidDid",
                    },
                )
            ]
        )
        code, _, _ = self.run_campaign(
            {"error-1": {"status": "rejected", "error": "invalidDid"}},
            {"error-1": {"status": "rejected", "error": "schemaViolation"}},
            only="error-1",
        )
        self.assertEqual(code, 3)
        self.assertEqual(
            self.artifact("error-1")["failedRules"][0]["rule"], "exactError"
        )

    def test_differing_symbols_under_unspecified_assertion_agree(self):
        self.write_cases(
            [
                case_manifest(
                    "unspec-1",
                    {"outcome": "rejected", "errorAssertion": "unspecified"},
                )
            ]
        )
        code, out, _ = self.run_campaign(
            {"unspec-1": {"status": "rejected", "error": "nonDeterministicCbor"}},
            {"unspec-1": {"status": "rejected", "error": "schemaViolation"}},
            only="unspec-1",
        )
        self.assertEqual(code, 0)
        self.assertIn("rejection-only comparisons: 1", out)

    def test_chained_stale_scenario_with_correct_flags_passes(self):
        self.write_cases([])
        code, out, err = self.run_campaign(*chained_responses(), only=CHAIN_ID)
        self.assertEqual(code, 0, err)
        self.assertIn("chained scenarios:         1 (3 steps", out)

    def test_chained_hard_coded_stale_fails_with_artifact(self):
        # An adapter pair agreeing on stale=false past the horizon (a
        # hard-coded stale result) must fail the normative expectation.
        self.write_cases([])
        rust, python = chained_responses(after_horizon_stale=False)
        code, _, _ = self.run_campaign(rust, python, only=CHAIN_ID)
        self.assertEqual(code, 3)
        artifact = self.artifact("chain-valid-until-stale-verify-after-horizon")
        self.assertEqual(artifact["failedRules"][0]["rule"], "specificationExpectation")
        self.assertEqual(artifact["failedRules"][0]["path"], "expectedResult.stale")
        self.assertIn("not specification-published", artifact["manifest"]["provenance"])

    def test_chained_inverted_stale_between_adapters_fails(self):
        self.write_cases([])
        rust, python = chained_responses()
        # Invert only the Python adapter's stale flag at the horizon step.
        at_horizon = "chain-valid-until-stale-verify-at-horizon"
        python[at_horizon]["result"]["stale"] = True
        code, _, _ = self.run_campaign(rust, python, only=CHAIN_ID)
        self.assertEqual(code, 3)
        artifact = self.artifact(at_horizon)
        self.assertEqual(artifact["failedRules"][0]["rule"], "resultEquality")
        self.assertEqual(artifact["failedRules"][0]["path"], "stale")

    def test_chained_author_disagreement_aborts_the_verify_steps(self):
        # If the authorRecord outputs do not agree, no envelope is fed
        # onward: only the author step runs and fails.
        self.write_cases([])
        rust, python = chained_responses()
        python["chain-valid-until-stale-author"]["result"]["envelopeHex"] = "d2ff"
        code, out, _ = self.run_campaign(rust, python, only=CHAIN_ID)
        self.assertEqual(code, 3)
        self.assertIn("(1 steps", out)
        self.assertFalse(
            (
                self.report_dir
                / "disagreement-chain-valid-until-stale-verify-at-horizon.json"
            ).exists()
        )

    def test_tampered_case_file_is_refused_before_execution(self):
        self.write_cases([case_manifest("agree-1", {"outcome": "accepted"})])
        path = self.cases_dir / "agree-1.json"
        path.write_text(path.read_text().replace("Appendix B.2", "Appendix X"))
        accepted = {"status": "accepted", "result": GOOD_RESULT}
        code, _, err = self.run_campaign(
            {"agree-1": accepted}, {"agree-1": accepted}, only="agree-1"
        )
        self.assertEqual(code, 2)
        self.assertIn("contentDigestMismatch", err)


if __name__ == "__main__":
    unittest.main()
