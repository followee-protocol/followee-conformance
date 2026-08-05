"""Handshake verification and orchestrator refusal tests (HARNESS.md 6, 8).

Covers: pin cross-checking of hello results, campaign refusal on wrong
pins or capabilities, and an end-to-end orchestrator run against fake
adapters that report the correct pins.
"""

import contextlib
import io
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from harness import pins
from harness.orchestrator import (
    HandshakeFailure,
    main,
    verify_hello_response,
)
from harness.schema import load_schema

REPO_ROOT = Path(__file__).resolve().parents[2]


def rust_hello_result() -> dict:
    return {
        "adapter": pins.RUST_ADAPTER_PIN.adapter,
        "adapterVersion": "1",
        "implementationRepository": pins.RUST_ADAPTER_PIN.repository_url,
        "implementationCommit": pins.RUST_COMMIT,
        "specificationCommit": pins.SPECIFICATION_COMMIT,
        "runnerProtocols": ["1"],
        "operations": ["hello"],
    }


def response_with(result: dict) -> dict:
    return {
        "runnerProtocol": "1",
        "caseId": "handshake",
        "status": "accepted",
        "result": result,
    }


class VerifyHelloResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.response_schema = load_schema(REPO_ROOT, "runner-response.schema.json")
        cls.hello_schema = load_schema(REPO_ROOT, "hello-result.schema.json")

    def verify(self, response: dict) -> dict:
        return verify_hello_response(
            response,
            pins.RUST_ADAPTER_PIN,
            self.response_schema,
            self.hello_schema,
        )

    def assert_symbol(self, response: dict, symbol: str):
        with self.assertRaises(HandshakeFailure) as ctx:
            self.verify(response)
        self.assertEqual(ctx.exception.symbol, symbol)

    def test_correctly_pinned_response_verifies(self):
        result = self.verify(response_with(rust_hello_result()))
        self.assertEqual(result["implementationCommit"], pins.RUST_COMMIT)

    def test_case_id_must_echo_exactly(self):
        response = response_with(rust_hello_result())
        response["caseId"] = "some-other-case"
        self.assert_symbol(response, "harness.caseIdMismatch")

    def test_wrong_runner_protocol_fails_schema(self):
        response = response_with(rust_hello_result())
        response["runnerProtocol"] = "2"
        self.assert_symbol(response, "harness.responseSchemaViolation")

    def test_rejected_handshake_is_a_failure(self):
        self.assert_symbol(
            {
                "runnerProtocol": "1",
                "caseId": "handshake",
                "status": "rejected",
                "error": "internalError",
            },
            "harness.handshakeRejected",
        )

    def test_adapter_error_handshake_is_a_failure(self):
        self.assert_symbol(
            {
                "runnerProtocol": "1",
                "caseId": "handshake",
                "status": "adapterError",
                "error": "adapter.startupFailed",
                "message": "boom",
            },
            "harness.handshakeRejected",
        )

    def test_wrong_implementation_commit_refused(self):
        result = rust_hello_result()
        result["implementationCommit"] = "0" * 40
        self.assert_symbol(response_with(result), "harness.pinMismatch")

    def test_wrong_specification_commit_refused(self):
        result = rust_hello_result()
        result["specificationCommit"] = "0" * 40
        self.assert_symbol(response_with(result), "harness.pinMismatch")

    def test_wrong_adapter_name_refused(self):
        result = rust_hello_result()
        result["adapter"] = "followee-python-cleanroom"
        self.assert_symbol(response_with(result), "harness.pinMismatch")

    def test_wrong_repository_refused(self):
        result = rust_hello_result()
        result["implementationRepository"] = "https://example.invalid/fork"
        self.assert_symbol(response_with(result), "harness.pinMismatch")

    def test_missing_runner_protocol_capability_refused(self):
        result = rust_hello_result()
        result["runnerProtocols"] = ["2"]
        self.assert_symbol(response_with(result), "harness.capabilityMismatch")

    def test_milestone_0_operation_set_is_exact(self):
        # No Followee protocol operation may be claimed yet (HARNESS.md
        # Section 20, Milestone 0 acceptance).
        result = rust_hello_result()
        result["operations"] = ["hello", "deriveIdentity"]
        self.assert_symbol(response_with(result), "harness.capabilityMismatch")

    def test_unknown_result_member_refused(self):
        result = rust_hello_result()
        result["buildHost"] = "leak"
        self.assert_symbol(response_with(result), "harness.helloSchemaViolation")

    def test_missing_result_member_refused(self):
        result = rust_hello_result()
        del result["specificationCommit"]
        self.assert_symbol(response_with(result), "harness.helloSchemaViolation")

    def test_uppercase_commit_refused(self):
        result = rust_hello_result()
        result["implementationCommit"] = pins.RUST_COMMIT.upper()
        self.assert_symbol(response_with(result), "harness.helloSchemaViolation")


FAKE_TEMPLATE = """#!/usr/bin/env python3
import json, sys
result = {result!r}
for line in sys.stdin:
    req = json.loads(line)
    print(json.dumps({{
        "runnerProtocol": "1",
        "caseId": req["caseId"],
        "status": "accepted",
        "result": result,
    }}, separators=(",", ":")), flush=True)
"""


class OrchestratorEndToEndTests(unittest.TestCase):
    """Full orchestrator runs against fake adapters.

    Integrity checks run against the real repository, so these tests also
    prove the actual checkout satisfies every pin before any handshake.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="followee-orch-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)

    def write_fake(self, name: str, result: dict) -> Path:
        script = self.tmp / f"{name}.py"
        script.write_text(FAKE_TEMPLATE.format(result=result))
        wrapper = self.tmp / name
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" -B "{script}" "$@"\n')
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        return wrapper

    def run_main(self, rust_result: dict, python_result: dict):
        rust = self.write_fake("fake-rust", rust_result)
        python = self.tmp / "fake-python.py"
        python.write_text(FAKE_TEMPLATE.format(result=python_result))
        stderr = io.StringIO()
        stdout = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            code = main(
                [
                    "--repo-root",
                    str(REPO_ROOT),
                    "--rust-adapter",
                    str(rust),
                    "--python-adapter",
                    str(python),
                ]
            )
        return code, stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def python_hello_result() -> dict:
        return {
            "adapter": pins.PYTHON_ADAPTER_PIN.adapter,
            "adapterVersion": "1",
            "implementationRepository": (pins.PYTHON_ADAPTER_PIN.repository_url),
            "implementationCommit": pins.PYTHON_COMMIT,
            "specificationCommit": pins.SPECIFICATION_COMMIT,
            "runnerProtocols": ["1"],
            "operations": ["hello"],
        }

    def test_correct_pins_complete_both_handshakes(self):
        code, out, err = self.run_main(rust_hello_result(), self.python_hello_result())
        self.assertEqual(code, 0, err)
        self.assertIn("integrity:", out)
        self.assertIn("handshake[rust]", out)
        self.assertIn("handshake[python]", out)

    def test_wrong_implementation_commit_fails_campaign(self):
        bad = rust_hello_result()
        bad["implementationCommit"] = "0" * 40
        code, _, err = self.run_main(bad, self.python_hello_result())
        self.assertEqual(code, 3)
        self.assertIn("harness.pinMismatch", err)

    def test_wrong_specification_commit_fails_campaign(self):
        bad = self.python_hello_result()
        bad["specificationCommit"] = "f" * 40
        code, _, err = self.run_main(rust_hello_result(), bad)
        self.assertEqual(code, 3)
        self.assertIn("harness.pinMismatch", err)


if __name__ == "__main__":
    unittest.main()
