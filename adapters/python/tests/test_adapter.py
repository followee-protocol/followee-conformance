"""Unit and process tests for the Python Milestone 1 adapter.

Operation tests drive the adapter with committed specification-status
inputs and assert every published expected-result member (HARNESS.md
Milestone 1 acceptance: every result field is compared and covered by an
adapter test).  Process tests exercise the real pinned checkout,
fresh-process repeatability, and framing behavior.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ADAPTER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = ADAPTER_DIR.parents[1]
CASES_DIR = REPO_ROOT / "cases" / "specification"
ADAPTER = ADAPTER_DIR / "adapter.py"

sys.path.insert(0, str(ADAPTER_DIR))
import adapter

RUST_COMMIT = "774acb7578795cf6d58f77b76b16ef010114ebd6"
PYTHON_COMMIT = "a39138dae8072c7b89dc922bcfe6f5717312c6e6"
SPEC_COMMIT = "abc9a55d90f1026e6509207abda73e5dc6d14241"

IDENTITY = {
    "adapter": "followee-python-cleanroom",
    "adapterVersion": "1",
    "implementationRepository": (
        "https://github.com/followee-protocol/followee-python-cleanroom"
    ),
    "implementationCommit": PYTHON_COMMIT,
    "specificationCommit": SPEC_COMMIT,
    "runnerProtocols": ["1"],
    "operations": ["hello", "deriveIdentity", "authorRecord", "verifyRecord"],
}

MODEL = adapter.load_model()


def load_case(case_id: str) -> dict:
    return json.loads((CASES_DIR / f"{case_id}.json").read_text())


def hello_line(case_id: str = "handshake") -> bytes:
    return json.dumps(
        {
            "runnerProtocol": "1",
            "caseId": case_id,
            "operation": "hello",
            "input": {},
        }
    ).encode()


def request_line(case: dict) -> bytes:
    return json.dumps(
        {
            "runnerProtocol": "1",
            "caseId": case["id"],
            "operation": case["operation"],
            "input": case["input"],
        }
    ).encode()


class OperationTests(unittest.TestCase):
    """The three protocol operations against published Appendix B values."""

    def run_case(self, case_id: str) -> tuple[dict, dict]:
        case = load_case(case_id)
        response = adapter.handle_line(IDENTITY, MODEL, request_line(case), False)
        return case, response

    def assert_expected_result(self, case_id: str):
        case, response = self.run_case(case_id)
        self.assertEqual(response["status"], "accepted", response)
        for member, value in case["expectedResult"].items():
            self.assertEqual(response["result"][member], value, f"{case_id}: {member}")
        return response["result"]

    def test_derive_identity_reproduces_appendix_b2_b3_exactly(self):
        result = self.assert_expected_result("derive-identity-alice")
        # Every deriveIdentity result member is pinned by the manifest.
        self.assertEqual(len(result), 7)

    def test_derive_identity_attacker_keys(self):
        self.assert_expected_result("derive-identity-attacker")

    def test_author_record_reproduces_appendix_b4_exactly(self):
        result = self.assert_expected_result("author-b4-root")
        self.assertEqual(len(result), 6)

    def test_author_record_reproduces_appendix_b5_exactly(self):
        self.assert_expected_result("author-b5-root-revoked")

    def test_author_record_reproduces_appendix_b6_digests(self):
        self.assert_expected_result("author-b6-alice-a")
        self.assert_expected_result("author-b6-alice-b")

    def test_verify_record_reproduces_appendix_b4_exactly(self):
        result = self.assert_expected_result("verify-b4-root")
        self.assertEqual(len(result), 10)
        self.assertEqual(result["record"]["contact"]["services"][0]["label"], "Writing")

    def test_verify_record_reproduces_appendix_b5_exactly(self):
        result = self.assert_expected_result("verify-b5-root-revoked")
        self.assertIsNotNone(result["record"]["revocationKey"])

    def test_verify_record_premature_classification(self):
        self.assert_expected_result("verify-b4-premature")
        self.assert_expected_result("verify-b4-premature-boundary")
        self.assert_expected_result("verify-b4-now-max-uint64")

    def test_descriptor_substitution_rejected_with_exact_error(self):
        case, response = self.run_case("verify-b8-descriptor-substitution")
        self.assertEqual(response["status"], "rejected")
        self.assertEqual(response["error"], case["expected"]["error"])

    def test_wrong_target_rejected_with_identity_binding_mismatch(self):
        _, response = self.run_case("verify-b7-binding-wrong-target")
        self.assertEqual(response["status"], "rejected")
        self.assertEqual(response["error"], "identityBindingMismatch")

    def test_invalid_did_targets_rejected_exactly(self):
        for case_id in (
            "verify-did-percent-encoded",
            "verify-did-uppercase-prefix",
            "verify-did-invalid-alphabet",
            "verify-did-missing-multibase-prefix",
            "verify-did-empty",
        ):
            _, response = self.run_case(case_id)
            self.assertEqual(response["status"], "rejected", case_id)
            self.assertEqual(response["error"], "invalidDid", case_id)

    def test_all_envelope_mutants_rejected(self):
        for path in sorted(CASES_DIR.glob("verify-b7-*.json")):
            case = json.loads(path.read_text())
            if case["expected"]["outcome"] != "rejected":
                continue
            response = adapter.handle_line(IDENTITY, MODEL, request_line(case), False)
            self.assertEqual(response["status"], "rejected", case["id"])

    def test_relative_uri_authoring_rejected(self):
        _, response = self.run_case("author-uri-relative-path")
        self.assertEqual(response["status"], "rejected")

    def test_incoherent_signing_seed_is_adapter_error_not_rejection(self):
        case = load_case("author-b4-root")
        case["input"]["signingSeed"] = "revocation"
        case["id"] = "incoherent"
        response = adapter.handle_line(IDENTITY, MODEL, request_line(case), False)
        self.assertEqual(response["status"], "adapterError")
        self.assertEqual(response["error"], "adapter.signingKeyMismatch")

    def test_duplicate_typed_map_keys_are_unrepresentable(self):
        case = load_case("author-b4-root")
        case["id"] = "dup-keys"
        case["input"]["extensions"] = {
            "https://ext.example/x": {
                "type": "map",
                "entries": [
                    {
                        "key": {"type": "uint", "value": "1"},
                        "value": {"type": "null"},
                    },
                    {
                        "key": {"type": "uint", "value": "1"},
                        "value": {"type": "null"},
                    },
                ],
            }
        }
        response = adapter.handle_line(IDENTITY, MODEL, request_line(case), False)
        self.assertEqual(response["status"], "adapterError")
        self.assertEqual(response["error"], "adapter.unrepresentableInput")

    def test_input_contract_violations_are_adapter_errors(self):
        base = load_case("derive-identity-alice")["input"]
        violations = [
            {**base, "rootSeedHex": base["rootSeedHex"].upper()},
            {**base, "rootSeedHex": base["rootSeedHex"][:-2]},
            {**base, "extra": "member"},
            {"rootSeedHex": base["rootSeedHex"]},
        ]
        for bad_input in violations:
            request = json.dumps(
                {
                    "runnerProtocol": "1",
                    "caseId": "bad",
                    "operation": "deriveIdentity",
                    "input": bad_input,
                }
            ).encode()
            response = adapter.handle_line(IDENTITY, MODEL, request, False)
            self.assertEqual(response["status"], "adapterError", bad_input)
            self.assertEqual(response["error"], "adapter.invalidInput")

    def test_non_canonical_decimal_is_adapter_error(self):
        case = load_case("verify-b4-root")
        case["id"] = "bad-now"
        case["input"]["nowMs"] = "01785589200123"
        response = adapter.handle_line(IDENTITY, MODEL, request_line(case), False)
        self.assertEqual(response["status"], "adapterError")
        self.assertEqual(response["error"], "adapter.invalidInput")

    def test_now_ms_beyond_uint64_is_adapter_error(self):
        case = load_case("verify-b4-root")
        case["id"] = "big-now"
        case["input"]["nowMs"] = "18446744073709551616"
        response = adapter.handle_line(IDENTITY, MODEL, request_line(case), False)
        self.assertEqual(response["status"], "adapterError")


class HandleLineFramingTests(unittest.TestCase):
    def handle(self, raw: bytes, truncated: bool = False) -> dict:
        return adapter.handle_line(IDENTITY, MODEL, raw, truncated)

    def test_hello_accepted(self):
        response = self.handle(hello_line())
        self.assertEqual(response["status"], "accepted")
        self.assertEqual(response["result"], IDENTITY)

    def assert_adapter_error(self, raw: bytes, symbol: str, truncated=False):
        response = self.handle(raw, truncated)
        self.assertEqual(response["status"], "adapterError")
        self.assertEqual(response["error"], symbol)
        return response

    def test_malformed_json(self):
        self.assert_adapter_error(b"{not json", "adapter.malformedRequest")

    def test_blank_line(self):
        self.assert_adapter_error(b"", "adapter.malformedRequest")

    def test_byte_order_mark(self):
        self.assert_adapter_error(
            b"\xef\xbb\xbf" + hello_line(), "adapter.malformedRequest"
        )

    def test_duplicate_member(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","runnerProtocol":"1",'
            b'"caseId":"x","operation":"hello","input":{}}',
            "adapter.malformedRequest",
        )

    def test_bare_number(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"hello","input":{"n":5}}',
            "adapter.malformedRequest",
        )

    def test_unknown_member(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"hello",'
            b'"input":{},"extra":true}',
            "adapter.malformedRequest",
        )

    def test_wrong_protocol_echoed(self):
        response = self.assert_adapter_error(
            b'{"runnerProtocol":"9","caseId":"x","operation":"hello","input":{}}',
            "adapter.unsupportedProtocol",
        )
        self.assertEqual(response["runnerProtocol"], "9")

    def test_unsupported_operation_is_not_a_followee_rejection(self):
        response = self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"selectCurrent",'
            b'"input":{}}',
            "adapter.unsupportedOperation",
        )
        self.assertNotEqual(response["status"], "rejected")

    def test_truncated_line(self):
        self.assert_adapter_error(b"", "adapter.lineTooLong", truncated=True)


class AdapterProcessTests(unittest.TestCase):
    """End-to-end runs of the real adapter against the pinned checkout."""

    def run_adapter(self, stdin: bytes):
        proc = subprocess.run(
            [sys.executable, "-B", str(ADAPTER)],
            input=stdin,
            capture_output=True,
            timeout=120,
            check=False,
        )
        lines = proc.stdout.split(b"\n")
        self.assertEqual(lines[-1], b"", "output ends with a newline")
        return [json.loads(line) for line in lines[:-1]], proc

    def test_hello_reports_the_pinned_identity(self):
        responses, proc = self.run_adapter(hello_line() + b"\n")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(responses[0]["result"], IDENTITY)

    def test_fresh_process_repeatability_for_protocol_operations(self):
        case = load_case("author-b4-root")
        stdin = request_line(case) + b"\n"
        first, _ = self.run_adapter(stdin)
        second, _ = self.run_adapter(stdin)
        self.assertEqual(first, second)
        self.assertEqual(first[0]["status"], "accepted")

    def test_survives_malformed_line_between_requests(self):
        responses, proc = self.run_adapter(b"garbage\n" + hello_line("after") + b"\n")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(responses[0]["status"], "adapterError")
        self.assertEqual(responses[1]["caseId"], "after")

    def test_oversized_line_is_drained_and_classified(self):
        huge = (
            b'{"runnerProtocol":"1","caseId":"big","operation":"hello",'
            b'"input":{"pad":"' + b"a" * (1024 * 1024 + 64) + b'"}}'
        )
        responses, proc = self.run_adapter(huge + b"\n" + hello_line("after") + b"\n")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(responses[0]["error"], "adapter.lineTooLong")
        self.assertEqual(responses[1]["caseId"], "after")

    def test_stdout_is_protocol_only_and_submodule_stays_clean(self):
        _, proc = self.run_adapter(hello_line() + b"\n")
        # Diagnostics may only appear on stderr (HARNESS.md 7.1); a clean
        # run emits none.
        self.assertEqual(proc.stderr, b"")
        status = subprocess.run(
            [
                "git",
                "-C",
                str(REPO_ROOT / "implementations/followee-python-cleanroom"),
                "status",
                "--porcelain",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(
            status.stdout, "", "adapter must not dirty the frozen submodule"
        )


if __name__ == "__main__":
    unittest.main()
