"""Unit and process tests for the Python Milestone 0 adapter.

The process tests exercise the real pinned checkout: the adapter's hello
identity must equal the HARNESS.md Section 2 pins, and a fresh process
must reproduce the identical response (fresh-process repeatability,
HARNESS.md 14.7).
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ADAPTER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = ADAPTER_DIR.parents[1]
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
    "operations": ["hello"],
}


def hello_line(case_id: str = "handshake") -> bytes:
    return json.dumps(
        {
            "runnerProtocol": "1",
            "caseId": case_id,
            "operation": "hello",
            "input": {},
        }
    ).encode()


class HandleLineTests(unittest.TestCase):
    def handle(self, raw: bytes, truncated: bool = False) -> dict:
        return adapter.handle_line(IDENTITY, raw, truncated)

    def test_hello_accepted(self):
        response = self.handle(hello_line())
        self.assertEqual(response["status"], "accepted")
        self.assertEqual(response["caseId"], "handshake")
        self.assertEqual(response["result"], IDENTITY)

    def assert_adapter_error(self, raw: bytes, symbol: str, truncated=False):
        response = self.handle(raw, truncated)
        self.assertEqual(response["status"], "adapterError")
        self.assertEqual(response["error"], symbol)
        self.assertTrue(response["error"].startswith("adapter."))
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

    def test_unknown_member(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"hello",'
            b'"input":{},"extra":true}',
            "adapter.malformedRequest",
        )

    def test_missing_member(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"hello"}',
            "adapter.malformedRequest",
        )

    def test_bare_number(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"hello","input":{"n":5}}',
            "adapter.malformedRequest",
        )

    def test_float(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"hello",'
            b'"input":{"n":1.5}}',
            "adapter.malformedRequest",
        )

    def test_non_object(self):
        self.assert_adapter_error(b'["array"]', "adapter.malformedRequest")

    def test_empty_case_id(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"","operation":"hello","input":{}}',
            "adapter.malformedRequest",
        )

    def test_wrong_protocol_echoed(self):
        response = self.assert_adapter_error(
            b'{"runnerProtocol":"9","caseId":"x","operation":"hello","input":{}}',
            "adapter.unsupportedProtocol",
        )
        self.assertEqual(response["runnerProtocol"], "9")
        self.assertEqual(response["caseId"], "x")

    def test_unsupported_operation_is_not_a_followee_rejection(self):
        response = self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"verifyRecord",'
            b'"input":{}}',
            "adapter.unsupportedOperation",
        )
        self.assertNotEqual(response["status"], "rejected")

    def test_nonempty_hello_input(self):
        self.assert_adapter_error(
            b'{"runnerProtocol":"1","caseId":"x","operation":"hello",'
            b'"input":{"a":true}}',
            "adapter.invalidInput",
        )

    def test_truncated_line(self):
        self.assert_adapter_error(b"", "adapter.lineTooLong", truncated=True)


class AdapterProcessTests(unittest.TestCase):
    """End-to-end runs of the real adapter against the pinned checkout."""

    def run_adapter(self, stdin: bytes):
        proc = subprocess.run(
            [sys.executable, "-B", str(ADAPTER)],
            input=stdin,
            capture_output=True,
            timeout=60,
            check=False,
        )
        lines = proc.stdout.split(b"\n")
        self.assertEqual(lines[-1], b"", "output ends with a newline")
        return [json.loads(line) for line in lines[:-1]], proc

    def test_hello_reports_the_pinned_identity(self):
        responses, proc = self.run_adapter(hello_line() + b"\n")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(len(responses), 1)
        response = responses[0]
        self.assertEqual(response["status"], "accepted")
        self.assertEqual(response["result"], IDENTITY)

    def test_fresh_process_repeatability(self):
        first, _ = self.run_adapter(hello_line() + b"\n")
        second, _ = self.run_adapter(hello_line() + b"\n")
        self.assertEqual(first, second)

    def test_two_requests_two_responses_in_order(self):
        responses, proc = self.run_adapter(
            hello_line("first") + b"\n" + hello_line("second") + b"\n"
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual([r["caseId"] for r in responses], ["first", "second"])
        self.assertEqual(responses[0]["result"], responses[1]["result"])

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
