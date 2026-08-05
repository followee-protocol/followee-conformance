"""Adapter supervision tests: every misbehavior mode is classified as an
infrastructure failure with a stable harness.* symbol (HARNESS.md 7.1, 18,
19), never as a Followee rejection."""

import sys
import tempfile
import unittest
from pathlib import Path

from harness.adapterproc import AdapterFailure, AdapterProcess

FAKE_ADAPTER = Path(__file__).resolve().parent / "fake_adapter.py"

HELLO = {
    "runnerProtocol": "1",
    "caseId": "handshake",
    "operation": "hello",
    "input": {},
}


class AdapterProcessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="followee-adapter-")
        self.addCleanup(self._tmp.cleanup)
        self.cwd = Path(self._tmp.name)

    def spawn(self, mode: str, timeout: float = 5.0) -> AdapterProcess:
        proc = AdapterProcess(
            f"fake-{mode}",
            [sys.executable, "-B", str(FAKE_ADAPTER), mode],
            self.cwd,
            timeout=timeout,
        )
        proc.start()
        self.addCleanup(proc.kill)
        return proc

    def assert_failure(self, mode: str, symbol: str, timeout: float = 5.0):
        proc = self.spawn(mode, timeout=timeout)
        with self.assertRaises(AdapterFailure) as ctx:
            proc.request(HELLO)
        self.assertEqual(ctx.exception.symbol, symbol)
        return ctx.exception

    def test_well_behaved_adapter_round_trips(self):
        proc = self.spawn("ok")
        response = proc.request(HELLO)
        self.assertEqual(response["status"], "accepted")
        self.assertEqual(response["caseId"], "handshake")
        proc.shutdown()

    def test_malformed_json_is_harness_failure(self):
        self.assert_failure("malformed", "harness.malformedJson")

    def test_stdout_pollution_is_harness_failure(self):
        # A startup banner before the response is not valid JSON, so the
        # first protocol line fails strict parsing.
        self.assert_failure("garbage-prefix", "harness.malformedJson")

    def test_blank_protocol_line_is_harness_failure(self):
        self.assert_failure("blank-line", "harness.blankLine")

    def test_byte_order_mark_is_harness_failure(self):
        self.assert_failure("bom", "harness.byteOrderMark")

    def test_duplicate_json_names_are_harness_failure(self):
        self.assert_failure("duplicate-keys", "harness.duplicateJsonName")

    def test_float_in_response_is_harness_failure(self):
        self.assert_failure("float", "harness.numberForbidden")

    def test_bare_integer_in_response_is_harness_failure(self):
        self.assert_failure("bare-int", "harness.numberForbidden")

    def test_timeout_is_harness_failure(self):
        self.assert_failure("timeout", "harness.timeout", timeout=0.5)

    def test_crash_is_harness_failure_with_stderr_excerpt(self):
        failure = self.assert_failure("crash", "harness.adapterExited")
        self.assertIn("panic: something went wrong", failure.stderr_excerpt)

    def test_oversized_response_line_is_harness_failure(self):
        self.assert_failure("oversized", "harness.lineTooLong")

    def test_extra_output_after_response_is_harness_failure(self):
        self.assert_failure("extra-output", "harness.extraOutput")

    def test_hang_after_stdin_close_is_harness_failure(self):
        proc = self.spawn("hang-on-shutdown")
        response = proc.request(HELLO)
        self.assertEqual(response["status"], "accepted")
        with self.assertRaises(AdapterFailure) as ctx:
            proc.shutdown(grace=0.5)
        self.assertEqual(ctx.exception.symbol, "harness.shutdownTimeout")

    def test_unclean_exit_is_harness_failure(self):
        proc = self.spawn("unclean-exit")
        proc.request(HELLO)
        with self.assertRaises(AdapterFailure) as ctx:
            proc.shutdown()
        self.assertEqual(ctx.exception.symbol, "harness.adapterExited")

    def test_unstartable_adapter_is_harness_failure(self):
        proc = AdapterProcess("missing", [str(self.cwd / "no-such-binary")], self.cwd)
        with self.assertRaises(AdapterFailure) as ctx:
            proc.start()
        self.assertEqual(ctx.exception.symbol, "harness.adapterStartFailed")

    def test_no_failure_symbol_reuses_followee_vocabulary(self):
        # HARNESS.md Section 11: adapter and runner failures use a separate
        # namespace and never reuse Followee error symbols.
        for mode, symbol in [
            ("malformed", "harness.malformedJson"),
            ("timeout", "harness.timeout"),
        ]:
            failure = self.assert_failure(
                mode, symbol, timeout=0.5 if mode == "timeout" else 5.0
            )
            self.assertTrue(failure.symbol.startswith("harness."))


if __name__ == "__main__":
    unittest.main()
