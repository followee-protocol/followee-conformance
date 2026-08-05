"""JSONL framing and JSON-profile unit tests (HARNESS.md 7.1 and 7.2)."""

import unittest

from harness.pins import MAX_LINE_BYTES
from harness.strictjson import StrictJsonError, dumps_line, loads_line


class LoadsLineTests(unittest.TestCase):
    def test_valid_request_line(self):
        obj = loads_line(
            b'{"runnerProtocol":"1","caseId":"handshake",'
            b'"operation":"hello","input":{}}'
        )
        self.assertEqual(obj["operation"], "hello")
        self.assertEqual(obj["input"], {})

    def assert_symbol(self, raw: bytes, symbol: str):
        with self.assertRaises(StrictJsonError) as ctx:
            loads_line(raw)
        self.assertEqual(ctx.exception.symbol, symbol)

    def test_duplicate_member_names_rejected(self):
        self.assert_symbol(b'{"a":true,"a":false}', "duplicateJsonName")

    def test_nested_duplicate_member_names_rejected(self):
        self.assert_symbol(b'{"outer":{"a":true,"a":false}}', "duplicateJsonName")

    def test_floats_rejected(self):
        self.assert_symbol(b'{"x":1.5}', "numberForbidden")

    def test_bare_integers_rejected(self):
        self.assert_symbol(b'{"x":0}', "numberForbidden")

    def test_exponent_rejected(self):
        self.assert_symbol(b'{"x":1e3}', "numberForbidden")

    def test_nan_and_infinity_rejected(self):
        self.assert_symbol(b'{"x":NaN}', "malformedJson")
        self.assert_symbol(b'{"x":Infinity}', "malformedJson")

    def test_byte_order_mark_rejected(self):
        self.assert_symbol(b'\xef\xbb\xbf{"a":true}', "byteOrderMark")

    def test_blank_lines_rejected(self):
        self.assert_symbol(b"", "blankLine")
        self.assert_symbol(b"   \t", "blankLine")

    def test_invalid_utf8_rejected(self):
        self.assert_symbol(b'{"a":"\xff"}', "invalidUtf8")

    def test_malformed_json_rejected(self):
        self.assert_symbol(b"{not json", "malformedJson")

    def test_trailing_garbage_rejected(self):
        self.assert_symbol(b'{"a":true} extra', "malformedJson")

    def test_top_level_non_object_rejected(self):
        self.assert_symbol(b'["array"]', "notAnObject")
        self.assert_symbol(b'"string"', "notAnObject")

    def test_line_over_cap_rejected(self):
        raw = b'{"pad":"' + b"a" * MAX_LINE_BYTES + b'"}'
        self.assert_symbol(raw, "lineTooLong")

    def test_line_at_cap_allowed(self):
        pad = MAX_LINE_BYTES - len(b'{"pad":""}')
        raw = b'{"pad":"' + b"a" * pad + b'"}'
        self.assertEqual(len(raw), MAX_LINE_BYTES)
        self.assertEqual(len(loads_line(raw)["pad"]), pad)


class DumpsLineTests(unittest.TestCase):
    def test_single_compact_line(self):
        line = dumps_line({"caseId": "x", "input": {"a": ["b", True, None]}})
        self.assertTrue(line.endswith(b"\n"))
        self.assertEqual(line.count(b"\n"), 1)
        self.assertEqual(
            loads_line(line[:-1]),
            {"caseId": "x", "input": {"a": ["b", True, None]}},
        )

    def test_numbers_refused_on_encode(self):
        for bad in [{"x": 1}, {"x": 1.5}, {"deep": {"list": [0]}}]:
            with self.assertRaises(StrictJsonError) as ctx:
                dumps_line(bad)
            self.assertEqual(ctx.exception.symbol, "numberForbidden")

    def test_non_object_refused_on_encode(self):
        with self.assertRaises(StrictJsonError):
            dumps_line(["not", "an", "object"])  # type: ignore[arg-type]

    def test_oversized_encode_refused(self):
        with self.assertRaises(StrictJsonError) as ctx:
            dumps_line({"pad": "a" * MAX_LINE_BYTES})
        self.assertEqual(ctx.exception.symbol, "lineTooLong")


if __name__ == "__main__":
    unittest.main()
