"""Committed-schema validation tests (HARNESS.md Sections 9 and 12)."""

import unittest
from pathlib import Path

from harness.schema import ValidationError, load_schema, validate

REPO_ROOT = Path(__file__).resolve().parents[2]


def hello_result() -> dict:
    return {
        "adapter": "followee-rust",
        "adapterVersion": "1",
        "implementationRepository": (
            "https://github.com/followee-protocol/followee-rs"
        ),
        "implementationCommit": "774acb7578795cf6d58f77b76b16ef010114ebd6",
        "specificationCommit": "abc9a55d90f1026e6509207abda73e5dc6d14241",
        "runnerProtocols": ["1"],
        "operations": ["hello"],
    }


class RequestSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load_schema(REPO_ROOT, "runner-request.schema.json")

    def test_hello_request_valid(self):
        validate(
            {
                "runnerProtocol": "1",
                "caseId": "handshake",
                "operation": "hello",
                "input": {},
            },
            self.schema,
        )

    def test_unknown_member_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                {
                    "runnerProtocol": "1",
                    "caseId": "handshake",
                    "operation": "hello",
                    "input": {},
                    "extra": True,
                },
                self.schema,
            )

    def test_missing_member_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                {"runnerProtocol": "1", "caseId": "x", "operation": "hello"},
                self.schema,
            )

    def test_nonempty_hello_input_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                {
                    "runnerProtocol": "1",
                    "caseId": "x",
                    "operation": "hello",
                    "input": {"seed": "00"},
                },
                self.schema,
            )

    def test_unpinned_protocol_version_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                {
                    "runnerProtocol": "2",
                    "caseId": "x",
                    "operation": "hello",
                    "input": {},
                },
                self.schema,
            )


class ResponseSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load_schema(REPO_ROOT, "runner-response.schema.json")

    def test_accepted_response_valid(self):
        validate(
            {
                "runnerProtocol": "1",
                "caseId": "handshake",
                "status": "accepted",
                "result": hello_result(),
            },
            self.schema,
        )

    def test_rejected_response_valid(self):
        validate(
            {
                "runnerProtocol": "1",
                "caseId": "b7-17a",
                "status": "rejected",
                "error": "schemaViolation",
            },
            self.schema,
        )

    def test_adapter_error_response_valid(self):
        validate(
            {
                "runnerProtocol": "1",
                "caseId": "x",
                "status": "adapterError",
                "error": "adapter.unsupportedOperation",
                "message": "operation not supported",
            },
            self.schema,
        )

    def test_adapter_error_must_not_reuse_followee_symbols(self):
        with self.assertRaises(ValidationError):
            validate(
                {
                    "runnerProtocol": "1",
                    "caseId": "x",
                    "status": "adapterError",
                    "error": "schemaViolation",
                    "message": "wrong namespace",
                },
                self.schema,
            )

    def test_rejected_with_unknown_symbol_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                {
                    "runnerProtocol": "1",
                    "caseId": "x",
                    "status": "rejected",
                    "error": "adapter.something",
                },
                self.schema,
            )

    def test_accepted_with_error_member_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                {
                    "runnerProtocol": "1",
                    "caseId": "x",
                    "status": "accepted",
                    "result": {},
                    "error": "invalidDid",
                },
                self.schema,
            )

    def test_rejected_without_error_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                {"runnerProtocol": "1", "caseId": "x", "status": "rejected"},
                self.schema,
            )


class HelloResultSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load_schema(REPO_ROOT, "hello-result.schema.json")

    def test_valid_result(self):
        validate(hello_result(), self.schema)

    def test_diagnostic_member_allowed(self):
        result = hello_result()
        result["diagnostic"] = {"followeeRust": {"note": "extra"}}
        validate(result, self.schema)

    def test_unknown_member_rejected(self):
        result = hello_result()
        result["buildHost"] = "leaky"
        with self.assertRaises(ValidationError):
            validate(result, self.schema)

    def test_uppercase_commit_rejected(self):
        result = hello_result()
        result["implementationCommit"] = result["implementationCommit"].upper()
        with self.assertRaises(ValidationError):
            validate(result, self.schema)

    def test_short_commit_rejected(self):
        result = hello_result()
        result["implementationCommit"] = "774acb7"
        with self.assertRaises(ValidationError):
            validate(result, self.schema)

    def test_non_canonical_protocol_number_rejected(self):
        result = hello_result()
        result["runnerProtocols"] = ["01"]
        with self.assertRaises(ValidationError):
            validate(result, self.schema)

    def test_unknown_operation_rejected(self):
        result = hello_result()
        result["operations"] = ["hello", "teleport"]
        with self.assertRaises(ValidationError):
            validate(result, self.schema)

    def test_empty_operations_rejected(self):
        result = hello_result()
        result["operations"] = []
        with self.assertRaises(ValidationError):
            validate(result, self.schema)


class CaseManifestSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load_schema(REPO_ROOT, "case-manifest.schema.json")

    @staticmethod
    def manifest(**overrides) -> dict:
        base = {
            "id": "appendix-b4",
            "runnerProtocol": "1",
            "operation": "verifyRecord",
            "input": {"targetDid": "did:flw:example"},
            "specificationCommit": "abc9a55d90f1026e6509207abda73e5dc6d14241",
            "specificationSections": ["B.4"],
            "derivationStatus": "specification",
            "faultProfile": "none",
            "expected": {"outcome": "accepted"},
        }
        base.update(overrides)
        return {k: v for k, v in base.items() if v is not None}

    def test_accepted_manifest_valid(self):
        validate(self.manifest(), self.schema)

    def test_rejected_exact_manifest_valid(self):
        validate(
            self.manifest(
                id="appendix-b7-17a",
                faultProfile="single",
                expected={
                    "outcome": "rejected",
                    "errorAssertion": "exact",
                    "error": "schemaViolation",
                },
            ),
            self.schema,
        )

    def test_rejected_unspecified_manifest_valid(self):
        validate(
            self.manifest(
                faultProfile="multiple",
                expected={
                    "outcome": "rejected",
                    "errorAssertion": "unspecified",
                },
            ),
            self.schema,
        )

    def test_input_path_variant_valid(self):
        validate(
            self.manifest(
                input=None,
                inputPath="cases/specification/appendix-b4.json",
                inputSha256="ab" * 32,
            ),
            self.schema,
        )

    def test_exact_without_error_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                self.manifest(
                    expected={
                        "outcome": "rejected",
                        "errorAssertion": "exact",
                    }
                ),
                self.schema,
            )

    def test_unspecified_with_error_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                self.manifest(
                    expected={
                        "outcome": "rejected",
                        "errorAssertion": "unspecified",
                        "error": "invalidCbor",
                    }
                ),
                self.schema,
            )

    def test_accepted_with_error_fields_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                self.manifest(expected={"outcome": "accepted", "error": "invalidDid"}),
                self.schema,
            )

    def test_both_input_and_input_path_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                self.manifest(
                    inputPath="cases/specification/x.json",
                    inputSha256="ab" * 32,
                ),
                self.schema,
            )

    def test_neither_input_nor_input_path_rejected(self):
        with self.assertRaises(ValidationError):
            validate(self.manifest(input=None), self.schema)

    def test_hello_is_not_a_case_operation(self):
        with self.assertRaises(ValidationError):
            validate(self.manifest(operation="hello"), self.schema)

    def test_wrong_specification_commit_rejected(self):
        with self.assertRaises(ValidationError):
            validate(self.manifest(specificationCommit="0" * 40), self.schema)

    def test_adapter_error_is_never_an_expected_outcome(self):
        with self.assertRaises(ValidationError):
            validate(
                self.manifest(expected={"outcome": "adapterError"}),
                self.schema,
            )


if __name__ == "__main__":
    unittest.main()
