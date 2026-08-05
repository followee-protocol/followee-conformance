"""Committed-schema validation tests (HARNESS.md Sections 9 and 12)."""

import json
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

    def test_operation_outside_the_enum_rejected(self):
        with self.assertRaises(ValidationError):
            validate(
                {
                    "runnerProtocol": "1",
                    "caseId": "x",
                    "operation": "selectCurrent",
                    "input": {},
                },
                self.schema,
            )

    def test_nonempty_hello_input_rejected_by_operations_schema(self):
        operations = load_schema(REPO_ROOT, "operations.schema.json")
        validate({}, operations["$defs"]["helloInput"], root=operations)
        with self.assertRaises(ValidationError):
            validate(
                {"seed": "00"},
                operations["$defs"]["helloInput"],
                root=operations,
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

    @staticmethod
    def derived_from(resigned: bool, key: str | None) -> dict:
        derivation = {
            "baseVector": "appendix-b4",
            "mutation": "flip byte 17 of the protected header",
            "protectedBytesChanged": True,
            "payloadBytesChanged": False,
            "resigned": resigned,
        }
        if key is not None:
            derivation["resignedKey"] = key
        return derivation

    def rejected_manifest_with(self, derivation: dict) -> dict:
        return self.manifest(
            faultProfile="single",
            expected={
                "outcome": "rejected",
                "errorAssertion": "unspecified",
            },
            derivedFrom=derivation,
        )

    def test_resigned_derivation_with_key_valid(self):
        validate(
            self.rejected_manifest_with(self.derived_from(True, "test-root-seed-1")),
            self.schema,
        )

    def test_unsigned_derivation_without_key_valid(self):
        validate(
            self.rejected_manifest_with(self.derived_from(False, None)),
            self.schema,
        )

    def test_resigned_true_requires_resigned_key(self):
        with self.assertRaises(ValidationError):
            validate(
                self.rejected_manifest_with(self.derived_from(True, None)),
                self.schema,
            )

    def test_resigned_false_forbids_resigned_key(self):
        with self.assertRaises(ValidationError):
            validate(
                self.rejected_manifest_with(
                    self.derived_from(False, "test-root-seed-1")
                ),
                self.schema,
            )

    def test_expected_result_member_allowed(self):
        validate(self.manifest(expectedResult={"did": "did:flw:zQm"}), self.schema)

    def test_adapter_error_is_never_an_expected_outcome(self):
        with self.assertRaises(ValidationError):
            validate(
                self.manifest(expected={"outcome": "adapterError"}),
                self.schema,
            )


class OperationsSchemaTests(unittest.TestCase):
    """The Milestone 1 operation input/result schemas, including the
    recursive Section 10 typed value tree."""

    @classmethod
    def setUpClass(cls):
        cls.schema = load_schema(REPO_ROOT, "operations.schema.json")

    def check(self, instance, name):
        validate(instance, self.schema["$defs"][name], root=self.schema)

    def assert_invalid(self, instance, name):
        with self.assertRaises(ValidationError):
            self.check(instance, name)

    def test_derive_identity_input(self):
        self.check(
            {"rootSeedHex": "00" * 32, "revocationSeedHex": "ff" * 32},
            "deriveIdentityInput",
        )
        self.assert_invalid(
            {"rootSeedHex": "00" * 31, "revocationSeedHex": "ff" * 32},
            "deriveIdentityInput",
        )
        self.assert_invalid(
            {
                "rootSeedHex": "00" * 32,
                "revocationSeedHex": "ff" * 32,
                "extra": True,
            },
            "deriveIdentityInput",
        )

    def test_uppercase_hex_rejected(self):
        self.assert_invalid(
            {"rootSeedHex": "AA" * 32, "revocationSeedHex": "ff" * 32},
            "deriveIdentityInput",
        )

    def test_recursive_typed_value_tree(self):
        nested = {
            "type": "map",
            "entries": [
                {
                    "key": {"type": "uint", "value": "1"},
                    "value": {
                        "type": "array",
                        "items": [
                            {"type": "nint", "value": "-18446744073709551616"},
                            {"type": "bytes", "hex": "00ff"},
                            {"type": "null"},
                        ],
                    },
                }
            ],
        }
        self.check(nested, "typedValue")

    def test_non_canonical_typed_integers_rejected(self):
        self.assert_invalid({"type": "uint", "value": "01"}, "typedValue")
        self.assert_invalid({"type": "nint", "value": "-0"}, "typedValue")
        self.assert_invalid({"type": "uint", "value": "1.5"}, "typedValue")

    def test_unknown_typed_value_type_rejected(self):
        self.assert_invalid({"type": "float", "value": "1"}, "typedValue")

    def test_corpus_inputs_validate(self):
        # Every committed specification case input satisfies its schema.
        cases_dir = REPO_ROOT / "cases" / "specification"
        checked = 0
        for path in sorted(cases_dir.glob("*.json")):
            document = json.loads(path.read_text())
            name = f"{document['operation']}Input"
            self.check(document["input"], name)
            checked += 1
        self.assertGreater(checked, 50)


if __name__ == "__main__":
    unittest.main()
