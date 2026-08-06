"""Comparator sensitivity tests (HARNESS.md Section 13).

These prove the comparator detects a one-byte disagreement, a one-field
disagreement, an acceptance disagreement, and an error-classification
disagreement — and that rejection-only comparisons retain but do not
compare differing symbols.
"""

import unittest

from harness.comparator import (
    RULE_ACCEPTANCE,
    RULE_EXACT_ERROR,
    RULE_EXPECTATION,
    RULE_RECEIVED_BYTES,
    RULE_RESULT_EQUALITY,
    RULE_SPECIFICATION,
    compare_case,
)

ACCEPTED = {"outcome": "accepted"}
REJECTED_EXACT = {
    "outcome": "rejected",
    "errorAssertion": "exact",
    "error": "identityBindingMismatch",
}
REJECTED_UNSPECIFIED = {"outcome": "rejected", "errorAssertion": "unspecified"}


def accepted(result: dict) -> dict:
    return {
        "runnerProtocol": "1",
        "caseId": "case-1",
        "status": "accepted",
        "result": result,
    }


def rejected(error: str) -> dict:
    return {
        "runnerProtocol": "1",
        "caseId": "case-1",
        "status": "rejected",
        "error": error,
    }


def derive_result() -> dict:
    return {
        "rootPublicKeyHex": "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        "revocationPublicKeyHex": "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7",
        "did": "did:flw:zQmPcGstBa7wW9hoYQbS6JZ4UxwZmoKr7YVf9y7qxiyD3Cm",
    }


class ComparatorSensitivityTests(unittest.TestCase):
    def compare(
        self,
        expected,
        rust,
        python,
        operation="deriveIdentity",
        case_input=None,
        expected_result=None,
    ):
        return compare_case(
            "case-1",
            operation,
            expected,
            expected_result,
            case_input or {},
            rust,
            python,
        )

    def test_identical_accepted_results_agree(self):
        c = self.compare(ACCEPTED, accepted(derive_result()), accepted(derive_result()))
        self.assertTrue(c.agreed)

    def test_single_hex_byte_disagreement_is_detected(self):
        mutated = derive_result()
        # One byte of one binary value: "03" -> "02" in the first position.
        mutated["rootPublicKeyHex"] = "02" + mutated["rootPublicKeyHex"][2:]
        c = self.compare(ACCEPTED, accepted(derive_result()), accepted(mutated))
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_RESULT_EQUALITY)
        self.assertEqual(c.differences[0].path, "rootPublicKeyHex")

    def test_single_field_disagreement_is_detected(self):
        mutated = derive_result()
        mutated["did"] = "did:flw:zQmPdjR6k8HFgbf4e51P7iMy4aY3buGsxQU49fSHdGhce7s"
        c = self.compare(ACCEPTED, accepted(derive_result()), accepted(mutated))
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].path, "did")

    def test_missing_member_is_detected(self):
        mutated = derive_result()
        del mutated["did"]
        c = self.compare(ACCEPTED, accepted(derive_result()), accepted(mutated))
        self.assertFalse(c.agreed)

    def test_nested_one_character_disagreement_is_detected(self):
        base = {
            "record": {
                "contact": {
                    "services": [
                        {"id": "feed", "label": "Writing"},
                    ]
                }
            }
        }
        mutated = {
            "record": {
                "contact": {
                    "services": [
                        {"id": "feed", "label": "writing"},
                    ]
                }
            }
        }
        c = self.compare(ACCEPTED, accepted(base), accepted(mutated))
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].path, "record.contact.services[0].label")

    def test_boolean_versus_string_type_disagreement_is_detected(self):
        c = self.compare(
            ACCEPTED,
            accepted({"premature": False}),
            accepted({"premature": "false"}),
        )
        self.assertFalse(c.agreed)

    def test_acceptance_disagreement_is_detected(self):
        c = self.compare(ACCEPTED, accepted(derive_result()), rejected("invalidDid"))
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_ACCEPTANCE)
        self.assertEqual(c.python_error, "invalidDid")

    def test_error_classification_disagreement_under_exact_assertion(self):
        c = self.compare(
            REJECTED_EXACT,
            rejected("identityBindingMismatch"),
            rejected("schemaViolation"),
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_EXACT_ERROR)
        self.assertEqual(c.error_comparison, "exact")

    def test_both_wrong_exact_errors_are_both_reported(self):
        c = self.compare(
            REJECTED_EXACT,
            rejected("invalidSignature"),
            rejected("schemaViolation"),
        )
        self.assertEqual(len(c.differences), 2)

    def test_rejection_only_comparison_retains_but_does_not_compare(self):
        c = self.compare(
            REJECTED_UNSPECIFIED,
            rejected("nonDeterministicCbor"),
            rejected("schemaViolation"),
        )
        self.assertTrue(c.agreed, "unspecified assertion compares rejection only")
        self.assertEqual(c.error_comparison, "rejectionOnly")
        self.assertEqual(c.rust_error, "nonDeterministicCbor")
        self.assertEqual(c.python_error, "schemaViolation")

    def test_expected_rejection_but_both_accept_fails(self):
        c = self.compare(
            REJECTED_UNSPECIFIED,
            accepted(derive_result()),
            accepted(derive_result()),
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_EXPECTATION)

    def test_expected_acceptance_but_both_reject_fails(self):
        c = self.compare(ACCEPTED, rejected("invalidDid"), rejected("invalidDid"))
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_EXPECTATION)

    def test_agreed_result_violating_published_expectation_fails(self):
        c = self.compare(
            ACCEPTED,
            accepted(derive_result()),
            accepted(derive_result()),
            expected_result={"did": "did:flw:zSomethingElse"},
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_SPECIFICATION)

    def test_verify_record_must_echo_exact_received_bytes(self):
        result = {"envelopeHex": "d2ff"}
        c = self.compare(
            ACCEPTED,
            accepted(dict(result)),
            accepted(dict(result)),
            operation="verifyRecord",
            case_input={"envelopeHex": "d200"},
        )
        self.assertFalse(c.agreed)
        self.assertEqual({d.rule for d in c.differences}, {RULE_RECEIVED_BYTES})

    def test_hard_coded_stale_result_fails_the_published_expectation(self):
        # Both adapters agreeing on a hard-coded/wrong stale value must
        # still fail against the scenario's normative expectation.
        agreed = {"stale": False, "validUntilMs": "1785589260123"}
        c = self.compare(
            ACCEPTED,
            accepted(dict(agreed)),
            accepted(dict(agreed)),
            operation="verifyRecord",
            case_input={"envelopeHex": None},
            expected_result={"stale": True},
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_SPECIFICATION)
        self.assertEqual(c.differences[0].path, "expectedResult.stale")

    def test_inverted_stale_between_adapters_is_detected(self):
        c = self.compare(
            ACCEPTED,
            accepted({"stale": False}),
            accepted({"stale": True}),
            operation="deriveIdentity",
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_RESULT_EQUALITY)
        self.assertEqual(c.differences[0].path, "stale")

    def test_strict_valid_flag_disagreement_is_detected(self):
        c = self.compare(
            ACCEPTED,
            accepted({"valid": True}),
            accepted({"valid": False}),
            operation="strictEd25519",
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].path, "valid")

    def test_next_timestamp_value_disagreement_is_detected(self):
        c = self.compare(
            ACCEPTED,
            accepted({"timestampMs": "201", "error": None}),
            accepted({"timestampMs": "202", "error": None}),
            operation="nextTimestamp",
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].path, "timestampMs")

    def test_overflow_versus_value_disagreement_is_detected(self):
        c = self.compare(
            ACCEPTED,
            accepted({"timestampMs": "18446744073709551615", "error": None}),
            accepted({"timestampMs": None, "error": "overflow"}),
            operation="nextTimestamp",
        )
        self.assertFalse(c.agreed)
        self.assertEqual({d.path for d in c.differences}, {"timestampMs", "error"})

    def test_select_winner_digest_one_byte_disagreement_is_detected(self):
        left = {"winnerRecordBodyDigestHex": "aa" * 32, "authorityState": "root"}
        right = {
            "winnerRecordBodyDigestHex": "ab" + "aa" * 31,
            "authorityState": "root",
        }
        c = self.compare(
            ACCEPTED, accepted(left), accepted(right), operation="selectCurrent"
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].path, "winnerRecordBodyDigestHex")

    def test_select_winner_null_versus_digest_is_detected(self):
        c = self.compare(
            ACCEPTED,
            accepted({"winnerRecordBodyDigestHex": None, "authorityState": "root"}),
            accepted(
                {
                    "winnerRecordBodyDigestHex": "aa" * 32,
                    "authorityState": "root",
                }
            ),
            operation="selectCurrent",
        )
        self.assertFalse(c.agreed)

    def test_select_authority_state_disagreement_is_detected(self):
        c = self.compare(
            ACCEPTED,
            accepted(
                {
                    "winnerRecordBodyDigestHex": None,
                    "authorityState": "rootRevoked",
                }
            ),
            accepted({"winnerRecordBodyDigestHex": None, "authorityState": "root"}),
            operation="selectCurrent",
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].path, "authorityState")

    def test_validate_cbor_acceptance_disagreement_is_detected(self):
        c = self.compare(
            ACCEPTED,
            accepted({"valid": True}),
            rejected("invalidCbor"),
            operation="validateCbor",
        )
        self.assertFalse(c.agreed)
        self.assertEqual(c.differences[0].rule, RULE_ACCEPTANCE)

    def test_validate_cbor_classification_disagreements_are_detected(self):
        # Each classification pair must fail under an exact assertion.
        for required, other in [
            ("invalidCbor", "nonDeterministicCbor"),
            ("nonDeterministicCbor", "schemaViolation"),
            ("schemaViolation", "invalidCbor"),
        ]:
            c = self.compare(
                {
                    "outcome": "rejected",
                    "errorAssertion": "exact",
                    "error": required,
                },
                rejected(required),
                rejected(other),
                operation="validateCbor",
            )
            self.assertFalse(c.agreed, f"{required} vs {other}")
            self.assertEqual(c.differences[0].rule, RULE_EXACT_ERROR)

    def test_validate_cbor_unspecified_retains_divergent_classifications(self):
        # The recorded invalid-UTF-8 divergence: both reject, symbols kept.
        c = self.compare(
            REJECTED_UNSPECIFIED,
            rejected("invalidCbor"),
            rejected("nonDeterministicCbor"),
            operation="validateCbor",
        )
        self.assertTrue(c.agreed)
        self.assertEqual(c.rust_error, "invalidCbor")
        self.assertEqual(c.python_error, "nonDeterministicCbor")

    def test_diagnostic_member_is_excluded_from_equality(self):
        with_diag = derive_result()
        with_diag["diagnostic"] = {"followeeRust": {"elapsedNs": "12"}}
        c = self.compare(ACCEPTED, accepted(with_diag), accepted(derive_result()))
        self.assertTrue(c.agreed)


if __name__ == "__main__":
    unittest.main()
