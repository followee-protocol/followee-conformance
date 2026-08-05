"""Neutral comparator for runner operations (HARNESS.md Section 13).

The comparator decides nothing about Followee semantics: it only tests the
required equalities between the two adapters' responses and, for
specification-status cases, between the agreed result and the expected
members normatively published by the pinned specification.  A namespaced
``diagnostic`` member is excluded from equality and retained in reports;
normative result fields are never excluded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Comparison-rule identifiers, cited in disagreement artifacts.
RULE_ACCEPTANCE = "acceptance"
RULE_EXACT_ERROR = "exactError"
RULE_RESULT_EQUALITY = "resultEquality"
RULE_RECEIVED_BYTES = "receivedBytesPreserved"
RULE_SPECIFICATION = "specificationExpectation"
RULE_EXPECTATION = "expectedOutcome"

MAX_REPORTED_DIFFERENCES = 20


@dataclass(frozen=True)
class Difference:
    rule: str
    path: str
    rust: Any
    python: Any

    def as_json(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "path": self.path,
            "rust": self.rust,
            "python": self.python,
        }


@dataclass
class Comparison:
    case_id: str
    operation: str
    differences: list[Difference] = field(default_factory=list)
    # Retained for diagnosis on rejection-only comparisons (HARNESS.md 9.3
    # and 12): the two symbolic errors, possibly different.
    rust_error: str | None = None
    python_error: str | None = None
    error_comparison: str | None = None  # "exact" or "rejectionOnly"

    @property
    def agreed(self) -> bool:
        return not self.differences


def _stripped(result: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in result.items() if k != "diagnostic"}


def _deep_diff(
    rule: str, path: str, rust: Any, python: Any, out: list[Difference]
) -> None:
    if len(out) >= MAX_REPORTED_DIFFERENCES:
        return
    if isinstance(rust, dict) and isinstance(python, dict):
        for key in sorted(set(rust) | set(python)):
            member_path = f"{path}.{key}" if path else key
            if key not in rust:
                out.append(Difference(rule, member_path, "<absent>", python[key]))
            elif key not in python:
                out.append(Difference(rule, member_path, rust[key], "<absent>"))
            else:
                _deep_diff(rule, member_path, rust[key], python[key], out)
        return
    if isinstance(rust, list) and isinstance(python, list):
        if len(rust) != len(python):
            out.append(
                Difference(
                    rule,
                    f"{path}.length",
                    str(len(rust)),
                    str(len(python)),
                )
            )
            return
        for i, (r, p) in enumerate(zip(rust, python)):
            _deep_diff(rule, f"{path}[{i}]", r, p, out)
        return
    if rust != python or type(rust) is not type(python):
        out.append(Difference(rule, path or "$", rust, python))


def compare_case(
    case_id: str,
    operation: str,
    expected: dict[str, Any],
    expected_result: dict[str, Any] | None,
    case_input: dict[str, Any],
    rust_response: dict[str, Any],
    python_response: dict[str, Any],
) -> Comparison:
    """Apply the Section 13 comparison rules to one pair of responses.

    Both responses must already be schema-validated non-adapterError
    envelopes; adapter errors are infrastructure failures handled before
    comparison.
    """
    comparison = Comparison(case_id=case_id, operation=operation)
    rust_status = rust_response["status"]
    python_status = python_response["status"]

    if rust_status != python_status:
        comparison.differences.append(
            Difference(RULE_ACCEPTANCE, "status", rust_status, python_status)
        )
        if rust_status == "rejected":
            comparison.rust_error = rust_response["error"]
        if python_status == "rejected":
            comparison.python_error = python_response["error"]
        return comparison

    if rust_status == "rejected":
        comparison.rust_error = rust_response["error"]
        comparison.python_error = python_response["error"]
        if expected.get("outcome") == "accepted":
            comparison.differences.append(
                Difference(
                    RULE_EXPECTATION,
                    "status",
                    "rejected (expected accepted)",
                    "rejected (expected accepted)",
                )
            )
            return comparison
        assertion = expected.get("errorAssertion")
        if assertion == "exact":
            comparison.error_comparison = "exact"
            required = expected["error"]
            for name, error in (
                ("rust", comparison.rust_error),
                ("python", comparison.python_error),
            ):
                if error != required:
                    comparison.differences.append(
                        Difference(
                            RULE_EXACT_ERROR,
                            f"error[{name}]",
                            required,
                            error,
                        )
                    )
        else:
            # Rejection-only comparison: both implementations rejected;
            # their possibly different symbols are retained, not compared
            # (HARNESS.md Sections 9.3 and 12).
            comparison.error_comparison = "rejectionOnly"
        return comparison

    # Both accepted.
    if expected.get("outcome") == "rejected":
        comparison.differences.append(
            Difference(
                RULE_EXPECTATION,
                "status",
                "accepted (expected rejected)",
                "accepted (expected rejected)",
            )
        )
        return comparison

    rust_result = _stripped(rust_response["result"])
    python_result = _stripped(python_response["result"])
    _deep_diff(
        RULE_RESULT_EQUALITY, "", rust_result, python_result, comparison.differences
    )

    # verifyRecord must preserve the exact received bytes (HARNESS.md 9.3
    # and Milestone 1 acceptance).
    if operation == "verifyRecord":
        supplied = case_input.get("envelopeHex")
        for name, result in (("rust", rust_result), ("python", python_result)):
            if result.get("envelopeHex") != supplied:
                comparison.differences.append(
                    Difference(
                        RULE_RECEIVED_BYTES,
                        f"envelopeHex[{name}]",
                        "<exact supplied envelope bytes>",
                        f"{name} returned different bytes",
                    )
                )

    # Specification-published expected members (HARNESS.md Section 12):
    # checked against the agreed result only after cross-implementation
    # equality, so a violation here means both implementations differ from
    # the pinned specification.
    if expected_result is not None and not comparison.differences:
        for member, value in expected_result.items():
            actual = rust_result.get(member, "<absent>")
            if actual != value:
                comparison.differences.append(
                    Difference(
                        RULE_SPECIFICATION,
                        f"expectedResult.{member}",
                        value,
                        actual,
                    )
                )

    return comparison
