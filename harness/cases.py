"""Retained-case loading, manifest validation, and content digests
(HARNESS.md Sections 6 and 12).

Every case file must be listed in the directory's ``DIGESTS.sha256``
manifest with a matching SHA-256, and every manifest must validate against
the committed case-manifest schema before execution.  Any inconsistency is
a harness error, never a conformance result.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness import pins
from harness.schema import ValidationError, load_schema, validate

DIGEST_MANIFEST = "DIGESTS.sha256"


class CaseError(ValueError):
    """A case-corpus integrity or manifest-validation failure."""

    def __init__(self, symbol: str, message: str) -> None:
        super().__init__(f"{symbol}: {message}")
        self.symbol = symbol
        self.message = message


@dataclass(frozen=True)
class Case:
    case_id: str
    operation: str
    input: dict[str, Any]
    manifest: dict[str, Any]
    path: Path

    @property
    def expected(self) -> dict[str, Any]:
        return self.manifest["expected"]

    @property
    def expected_result(self) -> dict[str, Any] | None:
        return self.manifest.get("expectedResult")

    def request(self) -> dict[str, Any]:
        return {
            "runnerProtocol": pins.RUNNER_PROTOCOL,
            "caseId": self.case_id,
            "operation": self.operation,
            "input": self.input,
        }


def _loads_profile(text: str, context: str) -> Any:
    """Parse a case document under the runner JSON value profile: duplicate
    member names and bare number tokens are rejected (HARNESS.md 7.2)."""

    def pairs(items: list) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in items:
            if key in obj:
                raise CaseError(
                    "harness.case.duplicateJsonName",
                    f"{context}: duplicate member {key!r}",
                )
            obj[key] = value
        return obj

    def reject_number(token: str) -> Any:
        raise CaseError(
            "harness.case.numberForbidden",
            f"{context}: bare JSON number {token!r}",
        )

    try:
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=reject_number,
            parse_int=reject_number,
            parse_constant=reject_number,
        )
    except json.JSONDecodeError as exc:
        raise CaseError("harness.case.malformedJson", f"{context}: {exc}") from exc


def verify_digest_manifest(cases_dir: Path) -> dict[str, str]:
    """Check the content-digest manifest covers exactly the case files."""
    manifest_path = cases_dir / DIGEST_MANIFEST
    if not manifest_path.is_file():
        raise CaseError(
            "harness.case.digestManifestMissing",
            f"{manifest_path} not found",
        )
    listed: dict[str, str] = {}
    for line_number, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line:
            continue

        # Exactly: 64 lowercase-hex digest, the two-space separator, and a
        # plain filename — no path components, no surrounding whitespace,
        # no extra separators anywhere on the line.
        problem: str | None = None
        digest = name = ""
        parts = line.split("  ")
        if len(parts) != 2:
            problem = "expected exactly one two-space separator"
        else:
            digest, name = parts
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                problem = "digest must be 64 lowercase hexadecimal chars"
            elif not name or name != name.strip():
                problem = "filename must have no surrounding whitespace"
            elif "/" in name or "\\" in name or name in (".", ".."):
                problem = "filename must not contain path components"
        if problem is not None:
            raise CaseError(
                "harness.case.digestManifestMalformed",
                f"{manifest_path.name}:{line_number}: {problem}: {line!r}",
            )
        if name in listed:
            raise CaseError(
                "harness.case.digestManifestDuplicate",
                f"{manifest_path.name}:{line_number}: duplicate entry for {name!r}",
            )
        listed[name] = digest

    actual_files = sorted(
        p.name for p in cases_dir.glob("*.json") if p.name != DIGEST_MANIFEST
    )
    if set(actual_files) != set(listed):
        raise CaseError(
            "harness.case.digestManifestMismatch",
            f"digest manifest lists {sorted(listed)} but directory holds "
            f"{actual_files}",
        )
    for name, expected in listed.items():
        actual = hashlib.sha256((cases_dir / name).read_bytes()).hexdigest()
        if actual != expected:
            raise CaseError(
                "harness.case.contentDigestMismatch",
                f"{name}: SHA-256 is {actual}, manifest records {expected}",
            )
    return listed


def load_cases(repo_root: Path, cases_dir: Path) -> list[Case]:
    """Load, digest-check, and schema-validate every case, sorted by ID."""
    verify_digest_manifest(cases_dir)
    manifest_schema = load_schema(repo_root, "case-manifest.schema.json")
    operations_schema = load_schema(repo_root, "operations.schema.json")

    cases: list[Case] = []
    for path in sorted(cases_dir.glob("*.json")):
        if path.name == DIGEST_MANIFEST:
            continue
        document = _loads_profile(path.read_text(encoding="utf-8"), path.name)
        try:
            validate(document, manifest_schema)
        except ValidationError as exc:
            raise CaseError(
                "harness.case.manifestInvalid", f"{path.name}: {exc}"
            ) from exc
        case_id = document["id"]
        if path.stem != case_id:
            raise CaseError(
                "harness.case.idMismatch",
                f"{path.name}: manifest id {case_id!r} must equal the file stem",
            )
        operation = document["operation"]
        if operation not in pins.SUPPORTED_OPERATIONS:
            raise CaseError(
                "harness.case.unsupportedOperation",
                f"{path.name}: operation {operation!r} is not runnable",
            )
        if "input" not in document:
            raise CaseError(
                "harness.case.externalInputUnsupported",
                f"{path.name}: inputPath cases are not supported yet",
            )
        input_schema = operations_schema["$defs"].get(f"{operation}Input")
        if input_schema is None:
            raise CaseError(
                "harness.case.unsupportedOperation",
                f"{path.name}: no committed input schema for {operation!r}",
            )
        try:
            validate(document["input"], input_schema, root=operations_schema)
        except ValidationError as exc:
            raise CaseError("harness.case.inputInvalid", f"{path.name}: {exc}") from exc
        cases.append(
            Case(
                case_id=case_id,
                operation=operation,
                input=document["input"],
                manifest=document,
                path=path,
            )
        )

    ids = [c.case_id for c in cases]
    if len(set(ids)) != len(ids):
        raise CaseError("harness.case.duplicateId", "case IDs must be unique")
    return cases
