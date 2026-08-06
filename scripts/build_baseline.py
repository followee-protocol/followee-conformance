#!/usr/bin/env python3
"""Build the v0.7 differential baseline archive
(``reports/v0.7-differential-baseline/``).

The archive is a deterministic checkpoint of the complete Milestone 0-2
differential gate: it records every pin, exact campaign counts, every
retained symbolic divergence, a digest bundle covering every regular file
under ``cases/``, and the exact inputs of every dynamically generated
chained-scenario step, so all baseline comparisons remain reconstructable.

The builder is read-only with respect to protocol behavior, adapters,
cases, fixtures, and pins: it only executes the existing gates and writes
the archive files.  Outputs contain no timestamps and are sorted, so
regeneration from the same tree is byte-stable.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from harness import chained, pins
from harness.campaign import CampaignRunner

BASELINE_DIR = REPO_ROOT / "reports" / "v0.7-differential-baseline"
CASES_DIR = REPO_ROOT / "cases"

# Review classification of retained rejection-only symbol divergences.
# "multi-fault" = permitted outcome of specification 8.1's reordering
# allowance for multi-fault inputs; "specification-ambiguity" = a genuine
# unassigned classification in the pinned specification.
DIVERGENCE_CLASSIFICATION = {
    "validate-cbor-invalid-utf8": (
        "specification-ambiguity",
        (
            "Invalid UTF-8 in a text string sits between 15.3 code 4 "
            "('CBOR cannot be parsed safely') and code 5 ('encoding violates "
            "Section 6.1', rule 8). Both readings are defensible; the Python "
            "clean-room documented exactly this interpretation decision. "
            "Candidate for specification clarification."
        ),
    ),
    "verify-b7-09-duplicate-map-key": (
        "multi-fault",
        (
            "Duplicate key inside the unprotected COSE header map violates "
            "both the Section 6.2 profile (unprotected map must be empty -> "
            "schemaViolation) and Section 6.1 rule 4 (duplicate keys -> "
            "nonDeterministicCbor). Section 8.1 permits reordering cheap "
            "independent checks; the re-signed single-fault twin "
            "impl-b7-9-duplicate-key classifies identically on both sides."
        ),
    ),
    "verify-b7-15-valid-until-before-timestamp": (
        "multi-fault",
        (
            "The label-6 splice is not re-signed, so the input violates both "
            "the validUntil relation (Section 5.5) and the signature "
            "(Section 3.3). The implementations check in different permitted "
            "orders; the re-signed single-fault twin "
            "impl-b7-15-valid-until-before-timestamp classifies identically "
            "(schemaViolation) on both sides."
        ),
    ),
}


def run_gate(argv: list[str], cwd: Path = REPO_ROOT) -> tuple[str, int]:
    proc = subprocess.run(
        argv, cwd=str(cwd), capture_output=True, text=True, check=False
    )
    return " ".join(argv), proc.returncode


def fixture_bundle() -> str:
    """Sorted SHA-256 entries for every regular file under cases/."""
    lines = []
    for path in sorted(CASES_DIR.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.relative_to(REPO_ROOT).as_posix()}")
    return "\n".join(lines) + "\n"


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def main() -> int:
    print("== v0.7 differential baseline builder ==")

    # -- gates (recorded verbatim in SUMMARY.md) ---------------------------
    gate_results: list[tuple[str, int]] = []
    for argv in [
        ["python3", "scripts/check_pins.py"],
        ["python3", "-m", "harness.orchestrator"],
        ["sh", "scripts/negative_pin_test.sh"],
        ["python3", "scripts/build_specification_corpus.py", "--check"],
        ["python3", "scripts/build_implementation_corpus.py", "--check"],
        ["python3", "-m", "unittest", "discover", "-s", "harness/tests", "-t", "."],
        [
            "python3",
            "-m",
            "unittest",
            "discover",
            "-s",
            "adapters/python/tests",
            "-t",
            ".",
        ],
        ["python3", "-m", "ruff", "check", "harness", "adapters/python", "scripts"],
        [
            "python3",
            "-m",
            "ruff",
            "format",
            "--check",
            "harness",
            "adapters/python",
            "scripts",
        ],
        [
            "cargo",
            "fmt",
            "--manifest-path",
            "adapters/rust/Cargo.toml",
            "--",
            "--check",
        ],
        [
            "cargo",
            "fmt",
            "--manifest-path",
            "tools/fixture-builder/Cargo.toml",
            "--",
            "--check",
        ],
        [
            "cargo",
            "clippy",
            "--manifest-path",
            "adapters/rust/Cargo.toml",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        [
            "cargo",
            "clippy",
            "--manifest-path",
            "tools/fixture-builder/Cargo.toml",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        ["cargo", "test", "--manifest-path", "adapters/rust/Cargo.toml", "--locked"],
        ["git", "diff", "--check"],
    ]:
        command, code = run_gate(argv)
        gate_results.append((command, code))
        print(f"  exit {code}: {command}")
        if code != 0:
            print("gate failed; baseline not written", file=sys.stderr)
            return 1

    # -- the differential campaign, run in-process for exact state ---------
    runner = CampaignRunner(
        repo_root=REPO_ROOT,
        cases_dirs=[CASES_DIR / "specification", CASES_DIR / "implementation"],
        report_dir=REPO_ROOT / "reports" / "scratch" / "campaign",
        timeout=pins.DEFAULT_TIMEOUT_SECONDS,
        rust_override=None,
        python_override=None,
        repeat=True,
        only=None,
    )
    campaign_exit = runner.run()
    gate_results.append(("python3 -m harness.campaign", campaign_exit))
    if campaign_exit != 0:
        print("campaign failed; baseline not written", file=sys.stderr)
        return 1

    comparisons = runner.comparisons
    agreed = sum(1 for c in comparisons if c.agreed)
    exact_errors = sum(1 for c in comparisons if c.error_comparison == "exact")
    rejection_only = sum(
        1 for c in comparisons if c.error_comparison == "rejectionOnly"
    )
    divergent = [
        c
        for c in comparisons
        if c.error_comparison == "rejectionOnly" and c.rust_error != c.python_error
    ]
    static_case_count = len(comparisons) - runner.chained_steps

    # -- chained-step inputs: exact bytes behind every dynamic comparison --
    static_ids = set()
    for cases_dir in ("specification", "implementation"):
        static_ids.update(p.stem for p in (CASES_DIR / cases_dir).glob("*.json"))
    chained_steps = [
        {
            "caseId": case_id,
            "operation": operation,
            "input": case_input,
            "inputSha256": hashlib.sha256(
                canonical_json(case_input).encode("utf-8")
            ).hexdigest(),
        }
        for case_id, operation, case_input in runner.executed_requests
        if case_id not in static_ids
    ]
    chained_document = {
        "note": (
            "Exact inputs of every dynamically generated chained-scenario "
            "step executed by the baseline campaign, in execution order. "
            "Envelope bytes are included verbatim (hex), so every baseline "
            "comparison is reconstructable without re-running the authoring "
            "steps. inputSha256 is the SHA-256 of the canonical JSON "
            "serialization (sorted keys, compact separators) of the input "
            "object. Provenance: intermediate envelopes are run-time output "
            "of both frozen implementations, admitted only after their "
            "complete authorRecord results agreed byte-for-byte; they are "
            "not specification-published material."
        ),
        "scenarios": [s["id"] for s in chained.SCENARIOS],
        "steps": chained_steps,
    }

    # -- archive files -----------------------------------------------------
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    bundle = fixture_bundle()
    (BASELINE_DIR / "FIXTURE-BUNDLE.sha256").write_text(bundle, encoding="utf-8")
    bundle_digest = hashlib.sha256(bundle.encode("utf-8")).hexdigest()
    (BASELINE_DIR / "CHAINED-STEP-INPUTS.json").write_text(
        json.dumps(chained_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    by_operation: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for case_id, operation, _ in runner.executed_requests:
        if case_id in static_ids:
            by_operation[operation] = by_operation.get(operation, 0) + 1
    for cases_dir, status in (
        ("specification", "specification"),
        ("implementation", "implementation"),
    ):
        by_status[status] = len(list((CASES_DIR / cases_dir).glob("*.json")))

    def divergence_rows() -> str:
        ordered = sorted(divergent, key=lambda c: c.case_id)
        rows = []
        for comparison in ordered:
            kind, _ = DIVERGENCE_CLASSIFICATION.get(
                comparison.case_id, ("unclassified", "requires review")
            )
            rows.append(
                f"| `{comparison.case_id}` | `{comparison.rust_error}` | "
                f"`{comparison.python_error}` | {kind} |\n"
            )
        rows.append("\n")
        for comparison in ordered:
            _, rationale = DIVERGENCE_CLASSIFICATION.get(
                comparison.case_id, ("unclassified", "requires review")
            )
            rows.append(f"- `{comparison.case_id}`: {rationale}\n")
        return "".join(rows)

    gate_table = "".join(
        f"| `{command}` | {code} |\n" for command, code in gate_results
    )

    summary = f"""# Followee v0.7 differential baseline

Checkpoint of the complete Milestone 0-2 differential-conformance gate:
two independently developed frozen implementations, identical neutral
inputs, mechanical comparison (HARNESS.md Sections 1-3 and 13). This is
independent core differential-conformance evidence for the executed
cases; it is not a relay-interoperability or formal-proof claim
(HARNESS.md Section 17).

## Pins and tags

| Artifact | Revision |
| --- | --- |
| Followee Specification v0.7 | `{pins.SPECIFICATION_COMMIT}` |
| Specification SHA-256 | `{pins.SPECIFICATION_SHA256}` |
| Rust protocol core | `{pins.RUST_COMMIT}` (tag `milestone-1-v0.7-conformance-api-reviewed`) |
| Rust audited parent / fixture-producing revision | `{pins.RUST_CONFORMANCE_API_PARENT}` (tag `milestone-1-v0.7-reviewed`) |
| Rust review-fix parent | `{pins.RUST_REVIEW_FIX_PARENT}` |
| Python clean-room model | `{pins.PYTHON_COMMIT}` (tag `cleanroom-v0.7-maintenance-freeze`) |
| Python v0.7 maintenance input | `{pins.PYTHON_V07_MAINTENANCE_INPUT}` |
| Python v0.6 freeze / reviewed correction | `{pins.PYTHON_V06_FREEZE}` / `{pins.PYTHON_V06_REVIEW_CORRECTION}` |
| Runner protocol | `{pins.RUNNER_PROTOCOL}` |
| Operations | {", ".join(f"`{op}`" for op in pins.SUPPORTED_OPERATIONS)} |

## Campaign result

| Count | Value |
| --- | --- |
| Static cases executed | {static_case_count} |
| by derivation status | specification {by_status["specification"]}, implementation {by_status["implementation"]} |
| by operation | {", ".join(f"{op} {n}" for op, n in sorted(by_operation.items()))} |
| Chained scenarios (dynamic steps) | {runner.chained_scenarios} ({runner.chained_steps} steps) |
| Total comparisons | {len(comparisons)} |
| Agreed comparisons | {agreed} |
| Exact-error comparisons | {exact_errors} |
| Rejection-only comparisons | {rejection_only} |
| Acceptance/rejection disagreements | {len(runner.disagreements)} |
| Infrastructure failures | {len(runner.infrastructure_failures)} |
| Executions per adapter per case | 2 (identical-request repetition) |
| Implementation-status cases proposed for promotion (pending review) | 49 of 49 |

## Retained symbolic divergences (unspecified assertions)

Every case below carries `errorAssertion: unspecified`: both
implementations reject, the comparison passes on rejection only, and both
symbols are retained diagnostically (HARNESS.md Sections 9.3 and 12).
Neither implementation is treated as authoritative.

| Case | followee-rs | followee-python-cleanroom | Classification |
| --- | --- | --- | --- |
{divergence_rows()}
No other unspecified-assertion case produced differing symbols.

## Fixture bundle

`FIXTURE-BUNDLE.sha256` lists sorted SHA-256 digests for every regular
file under `cases/` (case manifests, inputs, provenance records, and both
`DIGESTS.sha256` corpus manifests).

Aggregate SHA-256 of `FIXTURE-BUNDLE.sha256`:

```text
{bundle_digest}
```

`CHAINED-STEP-INPUTS.json` records the exact input bytes (verbatim hex)
and canonical-JSON digests of every dynamically generated chained-scenario
step, so the inputs behind all {len(comparisons)} baseline comparisons are
reconstructable from this archive plus the committed corpora.

## Gate commands and results

| Command | Exit |
| --- | --- |
{gate_table}
"""
    (BASELINE_DIR / "SUMMARY.md").write_text(summary, encoding="utf-8")

    print(f"baseline written to {BASELINE_DIR}")
    print(f"fixture-bundle aggregate sha256: {bundle_digest}")
    print(f"chained steps archived: {len(chained_steps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
