"""Milestone 1 differential campaign: identical neutral inputs to both
adapters, Section 13 comparison, disagreement artifacts, deterministic
summary (HARNESS.md Sections 4, 12, 13, 14, 16).

Exit codes:
    0  every case executed and agreed with every required expectation
    2  integrity or case-corpus refusal before any adapter was launched
    3  adapter/infrastructure failure or at least one disagreement
    4  usage or local-environment error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any

from harness import chained, integrity, pins
from harness.adapterproc import AdapterFailure, AdapterProcess
from harness.cases import Case, CaseError, load_cases
from harness.comparator import Comparison, compare_case
from harness.orchestrator import (
    HANDSHAKE_REQUEST,
    HandshakeFailure,
    SystemExit2,
    python_adapter_argv,
    repo_root_default,
    rust_adapter_argv,
    verify_hello_response,
)
from harness.schema import ValidationError, load_schema, validate


class CampaignFailure(Exception):
    """An infrastructure failure attributable to one adapter response."""

    def __init__(self, symbol: str, message: str) -> None:
        super().__init__(f"{symbol}: {message}")
        self.symbol = symbol
        self.message = message


def _git(repo_root: Path, *args: str) -> str:
    import subprocess

    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "<unavailable>"


class CampaignRunner:
    def __init__(
        self,
        repo_root: Path,
        cases_dirs: list[Path],
        report_dir: Path,
        timeout: float,
        rust_override: str | None,
        python_override: str | None,
        repeat: bool,
        only: str | None,
    ) -> None:
        self.repo_root = repo_root
        self.cases_dirs = cases_dirs
        self.report_dir = report_dir
        self.timeout = timeout
        self.rust_override = rust_override
        self.python_override = python_override
        self.repeat = repeat
        self.only = only
        self.response_schema = load_schema(repo_root, "runner-response.schema.json")
        self.operations_schema = load_schema(repo_root, "operations.schema.json")
        self.hello_schema = load_schema(repo_root, "hello-result.schema.json")
        self.infrastructure_failures: list[dict[str, Any]] = []
        self.disagreements: list[Comparison] = []
        self.comparisons: list[Comparison] = []
        self.chained_scenarios = 0
        self.chained_steps = 0
        # Exact requests executed, in order: (caseId, operation, input).
        # Chained-step inputs are produced at run time, so baseline
        # tooling reads them from here to archive reconstructable inputs.
        self.executed_requests: list[tuple[str, str, dict[str, Any]]] = []

    # -- response validation -------------------------------------------------

    def _validated_response(
        self, adapter_name: str, case: Case, response: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            validate(response, self.response_schema)
        except ValidationError as exc:
            raise CampaignFailure(
                "harness.responseSchemaViolation", f"{adapter_name}: {exc}"
            ) from exc
        if response["runnerProtocol"] != pins.RUNNER_PROTOCOL:
            raise CampaignFailure(
                "harness.protocolEchoMismatch",
                f"{adapter_name} echoed runnerProtocol {response['runnerProtocol']!r}",
            )
        if response["caseId"] != case.case_id:
            raise CampaignFailure(
                "harness.caseIdMismatch",
                f"{adapter_name} echoed caseId {response['caseId']!r} for "
                f"{case.case_id!r}",
            )
        if response["status"] == "adapterError":
            raise CampaignFailure(
                "harness.adapterError",
                f"{adapter_name} could not execute the case: "
                f"{response['error']}: {response.get('message', '')}",
            )
        if response["status"] == "accepted":
            result_schema = self.operations_schema["$defs"].get(
                f"{case.operation}Result"
            )
            if result_schema is None:
                raise CampaignFailure(
                    "harness.resultSchemaMissing",
                    f"no committed result schema for {case.operation!r}",
                )
            try:
                validate(response["result"], result_schema, root=self.operations_schema)
            except ValidationError as exc:
                raise CampaignFailure(
                    "harness.resultSchemaViolation", f"{adapter_name}: {exc}"
                ) from exc
        return response

    # -- artifacts -----------------------------------------------------------

    def _environment(self) -> dict[str, Any]:
        return {
            "harnessCommit": _git(self.repo_root, "rev-parse", "HEAD"),
            "harnessStatus": _git(self.repo_root, "status", "--porcelain"),
            "submoduleStatus": _git(self.repo_root, "submodule", "status"),
            "pins": {
                "specificationCommit": pins.SPECIFICATION_COMMIT,
                "rustCommit": pins.RUST_COMMIT,
                "pythonCommit": pins.PYTHON_COMMIT,
                "specificationSha256": pins.SPECIFICATION_SHA256,
            },
            "runnerProtocol": pins.RUNNER_PROTOCOL,
            "os": platform.platform(),
            "architecture": platform.machine(),
            "pythonVersion": sys.version,
        }

    def _write_disagreement(
        self,
        case: Case,
        rust_response: dict[str, Any] | None,
        python_response: dict[str, Any] | None,
        comparison: Comparison | None,
        failure: dict[str, Any] | None,
        rust_stderr: str,
        python_stderr: str,
    ) -> Path:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        artifact = {
            "caseId": case.case_id,
            "request": case.request(),
            "manifest": case.manifest,
            "responses": {"rust": rust_response, "python": python_response},
            "adapterStderr": {
                "rust": {
                    "excerpt": rust_stderr,
                    "sha256": hashlib.sha256(rust_stderr.encode()).hexdigest(),
                },
                "python": {
                    "excerpt": python_stderr,
                    "sha256": hashlib.sha256(python_stderr.encode()).hexdigest(),
                },
            },
            "failedRules": (
                [d.as_json() for d in comparison.differences] if comparison else []
            ),
            "infrastructureFailure": failure,
            "environment": self._environment(),
            "reproduceCommand": (f"python3 -m harness.campaign --only {case.case_id}"),
        }
        path = self.report_dir / f"disagreement-{case.case_id}.json"
        path.write_text(
            json.dumps(artifact, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    # -- execution -----------------------------------------------------------

    def _exchange(
        self, case: Case, rust: AdapterProcess, python: AdapterProcess
    ) -> dict[str, dict[str, Any]] | None:
        """Send one identical request to both adapters; return validated
        responses, or record an infrastructure failure and return None."""
        request = case.request()
        self.executed_requests.append((case.case_id, case.operation, case.input))
        # HARNESS.md Section 3: both implementations receive identical
        # neutral input; the identical request object is serialized once
        # per adapter by the same strict encoder.
        responses: dict[str, dict[str, Any]] = {}
        raw_responses: dict[str, dict[str, Any] | None] = {
            "rust": None,
            "python": None,
        }
        try:
            for name, proc in (("rust", rust), ("python", python)):
                response = proc.request(request)
                raw_responses[name] = response
                responses[name] = self._validated_response(name, case, response)
                if self.repeat:
                    again = proc.request(request)
                    if again != response:
                        raise CampaignFailure(
                            "harness.nonDeterministicAdapter",
                            f"{name} answered the identical request "
                            "differently on repetition",
                        )
        except (AdapterFailure, CampaignFailure) as exc:
            failure = {
                "symbol": exc.symbol,
                "message": getattr(exc, "message", str(exc)),
            }
            self.infrastructure_failures.append({"caseId": case.case_id, **failure})
            self._write_disagreement(
                case,
                raw_responses["rust"],
                raw_responses["python"],
                None,
                failure,
                rust.stderr_excerpt(),
                python.stderr_excerpt(),
            )
            return None
        return responses

    def _compare_and_record(
        self,
        case: Case,
        responses: dict[str, dict[str, Any]],
        rust: AdapterProcess,
        python: AdapterProcess,
    ) -> Comparison:
        comparison = compare_case(
            case.case_id,
            case.operation,
            case.expected,
            case.expected_result,
            case.input,
            responses["rust"],
            responses["python"],
        )
        self.comparisons.append(comparison)
        if not comparison.agreed:
            self.disagreements.append(comparison)
            self._write_disagreement(
                case,
                responses["rust"],
                responses["python"],
                comparison,
                None,
                rust.stderr_excerpt(),
                python.stderr_excerpt(),
            )
        return comparison

    def _run_case(
        self, case: Case, rust: AdapterProcess, python: AdapterProcess
    ) -> None:
        responses = self._exchange(case, rust, python)
        if responses is None:
            return
        self._compare_and_record(case, responses, rust, python)

    # -- chained cross-operation scenarios (harness/chained.py) --------------

    def _run_chained_scenario(
        self,
        scenario: dict[str, Any],
        rust: AdapterProcess,
        python: AdapterProcess,
    ) -> None:
        scenario_id = scenario["id"]

        # Author phase: every follow-up step runs only on envelopes both
        # implementations produced identically; a disagreement or rejection
        # aborts the scenario rather than feeding mismatched bytes onward.
        author_results: dict[str, dict[str, Any]] = {}
        for author_step in scenario["authorSteps"]:
            step_id = f"{scenario_id}-author-{author_step['name']}"
            author_case = Case(
                case_id=step_id,
                operation="authorRecord",
                input=author_step["input"],
                manifest={
                    **chained.step_manifest(
                        scenario, step_id, author_step.get("expectedResult")
                    ),
                    "expected": {"outcome": "accepted"},
                },
                path=self.cases_dirs[0],
            )
            self.chained_steps += 1
            responses = self._exchange(author_case, rust, python)
            if responses is None:
                return
            comparison = self._compare_and_record(author_case, responses, rust, python)
            if not comparison.agreed or responses["rust"]["status"] != "accepted":
                return
            author_results[author_step["name"]] = responses["rust"]["result"]

        for step in scenario["steps"]:
            step_id = f"{scenario_id}-{step['suffix']}"
            expected_result = chained.substitute(
                step.get("expectedResult"), author_results
            )
            step_case = Case(
                case_id=step_id,
                operation=step["operation"],
                input=chained.substitute(step["input"], author_results),
                manifest={
                    **chained.step_manifest(scenario, step_id, expected_result),
                    "expected": {"outcome": "accepted"},
                },
                path=self.cases_dirs[0],
            )
            self.chained_steps += 1
            step_responses = self._exchange(step_case, rust, python)
            if step_responses is None:
                continue
            self._compare_and_record(step_case, step_responses, rust, python)

    def _run_chained_scenarios(
        self, rust: AdapterProcess, python: AdapterProcess
    ) -> None:
        for scenario in chained.SCENARIOS:
            if self.only is not None and self.only != scenario["id"]:
                continue
            self.chained_scenarios += 1
            self._run_chained_scenario(scenario, rust, python)

    def run(self) -> int:
        failures = integrity.check_all(self.repo_root)
        if failures:
            print("INTEGRITY REFUSAL - no adapter was launched", file=sys.stderr)
            for failure in failures:
                print(f"  {failure}", file=sys.stderr)
            return 2

        try:
            cases = []
            for cases_dir in self.cases_dirs:
                cases.extend(load_cases(self.repo_root, cases_dir))
        except CaseError as exc:
            print(f"CASE-CORPUS REFUSAL {exc}", file=sys.stderr)
            return 2
        ids = [c.case_id for c in cases]
        if len(set(ids)) != len(ids):
            print(
                "CASE-CORPUS REFUSAL harness.case.duplicateId: case IDs "
                "must be unique across corpora",
                file=sys.stderr,
            )
            return 2
        cases.sort(key=lambda c: c.case_id)
        if self.only is not None:
            cases = [c for c in cases if c.case_id == self.only]
            scenario_ids = {s["id"] for s in chained.SCENARIOS}
            if not cases and self.only not in scenario_ids:
                print(
                    f"no case or chained scenario named {self.only!r}",
                    file=sys.stderr,
                )
                return 4
        print(
            f"integrity: pins verified; {len(cases)} validated cases from "
            f"{[str(d) for d in self.cases_dirs]}"
        )

        try:
            rust_argv = rust_adapter_argv(self.repo_root, self.rust_override)
            python_argv = python_adapter_argv(self.repo_root, self.python_override)
        except SystemExit2 as exc:
            print(exc.message, file=sys.stderr)
            return exc.code

        with tempfile.TemporaryDirectory(prefix="followee-campaign-") as tmp:
            tmp_path = Path(tmp)
            rust = AdapterProcess("rust", rust_argv, tmp_path, timeout=self.timeout)
            python = AdapterProcess(
                "python", python_argv, tmp_path, timeout=self.timeout
            )
            try:
                for name, proc, pin in (
                    ("rust", rust, pins.RUST_ADAPTER_PIN),
                    ("python", python, pins.PYTHON_ADAPTER_PIN),
                ):
                    proc.start()
                    response = proc.request(HANDSHAKE_REQUEST)
                    verify_hello_response(
                        response, pin, self.response_schema, self.hello_schema
                    )
                    print(f"handshake[{name}]: verified against every pin")
            except (AdapterFailure, HandshakeFailure) as exc:
                print(
                    f"HANDSHAKE FAILURE {exc.symbol}: {exc.message}",
                    file=sys.stderr,
                )
                rust.kill()
                python.kill()
                return 3

            try:
                for case in cases:
                    self._run_case(case, rust, python)
                self._run_chained_scenarios(rust, python)
                rust.shutdown()
                python.shutdown()
            except AdapterFailure as exc:
                print(
                    f"INFRASTRUCTURE FAILURE {exc.symbol}: {exc.message}",
                    file=sys.stderr,
                )
                rust.kill()
                python.kill()
                return 3
            finally:
                rust.kill()
                python.kill()

        return self._summarize(cases)

    def _write_promotion_proposal(self, cases: list[Case]) -> Path | None:
        """Proposed promotion report (HARNESS.md Section 12): implementation-
        status cases whose unchanged inputs produced independent agreement.
        Promotion to confirmed is metadata-only, requires review, and is
        never applied by the campaign itself."""
        implementation_cases = [
            c for c in cases if c.manifest["derivationStatus"] == "implementation"
        ]
        if not implementation_cases:
            return None
        agreed_by_id = {c.case_id: c.agreed for c in self.comparisons}
        entries = []
        for case in sorted(implementation_cases, key=lambda c: c.case_id):
            file_digest = hashlib.sha256(case.path.read_bytes()).hexdigest()
            entries.append(
                {
                    "caseId": case.case_id,
                    "operation": case.operation,
                    "caseFile": case.path.name,
                    "caseFileSha256": file_digest,
                    "currentStatus": "implementation",
                    "independentAgreement": agreed_by_id.get(case.case_id, False),
                    "proposedStatus": (
                        "confirmed"
                        if agreed_by_id.get(case.case_id, False)
                        else "implementation"
                    ),
                }
            )
        proposal = {
            "note": (
                "Proposed promotions only: agreement alone does not rewrite "
                "fixture bytes, expectations, or status. Promotion from "
                "implementation to confirmed changes metadata only and "
                "requires review (HARNESS.md Section 12)."
            ),
            "environment": self._environment(),
            "cases": entries,
        }
        self.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.report_dir / "promotion-proposal.json"
        path.write_text(
            json.dumps(proposal, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        proposed = sum(1 for e in entries if e["proposedStatus"] == "confirmed")
        print(
            f"promotion proposal: {proposed} of {len(entries)} "
            f"implementation-status cases agreed unchanged and are proposed "
            f"for confirmed status pending review ({path})"
        )
        return path

    def _summarize(self, cases: list[Case]) -> int:
        by_operation: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_fault: dict[str, int] = {}
        for case in cases:
            op = case.operation
            by_operation[op] = by_operation.get(op, 0) + 1
            by_status[case.manifest["derivationStatus"]] = (
                by_status.get(case.manifest["derivationStatus"], 0) + 1
            )
            by_fault[case.manifest["faultProfile"]] = (
                by_fault.get(case.manifest["faultProfile"], 0) + 1
            )
        exact_errors = sum(1 for c in self.comparisons if c.error_comparison == "exact")
        rejection_only = sum(
            1 for c in self.comparisons if c.error_comparison == "rejectionOnly"
        )
        agreed = sum(1 for c in self.comparisons if c.agreed)
        spec_expected = sum(1 for case in cases if case.expected_result is not None)

        self._write_promotion_proposal(cases)
        print("campaign summary (sorted by case ID, deterministic):")
        print(f"  static cases executed:     {len(cases)}")
        print(
            f"  chained scenarios:         {self.chained_scenarios} "
            f"({self.chained_steps} steps; intermediate envelopes are "
            "run-time implementation output, not specification-published)"
        )
        print(f"  by operation:              {dict(sorted(by_operation.items()))}")
        print(f"  by derivation status:      {dict(sorted(by_status.items()))}")
        print(f"  by fault profile:          {dict(sorted(by_fault.items()))}")
        print(
            f"  agreed comparisons:        {agreed} "
            f"(of {len(self.comparisons)} incl. chained steps)"
        )
        print(f"  exact-error comparisons:   {exact_errors}")
        print(f"  rejection-only comparisons: {rejection_only}")
        print(f"  specification-pinned expected results: {spec_expected}")
        print(f"  repeat-executions per adapter: {2 if self.repeat else 1}")
        divergent = [
            c
            for c in self.comparisons
            if c.error_comparison == "rejectionOnly" and c.rust_error != c.python_error
        ]
        print(
            f"  divergent rejection symbols (retained, not compared): {len(divergent)}"
        )
        for comparison in divergent:
            print(
                f"    {comparison.case_id}: rust={comparison.rust_error} "
                f"python={comparison.python_error}"
            )
        print(f"  disagreements:             {len(self.disagreements)}")
        print(f"  infrastructure failures:   {len(self.infrastructure_failures)}")

        if self.infrastructure_failures or self.disagreements:
            for failure in self.infrastructure_failures:
                print(
                    f"  INFRA {failure['caseId']}: {failure['symbol']}: "
                    f"{failure['message']}",
                    file=sys.stderr,
                )
            for comparison in self.disagreements:
                first = comparison.differences[0]
                print(
                    f"  DISAGREE {comparison.case_id} [{first.rule}] "
                    f"{first.path}: rust={first.rust!r} "
                    f"python={first.python!r}",
                    file=sys.stderr,
                )
            print(
                f"campaign FAILED; artifacts under {self.report_dir}",
                file=sys.stderr,
            )
            return 3
        print(
            "campaign PASSED: independent core differential-conformance "
            "evidence for the executed cases; no relay interoperability or "
            "proof claim is made."
        )
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Followee differential campaign (Milestone 1: "
        "deriveIdentity, authorRecord, verifyRecord)"
    )
    parser.add_argument("--repo-root", type=Path, default=repo_root_default())
    parser.add_argument(
        "--cases",
        type=Path,
        action="append",
        default=None,
        help="case directory; repeatable (default: cases/specification "
        "and cases/implementation)",
    )
    parser.add_argument("--report-dir", type=Path, default=None)
    parser.add_argument("--timeout", type=float, default=pins.DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--rust-adapter", default=None)
    parser.add_argument("--python-adapter", default=None)
    parser.add_argument("--only", default=None, help="run one case by ID")
    parser.add_argument(
        "--no-repeat",
        action="store_true",
        help="skip the identical-request repetition check",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    if args.cases:
        cases_dirs = [d.resolve() for d in args.cases]
    else:
        cases_dirs = [repo_root / "cases" / "specification"]
        implementation_dir = repo_root / "cases" / "implementation"
        if implementation_dir.is_dir():
            cases_dirs.append(implementation_dir)
    report_dir = (
        args.report_dir.resolve()
        if args.report_dir
        else repo_root / "reports" / "scratch" / "campaign"
    )
    runner = CampaignRunner(
        repo_root=repo_root,
        cases_dirs=cases_dirs,
        report_dir=report_dir,
        timeout=args.timeout,
        rust_override=args.rust_adapter,
        python_override=args.python_adapter,
        repeat=not args.no_repeat,
        only=args.only,
    )
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())
