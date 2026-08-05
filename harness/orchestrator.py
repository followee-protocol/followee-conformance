"""Milestone 0 orchestrator: integrity checks plus the two handshakes.

Launches both adapter processes, performs the ``hello`` handshake, and
refuses incorrect pins (HARNESS.md Sections 6, 8, and 20 Milestone 0).
No Followee protocol operation is exercised.

Exit codes:
    0  both handshakes verified against every pin
    2  integrity refusal before any adapter was launched
    3  adapter/infrastructure failure during handshake
    4  usage or local-environment error (e.g. adapter binary not built)
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from harness import integrity, pins
from harness.adapterproc import AdapterFailure, AdapterProcess
from harness.pins import AdapterPin
from harness.schema import ValidationError, load_schema, validate

HANDSHAKE_REQUEST: dict[str, Any] = {
    "runnerProtocol": pins.RUNNER_PROTOCOL,
    "caseId": "handshake",
    "operation": "hello",
    "input": {},
}


class HandshakeFailure(Exception):
    def __init__(self, symbol: str, message: str) -> None:
        super().__init__(f"{symbol}: {message}")
        self.symbol = symbol
        self.message = message


def repo_root_default() -> Path:
    return Path(__file__).resolve().parent.parent


def rust_adapter_argv(repo_root: Path, override: str | None) -> list[str]:
    if override:
        return [override]
    candidates = [
        repo_root / "adapters/rust/target/release/followee-adapter-rust",
        repo_root / "adapters/rust/target/debug/followee-adapter-rust",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate)]
    raise SystemExit2(
        4,
        "Rust adapter binary not found; build it first:\n"
        "  cargo build --locked --manifest-path adapters/rust/Cargo.toml",
    )


def python_adapter_argv(repo_root: Path, override: str | None) -> list[str]:
    script = Path(override) if override else repo_root / "adapters/python/adapter.py"
    if not script.is_file():
        raise SystemExit2(4, f"Python adapter not found at {script}")
    return [sys.executable, "-B", str(script)]


class SystemExit2(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def verify_hello_response(
    response: dict[str, Any],
    adapter_pin: AdapterPin,
    response_schema: dict[str, Any],
    hello_schema: dict[str, Any],
) -> dict[str, Any]:
    """Validate a handshake response against schemas and every pin."""
    try:
        validate(response, response_schema)
    except ValidationError as exc:
        raise HandshakeFailure("harness.responseSchemaViolation", str(exc)) from exc
    if response["runnerProtocol"] != HANDSHAKE_REQUEST["runnerProtocol"]:
        raise HandshakeFailure(
            "harness.protocolEchoMismatch",
            f"runnerProtocol {response['runnerProtocol']!r} does not repeat "
            f"the request's {HANDSHAKE_REQUEST['runnerProtocol']!r}",
        )
    if response["caseId"] != HANDSHAKE_REQUEST["caseId"]:
        raise HandshakeFailure(
            "harness.caseIdMismatch",
            f"caseId {response['caseId']!r} does not repeat "
            f"{HANDSHAKE_REQUEST['caseId']!r}",
        )
    if response["status"] != "accepted":
        raise HandshakeFailure(
            "harness.handshakeRejected",
            f"handshake returned status {response['status']!r}: "
            f"{response.get('error')!r}",
        )
    result = response["result"]
    try:
        validate(result, hello_schema)
    except ValidationError as exc:
        raise HandshakeFailure("harness.helloSchemaViolation", str(exc)) from exc

    checks = [
        ("adapter", result["adapter"], adapter_pin.adapter),
        (
            "implementationRepository",
            result["implementationRepository"],
            adapter_pin.repository_url,
        ),
        (
            "implementationCommit",
            result["implementationCommit"],
            adapter_pin.implementation_commit,
        ),
        (
            "specificationCommit",
            result["specificationCommit"],
            pins.SPECIFICATION_COMMIT,
        ),
    ]
    for field, actual, expected in checks:
        if actual != expected:
            raise HandshakeFailure(
                "harness.pinMismatch",
                f"{field} is {actual!r}, pinned {expected!r}",
            )
    if pins.RUNNER_PROTOCOL not in result["runnerProtocols"]:
        raise HandshakeFailure(
            "harness.capabilityMismatch",
            f"adapter does not speak runner protocol "
            f"{pins.RUNNER_PROTOCOL!r}: {result['runnerProtocols']!r}",
        )
    if tuple(result["operations"]) != pins.MILESTONE_0_OPERATIONS:
        raise HandshakeFailure(
            "harness.capabilityMismatch",
            "Milestone 0 requires the operation set "
            f"{list(pins.MILESTONE_0_OPERATIONS)!r}, adapter reports "
            f"{result['operations']!r}",
        )
    return result


def run_handshake(
    name: str,
    argv: list[str],
    adapter_pin: AdapterPin,
    repo_root: Path,
    timeout: float,
) -> dict[str, Any]:
    response_schema = load_schema(repo_root, "runner-response.schema.json")
    hello_schema = load_schema(repo_root, "hello-result.schema.json")
    with tempfile.TemporaryDirectory(prefix=f"followee-{name}-") as tmp:
        proc = AdapterProcess(name, argv, Path(tmp), timeout=timeout)
        proc.start()
        try:
            response = proc.request(HANDSHAKE_REQUEST)
            result = verify_hello_response(
                response, adapter_pin, response_schema, hello_schema
            )
            proc.shutdown()
        except Exception:
            proc.kill()
            raise
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Followee conformance orchestrator (Milestone 0: "
        "integrity checks and hello handshakes only)"
    )
    parser.add_argument("--repo-root", type=Path, default=repo_root_default())
    parser.add_argument("--timeout", type=float, default=pins.DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--rust-adapter", default=None)
    parser.add_argument("--python-adapter", default=None)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()

    # Phase 1: integrity (HARNESS.md 14.1).  Refusal happens before any
    # adapter process is launched.
    failures = integrity.check_all(repo_root)
    if failures:
        print("INTEGRITY REFUSAL - no adapter was launched", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 2

    print("integrity: all submodule pins, tags, and the specification digest verified")

    # Phase 2: handshakes, sequentially and deterministically.
    try:
        adapters = [
            (
                "rust",
                rust_adapter_argv(repo_root, args.rust_adapter),
                pins.RUST_ADAPTER_PIN,
            ),
            (
                "python",
                python_adapter_argv(repo_root, args.python_adapter),
                pins.PYTHON_ADAPTER_PIN,
            ),
        ]
    except SystemExit2 as exc:
        print(exc.message, file=sys.stderr)
        return exc.code

    for name, argv_, adapter_pin in adapters:
        try:
            result = run_handshake(name, argv_, adapter_pin, repo_root, args.timeout)
        except (AdapterFailure, HandshakeFailure) as exc:
            print(
                f"HANDSHAKE FAILURE [{name}] {exc.symbol}: {exc.message}",
                file=sys.stderr,
            )
            excerpt = getattr(exc, "stderr_excerpt", "")
            if excerpt:
                print(f"  adapter stderr: {excerpt}", file=sys.stderr)
            return 3
        print(
            f"handshake[{name}]: adapter={result['adapter']!r} "
            f"implementationCommit={result['implementationCommit']} "
            f"specificationCommit={result['specificationCommit']} "
            f"operations={result['operations']!r}"
        )

    print(
        "Milestone 0 handshake complete: both adapters verified against "
        "every Section 2 pin; no Followee protocol operation was exercised."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
