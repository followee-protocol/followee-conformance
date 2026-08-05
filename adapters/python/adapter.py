#!/usr/bin/env python3
"""Neutral runner-protocol v1 adapter for the pinned Python clean-room model.

Milestone 0 supports only the ``hello`` handshake (HARNESS.md Sections 8
and 20).  This file contains no Followee protocol logic; it imports the
frozen model read-only from the Git submodule (never copying it) purely to
prove the pinned checkout is present and importable.

The adapter is deliberately self-contained (standard library only, no
harness imports) so it can be launched from an isolated working directory.
Protocol responses go only to standard output; diagnostics go only to
standard error.

Identity (implementation and specification commits) is resolved from the
verified submodule checkouts at startup via git, never from an unchecked
environment variable.  The orchestrator independently re-verifies both
values against the HARNESS.md Section 2 pins.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

RUNNER_PROTOCOL = "1"
MAX_LINE_BYTES = 1 * 1024 * 1024
BOM = b"\xef\xbb\xbf"

ADAPTER_NAME = "followee-python-cleanroom"
ADAPTER_VERSION = "1"
IMPLEMENTATION_REPOSITORY = (
    "https://github.com/followee-protocol/followee-python-cleanroom"
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_SUBMODULE = REPO_ROOT / "implementations" / "followee-python-cleanroom"
MODEL_PACKAGE_DIR = MODEL_SUBMODULE / "tools" / "python-model"
SPEC_SUBMODULE = REPO_ROOT / "specification"


class AdapterStartupError(RuntimeError):
    pass


def _git_head(repo: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AdapterStartupError("git executable not found") from exc
    if proc.returncode != 0:
        raise AdapterStartupError(
            f"cannot resolve checkout identity of {repo}: {proc.stderr.strip()}"
        )
    commit = proc.stdout.strip()
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise AdapterStartupError(f"unexpected commit id {commit!r} for {repo}")
    return commit


def resolve_identity() -> dict[str, Any]:
    """Build the hello result from the verified checkouts."""
    if not MODEL_PACKAGE_DIR.is_dir():
        raise AdapterStartupError(
            f"frozen Python model not found at {MODEL_PACKAGE_DIR}; run "
            "`git submodule update --init`"
        )
    # Import the frozen model read-only, without copying or modifying it
    # (HARNESS.md Section 5).  No protocol function is called at
    # Milestone 0; the import proves the pinned checkout is usable.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(MODEL_PACKAGE_DIR))
    try:
        import followee_model  # noqa: F401
    except Exception as exc:
        raise AdapterStartupError(
            f"frozen Python model failed to import: {exc!r}"
        ) from exc
    finally:
        sys.path.remove(str(MODEL_PACKAGE_DIR))
    return {
        "adapter": ADAPTER_NAME,
        "adapterVersion": ADAPTER_VERSION,
        "implementationRepository": IMPLEMENTATION_REPOSITORY,
        "implementationCommit": _git_head(MODEL_SUBMODULE),
        "specificationCommit": _git_head(SPEC_SUBMODULE),
        "runnerProtocols": [RUNNER_PROTOCOL],
        "operations": ["hello"],
    }


class _ProfileError(ValueError):
    pass


def _reject_number(token: str) -> Any:
    raise _ProfileError(
        f"bare JSON number {token!r}; protocol integers are decimal strings"
    )


def _reject_constant(token: str) -> Any:
    raise _ProfileError(f"forbidden JSON constant {token!r}")


def _pairs_rejecting_duplicates(pairs: list) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _ProfileError(f"duplicate object member {key!r}")
        obj[key] = value
    return obj


def parse_request(raw: bytes) -> dict[str, Any]:
    """Parse one request line under the runner JSON profile (HARNESS.md 7.2)."""
    if raw.startswith(BOM):
        raise _ProfileError("request line begins with a UTF-8 byte-order mark")
    if raw.strip() == b"":
        raise _ProfileError("blank protocol line")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _ProfileError(f"request line is not UTF-8: {exc}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_rejecting_duplicates,
            parse_float=_reject_number,
            parse_int=_reject_number,
            parse_constant=_reject_constant,
        )
    except _ProfileError:
        raise
    except json.JSONDecodeError as exc:
        raise _ProfileError(str(exc)) from exc
    if not isinstance(value, dict):
        raise _ProfileError("request is not a JSON object")
    expected_members = {"runnerProtocol", "caseId", "operation", "input"}
    unknown = set(value) - expected_members
    if unknown:
        raise _ProfileError(f"unknown object members {sorted(unknown)}")
    missing = expected_members - set(value)
    if missing:
        raise _ProfileError(f"missing object members {sorted(missing)}")
    for member in ("runnerProtocol", "caseId", "operation"):
        if not isinstance(value[member], str):
            raise _ProfileError(f"{member} must be a string")
    if value["caseId"] == "":
        raise _ProfileError("caseId must be a nonempty string")
    if not isinstance(value["input"], dict):
        raise _ProfileError("input must be an object")
    return value


def _adapter_error(
    runner_protocol: str, case_id: str, symbol: str, message: str
) -> dict[str, Any]:
    return {
        "runnerProtocol": runner_protocol,
        "caseId": case_id,
        "status": "adapterError",
        "error": symbol,
        "message": message,
    }


def handle_line(
    identity: dict[str, Any], raw: bytes, truncated: bool
) -> dict[str, Any]:
    """Handle one raw request line; return the response object."""
    if truncated:
        return _adapter_error(
            RUNNER_PROTOCOL,
            "unknown",
            "adapter.lineTooLong",
            "request line exceeded the 1 MiB runner limit",
        )
    try:
        request = parse_request(raw)
    except _ProfileError as exc:
        return _adapter_error(
            RUNNER_PROTOCOL,
            "unknown",
            "adapter.malformedRequest",
            f"request does not satisfy the runner JSON profile: {exc}",
        )
    # Responses repeat the request's runnerProtocol and caseId exactly
    # (HARNESS.md 7.3), even on adapter errors.
    if request["runnerProtocol"] != RUNNER_PROTOCOL:
        return _adapter_error(
            request["runnerProtocol"],
            request["caseId"],
            "adapter.unsupportedProtocol",
            f"runner protocol {request['runnerProtocol']!r} is not "
            f"supported; this adapter speaks {RUNNER_PROTOCOL!r}",
        )
    if request["operation"] == "hello":
        if request["input"] != {}:
            return _adapter_error(
                RUNNER_PROTOCOL,
                request["caseId"],
                "adapter.invalidInput",
                "hello takes an empty input object",
            )
        return {
            "runnerProtocol": RUNNER_PROTOCOL,
            "caseId": request["caseId"],
            "status": "accepted",
            "result": identity,
        }
    return _adapter_error(
        RUNNER_PROTOCOL,
        request["caseId"],
        "adapter.unsupportedOperation",
        f"operation {request['operation']!r} is not supported at Milestone 0",
    )


def _read_line_capped(stream, max_bytes: int):
    """Read one line; return (line_without_newline, truncated) or None at EOF.

    A line longer than ``max_bytes`` is drained through its newline and
    flagged truncated.
    """
    line = stream.readline(max_bytes + 1)
    if line == b"":
        return None
    if line.endswith(b"\n"):
        return line[:-1], False
    if len(line) <= max_bytes:
        # Final unterminated line before EOF.
        return line, False
    while True:
        chunk = stream.readline(65536)
        if chunk == b"" or chunk.endswith(b"\n"):
            return b"", True


def main() -> int:
    try:
        identity = resolve_identity()
    except AdapterStartupError as exc:
        print(f"adapter startup failure: {exc}", file=sys.stderr)
        return 3
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        item = _read_line_capped(stdin, MAX_LINE_BYTES)
        if item is None:
            return 0
        raw, truncated = item
        response = handle_line(identity, raw, truncated)
        encoded = json.dumps(
            response, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        stdout.write(encoded + b"\n")
        stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
