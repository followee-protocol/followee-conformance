"""Acquisition and integrity checks (HARNESS.md Sections 2 and 6).

A run MUST refuse to start when a submodule is missing or dirty, a HEAD or
recorded gitlink disagrees with its pin, a public tag does not peel to the
recorded commit, or the specification bytes have the wrong SHA-256 digest.
A failed integrity check is an infrastructure failure, not a conformance
result.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

from harness import pins as default_pins
from harness.pins import SubmodulePin


@dataclass(frozen=True)
class IntegrityFailure:
    """One refused integrity condition.

    ``symbol`` is a stable machine classification in the ``harness.``
    namespace, e.g. ``harness.integrity.wrongCommit``.
    """

    symbol: str
    subject: str
    message: str

    def __str__(self) -> str:
        return f"{self.symbol} [{self.subject}]: {self.message}"


class GitUnavailableError(RuntimeError):
    pass


def _git(repo: Path, *args: str) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitUnavailableError("git executable not found") from exc
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def check_submodule(repo_root: Path, pin: SubmodulePin) -> list[IntegrityFailure]:
    failures: list[IntegrityFailure] = []
    subdir = repo_root / pin.path

    def fail(symbol: str, message: str) -> None:
        failures.append(
            IntegrityFailure(f"harness.integrity.{symbol}", pin.path, message)
        )

    if not (subdir / ".git").exists():
        fail(
            "uninitializedSubmodule",
            "submodule is not initialized; run `git submodule update --init`",
        )
        return failures

    # Superproject gitlink (index) must record the pinned commit.
    code, out, err = _git(repo_root, "ls-files", "-s", "--", pin.path)
    if code != 0 or not out:
        fail("gitlinkMissing", f"no gitlink recorded for {pin.path}: {err}")
    else:
        fields = out.split()
        if fields[0] != "160000" or fields[1] != pin.commit:
            fail(
                "gitlinkMismatch",
                f"superproject records {fields[1]}, pinned {pin.commit}",
            )

    # Checked-out HEAD must equal the pin.
    code, head, err = _git(subdir, "rev-parse", "HEAD")
    if code != 0:
        fail("gitError", f"rev-parse HEAD failed: {err}")
        return failures
    if head != pin.commit:
        fail("wrongCommit", f"HEAD is {head}, pinned {pin.commit}")

    # Working tree must be clean, including untracked files.
    code, status, err = _git(subdir, "status", "--porcelain")
    if code != 0:
        fail("gitError", f"status failed: {err}")
    elif status:
        excerpt = "; ".join(status.splitlines()[:5])
        fail("dirtySubmodule", f"working tree not clean: {excerpt}")

    # Public tags must peel to the recorded commits (tags are pins;
    # branches are not).
    for tag, expected in pin.tags.items():
        code, peeled, err = _git(subdir, "rev-parse", f"{tag}^{{commit}}")
        if code != 0:
            fail("tagMissing", f"tag {tag} not found: {err}")
        elif peeled != expected:
            fail(
                "tagMismatch",
                f"tag {tag} peels to {peeled}, expected {expected}",
            )

    # Audit continuity (HARNESS.md Section 2).
    if pin.parent is not None:
        code, parent, err = _git(subdir, "rev-parse", f"{pin.commit}^")
        if code != 0 or parent != pin.parent:
            fail(
                "parentMismatch",
                f"parent of {pin.commit[:12]} is {parent or err}, "
                f"expected {pin.parent}",
            )
    for commit in pin.audit_commits:
        code, _, err = _git(subdir, "cat-file", "-e", f"{commit}^{{commit}}")
        if code != 0:
            fail("auditCommitMissing", f"commit {commit} absent: {err}")

    return failures


def check_specification_digest(
    repo_root: Path,
    relative_path: str = default_pins.SPECIFICATION_FILE,
    expected_sha256: str = default_pins.SPECIFICATION_SHA256,
) -> list[IntegrityFailure]:
    spec = repo_root / relative_path
    if not spec.is_file():
        return [
            IntegrityFailure(
                "harness.integrity.specificationMissing",
                relative_path,
                "pinned specification file not found",
            )
        ]
    digest = hashlib.sha256(spec.read_bytes()).hexdigest()
    if digest != expected_sha256:
        return [
            IntegrityFailure(
                "harness.integrity.specificationDigestMismatch",
                relative_path,
                f"SHA-256 is {digest}, pinned {expected_sha256}",
            )
        ]
    return []


def check_all(
    repo_root: Path,
    submodule_pins: tuple[SubmodulePin, ...] = default_pins.ALL_SUBMODULE_PINS,
) -> list[IntegrityFailure]:
    """Run every Milestone 0 integrity check; return all failures found."""
    failures: list[IntegrityFailure] = []
    for pin in submodule_pins:
        failures.extend(check_submodule(repo_root, pin))
    failures.extend(check_specification_digest(repo_root))
    return failures
