"""Integrity-check unit tests against synthetic git trees (HARNESS.md 6).

Every scenario builds a disposable superproject with a real submodule and
then breaks exactly one pinned property.  A failed check must refuse the
run; refusal is an infrastructure failure, not a conformance result.
"""

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from harness.integrity import (
    check_all,
    check_specification_digest,
    check_submodule,
)
from harness.pins import SubmodulePin

GIT_ID = ["-c", "user.name=test", "-c", "user.email=test@example.invalid"]


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *GIT_ID, "-c", "protocol.file.allow=always", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"git {args} failed in {cwd}: {proc.stderr.strip()}")
    return proc.stdout.strip()


class Fixture:
    """A superproject containing one real pinned submodule."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        upstream = tmp / "upstream"
        upstream.mkdir()
        self.upstream_url = str(upstream)
        git(upstream, "init", "--quiet", "--initial-branch=main")
        (upstream / "file.txt").write_text("first\n")
        git(upstream, "add", "file.txt")
        git(upstream, "commit", "--quiet", "-m", "first")
        self.first_commit = git(upstream, "rev-parse", "HEAD")
        (upstream / "file.txt").write_text("second\n")
        git(upstream, "commit", "--quiet", "-am", "second")
        self.pinned_commit = git(upstream, "rev-parse", "HEAD")
        git(upstream, "tag", "-a", "frozen-v1", "-m", "freeze")
        git(upstream, "tag", "-a", "old-v0", "-m", "old", self.first_commit)

        self.root = tmp / "superproject"
        self.root.mkdir()
        git(self.root, "init", "--quiet", "--initial-branch=main")
        git(self.root, "submodule", "add", str(upstream), "sub")
        git(self.root, "commit", "--quiet", "-m", "add submodule")
        self.subdir = self.root / "sub"

    def pin(self, **overrides) -> SubmodulePin:
        values = {
            "path": "sub",
            "repository": self.upstream_url,
            "commit": self.pinned_commit,
            "tags": {
                "frozen-v1": self.pinned_commit,
                "old-v0": self.first_commit,
            },
            "parent": self.first_commit,
            "audit_commits": (self.first_commit,),
        }
        values.update(overrides)
        return SubmodulePin(**values)


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="followee-integrity-")
        self.addCleanup(self._tmp.cleanup)
        self.fx = Fixture(Path(self._tmp.name))

    def symbols(self, failures):
        return {f.symbol for f in failures}

    def test_clean_pinned_submodule_passes(self):
        failures = check_submodule(self.fx.root, self.fx.pin())
        self.assertEqual(failures, [])

    def test_wrong_checked_out_commit_refused(self):
        git(self.fx.subdir, "checkout", "--quiet", self.fx.first_commit)
        failures = check_submodule(self.fx.root, self.fx.pin())
        self.assertIn("harness.integrity.wrongCommit", self.symbols(failures))

    def test_gitlink_disagreeing_with_pin_refused(self):
        failures = check_submodule(
            self.fx.root, self.fx.pin(commit=self.fx.first_commit, parent=None)
        )
        self.assertIn("harness.integrity.gitlinkMismatch", self.symbols(failures))

    def test_dirty_working_tree_refused(self):
        (self.fx.subdir / "file.txt").write_text("tampered\n")
        failures = check_submodule(self.fx.root, self.fx.pin())
        self.assertIn("harness.integrity.dirtySubmodule", self.symbols(failures))

    def test_untracked_file_counts_as_dirty(self):
        (self.fx.subdir / "stray.txt").write_text("stray\n")
        failures = check_submodule(self.fx.root, self.fx.pin())
        self.assertIn("harness.integrity.dirtySubmodule", self.symbols(failures))

    def test_gitmodules_url_mismatch_refused(self):
        # Only the .gitmodules record is wrong; origin still matches.
        git(
            self.fx.root,
            "config",
            "--file",
            ".gitmodules",
            "submodule.sub.url",
            "https://example.invalid/other.git",
        )
        failures = check_submodule(self.fx.root, self.fx.pin())
        symbols = self.symbols(failures)
        self.assertIn("harness.integrity.gitmodulesUrlMismatch", symbols)
        self.assertNotIn("harness.integrity.originUrlMismatch", symbols)

    def test_missing_gitmodules_entry_refused(self):
        (self.fx.root / ".gitmodules").unlink()
        failures = check_submodule(self.fx.root, self.fx.pin())
        self.assertIn("harness.integrity.gitmodulesUrlMismatch", self.symbols(failures))

    def test_origin_url_mismatch_refused(self):
        # Only the submodule's configured origin is wrong; .gitmodules
        # still matches.
        git(
            self.fx.subdir,
            "remote",
            "set-url",
            "origin",
            "https://example.invalid/other.git",
        )
        failures = check_submodule(self.fx.root, self.fx.pin())
        symbols = self.symbols(failures)
        self.assertIn("harness.integrity.originUrlMismatch", symbols)
        self.assertNotIn("harness.integrity.gitmodulesUrlMismatch", symbols)

    def test_missing_origin_remote_refused(self):
        git(self.fx.subdir, "remote", "remove", "origin")
        failures = check_submodule(self.fx.root, self.fx.pin())
        self.assertIn("harness.integrity.originUrlMismatch", self.symbols(failures))

    def test_missing_tag_refused(self):
        pin = self.fx.pin(tags={"no-such-tag": self.fx.pinned_commit})
        failures = check_submodule(self.fx.root, pin)
        self.assertIn("harness.integrity.tagMissing", self.symbols(failures))

    def test_tag_peeling_to_wrong_commit_refused(self):
        pin = self.fx.pin(tags={"old-v0": self.fx.pinned_commit})
        failures = check_submodule(self.fx.root, pin)
        self.assertIn("harness.integrity.tagMismatch", self.symbols(failures))

    def test_moved_tag_refused(self):
        # An implementation correction must get a new tag, never a moved
        # one (HARNESS.md Section 16); a re-pointed tag is refused.
        git(
            self.fx.subdir,
            "tag",
            "-f",
            "-a",
            "frozen-v1",
            "-m",
            "moved",
            self.fx.first_commit,
        )
        failures = check_submodule(self.fx.root, self.fx.pin())
        self.assertIn("harness.integrity.tagMismatch", self.symbols(failures))

    def test_uninitialized_submodule_refused(self):
        pin = self.fx.pin(path="not-checked-out")
        failures = check_submodule(self.fx.root, pin)
        self.assertEqual(
            self.symbols(failures),
            {"harness.integrity.uninitializedSubmodule"},
        )

    def test_wrong_parent_refused(self):
        pin = self.fx.pin(parent="f" * 40)
        failures = check_submodule(self.fx.root, pin)
        self.assertIn("harness.integrity.parentMismatch", self.symbols(failures))

    def test_missing_audit_commit_refused(self):
        pin = self.fx.pin(audit_commits=("e" * 40,))
        failures = check_submodule(self.fx.root, pin)
        self.assertIn("harness.integrity.auditCommitMissing", self.symbols(failures))

    def test_specification_digest_verified(self):
        spec = self.fx.root / "spec.md"
        spec.write_bytes(b"specification bytes\n")
        digest = hashlib.sha256(b"specification bytes\n").hexdigest()
        self.assertEqual(
            check_specification_digest(self.fx.root, "spec.md", digest), []
        )

    def test_specification_digest_mismatch_refused(self):
        spec = self.fx.root / "spec.md"
        spec.write_bytes(b"tampered bytes\n")
        failures = check_specification_digest(
            self.fx.root, "spec.md", hashlib.sha256(b"original\n").hexdigest()
        )
        self.assertEqual(
            self.symbols(failures),
            {"harness.integrity.specificationDigestMismatch"},
        )

    def test_missing_specification_refused(self):
        failures = check_specification_digest(self.fx.root, "no-such-file.md", "0" * 64)
        self.assertEqual(
            self.symbols(failures),
            {"harness.integrity.specificationMissing"},
        )

    def test_check_all_collects_every_failure(self):
        git(self.fx.subdir, "checkout", "--quiet", self.fx.first_commit)
        (self.fx.subdir / "stray.txt").write_text("stray\n")
        failures = check_all(self.fx.root, (self.fx.pin(),))
        symbols = self.symbols(failures)
        self.assertIn("harness.integrity.wrongCommit", symbols)
        self.assertIn("harness.integrity.dirtySubmodule", symbols)
        # The real specification path does not exist in the synthetic tree.
        self.assertIn("harness.integrity.specificationMissing", symbols)


class RealRepositoryIntegrityTests(unittest.TestCase):
    """The actual working tree must satisfy every Milestone 0 pin."""

    def test_real_pins_verify(self):
        repo_root = Path(__file__).resolve().parents[2]
        failures = check_all(repo_root)
        self.assertEqual(failures, [], "\n".join(str(f) for f in failures))


if __name__ == "__main__":
    unittest.main()
