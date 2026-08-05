"""Digest-manifest hardening tests (HARNESS.md Sections 6 and 12).

``DIGESTS.sha256`` lines must be exactly ``<64-char lowercase hex
digest><two spaces><plain filename>``: no other separators, no path
components, no surrounding whitespace, and no duplicate entries.
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from harness.cases import CaseError, verify_digest_manifest

CONTENT = '{"placeholder": true}\n'
DIGEST = hashlib.sha256(CONTENT.encode()).hexdigest()


class DigestManifestTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="followee-digests-")
        self.addCleanup(self._tmp.cleanup)
        self.cases_dir = Path(self._tmp.name)
        (self.cases_dir / "a.json").write_text(CONTENT)

    def write_manifest(self, text: str) -> None:
        (self.cases_dir / "DIGESTS.sha256").write_text(text)

    def assert_symbol(self, manifest_text: str, symbol: str):
        self.write_manifest(manifest_text)
        with self.assertRaises(CaseError) as ctx:
            verify_digest_manifest(self.cases_dir)
        self.assertEqual(ctx.exception.symbol, symbol)

    def test_valid_manifest_passes(self):
        self.write_manifest(f"{DIGEST}  a.json\n")
        self.assertEqual(verify_digest_manifest(self.cases_dir), {"a.json": DIGEST})

    def test_uppercase_digest_rejected(self):
        self.assert_symbol(
            f"{DIGEST.upper()}  a.json\n",
            "harness.case.digestManifestMalformed",
        )

    def test_short_digest_rejected(self):
        self.assert_symbol(
            f"{DIGEST[:63]}  a.json\n", "harness.case.digestManifestMalformed"
        )

    def test_non_hex_digest_rejected(self):
        self.assert_symbol(
            f"g{DIGEST[1:]}  a.json\n", "harness.case.digestManifestMalformed"
        )

    def test_single_space_separator_rejected(self):
        self.assert_symbol(f"{DIGEST} a.json\n", "harness.case.digestManifestMalformed")

    def test_extra_separator_rejected(self):
        self.assert_symbol(
            f"{DIGEST}  a.json  b.json\n",
            "harness.case.digestManifestMalformed",
        )

    def test_leading_whitespace_filename_rejected(self):
        self.assert_symbol(
            f"{DIGEST}   a.json\n", "harness.case.digestManifestMalformed"
        )

    def test_trailing_whitespace_filename_rejected(self):
        self.assert_symbol(
            f"{DIGEST}  a.json \n", "harness.case.digestManifestMalformed"
        )

    def test_path_component_rejected(self):
        self.assert_symbol(
            f"{DIGEST}  sub/a.json\n", "harness.case.digestManifestMalformed"
        )

    def test_parent_traversal_rejected(self):
        self.assert_symbol(f"{DIGEST}  ..\n", "harness.case.digestManifestMalformed")

    def test_empty_filename_rejected(self):
        self.assert_symbol(f"{DIGEST}  \n", "harness.case.digestManifestMalformed")

    def test_duplicate_entry_rejected(self):
        self.assert_symbol(
            f"{DIGEST}  a.json\n{DIGEST}  a.json\n",
            "harness.case.digestManifestDuplicate",
        )

    def test_unlisted_file_rejected(self):
        (self.cases_dir / "b.json").write_text(CONTENT)
        self.assert_symbol(f"{DIGEST}  a.json\n", "harness.case.digestManifestMismatch")

    def test_wrong_digest_rejected(self):
        self.assert_symbol(
            f"{'0' * 64}  a.json\n", "harness.case.contentDigestMismatch"
        )


if __name__ == "__main__":
    unittest.main()
