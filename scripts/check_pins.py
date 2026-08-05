#!/usr/bin/env python3
"""Verify every HARNESS.md Section 2 pin (submodules, tags, digest).

Exit 0 when every pin verifies; exit 2 with one line per failure
otherwise.  Runs locally and in CI (HARNESS.md Section 6).
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from harness.integrity import check_all


def main() -> int:
    failures = check_all(REPO_ROOT)
    if failures:
        print("INTEGRITY REFUSAL", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 2
    print(
        "integrity: all submodule pins, tags, audit commits, and the "
        "specification digest verified"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
