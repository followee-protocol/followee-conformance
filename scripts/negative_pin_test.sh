#!/bin/sh
# Negative integrity test (HARNESS.md Section 19): prove that a wrong
# implementation commit is refused by the orchestrator BEFORE any adapter
# runs.  The Rust submodule is temporarily checked out at the pin's parent
# commit and restored afterwards; the submodule content is never modified.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUB="$REPO_ROOT/implementations/followee-rs"
PINNED="c30b2207aeccb4daa5fb06a388ecd0ec5e0ab625"
WRONG="774acb7578795cf6d58f77b76b16ef010114ebd6"

if [ -n "$(git -C "$SUB" status --porcelain)" ]; then
    echo "refusing: $SUB is dirty; the negative pin test needs a clean tree" >&2
    exit 4
fi
if [ "$(git -C "$SUB" rev-parse HEAD)" != "$PINNED" ]; then
    echo "refusing: $SUB is not at the pinned commit to begin with" >&2
    exit 4
fi

restore() {
    git -C "$SUB" checkout --quiet "$PINNED"
}
trap restore EXIT INT TERM

echo "checking out wrong commit $WRONG in implementations/followee-rs"
git -C "$SUB" checkout --quiet "$WRONG"

STDERR_LOG="$(mktemp)"
set +e
(cd "$REPO_ROOT" && python3 -m harness.orchestrator --repo-root "$REPO_ROOT") \
    >/dev/null 2>"$STDERR_LOG"
CODE=$?
set -e

if [ "$CODE" -ne 2 ]; then
    echo "FAIL: orchestrator exited $CODE, expected integrity refusal (2)" >&2
    cat "$STDERR_LOG" >&2
    rm -f "$STDERR_LOG"
    exit 1
fi
if ! grep -q "harness.integrity.wrongCommit" "$STDERR_LOG"; then
    echo "FAIL: refusal did not cite harness.integrity.wrongCommit" >&2
    cat "$STDERR_LOG" >&2
    rm -f "$STDERR_LOG"
    exit 1
fi
rm -f "$STDERR_LOG"

restore
trap - EXIT INT TERM
if [ "$(git -C "$SUB" rev-parse HEAD)" != "$PINNED" ]; then
    echo "FAIL: could not restore the pinned checkout" >&2
    exit 1
fi
echo "PASS: wrong implementation commit was refused before any adapter ran"
