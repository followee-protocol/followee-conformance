"""Machine-readable mirror of the frozen targets in HARNESS.md Section 2.

Every value here is a pin.  A run MUST refuse to start when a checkout
disagrees with these values; refusal is an infrastructure failure, never a
conformance result (HARNESS.md Sections 2 and 6).
"""

from __future__ import annotations

from dataclasses import dataclass, field

RUNNER_PROTOCOL = "1"

# Maximum runner-protocol line length in each direction (HARNESS.md 7.1).
MAX_LINE_BYTES = 1 * 1024 * 1024

# Default per-request adapter timeout in seconds (HARNESS.md 7.1).
DEFAULT_TIMEOUT_SECONDS = 5.0

SPECIFICATION_COMMIT = "abc9a55d90f1026e6509207abda73e5dc6d14241"
SPECIFICATION_SHA256 = (
    "2b264823ba68d9a7d69ce68de5c1408ac8a3d54ff6d726ab89ee2baa2707c81f"
)

RUST_COMMIT = "774acb7578795cf6d58f77b76b16ef010114ebd6"
RUST_REVIEW_FIX_PARENT = "d23d660c1efb8e1c8f0095a2b44040bc44cf5160"

PYTHON_COMMIT = "a39138dae8072c7b89dc922bcfe6f5717312c6e6"
PYTHON_V07_MAINTENANCE_INPUT = "6b944b952d1daec6840deae7e07f304f5349637d"
PYTHON_V06_FREEZE = "7ca1f623453065deefd1e6cfdf15e135d523dd7e"
PYTHON_V06_REVIEW_CORRECTION = "70e4a6caa8720f1dfbb3b183a5d305fca0cf3e57"


@dataclass(frozen=True)
class SubmodulePin:
    """One pinned Git submodule and its audit-continuity facts."""

    path: str
    repository: str
    commit: str
    # Tag name -> commit the tag must peel to.
    tags: dict[str, str] = field(default_factory=dict)
    # Commit that must be the first parent of ``commit``.
    parent: str | None = None
    # Commits that must merely exist in the repository (audit continuity,
    # HARNESS.md Section 2).
    audit_commits: tuple[str, ...] = ()


SPECIFICATION_PIN = SubmodulePin(
    path="specification",
    repository="https://github.com/followee-protocol/followee.git",
    commit=SPECIFICATION_COMMIT,
)

RUST_PIN = SubmodulePin(
    path="implementations/followee-rs",
    repository="https://github.com/followee-protocol/followee-rs.git",
    commit=RUST_COMMIT,
    tags={"milestone-1-v0.7-reviewed": RUST_COMMIT},
    parent=RUST_REVIEW_FIX_PARENT,
)

PYTHON_PIN = SubmodulePin(
    path="implementations/followee-python-cleanroom",
    repository=("https://github.com/followee-protocol/followee-python-cleanroom.git"),
    commit=PYTHON_COMMIT,
    tags={
        "cleanroom-v0.7-maintenance-freeze": PYTHON_COMMIT,
        "cleanroom-v0.6-freeze": PYTHON_V06_FREEZE,
        "cleanroom-v0.6-review1": PYTHON_V06_REVIEW_CORRECTION,
    },
    audit_commits=(
        PYTHON_V07_MAINTENANCE_INPUT,
        PYTHON_V06_FREEZE,
        PYTHON_V06_REVIEW_CORRECTION,
    ),
)

ALL_SUBMODULE_PINS = (SPECIFICATION_PIN, RUST_PIN, PYTHON_PIN)

# Path, relative to the repository root, of the pinned specification bytes.
SPECIFICATION_FILE = "specification/Followee-Specification.md"


@dataclass(frozen=True)
class AdapterPin:
    """Expected handshake identity for one adapter (HARNESS.md Section 8)."""

    name: str
    adapter: str
    repository_url: str
    implementation_commit: str


RUST_ADAPTER_PIN = AdapterPin(
    name="rust",
    adapter="followee-rust",
    repository_url="https://github.com/followee-protocol/followee-rs",
    implementation_commit=RUST_COMMIT,
)

PYTHON_ADAPTER_PIN = AdapterPin(
    name="python",
    adapter="followee-python-cleanroom",
    repository_url=("https://github.com/followee-protocol/followee-python-cleanroom"),
    implementation_commit=PYTHON_COMMIT,
)

# Milestone 1: adapters support exactly this operation set (HARNESS.md
# Section 20, Milestone 1).  The harness refuses adapters whose reported
# capabilities differ from the campaign's requirements (Section 8).
SUPPORTED_OPERATIONS = (
    "hello",
    "deriveIdentity",
    "authorRecord",
    "verifyRecord",
)
