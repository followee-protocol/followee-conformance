#!/usr/bin/env python3
"""Import the provisional followee-rs fixture inputs (HARNESS.md 14.3,
Milestone 2) into ``cases/implementation/``.

Sources, all pinned inside the frozen followee-rs submodule:

- ``fixtures/implementation/PROVENANCE.json`` — the provisional case
  manifest: mutation descriptions, fault profiles, re-signing keys, and
  expected outcomes (exact error assertions only where that manifest
  declares them portable);
- ``tools/fixture-builder`` output — the signed/derived constructions,
  reproduced byte-for-byte from the pinned test suite using only the
  frozen implementation's public API;
- documented byte splices of the published Appendix B envelopes for the
  constructions that need no signing (items 1a, 4a, 4b, 5, 6, 13, 14); and
- ``fixtures/external/ed25519_speccheck_cases.json`` — stored upstream
  Ed25519 edge-case vectors, imported verbatim with their provenance and
  digest verified.

Every produced case has ``derivationStatus: implementation`` and keeps its
exact provenance.  Expected Rust outputs are never inputs to any adapter:
manifest expectations live comparator-side only, and both adapters
discover their results independently (HARNESS.md Section 3).

Producing revision: these fixtures were originally generated at the
reviewed Milestone 1 revision ``774acb7578795cf6d58f77b76b16ef010114ebd6``
(tag ``milestone-1-v0.7-reviewed``).  The current pin
``c30b2207aeccb4daa5fb06a388ecd0ec5e0ab625`` is its API-only descendant;
the ``--check`` mode reconstructs every input at the current pin and
requires byte identity with the committed corpus, proving the descendant
changed no construction.

Usage:
    python3 scripts/build_implementation_corpus.py           # write corpus
    python3 scripts/build_implementation_corpus.py --check   # verify drift
    (add --inputs FILE to reuse a previously built fixture-builder output)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from build_specification_corpus import (
    B4_TIMESTAMP,
    B5_TIMESTAMP,
    ED25519_L,
    SPEC_COMMIT,
    Published,
)

CASES_DIR = REPO_ROOT / "cases" / "implementation"
RS_FIXTURES = REPO_ROOT / "implementations" / "followee-rs" / "fixtures"
PROVENANCE_PATH = RS_FIXTURES / "implementation" / "PROVENANCE.json"
SPECCHECK_PATH = RS_FIXTURES / "external" / "ed25519_speccheck_cases.json"
SPECCHECK_PROVENANCE_PATH = RS_FIXTURES / "external" / "PROVENANCE.json"
BUILDER_MANIFEST = REPO_ROOT / "tools" / "fixture-builder" / "Cargo.toml"

SOURCE_MANIFEST_REL = (
    "implementations/followee-rs/fixtures/implementation/PROVENANCE.json"
)


def builder_inputs(inputs_file: Path | None) -> dict[str, dict[str, str]]:
    """The signed/derived constructions from tools/fixture-builder."""
    if inputs_file is not None:
        document = json.loads(inputs_file.read_text(encoding="utf-8"))
    else:
        proc = subprocess.run(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "--manifest-path",
                str(BUILDER_MANIFEST),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise SystemExit(f"fixture-builder failed:\n{proc.stderr.strip()}")
        document = json.loads(proc.stdout)
    return document["inputs"]


def spliced_inputs(p: Published) -> dict[str, dict[str, str]]:
    """Constructions needing no signing: documented splices of the
    published Appendix B envelopes, per the pinned manifest descriptions."""
    env = p.b4_envelope
    s_value = int.from_bytes(bytes.fromhex(p.b4_signature[64:]), "little")
    s_plus_l = p.b4_signature[:64] + (s_value + ED25519_L).to_bytes(32, "little").hex()
    last_byte = int(env[-2:], 16) ^ 0x01
    return {
        "b7-1a-foreign-target": {
            "targetDid": p.attacker_did,
            "envelopeHex": env,
        },
        "b7-4a-missing-tag": {"targetDid": p.did, "envelopeHex": env[2:]},
        "b7-4b-non-minimal-tag": {
            "targetDid": p.did,
            "envelopeHex": "d812" + env[2:],
        },
        "b7-5-unprotected-headers": {
            "targetDid": p.did,
            "envelopeHex": env[:12] + "a10132" + env[14:],
        },
        "b7-6-detached-payload": {
            "targetDid": p.did,
            "envelopeHex": "d28443a10132a0f65840" + p.b4_signature,
        },
        "b7-13-flipped-signature-bit": {
            "targetDid": p.did,
            "envelopeHex": env[:-2] + f"{last_byte:02x}",
        },
        "b7-14-s-plus-l": {
            "targetDid": p.did,
            "envelopeHex": p.envelope_for(p.b4_body, s_plus_l),
        },
    }


# The one multi-variant manifest entry, expanded exactly as the pinned test
# suite enumerates it.
B7_16C_VARIANTS = [
    "b7-16c-display-name",
    "b7-16c-summary",
    "b7-16c-uri",
    "b7-16c-also-known-as-count",
    "b7-16c-service-count",
    "b7-16c-service-id-length",
    "b7-16c-extension-key-length",
    "b7-16c-nesting-depth",
    "b7-16c-member-count",
]


def item_section(source_id: str) -> str:
    item = source_id.split("-")[1]
    number = "".join(c for c in item if c.isdigit())
    return f"Appendix B.7 item {number}"


def b7_cases(provenance: dict, inputs: dict[str, dict[str, str]]) -> dict[str, dict]:
    cases: dict[str, dict] = {}
    for entry in provenance["cases"]:
        source_id = entry["id"]
        if source_id == "b7-16c-field-and-aggregate-boundaries":
            variant_ids = B7_16C_VARIANTS
        else:
            variant_ids = [source_id]
        for variant_id in variant_ids:
            case_input = inputs.get(variant_id)
            if case_input is None:
                raise SystemExit(f"no constructed input for {variant_id}")
            expected_entry = entry["expected"]
            if expected_entry["accepted"]:
                raise SystemExit(f"{source_id}: unexpected accepted case")
            expected: dict = {
                "outcome": "rejected",
                "errorAssertion": expected_entry["errorAssertion"],
            }
            if expected_entry["errorAssertion"] == "exact":
                expected["error"] = expected_entry["error"]
            now = B5_TIMESTAMP if entry.get("baseVector") == "B.5" else B4_TIMESTAMP
            derived_from = {
                "baseVector": entry["baseVector"].replace(" ", "-"),
                "mutation": entry["mutation"]
                + (
                    f" (variant: {variant_id[len('b7-16c-') :]})"
                    if variant_id != source_id
                    else ""
                ),
                "protectedBytesChanged": entry["protectedBytesChanged"],
                "payloadBytesChanged": entry["payloadBytesChanged"],
                "resigned": entry["resigned"],
            }
            if entry["resigned"]:
                derived_from["resignedKey"] = entry["signingKey"]
            case_id = f"impl-{variant_id}"
            document = {
                "id": case_id,
                "runnerProtocol": "1",
                "operation": "verifyRecord",
                "specificationCommit": SPEC_COMMIT,
                "specificationSections": [item_section(source_id)],
                "derivationStatus": "implementation",
                "faultProfile": entry["faultProfile"],
                "expected": expected,
                "input": {
                    "targetDid": case_input["targetDid"],
                    "envelopeHex": case_input["envelopeHex"],
                    "nowMs": now,
                },
                "derivedFrom": derived_from,
                "producedBy": "followee-rs",
                "provenance": {
                    "sourceManifest": SOURCE_MANIFEST_REL,
                    "sourceCaseId": source_id,
                    "sourceNote": entry.get("note"),
                    "constructedBy": (
                        "tools/fixture-builder (frozen followee-rs public "
                        "API and its pinned test suite's raw constructions)"
                        if variant_id in inputs and variant_id not in SPLICED_IDS
                        else "documented byte splice of published Appendix "
                        "B values per the pinned manifest description"
                    ),
                },
            }
            cases[case_id] = document
    return cases


SPLICED_IDS = {
    "b7-1a-foreign-target",
    "b7-4a-missing-tag",
    "b7-4b-non-minimal-tag",
    "b7-5-unprotected-headers",
    "b7-6-detached-payload",
    "b7-13-flipped-signature-bit",
    "b7-14-s-plus-l",
}


def speccheck_cases() -> dict[str, dict]:
    provenance = json.loads(SPECCHECK_PROVENANCE_PATH.read_text(encoding="utf-8"))
    raw = SPECCHECK_PATH.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != provenance["sha256"]:
        raise SystemExit(
            f"speccheck fixture digest {digest} does not match its "
            f"recorded provenance digest {provenance['sha256']}"
        )
    vectors = json.loads(raw.decode("utf-8"))
    cases: dict[str, dict] = {}
    for index, vector in enumerate(vectors):
        case_id = f"impl-speccheck-{index:02d}"
        cases[case_id] = {
            "id": case_id,
            "runnerProtocol": "1",
            "operation": "strictEd25519",
            "specificationCommit": SPEC_COMMIT,
            "specificationSections": ["Section 3.3"],
            "derivationStatus": "implementation",
            "faultProfile": "unknown",
            "expected": {"outcome": "accepted"},
            "input": {
                "publicKeyHex": vector["pub_key"].lower(),
                "messageHex": vector["message"].lower(),
                "signatureHex": vector["signature"].lower(),
            },
            # Per the pinned external provenance, every vector violates at
            # least one specification 3.3 rule and must fail strict
            # verification.
            "expectedResult": {"valid": False},
            "provenance": {
                "sourceManifest": (
                    "implementations/followee-rs/fixtures/external/PROVENANCE.json"
                ),
                "sourceFile": (
                    "implementations/followee-rs/fixtures/external/"
                    "ed25519_speccheck_cases.json"
                ),
                "sourceFileSha256": digest,
                "upstream": provenance["source"],
                "upstreamOrigin": provenance["origin"],
                "vectorIndex": str(index),
            },
        }
    return cases


def build_cases(inputs_file: Path | None) -> dict[str, dict]:
    published = Published()
    provenance = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    inputs = dict(builder_inputs(inputs_file))
    for case_id, case_input in spliced_inputs(published).items():
        if case_id in inputs:
            raise SystemExit(f"duplicate construction for {case_id}")
        inputs[case_id] = case_input
    cases = b7_cases(provenance, inputs)
    for case_id, document in speccheck_cases().items():
        if case_id in cases:
            raise SystemExit(f"duplicate case id {case_id}")
        cases[case_id] = document
    return cases


def render(cases: dict[str, dict]) -> dict[str, str]:
    files = {
        f"{case_id}.json": json.dumps(document, indent=2) + "\n"
        for case_id, document in sorted(cases.items())
    }
    digest_lines = [
        f"{hashlib.sha256(content.encode('utf-8')).hexdigest()}  {name}"
        for name, content in sorted(files.items())
    ]
    files["DIGESTS.sha256"] = "\n".join(digest_lines) + "\n"
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--inputs", type=Path, default=None)
    args = parser.parse_args()

    files = render(build_cases(args.inputs))

    if args.check:
        problems = []
        existing = {p.name for p in CASES_DIR.glob("*") if p.is_file()}
        for name, content in files.items():
            path = CASES_DIR / name
            if not path.is_file():
                problems.append(f"missing: {name}")
            elif path.read_text(encoding="utf-8") != content:
                problems.append(f"drifted: {name}")
        for name in sorted(existing - set(files) - {".gitkeep"}):
            problems.append(f"unexpected: {name}")
        if problems:
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1
        print(
            f"implementation corpus check: {len(files) - 1} cases match "
            "the builder exactly"
        )
        return 0

    CASES_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (CASES_DIR / name).write_text(content, encoding="utf-8")
    print(
        f"wrote {len(files) - 1} implementation-status cases and "
        f"DIGESTS.sha256 to {CASES_DIR}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
