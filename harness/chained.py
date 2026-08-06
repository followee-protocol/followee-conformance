"""Cross-operation differential scenarios (HARNESS.md Sections 13-14).

A chained scenario authors one or more records through both adapters,
requires each complete ``authorRecord`` output to agree byte-for-byte
first, and only then feeds the exact agreed envelopes into follow-up
operations (``verifyRecord``, ``selectCurrent``) on both adapters.

Provenance, recorded honestly: the structured authoring inputs below are
neutral harness data restating published Appendix B semantic values plus
harness-chosen timestamps/horizons.  The intermediate envelope bytes are
NOT specification-published — they are produced at run time by the frozen
implementations themselves and are admitted for the follow-up steps only
after byte-identical cross-implementation agreement.  Expected
classifications cite normative prose (specification Sections 5.5, 8.2,
and 8.3) or published Appendix B.6 digests, so these steps are campaign
scenarios rather than specification-status byte fixtures.

Step inputs and expected results may contain placeholder strings of the
form ``@author:<name>:<member>``, replaced at run time by the named agreed
authorRecord result member.
"""

from __future__ import annotations

from typing import Any

# Published Appendix B.4 ordering value (also used by the static corpus).
AUTHOR_TIMESTAMP_MS = "1785589200123"
# Harness-chosen freshness horizon: timestamp + 60,000 ms.  Not published.
VALID_UNTIL_MS = "1785589260123"
NOW_AT_HORIZON = VALID_UNTIL_MS  # now == validUntil: not yet stale
NOW_AFTER_HORIZON = "1785589260124"  # now == validUntil + 1: stale

# Published Appendix B.6 equal-time ordering digests: at equal authority
# and timestamp, "Alice A" wins because 6f… is lexicographically lower
# than 81….  The author steps below also pin these digests, so a wrong
# constant here cannot pass silently.
B6_ALICE_A_DIGEST = "6f347840328b2b2cd74cce2f9a222a313e9d9504305c3ac816987ff2f4b47d97"
B6_ALICE_B_DIGEST = "8123f2cdf1a414b34d38eb2e58b39fb7cf37e9f851d999402f64787b3361c162"

PROVENANCE = (
    "Chained campaign scenario: every envelope fed onward is run-time "
    "output of both frozen implementations, admitted only after their "
    "complete authorRecord results agreed byte-for-byte; it is not "
    "specification-published material.  Expected classifications cite "
    "specification Sections 5.5, 8.2-8.3 prose and the published Appendix "
    "B.6 digests."
)


def _alice_contact(display_name: str = "Alice Example") -> dict[str, Any]:
    """Appendix B.4 / 9.6 published semantic contact values (B.6 varies
    only the display name)."""
    return {
        "displayName": display_name,
        "summary": "Writer",
        "avatar": None,
        "alsoKnownAs": ["acct:alice@example.com"],
        "services": [
            {
                "id": "feed",
                "type": "Feed",
                "endpoint": "https://alice.example/feed.xml",
                "mediaType": "application/atom+xml",
                "label": "Writing",
                "language": None,
                "rel": None,
            }
        ],
        "migration": None,
        "extensions": {},
    }


def _author_input(
    contact: dict[str, Any], valid_until: str | None = None
) -> dict[str, Any]:
    return {
        "rootSeedHex": (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ),
        "revocationSeedHex": (
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        ),
        "authority": "root",
        "timestampMs": AUTHOR_TIMESTAMP_MS,
        "validUntilMs": valid_until,
        "contact": contact,
        "extensions": {},
        "signingSeed": "root",
    }


SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "chain-valid-until-stale",
        "specificationSections": ["Section 5.5", "Section 8.3", "Appendix B.4"],
        "provenance": PROVENANCE,
        "authorSteps": [
            {
                "name": "record",
                "input": _author_input(_alice_contact(), valid_until=VALID_UNTIL_MS),
            }
        ],
        "steps": [
            {
                "suffix": "verify-at-horizon",
                "operation": "verifyRecord",
                "input": {
                    "targetDid": "@author:record:did",
                    "envelopeHex": "@author:record:envelopeHex",
                    "nowMs": NOW_AT_HORIZON,
                },
                "expectedResult": {
                    "timestampMs": AUTHOR_TIMESTAMP_MS,
                    "authority": "root",
                    "validUntilMs": VALID_UNTIL_MS,
                    "premature": False,
                    "stale": False,
                },
            },
            {
                "suffix": "verify-after-horizon",
                "operation": "verifyRecord",
                "input": {
                    "targetDid": "@author:record:did",
                    "envelopeHex": "@author:record:envelopeHex",
                    "nowMs": NOW_AFTER_HORIZON,
                },
                "expectedResult": {
                    "timestampMs": AUTHOR_TIMESTAMP_MS,
                    "authority": "root",
                    "validUntilMs": VALID_UNTIL_MS,
                    "premature": False,
                    "stale": True,
                },
            },
            {
                # Staleness affects freshness metadata, never same-authority
                # ordering: a stale candidate is still selectable
                # (specification Sections 5.5 and 8.3).
                "suffix": "select-stale-candidate",
                "operation": "selectCurrent",
                "input": {
                    "targetDid": "@author:record:did",
                    "candidateEnvelopeHex": ["@author:record:envelopeHex"],
                    "nowMs": NOW_AFTER_HORIZON,
                    "stickyAuthority": "unknown",
                },
                "expectedResult": {
                    "winnerRecordBodyDigestHex": ("@author:record:recordBodyDigestHex"),
                    "authorityState": "root",
                },
            },
        ],
    },
    {
        "id": "chain-select-equal-time",
        "specificationSections": ["Section 8.3", "Appendix B.6"],
        "provenance": PROVENANCE,
        "authorSteps": [
            {
                "name": "alice-a",
                "input": _author_input(_alice_contact("Alice A")),
                "expectedResult": {"recordBodyDigestHex": B6_ALICE_A_DIGEST},
            },
            {
                "name": "alice-b",
                "input": _author_input(_alice_contact("Alice B")),
                "expectedResult": {"recordBodyDigestHex": B6_ALICE_B_DIGEST},
            },
        ],
        "steps": [
            {
                "suffix": "select-a-then-b",
                "operation": "selectCurrent",
                "input": {
                    "targetDid": "@author:alice-a:did",
                    "candidateEnvelopeHex": [
                        "@author:alice-a:envelopeHex",
                        "@author:alice-b:envelopeHex",
                    ],
                    "nowMs": AUTHOR_TIMESTAMP_MS,
                    "stickyAuthority": "unknown",
                },
                "expectedResult": {
                    "winnerRecordBodyDigestHex": B6_ALICE_A_DIGEST,
                    "authorityState": "root",
                },
            },
            {
                # Candidate order must not affect the winner (Section 8.3).
                "suffix": "select-b-then-a",
                "operation": "selectCurrent",
                "input": {
                    "targetDid": "@author:alice-a:did",
                    "candidateEnvelopeHex": [
                        "@author:alice-b:envelopeHex",
                        "@author:alice-a:envelopeHex",
                    ],
                    "nowMs": AUTHOR_TIMESTAMP_MS,
                    "stickyAuthority": "unknown",
                },
                "expectedResult": {
                    "winnerRecordBodyDigestHex": B6_ALICE_A_DIGEST,
                    "authorityState": "root",
                },
            },
        ],
    },
]


def substitute(value: Any, author_results: dict[str, dict[str, Any]]) -> Any:
    """Resolve ``@author:<name>:<member>`` placeholders against the agreed
    authorRecord results."""
    if isinstance(value, str) and value.startswith("@author:"):
        _, name, member = value.split(":", 2)
        return author_results[name][member]
    if isinstance(value, dict):
        return {k: substitute(v, author_results) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, author_results) for v in value]
    return value


def step_manifest(
    scenario: dict[str, Any],
    step_id: str,
    expected_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """Artifact metadata for one chained step, with honest provenance."""
    manifest: dict[str, Any] = {
        "id": step_id,
        "chainedScenario": scenario["id"],
        "specificationSections": scenario["specificationSections"],
        "derivation": "chained-campaign-scenario",
        "provenance": scenario["provenance"],
    }
    if expected_result is not None:
        manifest["expectedResult"] = expected_result
    return manifest
