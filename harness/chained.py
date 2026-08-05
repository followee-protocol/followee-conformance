"""Cross-operation differential scenarios (HARNESS.md Sections 13-14).

A chained scenario authors a record through both adapters, requires their
complete ``authorRecord`` outputs to agree byte-for-byte first, and only
then feeds the exact agreed envelope back through both adapters'
``verifyRecord``.

Provenance, recorded honestly: the structured authoring input below is
neutral harness data restating published Appendix B.4 semantic values
plus a harness-chosen ``validUntilMs``.  The intermediate envelope bytes
are NOT specification-published — they are produced at run time by the
frozen implementations themselves and are admitted for the verify steps
only after byte-identical cross-implementation agreement.  The expected
``stale`` classifications come from normative prose (specification
Section 5.5: a record becomes stale when ``recipient.now_ms >
validUntil_ms``), not from published bytes, so these steps are campaign
scenarios rather than specification-status byte fixtures.
"""

from __future__ import annotations

from typing import Any

# Published Appendix B.4 ordering value (also used by the static corpus).
AUTHOR_TIMESTAMP_MS = "1785589200123"
# Harness-chosen freshness horizon: timestamp + 60,000 ms.  Not published.
VALID_UNTIL_MS = "1785589260123"
NOW_AT_HORIZON = VALID_UNTIL_MS  # now == validUntil: not yet stale
NOW_AFTER_HORIZON = "1785589260124"  # now == validUntil + 1: stale

PROVENANCE = (
    "Chained campaign scenario: the verified envelope is run-time output "
    "of both frozen implementations, admitted only after their complete "
    "authorRecord results agreed byte-for-byte; it is not "
    "specification-published material.  Expected stale/premature "
    "classifications cite specification Section 5.5 prose."
)


def _alice_contact() -> dict[str, Any]:
    """Appendix B.4 / Section 9.6 published semantic contact values."""
    return {
        "displayName": "Alice Example",
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


SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "chain-valid-until-stale",
        "specificationSections": ["Section 5.5", "Appendix B.4"],
        "provenance": PROVENANCE,
        "authorInput": {
            "rootSeedHex": (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            ),
            "revocationSeedHex": (
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
            ),
            "authority": "root",
            "timestampMs": AUTHOR_TIMESTAMP_MS,
            "validUntilMs": VALID_UNTIL_MS,
            "contact": _alice_contact(),
            "extensions": {},
            "signingSeed": "root",
        },
        "verifySteps": [
            {
                "suffix": "verify-at-horizon",
                "nowMs": NOW_AT_HORIZON,
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
                "nowMs": NOW_AFTER_HORIZON,
                "expectedResult": {
                    "timestampMs": AUTHOR_TIMESTAMP_MS,
                    "authority": "root",
                    "validUntilMs": VALID_UNTIL_MS,
                    "premature": False,
                    "stale": True,
                },
            },
        ],
    }
]


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
