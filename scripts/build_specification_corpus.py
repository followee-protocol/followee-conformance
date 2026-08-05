#!/usr/bin/env python3
"""Build the Milestone 1 specification-status corpus (HARNESS.md 12, 14.2).

Every value in the generated cases comes from the pinned specification:

- published Appendix B hex vectors and DIDs are extracted verbatim from
  ``specification/Followee-Specification.md`` (whose SHA-256 is pinned);
- structured authoring inputs restate semantic values published in
  Appendix B.4 and Section 9.6, or exercise behavior stated normatively
  in Sections 5.5-5.6 and 7.1-7.4; and
- negative verifyRecord inputs are deterministic byte splices of the
  published envelopes, constructed with documented offsets and verified
  against the published bytes before any mutant is emitted.

The builder never signs, hashes, encodes CBOR structures, derives DIDs,
or predicts results: expected outputs come only from values the pinned
specification publishes, and cases whose required inputs cannot be built
from published material (B.7 items 1b/1c, 2's unsupportedHash forms, 14's
crafted-point forms, and 17's re-signed exact case) are deliberately
deferred to implementation-produced fixtures (HARNESS.md Milestone 2).

Usage:
    python3 scripts/build_specification_corpus.py          # write corpus
    python3 scripts/build_specification_corpus.py --check  # verify no drift
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = REPO_ROOT / "specification" / "Followee-Specification.md"
SPEC_SHA256 = "2b264823ba68d9a7d69ce68de5c1408ac8a3d54ff6d726ab89ee2baa2707c81f"
SPEC_COMMIT = "abc9a55d90f1026e6509207abda73e5dc6d14241"
CASES_DIR = REPO_ROOT / "cases" / "specification"

# Published timestamps: B.4 states 1785589200123 in prose; the B.5 value is
# the label-2 uint64 published inside the B.5 body bytes (1b 0000019fbd68f8e3).
B4_TIMESTAMP = "1785589200123"
B5_TIMESTAMP = "1785589201123"

# Ed25519 group order L (RFC 8032, cited normatively by specification 3.3).
ED25519_L = 2**252 + 27742317777372353535851937790883648493


def extract_labeled_values(spec_text: str) -> dict[str, list[str]]:
    """Collect ``label:`` / value pairs from the specification's text
    blocks, preserving occurrence order per label."""
    values: dict[str, list[str]] = {}
    lines = spec_text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.endswith(":") or stripped.startswith("```"):
            continue
        # The value is the next non-empty line inside the same block.
        j = i + 1
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j >= len(lines):
            continue
        value = lines[j].strip()
        if not value or value.startswith("```") or value.endswith(":"):
            continue
        label = stripped[:-1]
        values.setdefault(label, []).append(value)
    return values


class Published:
    """Verbatim published Appendix B values from the pinned specification."""

    def __init__(self) -> None:
        spec_bytes = SPEC_PATH.read_bytes()
        digest = hashlib.sha256(spec_bytes).hexdigest()
        if digest != SPEC_SHA256:
            raise SystemExit(
                f"specification digest is {digest}, pinned {SPEC_SHA256}; "
                "refusing to build the corpus"
            )
        v = extract_labeled_values(spec_bytes.decode("utf-8"))

        def one(label: str, occurrence: int = 0) -> str:
            return v[label][occurrence]

        # B.2 keys.
        self.root_seed = one("root seed")
        self.root_public_key = one("root public key")
        self.revocation_seed = one("revocation seed")
        self.revocation_public_key = one("revocation public key")
        # B.3 commitment, descriptor, DID.
        self.revocation_public_key_cbor = one("revocation public-key CBOR")
        self.revocation_commitment = one("revocation commitment")
        self.descriptor_cbor = one("Authority Descriptor CBOR")
        self.descriptor_digest = one("descriptor digest")
        self.did = one("Followee DID")
        # B.4 root record.
        self.b4_body = one("record body CBOR", 0)
        self.b4_sig_structure = one("COSE `Sig_structure` bytes")
        self.b4_body_digest = one("body digest", 0)
        self.b4_signature = one("signature", 0)
        self.b4_envelope = one("complete tagged COSE Identity Record", 0)
        # B.5 root-revoked record.
        self.b5_body = one("record body CBOR", 1)
        self.b5_body_digest = one("body digest", 1)
        self.b5_signature = one("signature", 1)
        self.b5_envelope = one("complete tagged COSE Identity Record", 1)
        # B.6 equal-time ordering digests.
        self.b6_alice_a_digest = one('"Alice A" body digest')
        self.b6_alice_b_digest = one('"Alice B" body digest')
        # B.8 attacker material.
        self.attacker_root_seed = one("attacker root seed")
        self.attacker_root_public_key = one("attacker root public key")
        self.attacker_revocation_seed = one("attacker revocation seed")
        self.attacker_revocation_public_key = one("attacker revocation public key")
        self.attacker_revocation_commitment = one("attacker revocation commitment")
        self.attacker_descriptor_cbor = one("attacker Authority Descriptor CBOR")
        self.attacker_did = one("attacker's own legitimate DID, for contrast")
        self.b8_body_digest = one("body digest", 2)
        self.b8_signature = one("signature, valid under the attacker's root key")
        self.b8_envelope = one("complete tagged COSE Identity Record", 2)

        self._self_check()

    # -- published-layout helpers (byte splicing only, never CBOR logic) ----

    @staticmethod
    def payload_head(body_hex: str) -> str:
        """COSE payload byte-string head for the published two-byte-length
        layout (0x59 llhh), exactly as exhibited by the published B.4
        (590118) and B.5 (59013f) envelopes."""
        length = len(body_hex) // 2
        if not 256 <= length <= 65535:
            raise SystemExit("body length outside the published head form")
        return f"59{length:04x}"

    def envelope_for(self, body_hex: str, signature_hex: str) -> str:
        """Reassemble an envelope from parts using the published layout
        d2 84 43 a10132 a0 <payload head> <body> 58 40 <signature>."""
        return (
            "d28443a10132a0"
            + self.payload_head(body_hex)
            + body_hex
            + "5840"
            + signature_hex
        )

    def _self_check(self) -> None:
        """The splicing rules must reproduce the published envelopes
        byte-for-byte before any mutant is constructed from them."""
        checks = [
            (self.envelope_for(self.b4_body, self.b4_signature), self.b4_envelope),
            (self.envelope_for(self.b5_body, self.b5_signature), self.b5_envelope),
        ]
        for produced, published in checks:
            if produced != published:
                raise SystemExit(
                    "published-layout reassembly failed; refusing to build"
                )
        # The published Sig_structure embeds the published B.4 body.
        if not self.b4_sig_structure.endswith(self.b4_body):
            raise SystemExit("published Sig_structure does not embed the body")
        # Published B.5 body embeds the stated B.5 timestamp bytes.
        if "021b0000019fbd68f8e3" not in self.b5_body:
            raise SystemExit("published B.5 timestamp bytes not found")
        if int("0000019fbd68f8e3", 16) != int(B5_TIMESTAMP):
            raise SystemExit("B.5 timestamp constant mismatch")
        # The published revocation public-key CBOR is the published prefix
        # plus the published key bytes (used to build the attacker's).
        if self.revocation_public_key_cbor != (
            "a20032015820" + self.revocation_public_key
        ):
            raise SystemExit("published public-key CBOR layout mismatch")

    # Fixed offsets into the published bodies, in hex characters.  Layout
    # (published B.4/B.5 bytes): map head (2), label0 entry "0001" (4),
    # label1 entry "01 7837 <55-byte DID>" (116), label2 entry
    # "02 1b <8-byte timestamp>" (20), label3 entry "03 0x" (4), label4
    # entry "04 <77-byte descriptor>" (156) -> label5/7 region at 302.
    OFFSET_AFTER_DESCRIPTOR = 302

    def check_offsets(self) -> None:
        if self.b4_body[self.OFFSET_AFTER_DESCRIPTOR :][:2] != "07":
            raise SystemExit("B.4 label-7 offset check failed")
        if self.b5_body[self.OFFSET_AFTER_DESCRIPTOR :][:2] != "05":
            raise SystemExit("B.5 label-5 offset check failed")


# ---------------------------------------------------------------------------
# Canonical structured inputs (semantic values published in B.4 / 9.6)
# ---------------------------------------------------------------------------


def empty_contact() -> dict:
    return {
        "displayName": None,
        "summary": None,
        "avatar": None,
        "alsoKnownAs": [],
        "services": [],
        "migration": None,
        "extensions": {},
    }


def alice_contact(display_name: str = "Alice Example") -> dict:
    contact = empty_contact()
    contact.update(
        {
            "displayName": display_name,
            "summary": "Writer",
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
        }
    )
    return contact


def author_input(
    p: Published,
    contact: dict,
    authority: str = "root",
    timestamp: str = B4_TIMESTAMP,
    valid_until: str | None = None,
    extensions: dict | None = None,
) -> dict:
    return {
        "rootSeedHex": p.root_seed,
        "revocationSeedHex": p.revocation_seed,
        "authority": authority,
        "timestampMs": timestamp,
        "validUntilMs": valid_until,
        "contact": contact,
        "extensions": extensions or {},
        "signingSeed": "root" if authority == "root" else "revocation",
    }


def verify_input(
    p: Published, envelope: str, target: str | None = None, now: str = B4_TIMESTAMP
) -> dict:
    return {
        "targetDid": target if target is not None else p.did,
        "envelopeHex": envelope,
        "nowMs": now,
    }


def semantic_record(p: Published, authority: str, timestamp: str) -> dict:
    record = {
        "protocolVersion": "1",
        "id": p.did,
        "timestampMs": timestamp,
        "authority": authority,
        "authorityDescriptor": {
            "descriptorVersion": "1",
            "rootKey": {"suite": "-19", "publicKeyHex": p.root_public_key},
            "revocationCommitmentHex": p.revocation_commitment,
        },
        "revocationKey": (
            None
            if authority == "root"
            else {"suite": "-19", "publicKeyHex": p.revocation_public_key}
        ),
        "validUntilMs": None,
        "contact": alice_contact(),
        "extensions": {},
    }
    return record


# ---------------------------------------------------------------------------
# Case construction
# ---------------------------------------------------------------------------


def manifest(
    case_id: str,
    operation: str,
    sections: list[str],
    fault_profile: str,
    expected: dict,
    case_input: dict,
    expected_result: dict | None = None,
    derived_from: dict | None = None,
) -> dict:
    document = {
        "id": case_id,
        "runnerProtocol": "1",
        "operation": operation,
        "specificationCommit": SPEC_COMMIT,
        "specificationSections": sections,
        "derivationStatus": "specification",
        "faultProfile": fault_profile,
        "expected": expected,
        "input": case_input,
    }
    if expected_result is not None:
        document["expectedResult"] = expected_result
    if derived_from is not None:
        document["derivedFrom"] = derived_from
    return document


ACCEPTED = {"outcome": "accepted"}


def rejected(error: str | None = None) -> dict:
    if error is None:
        return {"outcome": "rejected", "errorAssertion": "unspecified"}
    return {"outcome": "rejected", "errorAssertion": "exact", "error": error}


def mutation(base: str, description: str, protected: bool, payload: bool) -> dict:
    return {
        "baseVector": base,
        "mutation": description,
        "protectedBytesChanged": protected,
        "payloadBytesChanged": payload,
        "resigned": False,
    }


def build_cases(p: Published) -> dict[str, dict]:
    p.check_offsets()
    cases: dict[str, dict] = {}

    def add(document: dict) -> None:
        case_id = document["id"]
        if case_id in cases:
            raise SystemExit(f"duplicate case id {case_id}")
        cases[case_id] = document

    # -- deriveIdentity (Appendix B.2, B.3, B.8.1) -------------------------
    add(
        manifest(
            "derive-identity-alice",
            "deriveIdentity",
            ["Section 4.2", "Section 4.3", "Appendix B.2", "Appendix B.3"],
            "none",
            ACCEPTED,
            {"rootSeedHex": p.root_seed, "revocationSeedHex": p.revocation_seed},
            expected_result={
                "rootPublicKeyHex": p.root_public_key,
                "revocationPublicKeyHex": p.revocation_public_key,
                "revocationPublicKeyCborHex": p.revocation_public_key_cbor,
                "revocationCommitmentHex": p.revocation_commitment,
                "authorityDescriptorCborHex": p.descriptor_cbor,
                "authorityDescriptorDigestHex": p.descriptor_digest,
                "did": p.did,
            },
        )
    )
    add(
        manifest(
            "derive-identity-attacker",
            "deriveIdentity",
            ["Section 4.2", "Section 4.3", "Appendix B.8.1"],
            "none",
            ACCEPTED,
            {
                "rootSeedHex": p.attacker_root_seed,
                "revocationSeedHex": p.attacker_revocation_seed,
            },
            expected_result={
                "rootPublicKeyHex": p.attacker_root_public_key,
                "revocationPublicKeyHex": p.attacker_revocation_public_key,
                # Published public-key CBOR layout with the published
                # attacker key bytes (see Published._self_check).
                "revocationPublicKeyCborHex": (
                    "a20032015820" + p.attacker_revocation_public_key
                ),
                "revocationCommitmentHex": p.attacker_revocation_commitment,
                "authorityDescriptorCborHex": p.attacker_descriptor_cbor,
                "did": p.attacker_did,
            },
        )
    )

    # -- authorRecord positives (Appendix B.4, B.5, B.6; Section 9.6) ------
    add(
        manifest(
            "author-b4-root",
            "authorRecord",
            ["Appendix B.4", "Section 9.6"],
            "none",
            ACCEPTED,
            author_input(p, alice_contact()),
            expected_result={
                "did": p.did,
                "recordBodyCborHex": p.b4_body,
                "recordBodyDigestHex": p.b4_body_digest,
                "sigStructureHex": p.b4_sig_structure,
                "signatureHex": p.b4_signature,
                "envelopeHex": p.b4_envelope,
            },
        )
    )
    add(
        manifest(
            "author-b5-root-revoked",
            "authorRecord",
            ["Appendix B.5"],
            "none",
            ACCEPTED,
            author_input(
                p,
                alice_contact(),
                authority="rootRevoked",
                timestamp=B5_TIMESTAMP,
            ),
            expected_result={
                "did": p.did,
                "recordBodyCborHex": p.b5_body,
                "recordBodyDigestHex": p.b5_body_digest,
                "signatureHex": p.b5_signature,
                "envelopeHex": p.b5_envelope,
            },
        )
    )
    add(
        manifest(
            "author-b6-alice-a",
            "authorRecord",
            ["Appendix B.6"],
            "none",
            ACCEPTED,
            author_input(p, alice_contact("Alice A")),
            expected_result={"recordBodyDigestHex": p.b6_alice_a_digest},
        )
    )
    add(
        manifest(
            "author-b6-alice-b",
            "authorRecord",
            ["Appendix B.6"],
            "none",
            ACCEPTED,
            author_input(p, alice_contact("Alice B")),
            expected_result={"recordBodyDigestHex": p.b6_alice_b_digest},
        )
    )
    add(
        manifest(
            "author-contact-empty",
            "authorRecord",
            ["Section 7.1"],
            "none",
            ACCEPTED,
            author_input(p, empty_contact()),
        )
    )
    add(
        manifest(
            "author-valid-until-equal-timestamp",
            "authorRecord",
            ["Section 5.5"],
            "none",
            ACCEPTED,
            author_input(p, alice_contact(), valid_until=B4_TIMESTAMP),
        )
    )
    add(
        manifest(
            "author-valid-until-before-timestamp",
            "authorRecord",
            ["Section 5.5"],
            "single",
            rejected(),
            author_input(p, alice_contact(), valid_until="1785589200122"),
        )
    )

    # -- authorRecord URI behavior (Section 7.2, v0.7) ---------------------
    def avatar_case(case_id: str, avatar: str, ok: bool) -> None:
        contact = alice_contact()
        contact["avatar"] = avatar
        add(
            manifest(
                case_id,
                "authorRecord",
                ["Section 7.2"],
                "none" if ok else "single",
                ACCEPTED if ok else rejected(),
                author_input(p, contact),
            )
        )

    avatar_case("author-uri-fragment", "https://alice.example/profile#about", True)
    avatar_case("author-uri-query", "https://alice.example/p?view=full", True)
    avatar_case(
        "author-uri-query-and-fragment",
        "https://alice.example/p?view=full#top",
        True,
    )
    avatar_case("author-uri-relative-path", "/profile", False)
    avatar_case("author-uri-relative-bare", "profile", False)
    avatar_case("author-uri-query-only", "?view=full", False)
    avatar_case("author-uri-fragment-only", "#about", False)
    avatar_case("author-uri-network-path", "//alice.example/profile", False)

    def aka_case(case_id: str, uri: str, ok: bool) -> None:
        contact = alice_contact()
        contact["alsoKnownAs"] = [uri]
        add(
            manifest(
                case_id,
                "authorRecord",
                ["Section 7.2"],
                "none" if ok else "single",
                ACCEPTED if ok else rejected(),
                author_input(p, contact),
            )
        )

    aka_case("author-uri-did-web-fragment", "did:web:example.com#key-1", True)
    aka_case("author-uri-ipvfuture-lower", "http://[v1.a]/", True)
    aka_case("author-uri-ipvfuture-upper", "http://[V1.a]/", True)

    # -- authorRecord service metadata (Section 7.3) -----------------------
    def service_case(
        case_id: str, ok: bool, sections: list[str], **overrides: object
    ) -> None:
        contact = alice_contact()
        service = dict(contact["services"][0])
        service.update(overrides)
        contact["services"] = [service]
        add(
            manifest(
                case_id,
                "authorRecord",
                sections,
                "none" if ok else "single",
                ACCEPTED if ok else rejected(),
                author_input(p, contact),
            )
        )

    service_case(
        "author-service-endpoint-relative",
        False,
        ["Section 7.2", "Section 7.3"],
        endpoint="/feed.xml",
    )
    service_case(
        "author-service-type-uri",
        True,
        ["Section 7.3"],
        type="https://types.example/custom-service",
    )
    service_case(
        "author-service-type-unknown-token",
        False,
        ["Section 7.3"],
        type="Blog",
    )
    service_case(
        "author-service-mediatype-parameters",
        False,
        ["Section 7.3"],
        mediaType="application/atom+xml;charset=utf-8",
    )
    service_case(
        "author-service-mediatype-missing-subtype",
        False,
        ["Section 7.3"],
        mediaType="application/",
    )
    service_case(
        "author-service-language-valid",
        True,
        ["Section 7.3"],
        language="en-US",
    )
    service_case(
        "author-service-language-grandfathered",
        True,
        ["Section 7.3"],
        language="i-klingon",
    )
    service_case(
        "author-service-language-invalid",
        False,
        ["Section 7.3"],
        language="not a language tag",
    )
    service_case(
        "author-service-rel-token",
        True,
        ["Section 7.3"],
        rel="alternate",
    )
    service_case(
        "author-service-rel-uppercase-token",
        False,
        ["Section 7.3"],
        rel="Alternate",
    )
    service_case(
        "author-service-rel-uri",
        True,
        ["Section 7.3"],
        rel="https://rels.example/mirror",
    )

    # -- authorRecord migration (Section 7.4) ------------------------------
    def migration_case(case_id: str, ok: bool, migration_value: dict) -> None:
        contact = alice_contact()
        contact["migration"] = migration_value
        add(
            manifest(
                case_id,
                "authorRecord",
                ["Section 7.4"],
                "none" if ok else "single",
                ACCEPTED if ok else rejected(),
                author_input(p, contact),
            )
        )

    migration_case(
        "author-migration-predecessor",
        True,
        {"predecessor": p.attacker_did, "successor": None},
    )
    migration_case(
        "author-migration-successor",
        True,
        {"predecessor": None, "successor": p.attacker_did},
    )
    migration_case(
        "author-migration-empty",
        False,
        {"predecessor": None, "successor": None},
    )
    migration_case(
        "author-migration-self",
        False,
        {"predecessor": p.did, "successor": None},
    )

    # -- authorRecord extensions (Sections 5.6, 7.5, HARNESS.md 10) --------
    typed_extensions = {
        "https://ext.example/record": {
            "type": "map",
            "entries": [
                {
                    "key": {"type": "uint", "value": "1"},
                    "value": {"type": "text", "value": "one"},
                },
                {
                    "key": {"type": "nint", "value": "-1"},
                    "value": {"type": "bytes", "hex": "00ff"},
                },
                {
                    "key": {"type": "text", "value": "flag"},
                    "value": {"type": "bool", "value": True},
                },
            ],
        },
        "https://ext.example/list": {
            "type": "array",
            "items": [
                {"type": "uint", "value": "18446744073709551615"},
                {"type": "nint", "value": "-18446744073709551616"},
                {"type": "null"},
                {"type": "text", "value": "text"},
            ],
        },
    }
    contact_with_ext = alice_contact()
    contact_with_ext["extensions"] = {
        "https://ext.example/contact": {"type": "text", "value": "contact-level"}
    }
    add(
        manifest(
            "author-extensions-typed",
            "authorRecord",
            ["Section 5.6", "Section 7.5"],
            "none",
            ACCEPTED,
            author_input(p, contact_with_ext, extensions=typed_extensions),
        )
    )
    add(
        manifest(
            "author-extension-key-not-uri",
            "authorRecord",
            ["Section 5.6", "Section 7.2"],
            "single",
            rejected(),
            author_input(
                p,
                alice_contact(),
                extensions={"not a uri": {"type": "text", "value": "x"}},
            ),
        )
    )

    # -- verifyRecord positives (Appendix B.4, B.5; Sections 5.4, 5.5) ----
    add(
        manifest(
            "verify-b4-root",
            "verifyRecord",
            ["Section 8.1", "Appendix B.4"],
            "none",
            ACCEPTED,
            verify_input(p, p.b4_envelope),
            expected_result={
                "envelopeHex": p.b4_envelope,
                "recordBodyCborHex": p.b4_body,
                "recordBodyDigestHex": p.b4_body_digest,
                "id": p.did,
                "timestampMs": B4_TIMESTAMP,
                "authority": "root",
                "validUntilMs": None,
                "premature": False,
                "stale": False,
                "record": semantic_record(p, "root", B4_TIMESTAMP),
            },
        )
    )
    add(
        manifest(
            "verify-b5-root-revoked",
            "verifyRecord",
            ["Section 8.1", "Appendix B.5"],
            "none",
            ACCEPTED,
            verify_input(p, p.b5_envelope, now=B5_TIMESTAMP),
            expected_result={
                "envelopeHex": p.b5_envelope,
                "recordBodyCborHex": p.b5_body,
                "recordBodyDigestHex": p.b5_body_digest,
                "id": p.did,
                "timestampMs": B5_TIMESTAMP,
                "authority": "rootRevoked",
                "validUntilMs": None,
                "premature": False,
                "stale": False,
                "record": semantic_record(p, "rootRevoked", B5_TIMESTAMP),
            },
        )
    )
    # Recipient-time classification boundaries (Section 5.4): premature iff
    # timestamp_ms > now_ms + 300000.
    add(
        manifest(
            "verify-b4-premature",
            "verifyRecord",
            ["Section 5.4", "Appendix B.4"],
            "none",
            ACCEPTED,
            verify_input(p, p.b4_envelope, now="1785588900122"),
            expected_result={"premature": True, "stale": False},
        )
    )
    add(
        manifest(
            "verify-b4-premature-boundary",
            "verifyRecord",
            ["Section 5.4", "Appendix B.4"],
            "none",
            ACCEPTED,
            verify_input(p, p.b4_envelope, now="1785588900123"),
            expected_result={"premature": False, "stale": False},
        )
    )
    add(
        manifest(
            "verify-b4-now-max-uint64",
            "verifyRecord",
            ["Section 5.4", "Appendix B.4"],
            "none",
            ACCEPTED,
            verify_input(p, p.b4_envelope, now="18446744073709551615"),
            expected_result={"premature": False, "stale": False},
        )
    )

    # -- identity binding and descriptor substitution (B.7 item 1a, B.8) --
    add(
        manifest(
            "verify-b7-binding-wrong-target",
            "verifyRecord",
            ["Section 8.1", "Appendix B.7 item 1"],
            "single",
            rejected("identityBindingMismatch"),
            verify_input(p, p.b4_envelope, target=p.attacker_did),
        )
    )
    add(
        manifest(
            "verify-b8-descriptor-substitution",
            "verifyRecord",
            ["Section 8.1 step 9", "Appendix B.8"],
            "single",
            rejected("identityBindingMismatch"),
            verify_input(p, p.b8_envelope),
        )
    )
    add(
        manifest(
            "verify-b8-attacker-target",
            "verifyRecord",
            ["Section 8.1 step 7", "Appendix B.7 item 1", "Appendix B.8"],
            "single",
            rejected("identityBindingMismatch"),
            verify_input(p, p.b8_envelope, target=p.attacker_did),
        )
    )

    # -- target-DID string forms (Section 3.1, B.7 item 2 invalidDid) ------
    def did_case(case_id: str, target: str, description: str) -> None:
        add(
            manifest(
                case_id,
                "verifyRecord",
                ["Section 3.1", "Appendix B.7 item 2"],
                "single",
                rejected("invalidDid"),
                verify_input(p, p.b4_envelope, target=target),
                derived_from=mutation("verify-b4-root", description, False, False),
            )
        )

    msid = p.did[len("did:flw:") :]
    did_case(
        "verify-did-percent-encoded",
        "did:flw:%7A" + msid[1:],
        "target DID with the multibase prefix percent-encoded (Section 3.1 "
        "forbids percent-encoding)",
    )
    did_case(
        "verify-did-uppercase-prefix",
        "DID:FLW:" + msid,
        "target DID with an uppercase did:flw: prefix (must be lowercase)",
    )
    did_case(
        "verify-did-invalid-alphabet",
        p.did[:-1] + "0",
        "final character replaced with '0', outside the base58btc alphabet",
    )
    did_case(
        "verify-did-missing-multibase-prefix",
        "did:flw:" + msid[1:],
        "multibase 'z' prefix removed",
    )
    did_case("verify-did-empty", "did:flw:", "empty method-specific identifier")

    # -- envelope mutations (Appendix B.7 items 3-17) ----------------------
    def mutant(
        case_id: str,
        envelope: str,
        sections: list[str],
        fault_profile: str,
        description: str,
        protected: bool,
        payload: bool,
        base: str = "verify-b4-root",
        error: str | None = None,
        now: str = B4_TIMESTAMP,
    ) -> None:
        add(
            manifest(
                case_id,
                "verifyRecord",
                sections,
                fault_profile,
                rejected(error),
                verify_input(p, envelope, now=now),
                derived_from=mutation(base, description, protected, payload),
            )
        )

    env = p.b4_envelope
    if env[:14] != "d28443a10132a0":
        raise SystemExit("published B.4 envelope prefix check failed")

    mutant(
        "verify-b7-03-protected-alg-minus8",
        "d28443a10127" + env[12:],
        ["Section 3.2", "Section 6.2", "Appendix B.7 item 3"],
        "multiple",
        "protected header value -19 replaced with the deprecated -8 "
        "(a10132 -> a10127); the signature over the original protected "
        "bytes is consequently also stale",
        True,
        False,
    )
    mutant(
        "verify-b7-04-missing-cose-tag",
        env[2:],
        ["Section 6.2", "Appendix B.7 item 4"],
        "single",
        "leading COSE tag 18 byte (d2) removed",
        False,
        False,
    )
    mutant(
        "verify-b7-05-nonempty-unprotected",
        env[:12] + "a1046161" + env[14:],
        ["Section 6.2", "Appendix B.7 item 5"],
        "single",
        'empty unprotected header map (a0) replaced with {4: "a"} '
        "(a1046161); unprotected bytes are outside the Sig_structure so "
        "the signature remains valid",
        False,
        False,
    )
    mutant(
        "verify-b7-06-detached-payload",
        "d28443a10132a0" + "f6" + "5840" + p.b4_signature,
        ["Section 6.2", "Appendix B.7 item 6"],
        "single",
        "attached payload replaced with null (f6), producing a detached-"
        "payload envelope",
        False,
        True,
    )
    mutant(
        "verify-b7-07-nonminimal-protected-length",
        env[:4] + "5803" + env[6:],
        ["Section 6.1", "Appendix B.7 item 7"],
        "single",
        "protected byte-string head 43 re-encoded non-minimally as 5803; "
        "the protected content bytes are unchanged so the signature "
        "remains valid",
        True,
        False,
    )
    # Reordered deterministic map keys: swap the first two body entries
    # (label 0 entry occupies body hex [2:6], label 1 entry [6:122]).
    b4 = p.b4_body
    if b4[2:6] != "0001" or b4[6:8] != "01":
        raise SystemExit("B.4 body entry offsets check failed")
    reordered_body = b4[:2] + b4[6:122] + b4[2:6] + b4[122:]
    mutant(
        "verify-b7-08-reordered-body-keys",
        p.envelope_for(reordered_body, p.b4_signature),
        ["Section 6.1", "Appendix B.7 item 8"],
        "multiple",
        "record-body entries for labels 0 and 1 swapped, violating "
        "deterministic key order; the signature over the original body is "
        "consequently also stale",
        False,
        True,
    )
    mutant(
        "verify-b7-09-duplicate-map-key",
        env[:12] + "a2046161046162" + env[14:],
        ["Section 6.1", "Appendix B.7 item 9"],
        "single",
        'unprotected header map replaced with {4: "a", 4: "b"} '
        "(a2046161046162), a duplicate map key outside the signed bytes",
        False,
        False,
    )
    # Root record containing label 5 (published revocation key spliced in
    # before the label-7 entry; deterministic order 0,1,2,3,4,5,7).
    cut = p.OFFSET_AFTER_DESCRIPTOR
    root_with_label5 = "a7" + b4[2:cut] + "05" + p.revocation_public_key_cbor + b4[cut:]
    mutant(
        "verify-b7-10-root-with-revocation-key",
        p.envelope_for(root_with_label5, p.b4_signature),
        ["Section 5.1", "Appendix B.7 item 10"],
        "multiple",
        "published revocation public-key object inserted as label 5 of the "
        "root body (map head a6 -> a7); the signature is consequently "
        "also stale",
        False,
        True,
    )
    b5 = p.b5_body
    label5_len = 2 + len(p.revocation_public_key_cbor)
    if b5[cut : cut + 2] != "05":
        raise SystemExit("B.5 label-5 offset check failed")
    revoked_missing_label5 = "a6" + b5[2:cut] + b5[cut + label5_len :]
    mutant(
        "verify-b7-11-revoked-missing-revocation-key",
        p.envelope_for(revoked_missing_label5, p.b5_signature),
        ["Section 5.1", "Appendix B.7 item 11"],
        "multiple",
        "label-5 revocation key removed from the root-revoked body (map "
        "head a7 -> a6); the signature is consequently also stale",
        False,
        True,
        base="verify-b5-root-revoked",
        now=B5_TIMESTAMP,
    )
    key_end = cut + label5_len
    if b5[key_end - 2 : key_end] != "d7":
        raise SystemExit("B.5 revocation-key final byte check failed")
    revoked_flipped_key = b5[: key_end - 2] + "d6" + b5[key_end:]
    mutant(
        "verify-b7-12-revocation-key-bit-flip",
        p.envelope_for(revoked_flipped_key, p.b5_signature),
        ["Section 8.1 step 12", "Appendix B.7 item 12"],
        "multiple",
        "final byte of the revealed revocation key changed d7 -> d6, "
        "breaking the commitment; the signature is consequently also stale",
        False,
        True,
        base="verify-b5-root-revoked",
        now=B5_TIMESTAMP,
    )
    mutant(
        "verify-b7-13-signature-bit-flip",
        env[:-2] + "05",
        ["Section 3.3", "Appendix B.7 item 13"],
        "single",
        "final signature byte changed 04 -> 05",
        False,
        False,
    )
    # S >= L: replace S with S + L (pure integer arithmetic on the
    # published little-endian scalar; R unchanged).
    s = int.from_bytes(bytes.fromhex(p.b4_signature[64:]), "little")
    s_plus_l = s + ED25519_L
    if s_plus_l >= 2**256:
        raise SystemExit("S + L does not fit 32 bytes")
    sig_s_plus_l = p.b4_signature[:64] + s_plus_l.to_bytes(32, "little").hex()
    mutant(
        "verify-b7-14-signature-s-plus-l",
        p.envelope_for(b4, sig_s_plus_l),
        ["Section 3.3 item 4", "Appendix B.7 item 14"],
        "single",
        "signature scalar S replaced with S + L; the scalar now satisfies "
        "the permissive verification equation but violates S < L",
        False,
        False,
    )
    # validUntil_ms < timestamp_ms: insert label 6 with the published
    # timestamp bytes decremented by one (1b...f4fb -> 1b...f4fa), in
    # deterministic order 0,1,2,3,4,6,7.
    valid_until_entry = "06" + "1b0000019fbd68f4fa"
    body_valid_until = "a7" + b4[2:cut] + valid_until_entry + b4[cut:]
    mutant(
        "verify-b7-15-valid-until-before-timestamp",
        p.envelope_for(body_valid_until, p.b4_signature),
        ["Section 5.5", "Appendix B.7 item 15"],
        "multiple",
        "label 6 validUntil_ms inserted with timestamp_ms - 1; the "
        "signature is consequently also stale",
        False,
        True,
    )
    # Aggregate hard limit: displayName inflated to 20,000 bytes, driving
    # the envelope past the 16 KiB cap (and the field past its own cap).
    if b4[cut + 2 : cut + 10] != "a4006d41":
        raise SystemExit("B.4 contact displayName offset check failed")
    name_start = cut + 6  # position of the 6d text head inside the body
    inflated_name = "7a00004e20" + ("61" * 20000)
    inflated_body = b4[:name_start] + inflated_name + b4[name_start + 2 + 26 :]
    mutant(
        "verify-b7-16-envelope-too-large",
        p.envelope_for(inflated_body, p.b4_signature),
        ["Section 15.1", "Appendix B.7 item 16"],
        "multiple",
        "displayName inflated to 20,000 bytes, exceeding the display-name, "
        "contact, and complete-envelope limits; the signature is "
        "consequently also stale",
        False,
        True,
    )
    # Boolean substituted for an integer label (multi-fault variant of
    # B.7 item 17; the required internally consistent re-signed variant is
    # implementation-produced fixture work, see Milestone 2).
    # Descriptor entry: label 04 at [146:148], descriptor map a3 at
    # [148:150], entry {00: 01} at [150:154], label 01 at [154:156], the
    # public-key map a2 at [156:158], and its first key 00 at [158:160].
    desc_pubkey_label = 158
    if b4[desc_pubkey_label : desc_pubkey_label + 2] != "00":
        raise SystemExit("B.4 descriptor public-key label offset check failed")
    bool_label_body = b4[:desc_pubkey_label] + "f4" + b4[desc_pubkey_label + 2 :]
    mutant(
        "verify-b7-17-bool-label-multifault",
        p.envelope_for(bool_label_body, p.b4_signature),
        ["Section 6.1", "Appendix B.7 item 17"],
        "multiple",
        "unsigned-integer label 0 of the descriptor's public-key map "
        "replaced with CBOR false (f4); key order, schema, and the "
        "signature are all consequently violated",
        False,
        True,
    )

    return cases


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


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
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed corpus matches the built corpus exactly",
    )
    args = parser.parse_args()

    published = Published()
    files = render(build_cases(published))

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
        print(f"corpus check: {len(files) - 1} cases match the builder exactly")
        return 0

    CASES_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (CASES_DIR / name).write_text(content, encoding="utf-8")
    print(f"wrote {len(files) - 1} cases and DIGESTS.sha256 to {CASES_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
