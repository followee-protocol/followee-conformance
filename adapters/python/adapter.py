#!/usr/bin/env python3
"""Neutral runner-protocol v1 adapter for the pinned Python clean-room model.

Milestone 1 supports ``hello``, ``deriveIdentity``, ``authorRecord``, and
``verifyRecord`` (HARNESS.md Sections 8, 9, and 20).  This file is a thin
translation layer: every protocol decision — CBOR, COSE, DID derivation,
hashing, signing, verification, URI and Contact Document validity — is made
by the frozen ``followee_model`` package through its public API, imported
read-only from the Git submodule and never copied.  The adapter only
converts between the neutral runner JSON profile and that API, and enforces
the runner input contract (member shapes, hexadecimal and canonical-decimal
ranges, authority/signingSeed coherence) before calling the model.

The adapter is deliberately self-contained (standard library plus the
frozen model only, no harness imports) so it can be launched from an
isolated working directory.  Protocol responses go only to standard
output; diagnostics go only to standard error.

Identity (implementation and specification commits) is resolved from the
verified submodule checkouts at startup via git, never from an unchecked
environment variable.  The orchestrator independently re-verifies both
values against the HARNESS.md Section 2 pins.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

RUNNER_PROTOCOL = "1"
MAX_LINE_BYTES = 1 * 1024 * 1024
BOM = b"\xef\xbb\xbf"
UINT64_MAX = 2**64 - 1

ADAPTER_NAME = "followee-python-cleanroom"
ADAPTER_VERSION = "1"
IMPLEMENTATION_REPOSITORY = (
    "https://github.com/followee-protocol/followee-python-cleanroom"
)
OPERATIONS = ["hello", "deriveIdentity", "authorRecord", "verifyRecord"]

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MODEL_SUBMODULE = REPO_ROOT / "implementations" / "followee-python-cleanroom"
MODEL_PACKAGE_DIR = MODEL_SUBMODULE / "tools" / "python-model"
SPEC_SUBMODULE = REPO_ROOT / "specification"

# Contact Document and service-entry label tables (specification Section 7;
# translation only — validity is judged solely by the model).
_CONTACT_LABELS = {
    "displayName": 0,
    "summary": 1,
    "avatar": 2,
    "alsoKnownAs": 3,
    "services": 4,
    "migration": 5,
    "extensions": 6,
}
_SERVICE_LABELS = {
    "id": 0,
    "type": 1,
    "endpoint": 2,
    "mediaType": 3,
    "label": 4,
    "language": 5,
    "rel": 6,
}
_MIGRATION_LABELS = {"predecessor": 0, "successor": 1}


class AdapterStartupError(RuntimeError):
    pass


class OpAdapterError(Exception):
    """Runner input-contract violation; always fails the campaign."""

    def __init__(self, symbol: str, message: str) -> None:
        super().__init__(f"{symbol}: {message}")
        self.symbol = symbol
        self.message = message


class OpRejected(Exception):
    """Followee-level rejection carrying the model's symbolic error."""

    def __init__(self, error: str) -> None:
        super().__init__(error)
        self.error = error


def _bad_input(message: str) -> OpAdapterError:
    return OpAdapterError("adapter.invalidInput", message)


def _git_head(repo: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AdapterStartupError("git executable not found") from exc
    if proc.returncode != 0:
        raise AdapterStartupError(
            f"cannot resolve checkout identity of {repo}: {proc.stderr.strip()}"
        )
    commit = proc.stdout.strip()
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise AdapterStartupError(f"unexpected commit id {commit!r} for {repo}")
    return commit


def load_model() -> SimpleNamespace:
    """Import the frozen model read-only from the pinned submodule."""
    if not MODEL_PACKAGE_DIR.is_dir():
        raise AdapterStartupError(
            f"frozen Python model not found at {MODEL_PACKAGE_DIR}; run "
            "`git submodule update --init`"
        )
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(MODEL_PACKAGE_DIR))
    try:
        from followee_model import (
            cose,
            descriptor,
            detcbor,
            ed25519,
            errors,
            record,
            signing,
            verify,
        )
    except Exception as exc:
        raise AdapterStartupError(
            f"frozen Python model failed to import: {exc!r}"
        ) from exc
    finally:
        sys.path.remove(str(MODEL_PACKAGE_DIR))
    return SimpleNamespace(
        cose=cose,
        descriptor=descriptor,
        detcbor=detcbor,
        ed25519=ed25519,
        errors=errors,
        record=record,
        signing=signing,
        verify=verify,
    )


def resolve_identity() -> dict[str, Any]:
    """Build the hello result from the verified checkouts."""
    return {
        "adapter": ADAPTER_NAME,
        "adapterVersion": ADAPTER_VERSION,
        "implementationRepository": IMPLEMENTATION_REPOSITORY,
        "implementationCommit": _git_head(MODEL_SUBMODULE),
        "specificationCommit": _git_head(SPEC_SUBMODULE),
        "runnerProtocols": [RUNNER_PROTOCOL],
        "operations": OPERATIONS,
    }


# ---------------------------------------------------------------------------
# Runner input contract (HARNESS.md 7.2 and 10)
# ---------------------------------------------------------------------------


def _take_members(obj: Any, context: str, names: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise _bad_input(f"{context} must be an object")
    unknown = set(obj) - set(names)
    if unknown:
        raise _bad_input(f"{context}: unknown members {sorted(unknown)}")
    missing = set(names) - set(obj)
    if missing:
        raise _bad_input(f"{context}: missing members {sorted(missing)}")
    return obj


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise _bad_input(f"{what} must be a string")
    return value


def _text_or_none(value: Any, what: str) -> str | None:
    if value is None:
        return None
    return _text(value, what)


def _bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise _bad_input(f"{what} must be a boolean")
    return value


def _array(value: Any, what: str) -> list:
    if not isinstance(value, list):
        raise _bad_input(f"{what} must be an array")
    return value


def _decode_hex(text: Any, what: str) -> bytes:
    text = _text(text, what)
    if len(text) % 2 != 0:
        raise _bad_input(f"{what}: odd-length hexadecimal")
    if any(c not in "0123456789abcdef" for c in text):
        raise _bad_input(f"{what}: invalid or uppercase hexadecimal digit")
    return bytes.fromhex(text)


def _decode_hex32(text: Any, what: str) -> bytes:
    decoded = _decode_hex(text, what)
    if len(decoded) != 32:
        raise _bad_input(f"{what} must be exactly 32 bytes")
    return decoded


def _parse_u64(text: Any, what: str) -> int:
    text = _text(text, what)
    if not text.isdigit() or str(int(text)) != text:
        raise _bad_input(f"{what}: not a canonical uint64 decimal string")
    value = int(text)
    if value > UINT64_MAX:
        raise _bad_input(f"{what}: exceeds the uint64 range")
    return value


def _parse_opt_u64(value: Any, what: str) -> int | None:
    if value is None:
        return None
    return _parse_u64(value, what)


def _parse_nint(text: Any, what: str) -> int:
    text = _text(text, what)
    try:
        value = int(text)
    except ValueError as exc:
        raise _bad_input(f"{what}: not a canonical decimal string") from exc
    if str(value) != text or value >= 0 or value < -(2**64):
        raise _bad_input(f"{what}: outside the CBOR negative-integer range")
    return value


# ---------------------------------------------------------------------------
# Typed value tree (HARNESS.md Section 10) <-> model values
# ---------------------------------------------------------------------------


def _typed_to_model(value: Any) -> Any:
    if not isinstance(value, dict) or "type" not in value:
        raise _bad_input("typed value must be an object with a 'type' member")
    kind = _text(value["type"], "typed value type")

    def only(*names: str) -> None:
        _take_members(value, f"typed {kind} value", ("type", *names))

    if kind == "uint":
        only("value")
        return _parse_u64(value["value"], "uint value")
    if kind == "nint":
        only("value")
        return _parse_nint(value["value"], "nint value")
    if kind == "bytes":
        only("hex")
        return _decode_hex(value["hex"], "bytes hex")
    if kind == "text":
        only("value")
        return _text(value["value"], "text value")
    if kind == "bool":
        only("value")
        return _bool(value["value"], "bool value")
    if kind == "null":
        only()
        return None
    if kind == "array":
        only("items")
        return [_typed_to_model(item) for item in _array(value["items"], "array items")]
    if kind == "map":
        only("entries")
        out: dict[Any, Any] = {}
        for entry in _array(value["entries"], "map entries"):
            pair = _take_members(entry, "map entry", ("key", "value"))
            key = _typed_key_to_model(pair["key"])
            if key in out:
                raise OpAdapterError(
                    "adapter.unrepresentableInput",
                    "duplicate typed-map keys cannot be represented in the "
                    "Python model's dict-based extension values",
                )
            out[key] = _typed_to_model(pair["value"])
        return out
    raise _bad_input(f"unknown typed value type {kind!r}")


def _typed_key_to_model(value: Any) -> Any:
    if not isinstance(value, dict) or "type" not in value:
        raise _bad_input("typed key must be an object with a 'type' member")
    kind = _text(value["type"], "typed key type")
    _take_members(value, f"typed {kind} key", ("type", "value"))
    if kind == "uint":
        return _parse_u64(value["value"], "uint key")
    if kind == "nint":
        return _parse_nint(value["value"], "nint key")
    if kind == "text":
        return _text(value["value"], "text key")
    raise _bad_input(f"unknown typed key type {kind!r}")


def _model_to_typed(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        if value >= 0:
            return {"type": "uint", "value": str(value)}
        return {"type": "nint", "value": str(value)}
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, str):
        return {"type": "text", "value": value}
    if value is None:
        return {"type": "null"}
    if isinstance(value, list):
        return {"type": "array", "items": [_model_to_typed(v) for v in value]}
    if isinstance(value, dict):
        return {
            "type": "map",
            "entries": [
                {"key": _model_key_to_typed(k), "value": _model_to_typed(v)}
                for k, v in value.items()
            ],
        }
    raise OpAdapterError(
        "adapter.internalError",
        f"model produced an unmappable extension value {type(value).__name__}",
    )


def _model_key_to_typed(key: Any) -> dict[str, Any]:
    if isinstance(key, bool):
        raise OpAdapterError(
            "adapter.internalError", "model produced a boolean extension key"
        )
    if isinstance(key, int):
        if key >= 0:
            return {"type": "uint", "value": str(key)}
        return {"type": "nint", "value": str(key)}
    if isinstance(key, str):
        return {"type": "text", "value": key}
    raise OpAdapterError(
        "adapter.internalError",
        f"model produced an unmappable extension key {type(key).__name__}",
    )


def _extension_map_to_model(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _bad_input(f"{what} must be an object")
    return {
        _text(key, f"{what} key"): _typed_to_model(item) for key, item in value.items()
    }


def _extension_map_from_model(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    return {key: _model_to_typed(item) for key, item in value.items()}


# ---------------------------------------------------------------------------
# Contact Document translation (canonical runner shape, HARNESS.md 10)
# ---------------------------------------------------------------------------


def _contact_to_model(contact: Any) -> dict[int, Any]:
    members = _take_members(contact, "contact", tuple(_CONTACT_LABELS.keys()))
    out: dict[int, Any] = {}
    display_name = _text_or_none(members["displayName"], "contact.displayName")
    if display_name is not None:
        out[0] = display_name
    summary = _text_or_none(members["summary"], "contact.summary")
    if summary is not None:
        out[1] = summary
    avatar = _text_or_none(members["avatar"], "contact.avatar")
    if avatar is not None:
        out[2] = avatar
    aka = [
        _text(v, "contact.alsoKnownAs entry")
        for v in _array(members["alsoKnownAs"], "contact.alsoKnownAs")
    ]
    if aka:
        out[3] = aka
    services = [
        _service_to_model(s) for s in _array(members["services"], "contact.services")
    ]
    if services:
        out[4] = services
    if members["migration"] is not None:
        migration = _take_members(
            members["migration"], "migration", tuple(_MIGRATION_LABELS.keys())
        )
        migration_out: dict[int, Any] = {}
        predecessor = _text_or_none(migration["predecessor"], "migration.predecessor")
        if predecessor is not None:
            migration_out[0] = predecessor
        successor = _text_or_none(migration["successor"], "migration.successor")
        if successor is not None:
            migration_out[1] = successor
        out[5] = migration_out
    extensions = _extension_map_to_model(members["extensions"], "contact.extensions")
    if extensions:
        out[6] = extensions
    return out


def _service_to_model(service: Any) -> dict[int, Any]:
    members = _take_members(service, "service entry", tuple(_SERVICE_LABELS.keys()))
    out: dict[int, Any] = {
        0: _text(members["id"], "service.id"),
        1: _text(members["type"], "service.type"),
        2: _text(members["endpoint"], "service.endpoint"),
    }
    for name in ("mediaType", "label", "language", "rel"):
        value = _text_or_none(members[name], f"service.{name}")
        if value is not None:
            out[_SERVICE_LABELS[name]] = value
    return out


def _contact_from_model(contact: dict) -> dict[str, Any]:
    migration = contact.get(5)
    return {
        "displayName": contact.get(0),
        "summary": contact.get(1),
        "avatar": contact.get(2),
        "alsoKnownAs": list(contact.get(3, [])),
        "services": [
            {
                "id": s[0],
                "type": s[1],
                "endpoint": s[2],
                "mediaType": s.get(3),
                "label": s.get(4),
                "language": s.get(5),
                "rel": s.get(6),
            }
            for s in contact.get(4, [])
        ],
        "migration": (
            None
            if migration is None
            else {
                "predecessor": migration.get(0),
                "successor": migration.get(1),
            }
        ),
        "extensions": _extension_map_from_model(contact.get(6)),
    }


# ---------------------------------------------------------------------------
# Operations (HARNESS.md 9.1-9.3)
# ---------------------------------------------------------------------------


def _followee_symbol(model: SimpleNamespace, exc: Exception) -> str:
    return model.errors.ERROR_NAMES[exc.code]


def op_derive_identity(model: SimpleNamespace, input_value: Any) -> dict[str, Any]:
    members = _take_members(
        input_value, "deriveIdentity input", ("rootSeedHex", "revocationSeedHex")
    )
    root_seed = _decode_hex32(members["rootSeedHex"], "rootSeedHex")
    revocation_seed = _decode_hex32(members["revocationSeedHex"], "revocationSeedHex")

    root_public = model.ed25519.public_key_from_seed(root_seed)
    revocation_public = model.ed25519.public_key_from_seed(revocation_seed)
    revocation_obj = model.descriptor.make_public_key(revocation_public)
    revocation_cbor = model.detcbor.encode(revocation_obj)
    commitment = model.descriptor.revocation_commitment(revocation_obj)
    descriptor_obj = model.descriptor.make_descriptor(root_public, revocation_public)
    descriptor_cbor = model.detcbor.encode(descriptor_obj)
    digest = model.descriptor.descriptor_digest(descriptor_obj)
    did = model.descriptor.did_for_descriptor(descriptor_obj)

    return {
        "rootPublicKeyHex": root_public.hex(),
        "revocationPublicKeyHex": revocation_public.hex(),
        "revocationPublicKeyCborHex": revocation_cbor.hex(),
        "revocationCommitmentHex": commitment.hex(),
        "authorityDescriptorCborHex": descriptor_cbor.hex(),
        "authorityDescriptorDigestHex": digest.hex(),
        "did": did,
    }


def op_author_record(model: SimpleNamespace, input_value: Any) -> dict[str, Any]:
    members = _take_members(
        input_value,
        "authorRecord input",
        (
            "rootSeedHex",
            "revocationSeedHex",
            "authority",
            "timestampMs",
            "validUntilMs",
            "contact",
            "extensions",
            "signingSeed",
        ),
    )
    root_seed = _decode_hex32(members["rootSeedHex"], "rootSeedHex")
    revocation_seed = _decode_hex32(members["revocationSeedHex"], "revocationSeedHex")
    authority_name = _text(members["authority"], "authority")
    if authority_name not in ("root", "rootRevoked"):
        raise _bad_input(f"unknown authority {authority_name!r}")
    timestamp_ms = _parse_u64(members["timestampMs"], "timestampMs")
    valid_until_ms = _parse_opt_u64(members["validUntilMs"], "validUntilMs")
    contact_model = _contact_to_model(members["contact"])
    extensions_model = _extension_map_to_model(members["extensions"], "extensions")
    signing_seed_name = _text(members["signingSeed"], "signingSeed")
    if signing_seed_name not in ("root", "revocation"):
        raise _bad_input(f"unknown signingSeed {signing_seed_name!r}")

    # Runner input contract (HARNESS.md 9.2): an incoherent
    # authority/signingSeed pairing is refused, never silently re-keyed.
    coherent = (authority_name, signing_seed_name) in (
        ("root", "root"),
        ("rootRevoked", "revocation"),
    )
    if not coherent:
        raise OpAdapterError(
            "adapter.signingKeyMismatch",
            f"signingSeed {signing_seed_name!r} is not the key applicable "
            f"to authority {authority_name!r}",
        )
    signing_seed = root_seed if signing_seed_name == "root" else revocation_seed

    root_public = model.ed25519.public_key_from_seed(root_seed)
    revocation_public = model.ed25519.public_key_from_seed(revocation_seed)
    descriptor_obj = model.descriptor.make_descriptor(root_public, revocation_public)
    did = model.descriptor.did_for_descriptor(descriptor_obj)
    authority_value = (
        model.record.AUTHORITY_ROOT
        if authority_name == "root"
        else model.record.AUTHORITY_ROOT_REVOKED
    )
    revocation_key_obj = (
        model.descriptor.make_public_key(revocation_public)
        if authority_name == "rootRevoked"
        else None
    )

    try:
        body = model.signing.build_record_body(
            did=did,
            timestamp_ms=timestamp_ms,
            authority=authority_value,
            descriptor_obj=descriptor_obj,
            contact=contact_model,
            revocation_key_obj=revocation_key_obj,
            valid_until_ms=valid_until_ms,
            extensions=extensions_model or None,
        )
        body_bytes = model.signing.encode_record_body(body)
        envelope = model.signing.sign_record_body(body_bytes, signing_seed)
        # Self-check through the model's own full verification: the typed
        # authoring path must not sign what the model's verifier rejects.
        # nowMs is not an authoring input; the record's own timestamp is
        # used, and the resulting premature/stale metadata is discarded.
        verified = model.verify.verify_full_record(did, envelope, timestamp_ms)
    except model.errors.FolloweeError as exc:
        raise OpRejected(_followee_symbol(model, exc)) from exc

    sig_structure = model.cose.sig_structure(body_bytes)
    return {
        "did": did,
        "recordBodyCborHex": body_bytes.hex(),
        "recordBodyDigestHex": verified.body_digest.hex(),
        "sigStructureHex": sig_structure.hex(),
        "signatureHex": envelope[-64:].hex(),
        "envelopeHex": envelope.hex(),
    }


def op_verify_record(model: SimpleNamespace, input_value: Any) -> dict[str, Any]:
    members = _take_members(
        input_value, "verifyRecord input", ("targetDid", "envelopeHex", "nowMs")
    )
    target = _text(members["targetDid"], "targetDid")
    envelope = _decode_hex(members["envelopeHex"], "envelopeHex")
    now_ms = _parse_u64(members["nowMs"], "nowMs")

    try:
        verified = model.verify.verify_full_record(target, envelope, now_ms)
    except model.errors.FolloweeError as exc:
        raise OpRejected(_followee_symbol(model, exc)) from exc

    authority = (
        "root" if verified.authority == model.record.AUTHORITY_ROOT else "rootRevoked"
    )
    valid_until = (
        None if verified.valid_until_ms is None else str(verified.valid_until_ms)
    )
    return {
        "envelopeHex": verified.envelope_bytes.hex(),
        "recordBodyCborHex": verified.body_bytes.hex(),
        "recordBodyDigestHex": verified.body_digest.hex(),
        "id": verified.target,
        "timestampMs": str(verified.timestamp_ms),
        "authority": authority,
        "validUntilMs": valid_until,
        "premature": verified.premature,
        "stale": verified.stale,
        "record": {
            "protocolVersion": "1",
            "id": verified.target,
            "timestampMs": str(verified.timestamp_ms),
            "authority": authority,
            "authorityDescriptor": {
                "descriptorVersion": "1",
                "rootKey": {
                    "suite": "-19",
                    "publicKeyHex": verified.root_public_key.hex(),
                },
                "revocationCommitmentHex": (verified.revocation_commitment.hex()),
            },
            "revocationKey": (
                None
                if verified.revocation_public_key is None
                else {
                    "suite": "-19",
                    "publicKeyHex": verified.revocation_public_key.hex(),
                }
            ),
            "validUntilMs": valid_until,
            "contact": _contact_from_model(verified.contact),
            "extensions": _extension_map_from_model(verified.extensions),
        },
    }


# ---------------------------------------------------------------------------
# Strict request parsing and dispatch (HARNESS.md 7.1-7.3)
# ---------------------------------------------------------------------------


class _ProfileError(ValueError):
    pass


def _reject_number(token: str) -> Any:
    raise _ProfileError(
        f"bare JSON number {token!r}; protocol integers are decimal strings"
    )


def _reject_constant(token: str) -> Any:
    raise _ProfileError(f"forbidden JSON constant {token!r}")


def _pairs_rejecting_duplicates(pairs: list) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _ProfileError(f"duplicate object member {key!r}")
        obj[key] = value
    return obj


def parse_request(raw: bytes) -> dict[str, Any]:
    """Parse one request line under the runner JSON profile (HARNESS.md 7.2)."""
    if raw.startswith(BOM):
        raise _ProfileError("request line begins with a UTF-8 byte-order mark")
    if raw.strip() == b"":
        raise _ProfileError("blank protocol line")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _ProfileError(f"request line is not UTF-8: {exc}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_rejecting_duplicates,
            parse_float=_reject_number,
            parse_int=_reject_number,
            parse_constant=_reject_constant,
        )
    except _ProfileError:
        raise
    except json.JSONDecodeError as exc:
        raise _ProfileError(str(exc)) from exc
    if not isinstance(value, dict):
        raise _ProfileError("request is not a JSON object")
    expected_members = {"runnerProtocol", "caseId", "operation", "input"}
    unknown = set(value) - expected_members
    if unknown:
        raise _ProfileError(f"unknown object members {sorted(unknown)}")
    missing = expected_members - set(value)
    if missing:
        raise _ProfileError(f"missing object members {sorted(missing)}")
    for member in ("runnerProtocol", "caseId", "operation"):
        if not isinstance(value[member], str):
            raise _ProfileError(f"{member} must be a string")
    if value["caseId"] == "":
        raise _ProfileError("caseId must be a nonempty string")
    if not isinstance(value["input"], dict):
        raise _ProfileError("input must be an object")
    return value


def _adapter_error(
    runner_protocol: str, case_id: str, symbol: str, message: str
) -> dict[str, Any]:
    return {
        "runnerProtocol": runner_protocol,
        "caseId": case_id,
        "status": "adapterError",
        "error": symbol,
        "message": message,
    }


def handle_line(
    identity: dict[str, Any],
    model: SimpleNamespace | None,
    raw: bytes,
    truncated: bool,
) -> dict[str, Any]:
    """Handle one raw request line; return the response object."""
    if truncated:
        return _adapter_error(
            RUNNER_PROTOCOL,
            "unknown",
            "adapter.lineTooLong",
            "request line exceeded the 1 MiB runner limit",
        )
    try:
        request = parse_request(raw)
    except _ProfileError as exc:
        return _adapter_error(
            RUNNER_PROTOCOL,
            "unknown",
            "adapter.malformedRequest",
            f"request does not satisfy the runner JSON profile: {exc}",
        )
    # Responses repeat the request's runnerProtocol and caseId exactly
    # (HARNESS.md 7.3), even on adapter errors.
    case_id = request["caseId"]
    if request["runnerProtocol"] != RUNNER_PROTOCOL:
        return _adapter_error(
            request["runnerProtocol"],
            case_id,
            "adapter.unsupportedProtocol",
            f"runner protocol {request['runnerProtocol']!r} is not "
            f"supported; this adapter speaks {RUNNER_PROTOCOL!r}",
        )
    operation = request["operation"]
    if operation == "hello":
        if request["input"] != {}:
            return _adapter_error(
                RUNNER_PROTOCOL,
                case_id,
                "adapter.invalidInput",
                "hello takes an empty input object",
            )
        return {
            "runnerProtocol": RUNNER_PROTOCOL,
            "caseId": case_id,
            "status": "accepted",
            "result": identity,
        }
    handlers = {
        "deriveIdentity": op_derive_identity,
        "authorRecord": op_author_record,
        "verifyRecord": op_verify_record,
    }
    if operation not in handlers:
        return _adapter_error(
            RUNNER_PROTOCOL,
            case_id,
            "adapter.unsupportedOperation",
            f"operation {operation!r} is not supported at Milestone 1",
        )
    if model is None:
        return _adapter_error(
            RUNNER_PROTOCOL,
            case_id,
            "adapter.internalError",
            "frozen model is not loaded",
        )
    try:
        result = handlers[operation](model, request["input"])
    except OpRejected as exc:
        return {
            "runnerProtocol": RUNNER_PROTOCOL,
            "caseId": case_id,
            "status": "rejected",
            "error": exc.error,
        }
    except OpAdapterError as exc:
        return _adapter_error(RUNNER_PROTOCOL, case_id, exc.symbol, exc.message)
    except Exception as exc:  # noqa: BLE001 - never tear the process down
        print(
            f"adapter: unexpected exception in {operation}: {exc!r}",
            file=sys.stderr,
            flush=True,
        )
        return _adapter_error(
            RUNNER_PROTOCOL,
            case_id,
            "adapter.internalError",
            f"unexpected {type(exc).__name__} during {operation}",
        )
    return {
        "runnerProtocol": RUNNER_PROTOCOL,
        "caseId": case_id,
        "status": "accepted",
        "result": result,
    }


def _read_line_capped(stream, max_bytes: int):
    """Read one line; return (line_without_newline, truncated) or None at EOF.

    A line longer than ``max_bytes`` is drained through its newline and
    flagged truncated.
    """
    line = stream.readline(max_bytes + 1)
    if line == b"":
        return None
    if line.endswith(b"\n"):
        return line[:-1], False
    if len(line) <= max_bytes:
        # Final unterminated line before EOF.
        return line, False
    while True:
        chunk = stream.readline(65536)
        if chunk == b"" or chunk.endswith(b"\n"):
            return b"", True


def main() -> int:
    try:
        model = load_model()
        identity = resolve_identity()
    except AdapterStartupError as exc:
        print(f"adapter startup failure: {exc}", file=sys.stderr)
        return 3
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        item = _read_line_capped(stdin, MAX_LINE_BYTES)
        if item is None:
            return 0
        raw, truncated = item
        response = handle_line(identity, model, raw, truncated)
        encoded = json.dumps(
            response, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        stdout.write(encoded + b"\n")
        stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
