"""Strict JSON Lines codec for runner protocol v1 (HARNESS.md 7.1 and 7.2).

Runner JSON is not a Followee wire format.  On top of ordinary JSON it
rejects byte-order marks, blank lines, duplicate object member names, and
every bare JSON number (protocol integers are canonical decimal strings and
floating-point numbers are forbidden, so no conformant runner line contains
a number token).  Lines are capped at 1 MiB in each direction.

This module is harness infrastructure only; it knows nothing about Followee
semantics.
"""

from __future__ import annotations

import json
from typing import Any

from harness.pins import MAX_LINE_BYTES

BOM = b"\xef\xbb\xbf"


class StrictJsonError(ValueError):
    """A runner line violating the JSON profile.

    ``symbol`` is a stable classification suffix, e.g. ``"malformedJson"``.
    Callers prefix it with ``harness.`` or ``adapter.`` as appropriate.
    """

    def __init__(self, symbol: str, message: str) -> None:
        super().__init__(f"{symbol}: {message}")
        self.symbol = symbol
        self.message = message


def _reject_number(token: str) -> Any:
    raise StrictJsonError(
        "numberForbidden",
        f"bare JSON number {token!r}; protocol integers are decimal strings",
    )


def _reject_constant(token: str) -> Any:
    raise StrictJsonError("malformedJson", f"forbidden JSON constant {token!r}")


def _pairs_rejecting_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise StrictJsonError(
                "duplicateJsonName", f"duplicate object member {key!r}"
            )
        obj[key] = value
    return obj


def loads_line(raw: bytes) -> dict[str, Any]:
    """Decode one protocol line (without its trailing newline).

    Raises StrictJsonError with one of the symbols: lineTooLong,
    byteOrderMark, blankLine, invalidUtf8, malformedJson,
    duplicateJsonName, numberForbidden, notAnObject.
    """
    if len(raw) > MAX_LINE_BYTES:
        raise StrictJsonError(
            "lineTooLong", f"line of {len(raw)} bytes exceeds {MAX_LINE_BYTES}"
        )
    if raw.startswith(BOM):
        raise StrictJsonError("byteOrderMark", "line begins with a UTF-8 BOM")
    if raw.strip() == b"":
        raise StrictJsonError("blankLine", "blank protocol line")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJsonError("invalidUtf8", str(exc)) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_rejecting_duplicates,
            parse_float=_reject_number,
            parse_int=_reject_number,
            parse_constant=_reject_constant,
        )
    except StrictJsonError:
        raise
    except json.JSONDecodeError as exc:
        raise StrictJsonError("malformedJson", str(exc)) from exc
    if not isinstance(value, dict):
        raise StrictJsonError(
            "notAnObject", f"top-level value is {type(value).__name__}"
        )
    return value


def _check_no_numbers(value: Any, path: str) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, (int, float)):
        raise StrictJsonError("numberForbidden", f"bare number at {path or '$'}")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check_no_numbers(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise StrictJsonError(
                    "notAnObject", f"non-string member name at {path or '$'}"
                )
            _check_no_numbers(item, f"{path}.{key}")
        return
    raise StrictJsonError(
        "malformedJson", f"unencodable value {type(value).__name__} at {path}"
    )


def dumps_line(obj: dict[str, Any]) -> bytes:
    """Encode one protocol object as a single newline-terminated line."""
    if not isinstance(obj, dict):
        raise StrictJsonError("notAnObject", "protocol value must be an object")
    _check_no_numbers(obj, "")
    encoded = json.dumps(
        obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(encoded) > MAX_LINE_BYTES:
        raise StrictJsonError(
            "lineTooLong",
            f"encoded line of {len(encoded)} bytes exceeds {MAX_LINE_BYTES}",
        )
    return encoded + b"\n"
