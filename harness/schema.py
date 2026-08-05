"""Minimal JSON Schema subset validator (standard library only).

The committed schemas under ``schemas/`` are normative for the harness
(HARNESS.md Section 9).  The orchestrator SHOULD use only the Python
standard library (Section 4), so this module implements exactly the
subset of JSON Schema keywords those schemas use:

    type (string, boolean, object, array, null), enum, const, pattern,
    minLength, maxLength, properties, required, additionalProperties
    (boolean false only), items, minItems, maxItems, uniqueItems, oneOf.

Numeric instance types are deliberately unsupported: the runner JSON
profile forbids bare numbers (HARNESS.md 7.2).  Annotation keywords
($schema, $id, $comment, title, description) are ignored.  An unsupported
keyword in a schema is an error, not silently ignored.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_ANNOTATIONS = {"$schema", "$id", "$comment", "title", "description"}
_SUPPORTED = _ANNOTATIONS | {
    "type",
    "enum",
    "const",
    "pattern",
    "minLength",
    "maxLength",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "oneOf",
}

_TYPES = {
    "string": str,
    "boolean": bool,
    "object": dict,
    "array": list,
    "null": type(None),
}


class SchemaError(ValueError):
    """The schema itself is invalid or uses an unsupported keyword."""


class ValidationError(ValueError):
    """The instance does not satisfy the schema."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path or '$'}: {message}")
        self.path = path or "$"
        self.reason = message


def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return type(value).__name__


def _check_type(value: Any, expected: str, path: str) -> None:
    if expected not in _TYPES:
        raise SchemaError(f"unsupported schema type {expected!r}")
    cls = _TYPES[expected]
    # bool is a subclass of int in Python but no numbers reach here; still,
    # guard str/bool cross-matches explicitly.
    if expected != "boolean" and isinstance(value, bool):
        raise ValidationError(path, f"expected {expected}, got boolean")
    if not isinstance(value, cls):
        raise ValidationError(path, f"expected {expected}, got {_type_name(value)}")


def validate(instance: Any, schema: dict[str, Any], path: str = "") -> None:
    """Validate ``instance`` against the supported schema subset.

    Raises ValidationError on instance mismatch and SchemaError when the
    schema uses anything outside the supported subset.
    """
    if not isinstance(schema, dict):
        raise SchemaError(f"schema at {path or '$'} is not an object")
    unsupported = set(schema) - _SUPPORTED
    if unsupported:
        raise SchemaError(
            f"unsupported schema keywords at {path or '$'}: {sorted(unsupported)}"
        )

    if "oneOf" in schema:
        branches = schema["oneOf"]
        if not isinstance(branches, list) or not branches:
            raise SchemaError(f"oneOf at {path or '$'} must be a nonempty array")
        matches: list[int] = []
        errors: list[str] = []
        for i, branch in enumerate(branches):
            try:
                validate(instance, branch, path)
            except ValidationError as exc:
                errors.append(f"branch {i}: {exc}")
            else:
                matches.append(i)
        if len(matches) != 1:
            raise ValidationError(
                path,
                f"oneOf matched {len(matches)} branches "
                f"(need exactly 1): {'; '.join(errors)}",
            )

    if "type" in schema:
        _check_type(instance, schema["type"], path)

    if "const" in schema and instance != schema["const"]:
        raise ValidationError(
            path, f"expected constant {schema['const']!r}, got {instance!r}"
        )

    if "enum" in schema and instance not in schema["enum"]:
        raise ValidationError(path, f"{instance!r} not one of {schema['enum']!r}")

    if isinstance(instance, str):
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            raise ValidationError(
                path, f"{instance!r} does not match {schema['pattern']!r}"
            )
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise ValidationError(path, f"shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise ValidationError(path, f"longer than maxLength {schema['maxLength']}")

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in instance:
                raise ValidationError(path, f"missing required member {name!r}")
        if schema.get("additionalProperties", True) is False:
            extra = set(instance) - set(properties)
            if extra:
                raise ValidationError(path, f"unknown object members {sorted(extra)}")
        elif "additionalProperties" in schema and (
            schema["additionalProperties"] is not True
        ):
            raise SchemaError("additionalProperties must be boolean in this subset")
        for name, subschema in properties.items():
            if name in instance:
                validate(instance[name], subschema, f"{path}.{name}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            raise ValidationError(
                path, f"fewer than minItems {schema['minItems']} items"
            )
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            raise ValidationError(
                path, f"more than maxItems {schema['maxItems']} items"
            )
        if schema.get("uniqueItems", False):
            seen: list[Any] = []
            for i, item in enumerate(instance):
                if item in seen:
                    raise ValidationError(f"{path}[{i}]", "duplicate array item")
                seen.append(item)
        if "items" in schema:
            for i, item in enumerate(instance):
                validate(item, schema["items"], f"{path}[{i}]")


def schemas_dir(repo_root: Path) -> Path:
    return repo_root / "schemas"


def load_schema(repo_root: Path, name: str) -> dict[str, Any]:
    """Load a committed schema file.

    Schema files are ordinary JSON documents, not runner traffic, so they
    may contain numbers (minItems etc.); duplicate member names are still
    rejected.
    """

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in items:
            if key in obj:
                raise SchemaError(f"duplicate member {key!r} in schema {name}")
            obj[key] = value
        return obj

    text = (schemas_dir(repo_root) / name).read_text(encoding="utf-8")
    return json.loads(text, object_pairs_hook=pairs)
