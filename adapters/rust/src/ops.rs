//! Milestone 1 operations: `deriveIdentity`, `authorRecord`, and
//! `verifyRecord` (HARNESS.md 9.1–9.3).
//!
//! This module is a thin translation layer.  Every protocol decision —
//! CBOR, COSE, DID derivation, hashing, signing, verification, URI and
//! Contact Document validity — is made by the frozen `followee` crate
//! through its public API.  The adapter only converts between the neutral
//! runner JSON profile and that API, and enforces the runner input
//! contract (member shapes, hexadecimal and canonical-decimal ranges,
//! authority/signingSeed coherence) before calling the implementation.

use std::collections::BTreeMap;

use followee::contact::{
    ContactDocument, ExtensionKey, ExtensionMap, ExtensionValue, Migration, ServiceEntry,
};
use followee::crypto;
use followee::did::FolloweeDid;
use followee::record::{
    encode_public_key, revocation_commitment, Authority, AuthorityDescriptor, RecordBody, SignError,
};
use followee::timestamp::{freshness, time_status, Freshness, TimeStatus};
use followee::verify::{verify_record_for_target, VerifiedRecord};
use serde_json::{json, Map, Value};

use crate::StrictValue;

/// Operation failure: either a runner input-contract violation (adapter
/// namespace, always fails the campaign) or a Followee-level rejection
/// carrying the implementation's symbolic error.
pub enum OpError {
    Adapter {
        symbol: &'static str,
        message: String,
    },
    Rejected {
        error: &'static str,
    },
}

fn bad_input(message: impl Into<String>) -> OpError {
    OpError::Adapter {
        symbol: "adapter.invalidInput",
        message: message.into(),
    }
}

// ---------------------------------------------------------------------------
// Neutral input readers (runner JSON profile, HARNESS.md 7.2 and 10)
// ---------------------------------------------------------------------------

struct Fields {
    entries: Vec<(String, StrictValue)>,
    context: &'static str,
}

impl Fields {
    fn new(value: StrictValue, context: &'static str) -> Result<Fields, OpError> {
        match value {
            StrictValue::Object(entries) => Ok(Fields { entries, context }),
            _ => Err(bad_input(format!("{context} must be an object"))),
        }
    }

    fn take(&mut self, name: &str) -> Result<StrictValue, OpError> {
        let index = self
            .entries
            .iter()
            .position(|(k, _)| k == name)
            .ok_or_else(|| bad_input(format!("{}: missing member {name:?}", self.context)))?;
        Ok(self.entries.remove(index).1)
    }

    fn finish(self) -> Result<(), OpError> {
        if let Some((name, _)) = self.entries.first() {
            return Err(bad_input(format!(
                "{}: unknown member {name:?}",
                self.context
            )));
        }
        Ok(())
    }
}

fn as_text(value: StrictValue, what: &str) -> Result<String, OpError> {
    match value {
        StrictValue::Text(s) => Ok(s),
        _ => Err(bad_input(format!("{what} must be a string"))),
    }
}

fn as_bool(value: StrictValue, what: &str) -> Result<bool, OpError> {
    match value {
        StrictValue::Bool(b) => Ok(b),
        _ => Err(bad_input(format!("{what} must be a boolean"))),
    }
}

fn as_array(value: StrictValue, what: &str) -> Result<Vec<StrictValue>, OpError> {
    match value {
        StrictValue::Array(items) => Ok(items),
        _ => Err(bad_input(format!("{what} must be an array"))),
    }
}

fn opt_text(value: StrictValue, what: &str) -> Result<Option<String>, OpError> {
    match value {
        StrictValue::Null => Ok(None),
        StrictValue::Text(s) => Ok(Some(s)),
        _ => Err(bad_input(format!("{what} must be a string or null"))),
    }
}

fn decode_hex(text: &str, what: &str) -> Result<Vec<u8>, OpError> {
    if text.len() % 2 != 0 {
        return Err(bad_input(format!("{what}: odd-length hexadecimal")));
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = hex_nibble(pair[0])
            .ok_or_else(|| bad_input(format!("{what}: invalid or uppercase hexadecimal digit")))?;
        let lo = hex_nibble(pair[1])
            .ok_or_else(|| bad_input(format!("{what}: invalid or uppercase hexadecimal digit")))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn decode_hex32(text: &str, what: &str) -> Result<[u8; 32], OpError> {
    let bytes = decode_hex(text, what)?;
    bytes
        .try_into()
        .map_err(|_| bad_input(format!("{what} must be exactly 32 bytes")))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}

/// Parses a canonical unsigned decimal string into a `u64`, rejecting
/// non-canonical forms and out-of-range values (HARNESS.md 7.2).
fn parse_u64(text: &str, what: &str) -> Result<u64, OpError> {
    let value: u64 = text
        .parse()
        .map_err(|_| bad_input(format!("{what}: not a canonical uint64 decimal string")))?;
    if value.to_string() != text {
        return Err(bad_input(format!("{what}: non-canonical decimal encoding")));
    }
    Ok(value)
}

fn parse_opt_u64(value: StrictValue, what: &str) -> Result<Option<u64>, OpError> {
    match value {
        StrictValue::Null => Ok(None),
        StrictValue::Text(s) => Ok(Some(parse_u64(&s, what)?)),
        _ => Err(bad_input(format!(
            "{what} must be a decimal string or null"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Typed value tree (HARNESS.md Section 10) -> implementation extension types
// ---------------------------------------------------------------------------

fn typed_value(value: StrictValue) -> Result<ExtensionValue, OpError> {
    let mut fields = Fields::new(value, "typed value")?;
    let kind = as_text(fields.take("type")?, "typed value type")?;
    let result = match kind.as_str() {
        "uint" => {
            let v = parse_u64(&as_text(fields.take("value")?, "uint value")?, "uint value")?;
            ExtensionValue::Unsigned(v)
        }
        "nint" => {
            let text = as_text(fields.take("value")?, "nint value")?;
            ExtensionValue::Negative(parse_nint_magnitude(&text)?)
        }
        "bytes" => {
            let hex = as_text(fields.take("hex")?, "bytes hex")?;
            ExtensionValue::Bytes(decode_hex(&hex, "bytes hex")?)
        }
        "text" => ExtensionValue::Text(as_text(fields.take("value")?, "text value")?),
        "bool" => ExtensionValue::Bool(as_bool(fields.take("value")?, "bool value")?),
        "null" => ExtensionValue::Null,
        "array" => {
            let items = as_array(fields.take("items")?, "array items")?;
            ExtensionValue::Array(
                items
                    .into_iter()
                    .map(typed_value)
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
        "map" => {
            let entries = as_array(fields.take("entries")?, "map entries")?;
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                let mut pair = Fields::new(entry, "map entry")?;
                let key = typed_key(pair.take("key")?)?;
                let value = typed_value(pair.take("value")?)?;
                pair.finish()?;
                out.push((key, value));
            }
            ExtensionValue::Map(out)
        }
        other => return Err(bad_input(format!("unknown typed value type {other:?}"))),
    };
    fields.finish()?;
    Ok(result)
}

fn typed_key(value: StrictValue) -> Result<ExtensionKey, OpError> {
    let mut fields = Fields::new(value, "typed key")?;
    let kind = as_text(fields.take("type")?, "typed key type")?;
    let key = match kind.as_str() {
        "uint" => ExtensionKey::Unsigned(parse_u64(
            &as_text(fields.take("value")?, "uint key")?,
            "uint key",
        )?),
        "nint" => {
            let text = as_text(fields.take("value")?, "nint key")?;
            ExtensionKey::Negative(parse_nint_magnitude(&text)?)
        }
        "text" => ExtensionKey::Text(as_text(fields.take("value")?, "text key")?),
        other => return Err(bad_input(format!("unknown typed key type {other:?}"))),
    };
    fields.finish()?;
    Ok(key)
}

/// Parses a canonical negative decimal string `-1 ..= -(2^64)` into the
/// CBOR negative-integer magnitude (value = -(1 + magnitude)).
fn parse_nint_magnitude(text: &str) -> Result<u64, OpError> {
    let value: i128 = text
        .parse()
        .map_err(|_| bad_input("nint: not a canonical decimal string"))?;
    if value.to_string() != text {
        return Err(bad_input("nint: non-canonical decimal encoding"));
    }
    if !(-(1i128 << 64)..0).contains(&value) {
        return Err(bad_input("nint out of the CBOR negative-integer range"));
    }
    Ok(u64::try_from(-(value + 1)).expect("magnitude fits u64"))
}

fn extension_map(value: StrictValue, what: &str) -> Result<ExtensionMap, OpError> {
    let entries = match value {
        StrictValue::Object(entries) => entries,
        _ => return Err(bad_input(format!("{what} must be an object"))),
    };
    let mut map = BTreeMap::new();
    for (key, value) in entries {
        map.insert(key, typed_value(value)?);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Contact Document translation (canonical runner shape, HARNESS.md 10)
// ---------------------------------------------------------------------------

fn contact_from_input(value: StrictValue) -> Result<ContactDocument, OpError> {
    let mut fields = Fields::new(value, "contact")?;
    let display_name = opt_text(fields.take("displayName")?, "contact.displayName")?;
    let summary = opt_text(fields.take("summary")?, "contact.summary")?;
    let avatar = opt_text(fields.take("avatar")?, "contact.avatar")?;
    let also_known_as = as_array(fields.take("alsoKnownAs")?, "contact.alsoKnownAs")?
        .into_iter()
        .map(|v| as_text(v, "contact.alsoKnownAs entry"))
        .collect::<Result<Vec<_>, _>>()?;
    let services = as_array(fields.take("services")?, "contact.services")?
        .into_iter()
        .map(service_from_input)
        .collect::<Result<Vec<_>, _>>()?;
    let migration = match fields.take("migration")? {
        StrictValue::Null => None,
        value => Some(migration_from_input(value)?),
    };
    let extensions = extension_map(fields.take("extensions")?, "contact.extensions")?;
    fields.finish()?;
    Ok(ContactDocument {
        display_name,
        summary,
        avatar,
        also_known_as,
        services,
        migration,
        extensions,
    })
}

fn service_from_input(value: StrictValue) -> Result<ServiceEntry, OpError> {
    let mut fields = Fields::new(value, "service entry")?;
    let entry = ServiceEntry {
        id: as_text(fields.take("id")?, "service.id")?,
        service_type: as_text(fields.take("type")?, "service.type")?,
        endpoint: as_text(fields.take("endpoint")?, "service.endpoint")?,
        media_type: opt_text(fields.take("mediaType")?, "service.mediaType")?,
        label: opt_text(fields.take("label")?, "service.label")?,
        language: opt_text(fields.take("language")?, "service.language")?,
        rel: opt_text(fields.take("rel")?, "service.rel")?,
    };
    fields.finish()?;
    Ok(entry)
}

fn migration_from_input(value: StrictValue) -> Result<Migration, OpError> {
    let mut fields = Fields::new(value, "migration")?;
    let predecessor = opt_text(fields.take("predecessor")?, "migration.predecessor")?;
    let successor = opt_text(fields.take("successor")?, "migration.successor")?;
    fields.finish()?;
    // Migration values are typed DIDs in the implementation's authoring
    // path; a malformed value is the implementation's DID classification,
    // a Followee-level rejection rather than an adapter error.
    let parse = |text: Option<String>| -> Result<Option<FolloweeDid>, OpError> {
        match text {
            None => Ok(None),
            Some(text) => match FolloweeDid::parse(&text) {
                Ok(did) => Ok(Some(did)),
                Err(e) => Err(OpError::Rejected {
                    error: followee::error::VerifyError::from(e).symbol(),
                }),
            },
        }
    };
    Ok(Migration {
        predecessor: parse(predecessor)?,
        successor: parse(successor)?,
    })
}

// ---------------------------------------------------------------------------
// Result builders (implementation values -> canonical runner shapes)
// ---------------------------------------------------------------------------

fn text_or_null(value: &Option<String>) -> Value {
    match value {
        Some(s) => Value::String(s.clone()),
        None => Value::Null,
    }
}

fn uint_or_null(value: Option<u64>) -> Value {
    match value {
        Some(v) => Value::String(v.to_string()),
        None => Value::Null,
    }
}

fn typed_value_json(value: &ExtensionValue) -> Value {
    match value {
        ExtensionValue::Unsigned(v) => json!({"type": "uint", "value": v.to_string()}),
        ExtensionValue::Negative(m) => {
            let value = -(i128::from(*m) + 1);
            json!({"type": "nint", "value": value.to_string()})
        }
        ExtensionValue::Bytes(b) => json!({"type": "bytes", "hex": encode_hex(b)}),
        ExtensionValue::Text(s) => json!({"type": "text", "value": s}),
        ExtensionValue::Bool(b) => json!({"type": "bool", "value": b}),
        ExtensionValue::Null => json!({"type": "null"}),
        ExtensionValue::Array(items) => json!({
            "type": "array",
            "items": items.iter().map(typed_value_json).collect::<Vec<_>>(),
        }),
        ExtensionValue::Map(entries) => json!({
            "type": "map",
            "entries": entries
                .iter()
                .map(|(k, v)| json!({"key": typed_key_json(k), "value": typed_value_json(v)}))
                .collect::<Vec<_>>(),
        }),
    }
}

fn typed_key_json(key: &ExtensionKey) -> Value {
    match key {
        ExtensionKey::Unsigned(v) => json!({"type": "uint", "value": v.to_string()}),
        ExtensionKey::Negative(m) => {
            let value = -(i128::from(*m) + 1);
            json!({"type": "nint", "value": value.to_string()})
        }
        ExtensionKey::Text(s) => json!({"type": "text", "value": s}),
    }
}

fn extension_map_json(map: &ExtensionMap) -> Value {
    let mut out = Map::new();
    for (key, value) in map {
        out.insert(key.clone(), typed_value_json(value));
    }
    Value::Object(out)
}

fn contact_json(contact: &ContactDocument) -> Value {
    json!({
        "displayName": text_or_null(&contact.display_name),
        "summary": text_or_null(&contact.summary),
        "avatar": text_or_null(&contact.avatar),
        "alsoKnownAs": contact.also_known_as,
        "services": contact
            .services
            .iter()
            .map(|s| json!({
                "id": s.id,
                "type": s.service_type,
                "endpoint": s.endpoint,
                "mediaType": text_or_null(&s.media_type),
                "label": text_or_null(&s.label),
                "language": text_or_null(&s.language),
                "rel": text_or_null(&s.rel),
            }))
            .collect::<Vec<_>>(),
        "migration": match &contact.migration {
            None => Value::Null,
            Some(m) => json!({
                "predecessor": m.predecessor.as_ref().map(|d| d.as_str().to_owned()),
                "successor": m.successor.as_ref().map(|d| d.as_str().to_owned()),
            }),
        },
        "extensions": extension_map_json(&contact.extensions),
    })
}

fn public_key_json(key: &[u8; 32]) -> Value {
    json!({"suite": "-19", "publicKeyHex": encode_hex(key)})
}

fn authority_text(authority: Authority) -> &'static str {
    match authority {
        Authority::Root => "root",
        Authority::RootRevoked => "rootRevoked",
    }
}

fn semantic_record_json(record: &VerifiedRecord) -> Value {
    let body = record.body();
    json!({
        "protocolVersion": "1",
        "id": body.id.as_str(),
        "timestampMs": body.timestamp_ms.to_string(),
        "authority": authority_text(body.authority),
        "authorityDescriptor": {
            "descriptorVersion": "1",
            "rootKey": public_key_json(&body.descriptor.root_key),
            "revocationCommitmentHex": encode_hex(&body.descriptor.revocation_commitment),
        },
        "revocationKey": match &body.revocation_key {
            Some(key) => public_key_json(key),
            None => Value::Null,
        },
        "validUntilMs": uint_or_null(body.valid_until_ms),
        "contact": contact_json(&body.contact),
        "extensions": extension_map_json(&body.extensions),
    })
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// `deriveIdentity` (HARNESS.md 9.1): every output value is produced by the
/// frozen implementation's public derivation functions.
pub fn derive_identity(input: StrictValue) -> Result<Value, OpError> {
    let mut fields = Fields::new(input, "deriveIdentity input")?;
    let root_seed = decode_hex32(
        &as_text(fields.take("rootSeedHex")?, "rootSeedHex")?,
        "rootSeedHex",
    )?;
    let revocation_seed = decode_hex32(
        &as_text(fields.take("revocationSeedHex")?, "revocationSeedHex")?,
        "revocationSeedHex",
    )?;
    fields.finish()?;

    let root_public = crypto::ed25519_public_key(&root_seed);
    let revocation_public = crypto::ed25519_public_key(&revocation_seed);
    let revocation_public_cbor = encode_public_key(&revocation_public);
    let commitment = revocation_commitment(&revocation_public);
    let descriptor = AuthorityDescriptor {
        root_key: root_public,
        revocation_commitment: commitment,
    };
    let descriptor_bytes = descriptor.encode();
    let did = descriptor.did();

    Ok(json!({
        "rootPublicKeyHex": encode_hex(&root_public),
        "revocationPublicKeyHex": encode_hex(&revocation_public),
        "revocationPublicKeyCborHex": encode_hex(&revocation_public_cbor),
        "revocationCommitmentHex": encode_hex(&commitment),
        "authorityDescriptorCborHex": encode_hex(&descriptor_bytes),
        "authorityDescriptorDigestHex": encode_hex(did.digest()),
        "did": did.as_str(),
    }))
}

/// `authorRecord` (HARNESS.md 9.2): typed authoring through
/// `RecordBody::encode` and `sign_record`, followed by the implementation's
/// own full verification of the produced envelope as a self-check.
pub fn author_record(input: StrictValue) -> Result<Value, OpError> {
    let mut fields = Fields::new(input, "authorRecord input")?;
    let root_seed = decode_hex32(
        &as_text(fields.take("rootSeedHex")?, "rootSeedHex")?,
        "rootSeedHex",
    )?;
    let revocation_seed = decode_hex32(
        &as_text(fields.take("revocationSeedHex")?, "revocationSeedHex")?,
        "revocationSeedHex",
    )?;
    let authority = match as_text(fields.take("authority")?, "authority")?.as_str() {
        "root" => Authority::Root,
        "rootRevoked" => Authority::RootRevoked,
        other => return Err(bad_input(format!("unknown authority {other:?}"))),
    };
    let timestamp_ms = parse_u64(
        &as_text(fields.take("timestampMs")?, "timestampMs")?,
        "timestampMs",
    )?;
    let valid_until_ms = parse_opt_u64(fields.take("validUntilMs")?, "validUntilMs")?;
    let contact = contact_from_input(fields.take("contact")?)?;
    let extensions = extension_map(fields.take("extensions")?, "extensions")?;
    let signing_seed_name = as_text(fields.take("signingSeed")?, "signingSeed")?;
    fields.finish()?;

    // Runner input contract (HARNESS.md 9.2): an incoherent
    // authority/signingSeed pairing is refused, never silently re-keyed.
    let coherent = matches!(
        (authority, signing_seed_name.as_str()),
        (Authority::Root, "root") | (Authority::RootRevoked, "revocation")
    );
    if !matches!(signing_seed_name.as_str(), "root" | "revocation") {
        return Err(bad_input(format!(
            "unknown signingSeed {signing_seed_name:?}"
        )));
    }
    if !coherent {
        return Err(OpError::Adapter {
            symbol: "adapter.signingKeyMismatch",
            message: format!(
                "signingSeed {signing_seed_name:?} is not the key applicable to \
                 authority {:?}",
                authority_text(authority)
            ),
        });
    }
    let signing_seed = match signing_seed_name.as_str() {
        "root" => root_seed,
        _ => revocation_seed,
    };

    // Identity derivation from the two seeds (implementation API only).
    let root_public = crypto::ed25519_public_key(&root_seed);
    let revocation_public = crypto::ed25519_public_key(&revocation_seed);
    let descriptor = AuthorityDescriptor {
        root_key: root_public,
        revocation_commitment: revocation_commitment(&revocation_public),
    };
    let did = descriptor.did();

    let body = RecordBody {
        id: did.clone(),
        timestamp_ms,
        authority,
        descriptor,
        revocation_key: match authority {
            Authority::Root => None,
            Authority::RootRevoked => Some(revocation_public),
        },
        valid_until_ms,
        contact,
        extensions,
    };

    // Typed authoring path: validation and deterministic encoding.
    let body_bytes = body
        .encode()
        .map_err(|e| OpError::Rejected { error: e.symbol() })?;
    let envelope = match followee::record::sign_record(&body, &signing_seed) {
        Ok(envelope) => envelope,
        Err(SignError::InvalidBody(e)) => {
            return Err(OpError::Rejected { error: e.symbol() });
        }
        Err(SignError::RecordTooLarge) => {
            return Err(OpError::Rejected {
                error: "recordTooLarge",
            });
        }
        Err(SignError::KeyMismatch) => {
            return Err(OpError::Adapter {
                symbol: "adapter.signingKeyMismatch",
                message: "implementation refused the signing key".into(),
            });
        }
    };

    // Self-check through the implementation's own full verification; a
    // failure here is the implementation's classification of its own
    // authored record.
    verify_record_for_target(did.as_str(), &envelope)
        .map_err(|e| OpError::Rejected { error: e.symbol() })?;

    let sig_structure = followee::sig_structure(&body_bytes);
    let signature = &envelope[envelope.len() - 64..];
    let body_digest = crypto::sha256(&body_bytes);

    Ok(json!({
        "did": did.as_str(),
        "recordBodyCborHex": encode_hex(&body_bytes),
        "recordBodyDigestHex": encode_hex(&body_digest),
        "sigStructureHex": encode_hex(&sig_structure),
        "signatureHex": encode_hex(signature),
        "envelopeHex": encode_hex(&envelope),
    }))
}

/// `verifyRecord` (HARNESS.md 9.3): full verification plus recipient-time
/// classification with the supplied `nowMs`, never the system clock.
pub fn verify_record_op(input: StrictValue) -> Result<Value, OpError> {
    let mut fields = Fields::new(input, "verifyRecord input")?;
    let target = as_text(fields.take("targetDid")?, "targetDid")?;
    let envelope = decode_hex(
        &as_text(fields.take("envelopeHex")?, "envelopeHex")?,
        "envelopeHex",
    )?;
    let now_ms = parse_u64(&as_text(fields.take("nowMs")?, "nowMs")?, "nowMs")?;
    fields.finish()?;

    let record = verify_record_for_target(&target, &envelope)
        .map_err(|e| OpError::Rejected { error: e.symbol() })?;

    let premature = time_status(record.timestamp_ms(), now_ms) == TimeStatus::Premature;
    let stale = freshness(record.body().valid_until_ms, now_ms) == Freshness::Stale;

    Ok(json!({
        "envelopeHex": encode_hex(record.envelope_bytes()),
        "recordBodyCborHex": encode_hex(record.payload_bytes()),
        "recordBodyDigestHex": encode_hex(record.body_digest()),
        "id": record.body().id.as_str(),
        "timestampMs": record.timestamp_ms().to_string(),
        "authority": authority_text(record.authority()),
        "validUntilMs": uint_or_null(record.body().valid_until_ms),
        "premature": premature,
        "stale": stale,
        "record": semantic_record_json(&record),
    }))
}
