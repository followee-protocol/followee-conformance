//! Reconstructs the provisional followee-rs fixture INPUTS described by the
//! pinned `fixtures/implementation/PROVENANCE.json` manifest (HARNESS.md
//! 14.3, Milestone 2).
//!
//! Every construction replicates, byte for byte, the corresponding case in
//! the pinned `tests/negative_b7.rs`, using:
//!
//! - the frozen implementation's public API for all signing, public-key
//!   encoding, and DID derivation (`crypto::ed25519_sign`,
//!   `record::encode_public_key`, `FolloweeDid::from_descriptor_bytes`);
//! - raw CBOR byte emitters ported from the pinned
//!   `tests/common/mod.rs` (which is itself deliberately independent of
//!   the crate's writer, "so fixture mutations are not produced by the
//!   code under test"); and
//! - published Appendix B values loaded from the pinned
//!   `fixtures/specification/appendix_b.json`.
//!
//! This tool constructs test INPUTS only.  It never verifies, selects,
//! classifies, or predicts an expected output; expected outcomes come from
//! the pinned provenance manifest, and results are discovered
//! independently by each adapter at campaign time.
//!
//! Output: a JSON object on stdout mapping case IDs to
//! `{"targetDid": ..., "envelopeHex": ...}` inputs.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use followee::crypto::ed25519_sign;
use followee::did::FolloweeDid;
use followee::record::encode_public_key;
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Published fixture values (pinned appendix_b.json of followee-rs)
// ---------------------------------------------------------------------------

fn fixtures() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../implementations/followee-rs/fixtures/specification/appendix_b.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("pinned fixture file"))
        .expect("fixture JSON parses")
}

fn fx_str(fx: &Value, name: &str) -> String {
    fx[name]
        .as_str()
        .unwrap_or_else(|| panic!("fixture field {name}"))
        .to_owned()
}

fn fx_bytes(fx: &Value, name: &str) -> Vec<u8> {
    let text = fx_str(fx, name);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn fx32(fx: &Value, name: &str) -> [u8; 32] {
    fx_bytes(fx, name).try_into().expect("32 bytes")
}

const B4_TIMESTAMP_MS: u64 = 1_785_589_200_123;

// ---------------------------------------------------------------------------
// Raw CBOR emitters, ported from the pinned tests/common/mod.rs
// ---------------------------------------------------------------------------

fn r_head(major: u8, arg: u64) -> Vec<u8> {
    let ib = major << 5;
    if arg < 24 {
        vec![ib | arg as u8]
    } else if arg < 0x100 {
        vec![ib | 24, arg as u8]
    } else if arg < 0x1_0000 {
        let mut v = vec![ib | 25];
        v.extend((arg as u16).to_be_bytes());
        v
    } else if arg < 0x1_0000_0000 {
        let mut v = vec![ib | 26];
        v.extend((arg as u32).to_be_bytes());
        v
    } else {
        let mut v = vec![ib | 27];
        v.extend(arg.to_be_bytes());
        v
    }
}

fn r_uint(v: u64) -> Vec<u8> {
    r_head(0, v)
}

fn r_nint_mag(magnitude: u64) -> Vec<u8> {
    r_head(1, magnitude)
}

fn r_bstr(bytes: &[u8]) -> Vec<u8> {
    let mut v = r_head(2, bytes.len() as u64);
    v.extend_from_slice(bytes);
    v
}

fn r_tstr(s: &str) -> Vec<u8> {
    let mut v = r_head(3, s.len() as u64);
    v.extend_from_slice(s.as_bytes());
    v
}

fn r_array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v = r_head(4, items.len() as u64);
    for item in items {
        v.extend_from_slice(item);
    }
    v
}

fn r_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut v = r_head(5, entries.len() as u64);
    for (k, val) in entries {
        v.extend_from_slice(k);
        v.extend_from_slice(val);
    }
    v
}

fn r_bool(v: bool) -> Vec<u8> {
    vec![if v { 0xf5 } else { 0xf4 }]
}

/// Assembles a complete tagged envelope with an arbitrary protected header,
/// signing the corresponding Sig_structure with the implementation's public
/// signing primitive (port of the pinned `seal_with_protected`).
fn seal_with_protected(protected: &[u8], payload: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    let sig_structure = r_array(&[
        r_tstr("Signature1"),
        r_bstr(protected),
        r_bstr(b"Followee/IdentityRecord/v1"),
        r_bstr(payload),
    ]);
    let signature = ed25519_sign(seed, &sig_structure);
    let mut envelope = r_head(6, 18);
    envelope.extend(r_head(4, 4));
    envelope.extend(r_bstr(protected));
    envelope.extend(r_head(5, 0));
    envelope.extend(r_bstr(payload));
    envelope.extend(r_bstr(&signature));
    envelope
}

fn seal(payload: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    seal_with_protected(&[0xa1, 0x01, 0x32], payload, seed)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn did_from_multihash(bytes: &[u8]) -> String {
    format!("did:flw:z{}", bs58::encode(bytes).into_string())
}

// ---------------------------------------------------------------------------
// Construction context
// ---------------------------------------------------------------------------

struct Ctx {
    fx: Value,
}

impl Ctx {
    fn alice_contact_raw(&self) -> Vec<u8> {
        let service = r_map(&[
            (r_uint(0), r_tstr("feed")),
            (r_uint(1), r_tstr("Feed")),
            (r_uint(2), r_tstr("https://alice.example/feed.xml")),
            (r_uint(3), r_tstr("application/atom+xml")),
            (r_uint(4), r_tstr("Writing")),
        ]);
        r_map(&[
            (r_uint(0), r_tstr("Alice Example")),
            (r_uint(1), r_tstr("Writer")),
            (r_uint(3), r_array(&[r_tstr("acct:alice@example.com")])),
            (r_uint(4), r_array(&[service])),
        ])
    }

    fn b4_raw_entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (r_uint(0), r_uint(1)),
            (r_uint(1), r_tstr(&fx_str(&self.fx, "followee_did"))),
            (r_uint(2), r_uint(B4_TIMESTAMP_MS)),
            (r_uint(3), r_uint(0)),
            (r_uint(4), fx_bytes(&self.fx, "authority_descriptor_cbor")),
            (r_uint(7), self.alice_contact_raw()),
        ]
    }

    fn b5_raw_entries(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (r_uint(0), r_uint(1)),
            (r_uint(1), r_tstr(&fx_str(&self.fx, "followee_did"))),
            (r_uint(2), r_uint(1_785_589_201_123)),
            (r_uint(3), r_uint(1)),
            (r_uint(4), fx_bytes(&self.fx, "authority_descriptor_cbor")),
            (r_uint(5), fx_bytes(&self.fx, "revocation_public_key_cbor")),
            (r_uint(7), self.alice_contact_raw()),
        ]
    }

    fn alice_did(&self) -> String {
        fx_str(&self.fx, "followee_did")
    }

    fn attacker_did(&self) -> String {
        fx_str(&self.fx, "attacker_did")
    }

    fn root_seed(&self) -> [u8; 32] {
        fx32(&self.fx, "root_seed")
    }

    fn revocation_seed(&self) -> [u8; 32] {
        fx32(&self.fx, "revocation_seed")
    }

    fn body_with_contact(&self, contact: Vec<u8>) -> Vec<u8> {
        let mut entries = self.b4_raw_entries();
        entries[5].1 = contact;
        r_map(&entries)
    }

    /// Internally consistent B.7 item 17 record: the body id and target
    /// derive from the mutated descriptor via the implementation's public
    /// `FolloweeDid::from_descriptor_bytes`.
    fn item17_case(&self, descriptor: Vec<u8>) -> (String, Vec<u8>) {
        let did = FolloweeDid::from_descriptor_bytes(&descriptor);
        let entries = vec![
            (r_uint(0), r_uint(1)),
            (r_uint(1), r_tstr(did.as_str())),
            (r_uint(2), r_uint(B4_TIMESTAMP_MS)),
            (r_uint(3), r_uint(0)),
            (r_uint(4), descriptor),
            (r_uint(7), self.alice_contact_raw()),
        ];
        let envelope = seal(&r_map(&entries), &self.root_seed());
        (did.as_str().to_owned(), envelope)
    }
}

fn main() {
    let ctx = Ctx { fx: fixtures() };
    let fx = &ctx.fx;
    let mut out: BTreeMap<String, Value> = BTreeMap::new();
    let mut emit = |id: &str, target: String, envelope: Vec<u8>| {
        let mut entry = Map::new();
        entry.insert("targetDid".into(), Value::String(target));
        entry.insert("envelopeHex".into(), Value::String(hex(&envelope)));
        out.insert(id.to_owned(), Value::Object(entry));
    };

    // -- item 1b/1c: mutated body id, re-signed with the legitimate key --
    let mutated_id_envelope = {
        let mut entries = ctx.b4_raw_entries();
        entries[1].1 = r_tstr(&ctx.attacker_did());
        seal(&r_map(&entries), &ctx.root_seed())
    };
    emit(
        "b7-1b-mutated-id-original-target",
        ctx.alice_did(),
        mutated_id_envelope.clone(),
    );
    emit(
        "b7-1c-mutated-id-mutated-target",
        ctx.attacker_did(),
        mutated_id_envelope,
    );

    // -- item 2: target-DID multihash constructions (envelope unchanged) --
    let b4_envelope = fx_bytes(fx, "root_record_envelope");
    let digest = fx32(fx, "descriptor_digest");
    let did_cases: [(&str, Vec<u8>); 5] = [
        ("b7-2a-foreign-code", {
            let mut mh = vec![0x16, 0x20];
            mh.extend_from_slice(&digest);
            mh
        }),
        ("b7-2b-foreign-length", {
            let mut mh = vec![0x12, 0x1f];
            mh.extend_from_slice(&digest[..31]);
            mh
        }),
        ("b7-2c-non-minimal-varint", {
            let mut mh = vec![0x92, 0x00, 0x20];
            mh.extend_from_slice(&digest);
            mh
        }),
        ("b7-2d-length-disagreement", {
            let mut mh = vec![0x12, 0x20];
            mh.extend_from_slice(&digest[..31]);
            mh
        }),
        ("b7-2e-trailing-bytes", {
            let mut mh = vec![0x12, 0x20];
            mh.extend_from_slice(&digest);
            mh.push(0x00);
            mh
        }),
    ];
    for (id, mh) in did_cases {
        emit(id, did_from_multihash(&mh), b4_envelope.clone());
    }

    // -- item 3: deprecated alg -8, re-signed over the mutated protected --
    let payload = r_map(&ctx.b4_raw_entries());
    emit(
        "b7-3-alg-minus-8",
        ctx.alice_did(),
        seal_with_protected(&[0xa1, 0x01, 0x27], &payload, &ctx.root_seed()),
    );

    // -- items 7-9: deterministic-CBOR mutations, re-signed --
    {
        let mut entries = ctx.b4_raw_entries();
        entries[0].1 = vec![0x18, 0x01];
        emit(
            "b7-7-non-minimal-int",
            ctx.alice_did(),
            seal(&r_map(&entries), &ctx.root_seed()),
        );
    }
    {
        let mut entries = ctx.b4_raw_entries();
        entries.swap(0, 1);
        emit(
            "b7-8-reordered-keys",
            ctx.alice_did(),
            seal(&r_map(&entries), &ctx.root_seed()),
        );
    }
    {
        let mut entries = ctx.b4_raw_entries();
        entries.insert(1, (r_uint(0), r_uint(1)));
        emit(
            "b7-9-duplicate-key",
            ctx.alice_did(),
            seal(&r_map(&entries), &ctx.root_seed()),
        );
    }

    // -- items 10-12: authority-conditional label 5 mutations --
    {
        let mut entries = ctx.b4_raw_entries();
        entries.insert(5, (r_uint(5), fx_bytes(fx, "revocation_public_key_cbor")));
        emit(
            "b7-10-root-with-label-5",
            ctx.alice_did(),
            seal(&r_map(&entries), &ctx.root_seed()),
        );
    }
    {
        let entries: Vec<_> = ctx
            .b5_raw_entries()
            .into_iter()
            .filter(|(k, _)| k != &r_uint(5))
            .collect();
        emit(
            "b7-11-revoked-missing-label-5",
            ctx.alice_did(),
            seal(&r_map(&entries), &ctx.revocation_seed()),
        );
    }
    {
        let attacker_rev_cbor = encode_public_key(&fx32(fx, "attacker_revocation_public_key"));
        let mut entries = ctx.b5_raw_entries();
        let pos = entries
            .iter()
            .position(|(k, _)| k == &r_uint(5))
            .expect("label 5 present");
        entries[pos].1 = attacker_rev_cbor;
        emit(
            "b7-12-wrong-revealed-key",
            ctx.alice_did(),
            seal(&r_map(&entries), &fx32(fx, "attacker_revocation_seed")),
        );
    }

    // -- item 15: validUntil before timestamp, re-signed --
    {
        let mut entries = ctx.b4_raw_entries();
        entries.insert(5, (r_uint(6), r_uint(B4_TIMESTAMP_MS - 1)));
        emit(
            "b7-15-valid-until-before-timestamp",
            ctx.alice_did(),
            seal(&r_map(&entries), &ctx.root_seed()),
        );
    }

    // -- item 16: aggregate limits, each isolated, re-signed --
    {
        let big = r_bstr(&vec![0x41u8; 16 * 1024]);
        let ext = r_map(&[(r_tstr("https://example.com/x"), big)]);
        let mut entries = ctx.b4_raw_entries();
        entries.push((r_uint(8), ext));
        emit(
            "b7-16a-envelope-over-16kib",
            ctx.alice_did(),
            seal(&r_map(&entries), &ctx.root_seed()),
        );
    }
    {
        let big = r_bstr(&vec![0x41u8; 12 * 1024 + 64]);
        let contact = r_map(&[(r_uint(6), r_map(&[(r_tstr("https://example.com/x"), big)]))]);
        emit(
            "b7-16b-contact-over-12kib",
            ctx.alice_did(),
            seal(&ctx.body_with_contact(contact), &ctx.root_seed()),
        );
    }
    let contact_variants: Vec<(&str, Vec<u8>)> = vec![
        (
            "b7-16c-display-name",
            r_map(&[(r_uint(0), r_tstr(&"a".repeat(257)))]),
        ),
        (
            "b7-16c-summary",
            r_map(&[(r_uint(1), r_tstr(&"s".repeat(2049)))]),
        ),
        ("b7-16c-uri", {
            let long_uri = format!("https://example.com/{}", "p".repeat(2048));
            r_map(&[(r_uint(2), r_tstr(&long_uri))])
        }),
        ("b7-16c-also-known-as-count", {
            let entries: Vec<_> = (0..33)
                .map(|i| r_tstr(&format!("https://example.com/{i}")))
                .collect();
            r_map(&[(r_uint(3), r_array(&entries))])
        }),
        ("b7-16c-service-count", {
            let service = |i: usize| {
                r_map(&[
                    (r_uint(0), r_tstr(&format!("s{i}"))),
                    (r_uint(1), r_tstr("Website")),
                    (r_uint(2), r_tstr(&format!("https://example.com/{i}"))),
                ])
            };
            let services: Vec<_> = (0..65).map(service).collect();
            r_map(&[(r_uint(4), r_array(&services))])
        }),
        ("b7-16c-service-id-length", {
            r_map(&[(
                r_uint(4),
                r_array(&[r_map(&[
                    (r_uint(0), r_tstr(&"i".repeat(257))),
                    (r_uint(1), r_tstr("Website")),
                    (r_uint(2), r_tstr("https://example.com/")),
                ])]),
            )])
        }),
        ("b7-16c-extension-key-length", {
            let key = format!("https://example.com/{}", "k".repeat(240));
            r_map(&[(r_uint(6), r_map(&[(r_tstr(&key), r_uint(1))]))])
        }),
        ("b7-16c-nesting-depth", {
            let mut value = r_uint(1);
            for _ in 0..6 {
                value = r_array(&[value]);
            }
            r_map(&[(r_uint(6), r_map(&[(r_tstr("https://e.com/x"), value)]))])
        }),
        ("b7-16c-member-count", {
            let elements: Vec<_> = (0..250).map(|_| r_uint(0)).collect();
            r_map(&[(
                r_uint(6),
                r_map(&[(r_tstr("https://e.com/x"), r_array(&elements))]),
            )])
        }),
    ];
    for (id, contact) in contact_variants {
        emit(
            id,
            ctx.alice_did(),
            seal(&ctx.body_with_contact(contact), &ctx.root_seed()),
        );
    }

    // -- item 17: internally consistent Boolean-label records --
    let root_key_map = || {
        r_map(&[
            (r_uint(0), r_nint_mag(18)),
            (r_uint(1), r_bstr(&fx_bytes(fx, "root_public_key"))),
        ])
    };
    let commitment = fx_bytes(fx, "revocation_commitment");
    let item17: Vec<(&str, Vec<u8>)> = vec![
        (
            "b7-17a-descriptor-label0-false",
            r_map(&[
                (r_uint(1), root_key_map()),
                (r_uint(2), r_bstr(&commitment)),
                (r_bool(false), r_uint(1)),
            ]),
        ),
        (
            "b7-17b-descriptor-label1-true",
            r_map(&[
                (r_uint(0), r_uint(1)),
                (r_uint(2), r_bstr(&commitment)),
                (r_bool(true), root_key_map()),
            ]),
        ),
        (
            "b7-17c-public-key-label0-false",
            r_map(&[
                (r_uint(0), r_uint(1)),
                (
                    r_uint(1),
                    r_map(&[
                        (r_uint(1), r_bstr(&fx_bytes(fx, "root_public_key"))),
                        (r_bool(false), r_nint_mag(18)),
                    ]),
                ),
                (r_uint(2), r_bstr(&commitment)),
            ]),
        ),
        (
            "b7-17d-public-key-label1-true",
            r_map(&[
                (r_uint(0), r_uint(1)),
                (
                    r_uint(1),
                    r_map(&[
                        (r_uint(0), r_nint_mag(18)),
                        (r_bool(true), r_bstr(&fx_bytes(fx, "root_public_key"))),
                    ]),
                ),
                (r_uint(2), r_bstr(&commitment)),
            ]),
        ),
    ];
    for (id, descriptor) in item17 {
        let (target, envelope) = ctx.item17_case(descriptor);
        emit(id, target, envelope);
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "_provenance": {
                "constructedFrom": [
                    "implementations/followee-rs/fixtures/implementation/PROVENANCE.json",
                    "implementations/followee-rs/tests/negative_b7.rs",
                    "implementations/followee-rs/tests/common/mod.rs",
                    "implementations/followee-rs/fixtures/specification/appendix_b.json",
                ],
                "producedBy": "followee-rs public API via tools/fixture-builder",
            },
            "inputs": out,
        }))
        .expect("serializable")
    );
}
