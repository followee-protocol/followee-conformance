//! Operation tests driven by the committed specification-status corpus:
//! every published expected-result member is asserted per operation
//! (HARNESS.md Milestone 1 acceptance: every result field is compared and
//! covered by an adapter test).

use std::path::PathBuf;

use followee_adapter_rust::{handle_line, Identity};
use serde_json::{json, Value};

fn cases_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../cases/specification")
}

fn load_case(case_id: &str) -> Value {
    let path = cases_dir().join(format!("{case_id}.json"));
    serde_json::from_str(&std::fs::read_to_string(&path).expect("case file")).expect("case JSON")
}

fn identity() -> Identity {
    Identity::from_build()
}

fn respond_to(case: &Value) -> Value {
    let request = json!({
        "runnerProtocol": "1",
        "caseId": case["id"],
        "operation": case["operation"],
        "input": case["input"],
    });
    let line = handle_line(&identity(), request.to_string().as_bytes(), false);
    serde_json::from_str(&line).expect("adapter output is JSON")
}

fn assert_expected_result(case_id: &str) -> Value {
    let case = load_case(case_id);
    let response = respond_to(&case);
    assert_eq!(response["status"], "accepted", "{case_id}: {response}");
    let expected = case["expectedResult"].as_object().expect("expectedResult");
    for (member, value) in expected {
        assert_eq!(
            &response["result"][member], value,
            "{case_id}: member {member}"
        );
    }
    response["result"].clone()
}

#[test]
fn derive_identity_reproduces_appendix_b2_b3_exactly() {
    let result = assert_expected_result("derive-identity-alice");
    assert_eq!(result.as_object().unwrap().len(), 7);
}

#[test]
fn derive_identity_attacker_keys() {
    assert_expected_result("derive-identity-attacker");
}

#[test]
fn author_record_reproduces_appendix_b4_exactly() {
    let result = assert_expected_result("author-b4-root");
    assert_eq!(result.as_object().unwrap().len(), 6);
}

#[test]
fn author_record_reproduces_appendix_b5_exactly() {
    assert_expected_result("author-b5-root-revoked");
}

#[test]
fn author_signature_from_primitive_matches_the_sealed_envelope() {
    // signatureHex is produced by the implementation's public Ed25519
    // signing primitive over the Sig_structure, not by slicing the
    // envelope; deterministic Ed25519 makes both byte-identical, and the
    // published B.4/B.5 vectors pin the exact value independently.
    for case_id in ["author-b4-root", "author-b5-root-revoked"] {
        let case = load_case(case_id);
        let response = respond_to(&case);
        assert_eq!(response["status"], "accepted", "{case_id}");
        let result = &response["result"];
        let signature = result["signatureHex"].as_str().unwrap();
        let envelope = result["envelopeHex"].as_str().unwrap();
        assert_eq!(signature.len(), 128, "{case_id}: 64-byte signature");
        assert!(
            envelope.ends_with(signature),
            "{case_id}: primitive signature equals the envelope's"
        );
        assert_eq!(
            signature,
            case["expectedResult"]["signatureHex"].as_str().unwrap(),
            "{case_id}: published signature"
        );
    }
}

#[test]
fn author_record_reproduces_appendix_b6_digests() {
    assert_expected_result("author-b6-alice-a");
    assert_expected_result("author-b6-alice-b");
}

#[test]
fn verify_record_reproduces_appendix_b4_exactly() {
    let result = assert_expected_result("verify-b4-root");
    assert_eq!(result.as_object().unwrap().len(), 10);
    assert_eq!(
        result["record"]["contact"]["services"][0]["label"],
        "Writing"
    );
}

#[test]
fn verify_record_reproduces_appendix_b5_exactly() {
    let result = assert_expected_result("verify-b5-root-revoked");
    assert!(result["record"]["revocationKey"].is_object());
}

#[test]
fn verify_record_premature_classification() {
    assert_expected_result("verify-b4-premature");
    assert_expected_result("verify-b4-premature-boundary");
    assert_expected_result("verify-b4-now-max-uint64");
}

#[test]
fn descriptor_substitution_rejected_with_exact_error() {
    let case = load_case("verify-b8-descriptor-substitution");
    let response = respond_to(&case);
    assert_eq!(response["status"], "rejected");
    assert_eq!(response["error"], case["expected"]["error"]);
}

#[test]
fn invalid_did_targets_rejected_exactly() {
    for case_id in [
        "verify-did-percent-encoded",
        "verify-did-uppercase-prefix",
        "verify-did-invalid-alphabet",
        "verify-did-missing-multibase-prefix",
        "verify-did-empty",
    ] {
        let response = respond_to(&load_case(case_id));
        assert_eq!(response["status"], "rejected", "{case_id}");
        assert_eq!(response["error"], "invalidDid", "{case_id}");
    }
}

#[test]
fn all_envelope_mutants_rejected() {
    let mut checked = 0;
    for entry in std::fs::read_dir(cases_dir()).expect("cases dir") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with("verify-b7-") {
            continue;
        }
        let case: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        if case["expected"]["outcome"] != "rejected" {
            continue;
        }
        let response = respond_to(&case);
        assert_eq!(response["status"], "rejected", "{name}: {response}");
        checked += 1;
    }
    assert!(checked >= 15, "expected all B.7 mutants, saw {checked}");
}

#[test]
fn relative_uri_authoring_rejected() {
    let response = respond_to(&load_case("author-uri-relative-path"));
    assert_eq!(response["status"], "rejected");
}

#[test]
fn incoherent_signing_seed_is_adapter_error_not_rejection() {
    let mut case = load_case("author-b4-root");
    case["input"]["signingSeed"] = json!("revocation");
    let response = respond_to(&case);
    assert_eq!(response["status"], "adapterError");
    assert_eq!(response["error"], "adapter.signingKeyMismatch");
}

#[test]
fn input_contract_violations_are_adapter_errors() {
    let base = load_case("derive-identity-alice");
    let seed = base["input"]["rootSeedHex"].as_str().unwrap().to_owned();
    let mutations: Vec<Value> = vec![
        json!({"rootSeedHex": seed.to_uppercase(),
               "revocationSeedHex": base["input"]["revocationSeedHex"]}),
        json!({"rootSeedHex": &seed[..62],
               "revocationSeedHex": base["input"]["revocationSeedHex"]}),
        json!({"rootSeedHex": seed.clone(),
               "revocationSeedHex": base["input"]["revocationSeedHex"],
               "extra": true}),
        json!({"rootSeedHex": seed.clone()}),
    ];
    for input in mutations {
        let mut case = base.clone();
        case["input"] = input;
        let response = respond_to(&case);
        assert_eq!(response["status"], "adapterError", "{response}");
        assert_eq!(response["error"], "adapter.invalidInput");
    }
}

#[test]
fn non_canonical_decimal_is_adapter_error() {
    let mut case = load_case("verify-b4-root");
    case["input"]["nowMs"] = json!("01785589200123");
    let response = respond_to(&case);
    assert_eq!(response["status"], "adapterError");
    assert_eq!(response["error"], "adapter.invalidInput");
}

#[test]
fn now_ms_beyond_uint64_is_adapter_error() {
    let mut case = load_case("verify-b4-root");
    case["input"]["nowMs"] = json!("18446744073709551616");
    let response = respond_to(&case);
    assert_eq!(response["status"], "adapterError");
}

// ---------------------------------------------------------------------------
// Milestone 2 operations, driven by the committed corpora.
// ---------------------------------------------------------------------------

fn sweep_expected_results(prefix: &str, minimum: usize) -> usize {
    let mut checked = 0;
    for entry in std::fs::read_dir(cases_dir()).expect("cases dir") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with(prefix) || !name.ends_with(".json") {
            continue;
        }
        let case: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let response = respond_to(&case);
        if case["expected"]["outcome"] == "rejected" {
            assert_eq!(response["status"], "rejected", "{name}: {response}");
            if case["expected"]["errorAssertion"] == "exact" {
                assert_eq!(response["error"], case["expected"]["error"], "{name}");
            }
        } else {
            assert_eq!(response["status"], "accepted", "{name}: {response}");
            for (member, value) in case["expectedResult"].as_object().unwrap() {
                assert_eq!(&response["result"][member], value, "{name}: {member}");
            }
        }
        checked += 1;
    }
    assert!(checked >= minimum, "{prefix}: only {checked} cases swept");
    checked
}

#[test]
fn strict_ed25519_specification_cases() {
    sweep_expected_results("strict-", 11);
}

#[test]
fn next_timestamp_specification_cases() {
    sweep_expected_results("next-", 9);
}

#[test]
fn select_current_specification_cases() {
    sweep_expected_results("select-", 13);
}

#[test]
fn implementation_corpus_cases() {
    // Provisional followee-rs fixture inputs; expectations come from the
    // pinned provenance manifest and are re-discovered here through the
    // adapter's public path.
    let impl_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../cases/implementation");
    let mut checked = 0;
    for entry in std::fs::read_dir(&impl_dir).expect("implementation cases") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.starts_with("impl-") || !name.ends_with(".json") {
            continue;
        }
        let case: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let response = respond_to(&case);
        if case["expected"]["outcome"] == "rejected" {
            assert_eq!(response["status"], "rejected", "{name}: {response}");
            if case["expected"]["errorAssertion"] == "exact" {
                assert_eq!(response["error"], case["expected"]["error"], "{name}");
            }
        } else {
            assert_eq!(response["status"], "accepted", "{name}: {response}");
            if let Some(expected) = case["expectedResult"].as_object() {
                for (member, value) in expected {
                    assert_eq!(&response["result"][member], value, "{name}: {member}");
                }
            }
        }
        checked += 1;
    }
    assert!(checked >= 49, "only {checked} implementation cases swept");
}

#[test]
fn select_result_fields_are_complete() {
    let response = respond_to(&load_case("select-root-only"));
    let result = response["result"].as_object().unwrap();
    let mut members: Vec<_> = result.keys().filter(|k| *k != "diagnostic").collect();
    members.sort();
    assert_eq!(members, ["authorityState", "winnerRecordBodyDigestHex"]);
}

// ---------------------------------------------------------------------------
// validateCbor: corpus sweep, runner limit domain, and record-path parity.
// ---------------------------------------------------------------------------

#[test]
fn validate_cbor_specification_cases() {
    sweep_expected_results("validate-cbor-", 38);
}

#[test]
fn validate_cbor_limits_domain_is_runner_contract() {
    for (member, value) in [("maxDepth", "9"), ("maxMembers", "257")] {
        let mut case = load_case("validate-cbor-accept-uint-zero");
        case["input"][member] = json!(value);
        let response = respond_to(&case);
        assert_eq!(response["status"], "adapterError", "{member}");
        assert_eq!(response["error"], "adapter.invalidInput");
    }
}

#[test]
fn validate_cbor_parity_with_record_path() {
    // The primitive must exercise the same production validator as
    // full-record verification: identical payload bytes must classify
    // identically through both operations, and acceptance parity holds for
    // the published Appendix B.4 body.  A substitute validator in either
    // path would break this.
    let pairs: [(&str, &str, Option<&str>); 2] = [
        (
            "validate-cbor-accept-b4-record-body",
            "verify-b4-root",
            None,
        ),
        (
            "validate-cbor-reordered-b4-body",
            "verify-b7-08-reordered-body-keys",
            Some("nonDeterministicCbor"),
        ),
    ];
    for (cbor_case_id, verify_case_id, symbol) in pairs {
        let cbor_case = load_case(cbor_case_id);
        let verify_case = load_case(verify_case_id);
        let payload = cbor_case["input"]["cborHex"].as_str().unwrap();
        let envelope = verify_case["input"]["envelopeHex"].as_str().unwrap();
        assert!(
            envelope.contains(payload),
            "{cbor_case_id}: payload bytes embedded in the envelope"
        );
        let cbor_response = respond_to(&cbor_case);
        let verify_response = respond_to(&verify_case);
        match symbol {
            None => {
                assert_eq!(cbor_response["status"], "accepted");
                assert_eq!(verify_response["status"], "accepted");
            }
            Some(symbol) => {
                assert_eq!(cbor_response["error"], symbol);
                assert_eq!(verify_response["error"], symbol);
            }
        }
    }
}

#[test]
fn validate_cbor_parity_with_imported_duplicate_key_fixture() {
    let cbor_case = load_case("validate-cbor-duplicate-label-b4-body");
    let impl_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../cases/implementation/impl-b7-9-duplicate-key.json");
    let impl_case: Value =
        serde_json::from_str(&std::fs::read_to_string(&impl_path).unwrap()).unwrap();
    let payload = cbor_case["input"]["cborHex"].as_str().unwrap();
    let envelope = impl_case["input"]["envelopeHex"].as_str().unwrap();
    assert!(
        envelope.contains(payload),
        "duplicate-label body embedded in the imported envelope"
    );
    assert_eq!(respond_to(&cbor_case)["error"], "nonDeterministicCbor");
    assert_eq!(respond_to(&impl_case)["error"], "nonDeterministicCbor");
}
