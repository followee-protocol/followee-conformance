//! Neutral runner-protocol v1 adapter core for the pinned `followee-rs`
//! implementation.
//!
//! Milestone 1 supports `hello`, `deriveIdentity`, `authorRecord`, and
//! `verifyRecord` (HARNESS.md Sections 8, 9, and 20).  This crate contains
//! no Followee parsing, encoding, cryptography, verification, ordering, or
//! selection logic; every protocol decision is delegated to the frozen
//! implementation's public API through the thin mappings in [`ops`].

#![forbid(unsafe_code)]

pub mod ops;

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// Runner protocol version implemented by this adapter.
pub const RUNNER_PROTOCOL: &str = "1";

/// Maximum runner line length in each direction (HARNESS.md 7.1).
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Handshake identity, fixed at build time from the verified checkouts.
pub struct Identity {
    pub adapter: &'static str,
    pub adapter_version: &'static str,
    pub implementation_repository: &'static str,
    pub implementation_commit: &'static str,
    pub specification_commit: &'static str,
}

impl Identity {
    /// The identity embedded by `build.rs` from the submodule checkouts.
    pub fn from_build() -> Self {
        Identity {
            adapter: "followee-rust",
            adapter_version: "1",
            implementation_repository: "https://github.com/followee-protocol/followee-rs",
            implementation_commit: env!("FOLLOWEE_IMPL_COMMIT"),
            specification_commit: env!("FOLLOWEE_SPEC_COMMIT"),
        }
    }
}

/// JSON value restricted to the runner profile (HARNESS.md 7.2): no bare
/// numbers and no duplicate object member names.
#[derive(Debug, Clone, PartialEq)]
pub enum StrictValue {
    Null,
    Bool(bool),
    Text(String),
    Array(Vec<StrictValue>),
    Object(Vec<(String, StrictValue)>),
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a runner-profile JSON value (no bare numbers)")
    }

    fn visit_unit<E: de::Error>(self) -> Result<StrictValue, E> {
        Ok(StrictValue::Null)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<StrictValue, E> {
        Ok(StrictValue::Bool(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<StrictValue, E> {
        Ok(StrictValue::Text(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<StrictValue, E> {
        Ok(StrictValue::Text(v))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<StrictValue, E> {
        Err(E::custom(
            "bare JSON numbers are forbidden; use decimal strings",
        ))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<StrictValue, E> {
        Err(E::custom(
            "bare JSON numbers are forbidden; use decimal strings",
        ))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<StrictValue, E> {
        Err(E::custom("floating-point numbers are forbidden"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StrictValue, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<StrictValue>()? {
            items.push(item);
        }
        Ok(StrictValue::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictValue, A::Error> {
        let mut entries: Vec<(String, StrictValue)> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if entries.iter().any(|(k, _)| *k == key) {
                return Err(de::Error::custom(format!(
                    "duplicate object member {key:?}"
                )));
            }
            let value = map.next_value::<StrictValue>()?;
            entries.push((key, value));
        }
        Ok(StrictValue::Object(entries))
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictValueVisitor)
    }
}

/// A parsed runner request envelope (HARNESS.md 7.3).
#[derive(Debug)]
pub struct Request {
    pub runner_protocol: String,
    pub case_id: String,
    pub operation: String,
    pub input: StrictValue,
}

struct RequestVisitor;

impl<'de> Visitor<'de> for RequestVisitor {
    type Value = Request;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a runner request object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Request, A::Error> {
        let mut runner_protocol: Option<String> = None;
        let mut case_id: Option<String> = None;
        let mut operation: Option<String> = None;
        let mut input: Option<StrictValue> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "runnerProtocol" => {
                    if runner_protocol.is_some() {
                        return Err(de::Error::duplicate_field("runnerProtocol"));
                    }
                    runner_protocol = Some(map.next_value()?);
                }
                "caseId" => {
                    if case_id.is_some() {
                        return Err(de::Error::duplicate_field("caseId"));
                    }
                    case_id = Some(map.next_value()?);
                }
                "operation" => {
                    if operation.is_some() {
                        return Err(de::Error::duplicate_field("operation"));
                    }
                    operation = Some(map.next_value()?);
                }
                "input" => {
                    if input.is_some() {
                        return Err(de::Error::duplicate_field("input"));
                    }
                    input = Some(map.next_value()?);
                }
                other => {
                    return Err(de::Error::custom(format!(
                        "unknown object member {other:?}"
                    )));
                }
            }
        }
        Ok(Request {
            runner_protocol: runner_protocol
                .ok_or_else(|| de::Error::missing_field("runnerProtocol"))?,
            case_id: case_id.ok_or_else(|| de::Error::missing_field("caseId"))?,
            operation: operation.ok_or_else(|| de::Error::missing_field("operation"))?,
            input: input.ok_or_else(|| de::Error::missing_field("input"))?,
        })
    }
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(RequestVisitor)
    }
}

fn adapter_error(runner_protocol: &str, case_id: &str, symbol: &str, message: &str) -> String {
    json!({
        "runnerProtocol": runner_protocol,
        "caseId": case_id,
        "status": "adapterError",
        "error": symbol,
        "message": message,
    })
    .to_string()
}

fn hello_result(identity: &Identity) -> Value {
    let mut result = Map::new();
    result.insert("adapter".into(), identity.adapter.into());
    result.insert("adapterVersion".into(), identity.adapter_version.into());
    result.insert(
        "implementationRepository".into(),
        identity.implementation_repository.into(),
    );
    result.insert(
        "implementationCommit".into(),
        identity.implementation_commit.into(),
    );
    result.insert(
        "specificationCommit".into(),
        identity.specification_commit.into(),
    );
    result.insert("runnerProtocols".into(), json!([RUNNER_PROTOCOL]));
    result.insert(
        "operations".into(),
        json!(["hello", "deriveIdentity", "authorRecord", "verifyRecord"]),
    );
    Value::Object(result)
}

fn operation_response(case_id: &str, outcome: Result<Value, ops::OpError>) -> String {
    match outcome {
        Ok(result) => json!({
            "runnerProtocol": RUNNER_PROTOCOL,
            "caseId": case_id,
            "status": "accepted",
            "result": result,
        })
        .to_string(),
        Err(ops::OpError::Rejected { error }) => json!({
            "runnerProtocol": RUNNER_PROTOCOL,
            "caseId": case_id,
            "status": "rejected",
            "error": error,
        })
        .to_string(),
        Err(ops::OpError::Adapter { symbol, message }) => {
            adapter_error(RUNNER_PROTOCOL, case_id, symbol, &message)
        }
    }
}

/// Handle one raw request line (without its newline) and return the
/// response line (without a newline).
///
/// `truncated` marks a line that exceeded [`MAX_LINE_BYTES`]; the excess
/// bytes were discarded by the reader.
pub fn handle_line(identity: &Identity, raw: &[u8], truncated: bool) -> String {
    if truncated {
        return adapter_error(
            RUNNER_PROTOCOL,
            "unknown",
            "adapter.lineTooLong",
            "request line exceeded the 1 MiB runner limit",
        );
    }
    if raw.starts_with(b"\xef\xbb\xbf") {
        return adapter_error(
            RUNNER_PROTOCOL,
            "unknown",
            "adapter.malformedRequest",
            "request line begins with a UTF-8 byte-order mark",
        );
    }
    if raw.iter().all(|b| b.is_ascii_whitespace()) {
        return adapter_error(
            RUNNER_PROTOCOL,
            "unknown",
            "adapter.malformedRequest",
            "blank protocol line",
        );
    }
    let text = match std::str::from_utf8(raw) {
        Ok(text) => text,
        Err(e) => {
            return adapter_error(
                RUNNER_PROTOCOL,
                "unknown",
                "adapter.malformedRequest",
                &format!("request line is not UTF-8: {e}"),
            );
        }
    };
    let request: Request = match serde_json::from_str(text) {
        Ok(request) => request,
        Err(e) => {
            return adapter_error(
                RUNNER_PROTOCOL,
                "unknown",
                "adapter.malformedRequest",
                &format!("request does not satisfy the runner JSON profile: {e}"),
            );
        }
    };
    // Responses repeat the request's runnerProtocol and caseId exactly
    // (HARNESS.md 7.3), even on adapter errors.
    if request.case_id.is_empty() {
        return adapter_error(
            request.runner_protocol.as_str(),
            "unknown",
            "adapter.malformedRequest",
            "caseId must be a nonempty string",
        );
    }
    if request.runner_protocol != RUNNER_PROTOCOL {
        return adapter_error(
            request.runner_protocol.as_str(),
            request.case_id.as_str(),
            "adapter.unsupportedProtocol",
            &format!(
                "runner protocol {:?} is not supported; this adapter speaks {:?}",
                request.runner_protocol, RUNNER_PROTOCOL
            ),
        );
    }
    match request.operation.as_str() {
        "hello" => {
            if !matches!(&request.input, StrictValue::Object(entries) if entries.is_empty()) {
                return adapter_error(
                    RUNNER_PROTOCOL,
                    request.case_id.as_str(),
                    "adapter.invalidInput",
                    "hello takes an empty input object",
                );
            }
            json!({
                "runnerProtocol": RUNNER_PROTOCOL,
                "caseId": request.case_id,
                "status": "accepted",
                "result": hello_result(identity),
            })
            .to_string()
        }
        "deriveIdentity" => {
            operation_response(&request.case_id, ops::derive_identity(request.input))
        }
        "authorRecord" => operation_response(&request.case_id, ops::author_record(request.input)),
        "verifyRecord" => {
            operation_response(&request.case_id, ops::verify_record_op(request.input))
        }
        other => adapter_error(
            RUNNER_PROTOCOL,
            request.case_id.as_str(),
            "adapter.unsupportedOperation",
            &format!("operation {other:?} is not supported at Milestone 1"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            adapter: "followee-rust",
            adapter_version: "1",
            implementation_repository: "https://github.com/followee-protocol/followee-rs",
            implementation_commit: "774acb7578795cf6d58f77b76b16ef010114ebd6",
            specification_commit: "abc9a55d90f1026e6509207abda73e5dc6d14241",
        }
    }

    fn respond(raw: &str) -> Value {
        serde_json::from_str(&handle_line(&identity(), raw.as_bytes(), false))
            .expect("adapter output is JSON")
    }

    #[test]
    fn hello_is_accepted_with_full_identity() {
        let r = respond(
            r#"{"runnerProtocol":"1","caseId":"handshake","operation":"hello","input":{}}"#,
        );
        assert_eq!(r["runnerProtocol"], "1");
        assert_eq!(r["caseId"], "handshake");
        assert_eq!(r["status"], "accepted");
        let result = &r["result"];
        assert_eq!(result["adapter"], "followee-rust");
        assert_eq!(
            result["implementationCommit"],
            "774acb7578795cf6d58f77b76b16ef010114ebd6"
        );
        assert_eq!(
            result["specificationCommit"],
            "abc9a55d90f1026e6509207abda73e5dc6d14241"
        );
        assert_eq!(result["runnerProtocols"], json!(["1"]));
        assert_eq!(
            result["operations"],
            json!(["hello", "deriveIdentity", "authorRecord", "verifyRecord"])
        );
    }

    #[test]
    fn build_identity_commits_are_pinned_shape() {
        let id = Identity::from_build();
        for commit in [id.implementation_commit, id.specification_commit] {
            assert_eq!(commit.len(), 40);
            assert!(commit
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn unknown_member_is_rejected() {
        let r = respond(
            r#"{"runnerProtocol":"1","caseId":"x","operation":"hello","input":{},"extra":true}"#,
        );
        assert_eq!(r["status"], "adapterError");
        assert_eq!(r["error"], "adapter.malformedRequest");
    }

    #[test]
    fn duplicate_member_is_rejected() {
        let r = respond(
            r#"{"runnerProtocol":"1","caseId":"x","caseId":"y","operation":"hello","input":{}}"#,
        );
        assert_eq!(r["status"], "adapterError");
        assert_eq!(r["error"], "adapter.malformedRequest");
    }

    #[test]
    fn duplicate_member_inside_input_is_rejected() {
        let r = respond(
            r#"{"runnerProtocol":"1","caseId":"x","operation":"hello","input":{"a":true,"a":false}}"#,
        );
        assert_eq!(r["status"], "adapterError");
        assert_eq!(r["error"], "adapter.malformedRequest");
    }

    #[test]
    fn bare_numbers_are_rejected() {
        for line in [
            r#"{"runnerProtocol":1,"caseId":"x","operation":"hello","input":{}}"#,
            r#"{"runnerProtocol":"1","caseId":"x","operation":"hello","input":{"n":0}}"#,
            r#"{"runnerProtocol":"1","caseId":"x","operation":"hello","input":{"n":1.5}}"#,
        ] {
            let r = respond(line);
            assert_eq!(r["status"], "adapterError", "line: {line}");
            assert_eq!(r["error"], "adapter.malformedRequest");
        }
    }

    #[test]
    fn malformed_json_blank_and_bom_are_adapter_errors() {
        for raw in ["{not json", "", "   ", "\u{feff}{}"] {
            let r = respond(raw);
            assert_eq!(r["status"], "adapterError", "raw: {raw:?}");
            assert_eq!(r["error"], "adapter.malformedRequest");
        }
    }

    #[test]
    fn top_level_non_object_is_rejected() {
        let r = respond(r#"["not","an","object"]"#);
        assert_eq!(r["status"], "adapterError");
        assert_eq!(r["error"], "adapter.malformedRequest");
    }

    #[test]
    fn wrong_runner_protocol_is_refused_and_echoed() {
        let r = respond(r#"{"runnerProtocol":"2","caseId":"x","operation":"hello","input":{}}"#);
        assert_eq!(r["runnerProtocol"], "2");
        assert_eq!(r["caseId"], "x");
        assert_eq!(r["status"], "adapterError");
        assert_eq!(r["error"], "adapter.unsupportedProtocol");
    }

    #[test]
    fn unsupported_operation_is_refused_not_rejected() {
        let r = respond(
            r#"{"runnerProtocol":"1","caseId":"x","operation":"selectCurrent","input":{}}"#,
        );
        assert_eq!(r["status"], "adapterError");
        assert_eq!(r["error"], "adapter.unsupportedOperation");
    }

    #[test]
    fn nonempty_hello_input_is_refused() {
        let r = respond(
            r#"{"runnerProtocol":"1","caseId":"x","operation":"hello","input":{"a":true}}"#,
        );
        assert_eq!(r["status"], "adapterError");
        assert_eq!(r["error"], "adapter.invalidInput");
    }

    #[test]
    fn truncated_line_is_line_too_long() {
        let r: Value = serde_json::from_str(&handle_line(&identity(), b"garbage", true)).unwrap();
        assert_eq!(r["status"], "adapterError");
        assert_eq!(r["error"], "adapter.lineTooLong");
    }

    #[test]
    fn responses_are_single_lines() {
        let line = handle_line(
            &identity(),
            br#"{"runnerProtocol":"1","caseId":"handshake","operation":"hello","input":{}}"#,
            false,
        );
        assert!(!line.contains('\n'));
    }
}
