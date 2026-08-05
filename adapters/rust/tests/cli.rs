//! Integration tests for the adapter process: JSONL framing over real
//! pipes, clean EOF shutdown, and misbehavior classification.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use serde_json::Value;

fn spawn_adapter() -> Child {
    Command::new(env!("CARGO_BIN_EXE_followee-adapter-rust"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("adapter binary spawns")
}

fn roundtrip(lines: &[&str]) -> (Vec<Value>, i32) {
    let mut child = spawn_adapter();
    {
        let stdin = child.stdin.as_mut().unwrap();
        for line in lines {
            stdin.write_all(line.as_bytes()).unwrap();
            stdin.write_all(b"\n").unwrap();
        }
    }
    drop(child.stdin.take());
    let stdout = child.stdout.take().unwrap();
    let responses: Vec<Value> = BufReader::new(stdout)
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).expect("one JSON object per line"))
        .collect();
    let status = child.wait().unwrap();
    (responses, status.code().unwrap_or(-1))
}

#[test]
fn hello_handshake_roundtrip() {
    let (responses, code) = roundtrip(&[
        r#"{"runnerProtocol":"1","caseId":"handshake","operation":"hello","input":{}}"#,
    ]);
    assert_eq!(code, 0, "clean exit after stdin EOF");
    assert_eq!(responses.len(), 1, "exactly one response line per request");
    let r = &responses[0];
    assert_eq!(r["status"], "accepted");
    assert_eq!(r["caseId"], "handshake");
    assert_eq!(r["result"]["operations"], serde_json::json!(["hello"]));
    let commit = r["result"]["implementationCommit"].as_str().unwrap();
    assert_eq!(commit.len(), 40);
}

#[test]
fn repeated_hello_is_deterministic_within_one_process() {
    let line = r#"{"runnerProtocol":"1","caseId":"handshake","operation":"hello","input":{}}"#;
    let (responses, code) = roundtrip(&[line, line]);
    assert_eq!(code, 0);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0], responses[1]);
}

#[test]
fn malformed_line_yields_adapter_error_and_process_survives() {
    let (responses, code) = roundtrip(&[
        "this is not json",
        r#"{"runnerProtocol":"1","caseId":"after","operation":"hello","input":{}}"#,
    ]);
    assert_eq!(code, 0);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["status"], "adapterError");
    assert_eq!(responses[0]["error"], "adapter.malformedRequest");
    assert_eq!(responses[1]["status"], "accepted");
    assert_eq!(responses[1]["caseId"], "after");
}

#[test]
fn oversized_line_is_classified_and_drained() {
    let huge = format!(
        r#"{{"runnerProtocol":"1","caseId":"big","operation":"hello","input":{{"pad":"{}"}}}}"#,
        "a".repeat(1024 * 1024 + 64)
    );
    let (responses, code) = roundtrip(&[
        huge.as_str(),
        r#"{"runnerProtocol":"1","caseId":"after","operation":"hello","input":{}}"#,
    ]);
    assert_eq!(code, 0);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["status"], "adapterError");
    assert_eq!(responses[0]["error"], "adapter.lineTooLong");
    assert_eq!(responses[1]["status"], "accepted", "line was fully drained");
}

#[test]
fn stdout_carries_only_protocol_lines() {
    let (responses, _) = roundtrip(&[
        r#"{"runnerProtocol":"1","caseId":"handshake","operation":"hello","input":{}}"#,
    ]);
    // Every stdout line parsed as JSON in roundtrip(); one request produced
    // exactly one line, so there was no banner or stray diagnostic output.
    assert_eq!(responses.len(), 1);
}
