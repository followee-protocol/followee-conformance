//! Persistent JSONL adapter process (HARNESS.md 7.1).
//!
//! Protocol responses go only to standard output; diagnostics go only to
//! standard error.  The process reads one request per line until EOF and
//! then exits 0.

#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};

use followee_adapter_rust::{handle_line, Identity, MAX_LINE_BYTES};

/// Read one newline-terminated line, enforcing the 1 MiB cap.
///
/// Returns `Ok(None)` at clean EOF.  When a line exceeds the cap its
/// remainder is drained and discarded and the line is flagged truncated.
fn read_line_capped<R: BufRead>(reader: &mut R, max: usize) -> io::Result<Option<(Vec<u8>, bool)>> {
    let mut line: Vec<u8> = Vec::new();
    let mut truncated = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            // EOF: a final unterminated line is still handled.
            if line.is_empty() && !truncated {
                return Ok(None);
            }
            return Ok(Some((line, truncated)));
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                if !truncated {
                    if line.len() + pos > max {
                        truncated = true;
                        line.clear();
                    } else {
                        line.extend_from_slice(&available[..pos]);
                    }
                }
                reader.consume(pos + 1);
                return Ok(Some((line, truncated)));
            }
            None => {
                let len = available.len();
                if !truncated {
                    if line.len() + len > max {
                        truncated = true;
                        line.clear();
                    } else {
                        line.extend_from_slice(available);
                    }
                }
                reader.consume(len);
            }
        }
    }
}

fn main() -> io::Result<()> {
    let identity = Identity::from_build();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    while let Some((raw, truncated)) = read_line_capped(&mut reader, MAX_LINE_BYTES)? {
        let response = handle_line(&identity, &raw, truncated);
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
    Ok(())
}
