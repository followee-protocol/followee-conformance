#!/usr/bin/env python3
"""Configurable fake adapter for harness supervision tests.

Each mode simulates one class of adapter misbehavior (HARNESS.md 7.1 and
Section 19: stdout pollution, malformed JSON, duplicate JSON names, bare
numbers, timeout, crash, oversized output, extra output, unclean exit).
The harness must classify every one of these as an infrastructure
failure, never as a Followee rejection.
"""

from __future__ import annotations

import json
import sys
import time

HELLO_RESULT = {
    "adapter": "fake",
    "adapterVersion": "1",
    "implementationRepository": "https://example.invalid/fake",
    "implementationCommit": "0" * 40,
    "specificationCommit": "1" * 40,
    "runnerProtocols": ["1"],
    "operations": ["hello"],
}


def ok_response(case_id: str) -> str:
    return json.dumps(
        {
            "runnerProtocol": "1",
            "caseId": case_id,
            "status": "accepted",
            "result": HELLO_RESULT,
        },
        separators=(",", ":"),
    )


def main() -> int:
    mode = sys.argv[1]
    out = sys.stdout
    if mode == "never-reads":
        # Never drains stdin: a large request must hit the pipe capacity
        # and surface as a harness timeout on the send side.
        time.sleep(600)
        return 0
    line = sys.stdin.readline()
    request = json.loads(line) if line.strip().startswith("{") else {}
    case_id = request.get("caseId", "handshake")

    if mode == "ok":
        print(ok_response(case_id), flush=True)
        sys.stdin.read()  # wait for EOF
        return 0
    if mode == "malformed":
        print("this is not json", flush=True)
        return 0
    if mode == "garbage-prefix":
        out.write("adapter starting up...\n")
        out.write(ok_response(case_id) + "\n")
        out.flush()
        return 0
    if mode == "blank-line":
        out.write("\n" + ok_response(case_id) + "\n")
        out.flush()
        return 0
    if mode == "bom":
        sys.stdout.buffer.write(b"\xef\xbb\xbf" + ok_response(case_id).encode() + b"\n")
        sys.stdout.buffer.flush()
        return 0
    if mode == "duplicate-keys":
        print(
            f'{{"runnerProtocol":"1","caseId":"{case_id}","caseId":"{case_id}",'
            '"status":"accepted","result":{}}',
            flush=True,
        )
        return 0
    if mode == "float":
        print(
            f'{{"runnerProtocol":"1","caseId":"{case_id}","status":"accepted",'
            '"result":{"x":1.5}}',
            flush=True,
        )
        return 0
    if mode == "bare-int":
        print(
            f'{{"runnerProtocol":"1","caseId":"{case_id}","status":"accepted",'
            '"result":{"x":7}}',
            flush=True,
        )
        return 0
    if mode == "timeout":
        time.sleep(600)
        return 0
    if mode == "crash":
        print("panic: something went wrong", file=sys.stderr, flush=True)
        return 42
    if mode == "oversized":
        out.write("x" * (1024 * 1024 + 100) + "\n")
        out.flush()
        sys.stdin.read()
        return 0
    if mode == "extra-output":
        out.write(ok_response(case_id) + "\n" + '{"stray":"line"}' + "\n")
        out.flush()
        sys.stdin.read()
        return 0
    if mode == "trailing-blank-line":
        out.write(ok_response(case_id) + "\n\n")
        out.flush()
        sys.stdin.read()
        return 0
    if mode == "trailing-spaces":
        out.write(ok_response(case_id) + "\n   ")
        out.flush()
        sys.stdin.read()
        return 0
    if mode == "output-at-shutdown":
        print(ok_response(case_id), flush=True)
        sys.stdin.read()  # wait for EOF, then pollute stdout
        print("late shutdown diagnostic on stdout", flush=True)
        return 0
    if mode == "wrong-case-id":
        print(ok_response("someone-else"), flush=True)
        sys.stdin.read()
        return 0
    if mode == "hang-on-shutdown":
        print(ok_response(case_id), flush=True)
        time.sleep(600)
        return 0
    if mode == "unclean-exit":
        print(ok_response(case_id), flush=True)
        sys.stdin.read()
        return 17
    raise SystemExit(f"unknown fake adapter mode {mode!r}")


if __name__ == "__main__":
    sys.exit(main())
