# followee-conformance

Neutral conformance and differential-testing harness for independent
Followee protocol implementations. The governing implementation brief is
[HARNESS.md](HARNESS.md); this README covers setup and the commands for
the current milestone.

**Status: Milestone 0 (neutral scaffold).** The harness verifies every
pinned revision and completes the `hello` handshake with both adapters.
No Followee protocol operation is claimed yet.

## Frozen targets

All work is pinned to the exact revisions in HARNESS.md Section 2:

| Submodule | Repository | Pinned revision |
| --- | --- | --- |
| `specification/` | `followee-protocol/followee` | `abc9a55d90f1026e6509207abda73e5dc6d14241` |
| `implementations/followee-rs/` | `followee-protocol/followee-rs` | tag `milestone-1-v0.7-reviewed` = `774acb7578795cf6d58f77b76b16ef010114ebd6` |
| `implementations/followee-python-cleanroom/` | `followee-protocol/followee-python-cleanroom` | tag `cleanroom-v0.7-maintenance-freeze` = `a39138dae8072c7b89dc922bcfe6f5717312c6e6` |

The `specification/` submodule holds the pinned specification bytes so the
SHA-256 digest check in HARNESS.md Section 6 is reproducible offline and
independent of either implementation (HARNESS.md Sections 5 and 6).

Both implementation submodules are read-only. Never edit, build inside, or
commit to them from this repository.

## Setup

Requires: git, Python ≥ 3.10, Rust ≥ 1.85 (stable), a POSIX shell.

```sh
git clone https://github.com/followee-protocol/followee-conformance.git
cd followee-conformance
git submodule update --init

# Verify every pin (submodule commits, tags, audit commits, spec digest)
python3 scripts/check_pins.py

# Build both adapters (the Rust build compiles the frozen core via a path
# dependency; the Python adapter is interpreted and needs no build step)
cargo build --manifest-path adapters/rust/Cargo.toml --locked
```

After checkout and dependency installation, everything below runs without
network access.

## Running the Milestone 0 gate

```sh
# Integrity checks + both hello handshakes, refusing incorrect pins
python3 -m harness.orchestrator

# Harness unit tests (JSONL framing, schemas, integrity, supervision)
python3 -m unittest discover -s harness/tests -t .

# Python adapter tests
python3 -m unittest discover -s adapters/python/tests -t .

# Rust adapter tests
cargo test --manifest-path adapters/rust/Cargo.toml --locked

# Negative integrity test: a wrong implementation commit must be refused
sh scripts/negative_pin_test.sh
```

## Layout

See HARNESS.md Section 5. In brief: `harness/` owns orchestration,
integrity, and comparison; `adapters/` contains one thin translation
process per implementation (no protocol logic, no copied model code);
`schemas/` holds the normative runner and case JSON Schemas; `cases/` and
`reports/` are empty at Milestone 0.

## License

MIT for the harness material authored here. The submodules retain their
own licenses and histories.
