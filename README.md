# followee-conformance

Neutral conformance and differential-testing harness for independent
Followee protocol implementations. The governing implementation brief is
[HARNESS.md](HARNESS.md); this README covers setup and the commands for
the current milestone.

**Status: Milestone 2 (primitives and selection), complete.** The harness
verifies every pinned revision, completes both handshakes, and runs the
specification-status corpus (Appendix B, B.7, B.8) plus the imported
provisional followee-rs fixture corpus for all seven protocol operations
— `deriveIdentity`, `authorRecord`, `verifyRecord`, `strictEd25519`,
`nextTimestamp`, `validateCbor`, and `selectCurrent` — against both
frozen implementations, producing a proposed promotion report for
review. `validateCbor` became runnable at the pinned
`milestone-1-v0.7-conformance-api-reviewed` revision, whose only change
adds the public classified `followee::validate_cbor` wrapper over the
same deterministic-CBOR validator the record path uses. Generated
campaigns are Milestone 3.

## Frozen targets

All work is pinned to the exact revisions in HARNESS.md Section 2:

| Submodule | Repository | Pinned revision |
| --- | --- | --- |
| `specification/` | `followee-protocol/followee` | `abc9a55d90f1026e6509207abda73e5dc6d14241` |
| `implementations/followee-rs/` | `followee-protocol/followee-rs` | tag `milestone-1-v0.7-conformance-api-reviewed` = `c30b2207aeccb4daa5fb06a388ecd0ec5e0ab625` (API-only descendant of the reviewed `milestone-1-v0.7-reviewed` = `774acb75…`, which remains the producing revision of the imported provisional fixtures) |
| `implementations/followee-python-cleanroom/` | `followee-protocol/followee-python-cleanroom` | tag `cleanroom-v0.7-maintenance-freeze` = `a39138dae8072c7b89dc922bcfe6f5717312c6e6` |

The `specification/` submodule holds the pinned specification bytes so the
SHA-256 digest check in HARNESS.md Section 6 is reproducible offline and
independent of either implementation (HARNESS.md Sections 5 and 6).

Both implementation submodules are read-only. Never edit, build inside, or
commit to them from this repository.

## Setup

Requires: git, Python ≥ 3.10, a POSIX shell, and the pinned Rust
toolchain `1.97.1` (the repository-root `rust-toolchain.toml` matches the
frozen implementation's own pin; with rustup installed, the right
toolchain is selected and fetched automatically).

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

## Running the gates

```sh
# Milestone 0: integrity checks + both hello handshakes
python3 -m harness.orchestrator

# Milestone 1: the specification-status differential campaign
# (identical neutral inputs to both adapters, Section 13 comparison),
# plus the chained validUntil/stale scenario, whose intermediate
# envelope is run-time implementation output admitted only after both
# authorRecord results agree byte-for-byte (harness/chained.py)
python3 -m harness.campaign

# The committed corpora must match their builders byte-for-byte
python3 scripts/build_specification_corpus.py --check
python3 scripts/build_implementation_corpus.py --check  # runs tools/fixture-builder

# Harness unit tests (framing, schemas, integrity, supervision,
# comparator sensitivity, campaign end-to-end)
python3 -m unittest discover -s harness/tests -t .

# Python adapter tests
python3 -m unittest discover -s adapters/python/tests -t .

# Rust adapter tests
cargo test --manifest-path adapters/rust/Cargo.toml --locked

# Negative integrity test: a wrong implementation commit must be refused
sh scripts/negative_pin_test.sh
```

Disagreement artifacts and scratch summaries are written under
`reports/scratch/` (ignored); each artifact contains the exact request,
both responses, adapter stderr excerpts, every pinned revision, and a
single-case reproduction command (HARNESS.md Section 16).

## Layout

See HARNESS.md Section 5. In brief: `harness/` owns orchestration,
integrity, comparison, and the chained scenarios; `adapters/` contains
one thin translation process per implementation (no protocol logic, no
copied model code); `schemas/` holds the normative runner and case JSON
Schemas; `cases/specification/` holds the 136 specification-status cases
and `cases/implementation/` the 49 imported provisional followee-rs
cases, each with a `DIGESTS.sha256` content manifest and regenerable
byte-for-byte by `scripts/build_specification_corpus.py` and
`scripts/build_implementation_corpus.py` (the latter drives
`tools/fixture-builder`, which reconstructs the pinned provisional
inputs through the frozen implementation's public API); committed
milestone reports live under `reports/` while scratch output stays in
`reports/scratch/` (ignored).

## License

MIT for the harness material authored here. The submodules retain their
own licenses and histories.
