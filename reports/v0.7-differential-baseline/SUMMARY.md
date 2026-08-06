# Followee v0.7 differential baseline

Checkpoint of the complete Milestone 0-2 differential-conformance gate:
two independently developed frozen implementations, identical neutral
inputs, mechanical comparison (HARNESS.md Sections 1-3 and 13). This is
independent core differential-conformance evidence for the executed
cases; it is not a relay-interoperability or formal-proof claim
(HARNESS.md Section 17).

## Pins and tags

| Artifact | Revision |
| --- | --- |
| Followee Specification v0.7 | `abc9a55d90f1026e6509207abda73e5dc6d14241` |
| Specification SHA-256 | `2b264823ba68d9a7d69ce68de5c1408ac8a3d54ff6d726ab89ee2baa2707c81f` |
| Rust protocol core | `c30b2207aeccb4daa5fb06a388ecd0ec5e0ab625` (tag `milestone-1-v0.7-conformance-api-reviewed`) |
| Rust audited parent / fixture-producing revision | `774acb7578795cf6d58f77b76b16ef010114ebd6` (tag `milestone-1-v0.7-reviewed`) |
| Rust review-fix parent | `d23d660c1efb8e1c8f0095a2b44040bc44cf5160` |
| Python clean-room model | `a39138dae8072c7b89dc922bcfe6f5717312c6e6` (tag `cleanroom-v0.7-maintenance-freeze`) |
| Python v0.7 maintenance input | `6b944b952d1daec6840deae7e07f304f5349637d` |
| Python v0.6 freeze / reviewed correction | `7ca1f623453065deefd1e6cfdf15e135d523dd7e` / `70e4a6caa8720f1dfbb3b183a5d305fca0cf3e57` |
| Runner protocol | `1` |
| Operations | `hello`, `deriveIdentity`, `authorRecord`, `verifyRecord`, `strictEd25519`, `nextTimestamp`, `validateCbor`, `selectCurrent` |

## Campaign result

| Count | Value |
| --- | --- |
| Static cases executed | 185 |
| by derivation status | specification 136, implementation 49 |
| by operation | authorRecord 35, deriveIdentity 2, nextTimestamp 9, selectCurrent 13, strictEd25519 23, validateCbor 38, verifyRecord 65 |
| Chained scenarios (dynamic steps) | 2 (8 steps) |
| Total comparisons | 193 |
| Agreed comparisons | 193 |
| Exact-error comparisons | 48 |
| Rejection-only comparisons | 49 |
| Acceptance/rejection disagreements | 0 |
| Infrastructure failures | 0 |
| Executions per adapter per case | 2 (identical-request repetition) |
| Implementation-status cases proposed for promotion (pending review) | 49 of 49 |

## Retained symbolic divergences (unspecified assertions)

Every case below carries `errorAssertion: unspecified`: both
implementations reject, the comparison passes on rejection only, and both
symbols are retained diagnostically (HARNESS.md Sections 9.3 and 12).
Neither implementation is treated as authoritative.

| Case | followee-rs | followee-python-cleanroom | Classification |
| --- | --- | --- | --- |
| `validate-cbor-invalid-utf8` | `invalidCbor` | `nonDeterministicCbor` | specification-ambiguity |
| `verify-b7-09-duplicate-map-key` | `schemaViolation` | `nonDeterministicCbor` | multi-fault |
| `verify-b7-15-valid-until-before-timestamp` | `schemaViolation` | `invalidSignature` | multi-fault |

- `validate-cbor-invalid-utf8`: Invalid UTF-8 in a text string sits between 15.3 code 4 ('CBOR cannot be parsed safely') and code 5 ('encoding violates Section 6.1', rule 8). Both readings are defensible; the Python clean-room documented exactly this interpretation decision. Candidate for specification clarification.
- `verify-b7-09-duplicate-map-key`: Duplicate key inside the unprotected COSE header map violates both the Section 6.2 profile (unprotected map must be empty -> schemaViolation) and Section 6.1 rule 4 (duplicate keys -> nonDeterministicCbor). Section 8.1 permits reordering cheap independent checks; the re-signed single-fault twin impl-b7-9-duplicate-key classifies identically on both sides.
- `verify-b7-15-valid-until-before-timestamp`: The label-6 splice is not re-signed, so the input violates both the validUntil relation (Section 5.5) and the signature (Section 3.3). The implementations check in different permitted orders; the re-signed single-fault twin impl-b7-15-valid-until-before-timestamp classifies identically (schemaViolation) on both sides.

No other unspecified-assertion case produced differing symbols.

## Fixture bundle

`FIXTURE-BUNDLE.sha256` lists sorted SHA-256 digests for every regular
file under `cases/` (case manifests, inputs, provenance records, and both
`DIGESTS.sha256` corpus manifests).

Aggregate SHA-256 of `FIXTURE-BUNDLE.sha256`:

```text
97ce36edfd06136afcc8396a237ad8d92f59ddba02d6b192f6ccdeaef4b7e82c
```

`CHAINED-STEP-INPUTS.json` records the exact input bytes (verbatim hex)
and canonical-JSON digests of every dynamically generated chained-scenario
step, so the inputs behind all 193 baseline comparisons are
reconstructable from this archive plus the committed corpora.

## Gate commands and results

| Command | Exit |
| --- | --- |
| `python3 scripts/check_pins.py` | 0 |
| `python3 -m harness.orchestrator` | 0 |
| `sh scripts/negative_pin_test.sh` | 0 |
| `python3 scripts/build_specification_corpus.py --check` | 0 |
| `python3 scripts/build_implementation_corpus.py --check` | 0 |
| `python3 -m unittest discover -s harness/tests -t .` | 0 |
| `python3 -m unittest discover -s adapters/python/tests -t .` | 0 |
| `python3 -m ruff check harness adapters/python scripts` | 0 |
| `python3 -m ruff format --check harness adapters/python scripts` | 0 |
| `cargo fmt --manifest-path adapters/rust/Cargo.toml -- --check` | 0 |
| `cargo fmt --manifest-path tools/fixture-builder/Cargo.toml -- --check` | 0 |
| `cargo clippy --manifest-path adapters/rust/Cargo.toml --all-targets --locked -- -D warnings` | 0 |
| `cargo clippy --manifest-path tools/fixture-builder/Cargo.toml --locked -- -D warnings` | 0 |
| `cargo test --manifest-path adapters/rust/Cargo.toml --locked` | 0 |
| `git diff --check` | 0 |
| `python3 -m harness.campaign` | 0 |

