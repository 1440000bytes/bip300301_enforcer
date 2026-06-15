# Differential fuzzing

`cargo-fuzz` (libFuzzer) harness that differentially tests the enforcer's
hand-rolled BIP300/301 parsers against [rust-bitcoin].

The enforcer reimplements byte-level parsing for several consensus structures
that overlap with rust-bitcoin's domain (`nom`/`tag` script parsers, manual
transaction surgery in `compute_m6id`/`BlindedM6`). rust-bitcoin's own decoders
treat *all* adversarial input as ordinary `Err` and never panic. These targets
hold the enforcer to the same contract and check serialize round-trips, using
rust-bitcoin as the oracle.

## Targets

| target | under test | oracle / property |
|---|---|---|
| `sidechain_declaration` | `SidechainDeclaration::try_from` | M1 description bytes (attacker-controlled) must parse to `Ok`/`Err`, never panic |
| `coinbase_message` | `CoinbaseMessage::parse` | no panic + canonical serialize round-trip |
| `m8_request` | `M8BmmRequest::parse` | no panic + builder round-trip + valid rust-bitcoin script |
| `op_drivechain` | `parse_op_drivechain` | no panic + builder round-trip + valid rust-bitcoin script |
| `compute_m6id` | `compute_m6id` | rust-bitcoin-decoded tx must not panic the M6 blinding |
| `blinded_m6` | `BlindedM6::try_from` | rust-bitcoin-decoded tx must be rejected typed, not by panic |
| `validate_tx` | `Validator::validate_tx` (M5/M6/M8) | stateful: no panic + deterministic accept/reject/fatal verdict |

The first six targets are stateless. `validate_tx` is *stateful*: it builds a
small validator state (active sidechains, treasury CTIPs, pending withdrawal
bundles, chain tip) via the `bip300301_enforcer_lib` `fuzzing` feature, then runs
a fuzzer-built transaction through the mempool-time validation path so the deep
money-path logic (treasury-spend tracking, M5 deposit / M6 withdrawal
classification) is actually reached. Its oracle: a consensus validator must
never panic and must return the same accept/reject/fatal verdict for the same
`(state, tx)` — a run-to-run divergence, especially on the fatal axis, would
split the network. The `fuzzing` feature is off in normal/release builds.

The fuzz profile keeps `overflow-checks` and `debug-assertions` on so that
unchecked arithmetic (a real divergence from rust-bitcoin's checked decoders)
surfaces as a crash.

## Running

```sh
# nightly + cargo-fuzz required
cargo install cargo-fuzz
cd fuzz # or run from repo root with --fuzz-dir fuzz
cargo +nightly fuzz run sidechain_declaration
cargo +nightly fuzz run compute_m6id -- -max_total_time=120
```

Reproduce a saved crash:

```sh
cargo +nightly fuzz run <target> artifacts/<target>/crash-<hash>
```

[rust-bitcoin]: https://github.com/rust-bitcoin/rust-bitcoin
