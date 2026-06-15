#![no_main]

//! Differential target: `SidechainDeclaration` parsing.
//!
//! On-chain path: a miner's M1 (`OP_RETURN` coinbase output) carries an
//! arbitrary `description` byte string (`M1ProposeSidechain::parse` reads it
//! via `rest`, so it is fully attacker-controlled and unvalidated when stored
//! in `handle_m1_propose_sidechain`). Later, `sync_state_summary` and the
//! validator gRPC service call `SidechainDeclaration::try_from(&description)`.
//!
//! rust-bitcoin's own decoders never panic on adversarial input — they return
//! `Err`. This target asserts the enforcer's hand-rolled declaration parser
//! upholds the same contract: every input must yield `Ok`/`Err`, never a
//! panic. A crash here is a remotely-triggerable DoS reachable from a single
//! malformed coinbase.

use bip300301_enforcer_lib::types::{SidechainDeclaration, SidechainDescription};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let description = SidechainDescription(data.to_vec());
    // Must not panic. Either outcome is acceptable; a panic is the bug.
    let _ = SidechainDeclaration::try_from(&description);
});
