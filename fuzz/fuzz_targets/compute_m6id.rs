#![no_main]

//! Differential target: `compute_m6id` driven by rust-bitcoin's transaction
//! decoder.
//!
//! Oracle: if `bitcoin::consensus::deserialize::<Transaction>` accepts the
//! bytes, rust-bitcoin considers them a structurally valid transaction. The
//! enforcer's `compute_m6id` (BIP300 M6 blinding) must then handle that
//! transaction without panicking — it should only ever return its typed
//! `M6idError`. Any panic (overflow, slice/index, unwrap) is a bug reachable
//! from a withdrawal-bundle transaction on the wire.

use bip300301_enforcer_lib::messages::compute_m6id;
use bitcoin::{Amount, Transaction, consensus::Decodable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 8 bytes (if present) seed the previous treasury balance; the rest
    // is the transaction. This lets the fuzzer explore the treasury arithmetic.
    let (prev_treasury, tx_bytes) = if data.len() >= 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[..8]);
        (Amount::from_sat(u64::from_le_bytes(buf)), &data[8..])
    } else {
        (Amount::ZERO, data)
    };

    let mut cursor = tx_bytes;
    let Ok(tx) = Transaction::consensus_decode(&mut cursor) else {
        return;
    };

    // rust-bitcoin accepted it as a transaction; the enforcer must not panic.
    let _ = compute_m6id(tx, prev_treasury);
});
