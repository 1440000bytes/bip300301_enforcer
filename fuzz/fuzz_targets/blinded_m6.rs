#![no_main]

//! Differential target: `BlindedM6` construction driven by rust-bitcoin's
//! transaction decoder.
//!
//! Oracle: any byte string rust-bitcoin decodes into a `Transaction` is a valid
//! transaction. `BlindedM6::try_from` validates the M6-blinded shape (no
//! inputs, zero-value OP_RETURN fee output at index 0, non-zero payout). It
//! must reject malformed transactions via its typed `BlindedM6Error`, never by
//! panicking. When it succeeds, `compute_m6id` on the same value must also be
//! panic-free.

use bip300301_enforcer_lib::types::BlindedM6;
use bitcoin::{Transaction, consensus::Decodable};
use libfuzzer_sys::fuzz_target;
use std::borrow::Cow;

fuzz_target!(|data: &[u8]| {
    let mut cursor = data;
    let Ok(tx) = Transaction::consensus_decode(&mut cursor) else {
        return;
    };

    if let Ok(blinded) = BlindedM6::try_from(Cow::Owned(tx)) {
        // A successfully blinded M6 must yield an id without panicking.
        let _ = blinded.compute_m6id();
    }
});
