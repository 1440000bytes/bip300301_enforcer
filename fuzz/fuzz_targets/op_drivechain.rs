#![no_main]

//! Differential target: `parse_op_drivechain` (raw byte / `nom` parser) vs the
//! `op_drivechain_script` builder.
//!
//! A treasury UTXO scriptPubKey is `OP_DRIVECHAIN OP_PUSHBYTES_1 <S> OP_TRUE`.
//! `parse_op_drivechain` reads the raw bytes with `tag`/`take`; the builder
//! `op_drivechain_script` produces them. Invariants:
//!   1. parsing never panics;
//!   2. a parsed script round-trips through the builder to identical bytes;
//!   3. rust-bitcoin accepts the canonical bytes as a valid script.

use bip300301_enforcer_lib::messages::parse_op_drivechain;
use bip300301_enforcer_lib::types::op_drivechain_script;
use bitcoin::ScriptBuf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((rest, sidechain_number)) = parse_op_drivechain(data) else {
        return;
    };
    assert!(rest.is_empty(), "op_drivechain parse left trailing bytes");

    let reencoded = op_drivechain_script(sidechain_number);
    assert_eq!(
        reencoded.as_bytes(),
        data,
        "op_drivechain round-trip mismatch: non-canonical encoding accepted"
    );

    assert!(
        ScriptBuf::from_bytes(data.to_vec())
            .instructions()
            .all(|i| i.is_ok()),
        "op_drivechain canonical bytes are not a valid rust-bitcoin script"
    );
});
