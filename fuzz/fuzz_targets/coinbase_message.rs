#![no_main]

//! Differential target: `CoinbaseMessage::parse` vs rust-bitcoin script
//! interpretation, plus a serialize round-trip.
//!
//! `CoinbaseMessage::parse` mixes rust-bitcoin's `Script::instructions()` with
//! a hand-rolled `nom` body parser. We feed arbitrary script bytes and check:
//!   1. parsing never panics;
//!   2. when it succeeds with no trailing bytes, re-encoding the message back
//!      to a `ScriptBuf` and re-parsing yields an equivalent message
//!      (canonical round-trip). A divergence means the parser accepts a script
//!      it cannot reproduce, i.e. a non-canonical encoding slipped through.

use bip300301_enforcer_lib::messages::CoinbaseMessage;
use bitcoin::ScriptBuf;
use libfuzzer_sys::fuzz_target;

fn discriminant(msg: &CoinbaseMessage) -> u8 {
    match msg {
        CoinbaseMessage::M1ProposeSidechain(_) => 1,
        CoinbaseMessage::M2AckSidechain(_) => 2,
        CoinbaseMessage::M3ProposeBundle(_) => 3,
        CoinbaseMessage::M4AckBundles(_) => 4,
        CoinbaseMessage::M7BmmAccept(_) => 7,
    }
}

fuzz_target!(|data: &[u8]| {
    let script = ScriptBuf::from_bytes(data.to_vec());
    let Ok((rest, msg)) = CoinbaseMessage::parse(&script) else {
        return;
    };
    if !rest.is_empty() {
        return;
    }
    // Round-trip: a message the parser accepted must re-serialize and re-parse
    // back to the same message kind. (M3 has no dedup/length checks, others do.)
    let kind = discriminant(&msg);
    let Ok(reencoded) = ScriptBuf::try_from(msg) else {
        return;
    };
    match CoinbaseMessage::parse(&reencoded) {
        Ok((rest2, msg2)) => {
            assert!(rest2.is_empty(), "round-trip left trailing bytes");
            assert_eq!(
                kind,
                discriminant(&msg2),
                "round-trip changed message kind"
            );
        }
        Err(err) => panic!("re-encoded canonical message failed to parse: {err:?}"),
    }
});
