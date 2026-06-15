#![no_main]

//! Differential target: `M8BmmRequest::parse` (raw byte / `nom` parser) vs
//! rust-bitcoin script interpretation, plus a builder round-trip.
//!
//! `M8BmmRequest::parse` decodes the raw script bytes directly with `tag`
//! (`OP_RETURN <len> [tag] <S> <H> <P>`) rather than via `Script::instructions`.
//! Invariants checked:
//!   1. parsing never panics;
//!   2. a parsed request re-encodes via `M8BmmRequest::script_pubkey` to
//!      exactly the bytes that were consumed (canonical, no trailing data);
//!   3. rust-bitcoin agrees the canonical encoding is a single `OP_RETURN`
//!      push-data script.

use bip300301_enforcer_lib::messages::M8BmmRequest;
use bitcoin::ScriptBuf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((rest, req)) = M8BmmRequest::parse(data) else {
        return;
    };
    // The parser enforces `eof`, so success implies the whole input was the
    // canonical form.
    assert!(rest.is_empty(), "M8 parse left trailing bytes despite eof()");

    let reencoded = M8BmmRequest::script_pubkey(
        req.sidechain_number,
        req.sidechain_block_hash,
        req.prev_mainchain_block_hash,
    )
    .expect("re-encoding a parsed M8 must not overflow push limits");

    assert_eq!(
        reencoded.as_bytes(),
        data,
        "M8 round-trip mismatch: parser accepted a non-canonical encoding"
    );

    // rust-bitcoin must see the canonical encoding as a well-formed script.
    assert!(
        ScriptBuf::from_bytes(data.to_vec())
            .instructions()
            .all(|i| i.is_ok()),
        "M8 canonical bytes are not a valid rust-bitcoin script"
    );
});
