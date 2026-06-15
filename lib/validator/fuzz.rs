//! `feature = "fuzzing"` entry points for property fuzzing of the validator's
//! mempool-time transaction validation (`validate_tx`). Not compiled into
//! normal or release builds; used by the `validate_tx` target in `../fuzz`.

use bitcoin::{Amount, BlockHash, OutPoint, Transaction, Txid, hashes::Hash as _};

use super::task::BlockHandler;
use super::test_utils::{create_test_dbs, test_block_header, test_sidechain};
use crate::types::{Ctip, M6id, SidechainNumber};

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
    Fatal,
}

fn verdict<E>(result: Result<bool, E>) -> Verdict {
    match result {
        Ok(true) => Verdict::Accept,
        Ok(false) => Verdict::Reject,
        Err(_) => Verdict::Fatal,
    }
}

/// A treasury UTXO to pre-load into the validator state.
#[derive(Debug)]
pub struct CtipSeed {
    pub sidechain: u8,
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
}

/// Build a validator state from the fuzzer-provided pieces, run `validate_tx`
/// against `tx`, and assert the verdict is deterministic.
///
/// The state lives in one uncommitted write txn; `validate_tx` runs in an
/// aborted nested txn, so nothing is persisted and both runs observe identical
/// state. The oracle is twofold:
///  1. `validate_tx` must never panic on any (state, tx) where `tx` is a
///     rust-bitcoin-decodable transaction — it should only ever return its
///     typed `ValidateTransaction` error;
///  2. it must return the same accept / reject / fatal verdict every time for
///     the same input. A consensus validator that diverged run-to-run (or, on
///     the fatal axis, halted on one node but not another) would split the
///     network.
pub fn run_validate_tx(
    active_sidechains: &[u8],
    ctips: &[CtipSeed],
    pending: &[(u8, u8)],
    tx: &Transaction,
) {
    let Ok((_dir, dbs)) = create_test_dbs() else {
        return;
    };
    let Ok(mut rwtxn) = dbs.write_txn() else {
        return;
    };

    let active: std::collections::HashSet<u8> = active_sidechains.iter().copied().collect();
    for &sc in &active {
        if dbs
            .active_sidechains
            .put_sidechain(&mut rwtxn, &SidechainNumber(sc), &test_sidechain(sc, 0))
            .is_err()
        {
            return;
        }
    }
    for seed in ctips {
        let ctip = Ctip {
            outpoint: OutPoint {
                txid: Txid::from_byte_array(seed.txid),
                vout: seed.vout,
            },
            value: Amount::from_sat(seed.value),
        };
        if dbs
            .active_sidechains
            .put_ctip(&mut rwtxn, SidechainNumber(seed.sidechain), &ctip)
            .is_err()
        {
            return;
        }
    }
    for &(sc, m6) in pending {
        // Pending bundles only exist for active sidechains (their entry is
        // created by `put_sidechain`); skip others to avoid a setup error.
        if !active.contains(&sc) {
            continue;
        }
        let m6id = M6id(Txid::from_byte_array([m6; 32]));
        if dbs
            .active_sidechains
            .put_pending_m6id(&mut rwtxn, &SidechainNumber(sc), m6id, 0)
            .is_err()
        {
            return;
        }
    }

    // Minimal chain tip so `validate_tx` finds a tip hash and its height.
    let header = test_block_header(BlockHash::all_zeros());
    if dbs
        .block_hashes
        .put_headers(&mut rwtxn, &[(header, 0)])
        .is_err()
    {
        return;
    }
    if dbs
        .current_chain_tip
        .put(&mut rwtxn, &(), &header.block_hash())
        .is_err()
    {
        return;
    }

    let handler = BlockHandler::new(&dbs, bitcoin::Network::Regtest);
    let first = verdict(handler.validate_tx(&mut rwtxn, tx));
    let second = verdict(handler.validate_tx(&mut rwtxn, tx));
    assert_eq!(
        first, second,
        "validate_tx returned a non-deterministic verdict for the same (state, tx)"
    );
}
