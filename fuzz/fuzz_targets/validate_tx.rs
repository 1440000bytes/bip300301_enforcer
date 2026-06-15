#![no_main]

//! Stateful property target for the enforcer's mempool-time transaction
//! validation (`Validator::validate_tx` → `handle_transaction` → M5/M6/M8).
//!
//! Unlike the stateless `compute_m6id` / `blinded_m6` targets, this one builds a
//! small validator state (active sidechains, treasury CTIPs, pending withdrawal
//! bundles, a chain tip) and runs a fuzzer-built transaction against it, so the
//! deep money-path logic (treasury spend tracking, M5 deposit / M6 withdrawal
//! classification, the multi-CTIP loop) is actually reached.
//!
//! Oracle (in `bip300301_enforcer_lib::validator::fuzz::run_validate_tx`): the
//! validator must (1) never panic on a rust-bitcoin-decodable transaction, and
//! (2) return the same accept/reject/fatal verdict every time for the same
//! (state, tx) — a non-deterministic consensus verdict would split the network.

use arbitrary::{Arbitrary, Unstructured};
use bip300301_enforcer_lib::types::{SidechainNumber, op_drivechain_script};
use bip300301_enforcer_lib::validator::fuzz::{CtipSeed, run_validate_tx};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, hashes::Hash as _, script::PushBytesBuf, transaction::Version,
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct Scenario {
    active: Vec<u8>,
    ctips: Vec<CtipSeed>,
    pending: Vec<(u8, u8)>,
    tx: Transaction,
    m6_mode: bool,
}

fn txin(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

impl<'a> Arbitrary<'a> for Scenario {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut ctips = Vec::new();
        for _ in 0..u.int_in_range(0..=4)? {
            ctips.push(CtipSeed {
                sidechain: u.arbitrary()?,
                txid: u.arbitrary()?,
                vout: u.int_in_range(0..=3)?,
                value: u.arbitrary()?,
            });
        }

        let mut active = Vec::new();
        for _ in 0..u.int_in_range(0..=4)? {
            active.push(u.arbitrary()?);
        }

        let mut pending = Vec::new();
        for _ in 0..u.int_in_range(0..=4)? {
            pending.push((u.arbitrary()?, u.arbitrary()?));
        }

        // In M6 mode, build a clean withdrawal-shaped tx: exactly one input
        // spending a seeded CTIP, a treasury OP_DRIVECHAIN output at index 0
        // worth less than the old treasury, then payout outputs. The lib side
        // pre-registers the matching bundle so the M6 success path is reached.
        let m6_mode = !ctips.is_empty() && u.arbitrary()?;
        let tx = if m6_mode {
            let c = &ctips[u.choose_index(ctips.len())?];
            // Ensure the spent CTIP's sidechain is active (required for M6).
            if !active.contains(&c.sidechain) {
                active.push(c.sidechain);
            }
            let input = vec![txin(OutPoint {
                txid: Txid::from_byte_array(c.txid),
                vout: c.vout,
            })];
            // Treasury output: strictly less than old value => M6 classification.
            let new_treasury = if c.value > 0 {
                u.int_in_range(0..=c.value - 1)?
            } else {
                0
            };
            let mut output = vec![TxOut {
                value: Amount::from_sat(new_treasury),
                script_pubkey: op_drivechain_script(SidechainNumber(c.sidechain)),
            }];
            for _ in 0..u.int_in_range(0..=3)? {
                output.push(TxOut {
                    value: Amount::from_sat(u.int_in_range(0..=c.value)?),
                    script_pubkey: ScriptBuf::new(),
                });
            }
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input,
                output,
            }
        } else {
            // Generic tx: inputs biased toward spending seeded CTIPs, outputs
            // toward OP_DRIVECHAIN treasury / OP_RETURN address shapes.
            let mut input = Vec::new();
            for _ in 0..u.int_in_range(0..=3)? {
                let previous_output = if !ctips.is_empty() && u.arbitrary()? {
                    let c = &ctips[u.choose_index(ctips.len())?];
                    OutPoint {
                        txid: Txid::from_byte_array(c.txid),
                        vout: c.vout,
                    }
                } else {
                    OutPoint {
                        txid: Txid::from_byte_array(u.arbitrary()?),
                        vout: u.int_in_range(0..=3)?,
                    }
                };
                input.push(txin(previous_output));
            }

            let mut output = Vec::new();
            for _ in 0..u.int_in_range(0..=4)? {
                let script_pubkey = match u.int_in_range(0u8..=2)? {
                    0 => op_drivechain_script(SidechainNumber(u.arbitrary()?)),
                    1 => {
                        let len = u.int_in_range(0..=40usize)?;
                        let bytes = u.bytes(len)?.to_vec();
                        match PushBytesBuf::try_from(bytes) {
                            Ok(pb) => ScriptBuf::new_op_return(pb),
                            Err(_) => ScriptBuf::new(),
                        }
                    }
                    _ => ScriptBuf::new(),
                };
                output.push(TxOut {
                    value: Amount::from_sat(u.arbitrary()?),
                    script_pubkey,
                });
            }

            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input,
                output,
            }
        };

        Ok(Scenario {
            active,
            ctips,
            pending,
            tx,
            m6_mode,
        })
    }
}

fuzz_target!(|scenario: Scenario| {
    run_validate_tx(
        &scenario.active,
        &scenario.ctips,
        &scenario.pending,
        &scenario.tx,
        scenario.m6_mode,
    );
});
