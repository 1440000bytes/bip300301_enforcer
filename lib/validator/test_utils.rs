//! Shared test utilities for `crate::validator`. Gated behind
//! `#[cfg(any(test, feature = "fuzzing"))]` in the parent module: the fuzz
//! harness (`validator::fuzz`) reuses the state builders.

use bitcoin::{BlockHash, hashes::Hash as _};
use miette::IntoDiagnostic;

use super::dbs::Dbs;
use crate::types::{
    Sidechain, SidechainDescription, SidechainNumber, SidechainProposal, SidechainProposalStatus,
};

pub fn create_test_dbs() -> miette::Result<(temp_dir::TempDir, Dbs)> {
    let dir = temp_dir::TempDir::new().into_diagnostic()?;
    let dbs = Dbs::new(dir.path(), bitcoin::Network::Regtest).into_diagnostic()?;
    Ok((dir, dbs))
}

pub fn test_sidechain(sidechain_number: u8, proposal_height: u32) -> Sidechain {
    Sidechain {
        proposal: SidechainProposal {
            sidechain_number: SidechainNumber(sidechain_number),
            description: SidechainDescription(vec![0x00, sidechain_number]),
        },
        status: SidechainProposalStatus {
            vote_count: 0,
            proposal_height,
            activation_height: None,
        },
    }
}

#[cfg(test)]
pub fn test_m6id(byte: u8) -> crate::types::M6id {
    use bitcoin::Txid;
    crate::types::M6id(Txid::from_byte_array([byte; 32]))
}

/// Minimal block header for tests — only `prev_blockhash` is meaningful
pub fn test_block_header(prev_blockhash: BlockHash) -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash,
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x2000_0000),
        nonce: 0,
    }
}
