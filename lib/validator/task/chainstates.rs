//! Querying the node's chainstates (`getchainstates`) to determine how far
//! block data is available during an assumeutxo background sync.

use jsonrpsee::core::client::ClientT;
use serde::Deserialize;

/// One chainstate entry from `getchainstates`. All fields are optional:
/// Bitcoin Core returns an empty object for a chainstate without a tip.
#[derive(Debug, Deserialize)]
pub(super) struct ChainstateInfo {
    /// Height of the chainstate's tip.
    #[serde(default)]
    blocks: Option<u32>,
    /// Set iff this chainstate was activated from an assumeutxo snapshot
    /// (`loadtxoutset`).
    #[serde(default)]
    snapshot_blockhash: Option<bitcoin::BlockHash>,
    /// Whether every block in this chainstate has been fully validated.
    #[serde(default)]
    validated: Option<bool>,
}

/// Response of the `getchainstates` RPC. Normally a single chainstate. Two
/// while the node is validating an assumeutxo snapshot in the background.
#[derive(Debug, Deserialize)]
pub(super) struct Chainstates {
    chainstates: Vec<ChainstateInfo>,
}

impl Chainstates {
    /// The highest block height the node guarantees full block data for,
    /// or `None` if every block on the active chain is available.
    pub(super) fn block_data_available_height(&self) -> Option<u32> {
        let unvalidated_snapshot = self.chainstates.iter().any(|chainstate| {
            chainstate.snapshot_blockhash.is_some() && chainstate.validated != Some(true)
        });
        if !unvalidated_snapshot {
            return None;
        }
        let background_height = self
            .chainstates
            .iter()
            .filter(|chainstate| chainstate.snapshot_blockhash.is_none())
            .filter_map(|chainstate| chainstate.blocks)
            .max()
            // A background chainstate that hasn't connected anything yet
            // (or reports an empty object) has served nothing but genesis.
            .unwrap_or(0);
        Some(background_height)
    }
}

/// Query `getchainstates`. Available on all supported Bitcoin Core versions.
pub(super) async fn get_chainstates<C>(
    client: &C,
) -> Result<Chainstates, jsonrpsee::core::client::Error>
where
    C: ClientT + Sync,
{
    client
        .request("getchainstates", jsonrpsee::rpc_params![])
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_block_data_available_on_a_normal_node() {
        let normal: Chainstates = serde_json::from_str(
            r#"{"headers":300,"chainstates":[{"blocks":300,"bestblockhash":"aa","validated":true}]}"#,
        )
        .unwrap();
        assert_eq!(normal.block_data_available_height(), None);
    }

    #[test]
    fn background_sync_limits_available_block_data() {
        let syncing: Chainstates = serde_json::from_str(
            r#"{"headers":299,"chainstates":[
                {"blocks":150,"validated":true},
                {"blocks":299,
                 "snapshot_blockhash":
                    "3bb7ce5eba0be48939b7a521ac1ba9316afee2c7bada3a0cca24188e6d7d96c0",
                 "validated":false}
            ]}"#,
        )
        .unwrap();
        assert_eq!(syncing.block_data_available_height(), Some(150));

        // Right after `loadtxoutset` the background chainstate can be an
        // empty object (no tip yet): nothing but genesis is available.
        let fresh: Chainstates = serde_json::from_str(
            r#"{"headers":299,"chainstates":[
                {},
                {"blocks":299,
                 "snapshot_blockhash":
                    "3bb7ce5eba0be48939b7a521ac1ba9316afee2c7bada3a0cca24188e6d7d96c0",
                 "validated":false}
            ]}"#,
        )
        .unwrap();
        assert_eq!(fresh.block_data_available_height(), Some(0));
    }

    #[test]
    fn validated_snapshot_chainstate_has_all_block_data() {
        // Once background validation completes, the remaining chainstate may
        // still carry its snapshot_blockhash, but is fully validated.
        let merged: Chainstates = serde_json::from_str(
            r#"{"headers":300,"chainstates":[
                {"blocks":300,
                 "snapshot_blockhash":
                    "3bb7ce5eba0be48939b7a521ac1ba9316afee2c7bada3a0cca24188e6d7d96c0",
                 "validated":true}
            ]}"#,
        )
        .unwrap();
        assert_eq!(merged.block_data_available_height(), None);
    }

    /// Verbatim `getchainstates` output from a Bitcoin Core master node
    /// (v31.99.0-67efced1fc83) that loaded a regtest snapshot with base
    /// height 299 and then synced its snapshot chainstate on to height 399,
    /// while the background chainstate is still sitting at genesis.
    ///
    /// The same node, in this exact state, answered `getblock` with:
    ///
    ///   height   1  Block not available (not fully downloaded)
    ///   height 149  Block not available (not fully downloaded)
    ///   height 299  Block not available (not fully downloaded)
    ///   height 300  available
    ///   height 349  available
    ///   height 399  available
    ///
    /// Blocks above the snapshot base are downloaded and stored by the
    /// snapshot chainstate as it syncs to the tip, so they are readable the
    /// whole time the background chainstate is catching up.
    const BACKGROUND_AT_GENESIS_TIP_AT_399: &str = r#"{
        "headers": 399,
        "chainstates": [
            {"blocks": 0,
             "bestblockhash":
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
             "validated": true},
            {"blocks": 399,
             "bestblockhash":
                "2196b2ae5ac07980bcb65106a9638e24ff168834b4d433e59df73c3e33a5ef22",
             "snapshot_blockhash":
                "0c552ced4721c249a389eb9b08cb8da261cd46f0e7b5f9d064d48f3113406853",
             "validated": false}
        ]
    }"#;

    /// Block data above the snapshot base is available while the background
    /// chainstate is still behind, so it must not be gated on the background
    /// chainstate's height.
    #[test]
    fn block_data_above_the_snapshot_base_is_available_during_background_sync() {
        let chainstates: Chainstates =
            serde_json::from_str(BACKGROUND_AT_GENESIS_TIP_AT_399).unwrap();

        // Reading the capture back: the background chainstate is at genesis,
        // so nothing between 1 and the snapshot base can be served.
        let available = chainstates.block_data_available_height();

        // ...but the node served heights 300 through 399 in this same state.
        // Reporting a flat ceiling of 0 makes `sync_blocks` refuse every one
        // of them and poll `getchainstates` until background validation
        // completes, even though `getblock` would answer immediately.
        assert_ne!(
            available,
            Some(0),
            "heights 300..=399 are available on the node, so a ceiling of 0 \
             stalls the enforcer on block data it could fetch right now"
        );
    }

    /// An enforcer whose tip is already at or above the snapshot base has
    /// every block it still needs available on the node.
    #[test]
    fn enforcer_above_the_snapshot_base_is_not_blocked_by_background_sync() {
        let chainstates: Chainstates =
            serde_json::from_str(BACKGROUND_AT_GENESIS_TIP_AT_399).unwrap();

        // The state an operator lands in by re-bootstrapping an existing node
        // with `loadtxoutset` while keeping their enforcer data dir: the
        // enforcer's tip is 399 and it needs the next block on top.
        let next_needed_height = 400;
        let stalls = matches!(
            chainstates.block_data_available_height(),
            Some(available) if available < next_needed_height
        );
        assert!(
            !stalls,
            "the enforcer stalls waiting for the node's background sync while \
             the node can serve every block from the snapshot base upwards"
        );
    }
}
