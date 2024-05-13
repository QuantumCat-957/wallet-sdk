pub mod api;
pub mod error;
pub mod eth_keystore;
pub mod keystore;
pub mod language;
pub mod signer;
pub mod wallet;

use error::Error;

/// Utility to get and set the chain ID on a transaction and the resulting signature within a
/// signer's `sign_transaction`.
#[macro_export]
macro_rules! sign_transaction_with_chain_id {
    // async (
    //    signer: impl Signer,
    //    tx: &mut impl SignableTransaction<Signature>,
    //    sign: lazy Signature,
    // )
    ($signer:expr, $tx:expr, $sign:expr) => {{
        if let Some(chain_id) = $signer.chain_id() {
            if !$tx.set_chain_id_checked(chain_id) {
                return Err(alloy::signers::Error::TransactionChainIdMismatch {
                    signer: chain_id,
                    // we can only end up here if the tx has a chain id
                    tx: $tx.chain_id().unwrap(),
                });
            }
        }

        let mut sig = $sign.map_err(alloy::signers::Error::other)?;

        if let Some(chain_id) = $signer.chain_id().or_else(|| $tx.chain_id()) {
            sig = sig.with_chain_id(chain_id);
        }

        Ok(sig)
    }};
}
