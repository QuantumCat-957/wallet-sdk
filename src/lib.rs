#![feature(try_trait_v2)]
mod error;
mod eth_keystore;
mod keystore;
mod response;
mod signer;
mod utils;
mod wallet;
mod wallet_manager;
mod wallet_tree;

pub use error::{common::parse::ParseError, system::SystemError, Error};

pub use alloy::primitives::Address;
pub use response::Response;
pub use wallet_manager::WalletManager;

pub fn init_log() {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .init();
}

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

        if $tx.use_eip155() {
            if let Some(chain_id) = $signer.chain_id().or_else(|| $tx.chain_id()) {
                sig = sig.with_chain_id(chain_id);
            }
        }

        Ok(sig)
    }};
}
