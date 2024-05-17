pub mod api;
pub mod error;
pub mod eth_keystore;
pub mod keystore;
pub mod signer;
pub mod utils;
pub mod wallet;
pub mod wallet_tree;

use error::Error;

pub(crate) fn init_log() {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .init();
}
