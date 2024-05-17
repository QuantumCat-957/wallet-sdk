mod api;
mod error;
mod eth_keystore;
mod keystore;
mod signer;
mod utils;
mod wallet;
mod wallet_tree;

use error::Error;

pub use api::*;



pub(crate) fn init_log() {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .init();
}
