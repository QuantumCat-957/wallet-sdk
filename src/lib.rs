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

use error::{common::parse::ParseError, system::SystemError, Error};

pub use wallet_manager::WalletManager;
pub use response::Response;

pub(crate) fn init_log() {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .init();
}
