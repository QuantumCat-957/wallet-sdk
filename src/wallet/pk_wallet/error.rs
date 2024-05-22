use alloy::primitives::hex;
use alloy::signers::k256::ecdsa;
use thiserror::Error;

/// Error thrown by [`Wallet`](crate::Wallet).
#[derive(Debug, Error)]
pub enum WalletError {
    /// [`ecdsa`] error.
    #[error(transparent)]
    EcdsaError(#[from] ecdsa::Error),
    /// [`hex`](mod@hex) error.
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    /// [`std::io`] error.
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// [`coins_bip32`] error.
    #[error(transparent)]
    Bip32Error(#[from] coins_bip32::Bip32Error),
    /// [`coins_bip39`] error.
    #[error(transparent)]
    Bip39Error(#[from] coins_bip39::MnemonicError),
    /// [`MnemonicBuilder`](super::mnemonic::MnemonicBuilder) error.
    #[error(transparent)]
    MnemonicBuilderError(#[from] super::mnemonic::MnemonicBuilderError),

    /// [`eth_keystore`] error.
    #[error(transparent)]
    EthKeystoreError(#[from] eth_keystore::KeystoreError),
}
