#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Wallet error: `{0}`")]
    Wallet(#[from] alloy::signers::wallet::WalletError),
    #[error("Bip39 error: `{0}`")]
    Bip39(String),
}
