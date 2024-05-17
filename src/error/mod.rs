pub(crate) mod bad_request;
pub(crate) mod common;
pub(crate) mod system;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Wallet error: `{0}`")]
    Wallet(#[from] alloy::signers::wallet::WalletError),
    #[error("Bip39 error: `{0}`")]
    Bip39(String),
    // 请求错误
    #[error("{0}")]
    BadRequest(#[from] bad_request::BadRequest),
    // 内部错误
    #[error("Server error: {0}")]
    System(#[from] system::SystemError),
    // 鉴权错误
    #[error("Unauthorized")]
    UnAuthorize,

    #[error("parse failed: {0:?}")]
    Parse(String),
    // #[error("Database error: {0}")]
    // Database(#[from] common::database::DatabaseError),
}
