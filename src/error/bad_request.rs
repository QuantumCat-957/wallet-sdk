#[derive(Debug, thiserror::Error)]
pub enum BadRequest {
    // #[error("Community error: {0}")]
    // Community(#[from] super::api::community::CommunityError),
    // #[error("Account error: {0}")]
    // Account(#[from] super::api::account::AccountError),
}

impl BadRequest {
    // pub(crate) fn get_status_code(&self) -> u32 {
    //     match self {
    //         BadRequest::InitDatabase(msg) => msg.get_status_code(),
    //     }
    // }
}
