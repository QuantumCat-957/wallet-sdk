pub mod database;
pub mod parse;
pub mod serde;

#[derive(Debug, thiserror::Error)]
pub enum BadRequest {
    #[error("Parse error: {0}")]
    Parse(#[from] parse::ParseError),
    #[error("Database error: {0}")]
    Database(#[from] database::DatabaseError),
    #[error("Serde error: {0}")]
    Serde(#[from] serde::SerdeError),
}

impl BadRequest {
    pub fn get_status_code(&self) -> u32 {
        match self {
            BadRequest::Parse(msg) => msg.get_status_code(),
            BadRequest::Database(msg) => msg.get_status_code(),
            BadRequest::Serde(msg) => msg.get_status_code(),
        }
    }
}
