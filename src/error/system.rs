#[derive(Debug, thiserror::Error)]
pub enum SystemError {
    #[error("Database error: {0}")]
    Database(#[from] super::common::database::DatabaseError),
    #[error("Serde error: {0}")]
    Serde(#[from] super::common::serde::SerdeError),
    #[error("Parse error: {0}")]
    Parse(#[from] super::common::parse::ParseError),
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    // #[error("Payload failed: {0:?}")]
    // Payload(#[from] payload::error::PayloadError),
    // #[error("Net failed: {0:?}")]
    // Net(#[from] super::common::net::NetError),
    #[error("Service error: {0}")]
    Service(String),
}

impl SystemError {
    pub fn get_status_code(&self) -> u32 {
        match self {
            SystemError::Database(_) => 6300,
            SystemError::Parse(_) => 6300,
            // SystemError::Payload(_) => 6300,
            SystemError::Serde(_) => 6300,
            SystemError::IO(_) => 6300,
            SystemError::Service(_) => 6300,
            // SystemError::Net(_) => 6300,
        }
    }
}
