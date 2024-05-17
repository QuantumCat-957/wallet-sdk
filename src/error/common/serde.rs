#[derive(Debug, thiserror::Error)]
pub enum SerdeError {
    #[error("Json error")]
    Json(#[from] serde_json::Error),
    // #[error("Bson serialize error")]
    // BsonSer(#[from] bson::ser::Error),
    // #[error("Bson deserialize error")]
    // BsonDeser(#[from] bson::de::Error),
    #[error("Parse value to vector failed")]
    ValueToVecFailed,
}

impl SerdeError {
    pub fn get_status_code(&self) -> u32 {
        match self {
            SerdeError::Json(_) => 6061,
            // SerdeError::BsonSer(_) => 6061,
            // SerdeError::BsonDeser(_) => 6061,
            SerdeError::ValueToVecFailed => 6062,
        }
    }
}
