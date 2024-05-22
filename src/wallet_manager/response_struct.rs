#[derive(Debug, serde::Serialize)]
pub struct GeneratePhraseRes {
    pub phrases: Vec<String>,
}
