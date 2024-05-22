#[derive(Debug, serde::Serialize)]
pub struct GeneratePhraseRes {
    pub phrases: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct GenerateRootRes {
    pub address: alloy::primitives::Address,
}

#[derive(Debug, serde::Serialize)]
pub struct ResetRootRes {
    pub address: alloy::primitives::Address,
}

#[derive(Debug, serde::Serialize)]
pub struct DeriveSubkeyRes {
    pub address: alloy::primitives::Address,
    pub wallet_tree: crate::wallet_tree::WalletTree,
}
