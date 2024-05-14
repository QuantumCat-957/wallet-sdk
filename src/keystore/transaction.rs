use alloy::{network::TransactionBuilder as _, providers::Provider as _};

impl super::Keystore {
    // 传入密码、keystore文件路径，交易
    pub async fn transaction(
        self,
        password: &str,
        path: &std::path::PathBuf,
        rpc_url: url::Url,
        to: &str,
        value: usize,
    ) -> Result<(), anyhow::Error> {
        let signer = crate::keystore::Keystore::open_with_password(password, path)?;
        let to = to.parse::<alloy::primitives::Address>()?;

        let address = signer.address();
        // Create a provider with the signer.
        let provider = alloy::providers::ProviderBuilder::new()
            .with_recommended_fillers()
            .signer(alloy::network::EthereumSigner::from(signer))
            .on_http(rpc_url);

        let tx = alloy::rpc::types::eth::TransactionRequest::default()
            .with_from(address)
            .with_to(to)
            .with_value(alloy::primitives::U256::from(value));

        // Send the transaction and wait for the receipt.
        let receipt = provider.send_transaction(tx).await?.get_receipt().await?;

        println!("Send transaction: {:?}", receipt.transaction_hash);

        Ok(())
    }
}
