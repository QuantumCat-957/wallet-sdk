impl super::Keystore {
    // 签名
    pub async fn sign_message(
        &self,
        message: &str,
    ) -> Result<alloy::primitives::Signature, anyhow::Error> {
        use alloy::signers::Signer;

        let Some(wallet_wrapper) = &self.wallet_wrapper else {
            return Err(anyhow::anyhow!("No wallet"));
        };

        let pk_wallet = match wallet_wrapper {
            crate::keystore::WalletWrapper::Root { pk_wallet } => pk_wallet,
            crate::keystore::WalletWrapper::Child { pk_wallet } => pk_wallet,
        };
        let signature = pk_wallet.sign_message(message.as_bytes()).await?;

        tracing::info!(
            "Signature produced by {:?}: {:?}",
            pk_wallet.address(),
            signature
        );
        tracing::info!(
            "Signature recovered address: {:?}",
            signature.recover_address_from_msg(message)?
        );

        Ok(signature)
    }
}
