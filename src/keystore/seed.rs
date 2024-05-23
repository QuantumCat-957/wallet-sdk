impl super::Keystore {
    pub fn save_seed_keystore(
        address: alloy::primitives::Address,
        // derivation_path: &str,
        seed: &[u8],
        dir: &std::path::PathBuf,
        password: &str,
    ) -> Result<crate::wallet::seed_wallet::SeedWallet, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let name =
            crate::wallet_tree::KeystoreInfo::new(crate::utils::file::Suffix::seed(), address)
                .from_address_to_name();
        // let path = dir.path().join(name);
        crate::eth_keystore::encrypt_data(dir, &mut rng, seed, password, Some(&name))?;

        Ok(crate::wallet::seed_wallet::SeedWallet {
            seed: seed.to_vec(),
            address,
        })
    }

    pub fn get_seed_keystore(
        address: &alloy::primitives::Address,
        // derivation_path: &str,
        dir: &std::path::PathBuf,
        password: &str,
    ) -> Result<crate::wallet::seed_wallet::SeedWallet, anyhow::Error> {
        let name =
            crate::wallet_tree::KeystoreInfo::new(crate::utils::file::Suffix::seed(), *address)
                .from_address_to_name();
        let dir = std::path::Path::new(dir);
        let path = dir.join(name);
        tracing::info!("[get_seed_keystore] path: {path:?}, password: {password}");
        let seed = crate::eth_keystore::decrypt_data(path, password)?;
        tracing::info!("[get_seed_keystore] seed: {seed:?}");
        Ok(crate::wallet::seed_wallet::SeedWallet::from_seed(seed)?)
    }

    pub(crate) fn get_seed_with_password<P: AsRef<std::path::Path>>(
        address: &alloy::primitives::Address,
        password: &str,
        path: P,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let filename =
            crate::wallet_tree::KeystoreInfo::new(crate::utils::file::Suffix::seed(), *address)
                .from_address_to_name();
        let path = path.as_ref().join(filename);
        let recovered_wallet =
            crate::wallet::seed_wallet::SeedWallet::decrypt_keystore(path, password)?;
        Ok(recovered_wallet.into_seed())
    }
}
