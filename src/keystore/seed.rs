impl super::Keystore {
    pub fn save_seed_keystore(
        address: alloy::primitives::Address,
        // derivation_path: &str,
        seed: &[u8],
        dir: &std::path::PathBuf,
        password: &str,
    ) -> Result<crate::wallet::SeedWallet, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let name = Self::from_address_to_name(address, "seed");
        // let path = dir.path().join(name);
        crate::eth_keystore::encrypt_data(dir, &mut rng, seed, password, Some(&name))?;

        Ok(crate::wallet::SeedWallet {
            seed: seed.to_vec(),
            address,
        })
    }

    pub fn get_seed_keystore(
        address: alloy::primitives::Address,
        // derivation_path: &str,
        dir: &std::path::PathBuf,
        password: &str,
    ) -> Result<crate::wallet::SeedWallet, anyhow::Error> {
        let name = Self::from_address_to_name(address, "seed");
        let dir = std::path::Path::new(dir);
        let path = dir.join(name);
        println!("path: {path:?}, password: {password}");
        let seed = crate::eth_keystore::decrypt_data(path, password)?;
        Ok(crate::wallet::SeedWallet::from_seed(seed)?)
    }
}
