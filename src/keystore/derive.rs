use crate::keystore::Keystore;

impl super::Keystore {
    // pub fn derive_child_with_address_and_save(
    //     mut self,
    //     chain: &str,
    //     root_path: &str,
    //     root_password: &str,
    //     child_password: &str,
    // ) -> Result<Self, anyhow::Error> {

    //     // let master_key = mnemonic.derive_key(chain, Some(salt))?;
    //     let root_wallet = Wallet::decrypt_keystore(root_path, root_password)?;

    //     let root_signer = root_wallet.signer();
    //     root_signer

    //     let signingkey: &coins_bip32::ecdsa::SigningKey = derive_key.as_ref();
    //     let private_key = signingkey.to_bytes();

    //     let key = alloy::hex::encode(private_key);
    //     println!("十六进制派生私钥: {:#?}", key);

    //     let (wallet, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
    //         path,
    //         &mut rng,
    //         private_key,
    //         password,
    //         None,
    //     )?;

    //     self.wallet = Some(wallet);
    //     Ok(self)
    // }

    // 传入助记词、盐、chain_code，由根私钥派生出子私钥，创建子Keystore，并生成keystore文件
    // pub fn derive_child_with_address_and_save(
    //     mut self,
    //     chain: &str,
    //     root_path: &str,
    //     root_password: &str,
    //     child_password: &str,
    // ) -> Result<Self, anyhow::Error> {

    //     // let master_key = mnemonic.derive_key(chain, Some(salt))?;
    //     let root_wallet = Wallet::decrypt_keystore(root_path, root_password)?;

    //     let root_signer = root_wallet.signer();
    //     root_signer

    //     let signingkey: &coins_bip32::ecdsa::SigningKey = derive_key.as_ref();
    //     let private_key = signingkey.to_bytes();

    //     let key = alloy::hex::encode(private_key);
    //     println!("十六进制派生私钥: {:#?}", key);

    //     let (wallet, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
    //         path,
    //         &mut rng,
    //         private_key,
    //         password,
    //         None,
    //     )?;

    //     self.wallet = Some(wallet);
    //     Ok(self)
    // }

    // 传入chain_code，由根私钥派生出子私钥，创建子Keystore，并生成keystore文件

    pub fn derive_child_with_seed_and_chain_code_save(
        // phrase: &str,
        // salt: &str,
        seed: Vec<u8>,
        derivation_path: &str,
        path: &str,
        password: &str,
    ) -> Result<
        alloy::signers::wallet::Wallet<alloy::signers::k256::ecdsa::SigningKey>,
        anyhow::Error,
    > {
        let seed_wallet = crate::wallet::SeedWallet::from_seed(seed)?;
        let derive_key = seed_wallet.derive_path(derivation_path)?;

        let mut rng = rand::thread_rng();
        // let master_key = self.phrase_to_master_key(phrase, salt)?;
        // let derive_key = mnemonic.derive_key(chain, Some(salt))?;

        // let mnemonic = Self::phrase_to_master_key(phrase, chain, Some(salt))?;
        // let master_key = mnemonic.derive_key(chain, Some(salt))?;

        let signingkey: &coins_bip32::ecdsa::SigningKey = derive_key.as_ref();

        let address = alloy::signers::utils::secret_key_to_address(&signingkey);

        let name =
            Keystore::from_address_and_derivation_path_to_name(address, derivation_path, "pk");

        let private_key = signingkey.to_bytes();

        let key = alloy::hex::encode(private_key);
        println!("十六进制派生私钥: {:#?}", key);

        let (wallet, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
            path,
            &mut rng,
            private_key,
            password,
            Some(&name),
        )?;

        Ok(wallet)
    }

    // 传入助记词、盐、派生路径，由根私钥派生出子私钥，创建子Keystore，不生成keystore文件
    pub(crate) fn derive_child_with_phrase_and_salt_no_save<W: coins_bip39::Wordlist>(
        mut self,
        phrase: &str,
        salt: &str,
        chain: &str,
    ) -> Result<Self, anyhow::Error> {
        let pk_wallet = alloy::signers::wallet::MnemonicBuilder::<W>::default()
            .phrase(phrase)
            .derivation_path(chain)?
            // Use this if your mnemonic is encrypted
            .password(salt)
            .build()?;

        let key = self.clone().get_private()?;
        println!("key: {key}");
        // self.wallet_wrapper = Some(WalletWrapper::Root {
        //     pk_wallet,
        //     seed_wallet,
        // });
        Ok(self)
    }
}
