use crate::wallet::pk_wallet::PkWallet;
use coins_bip39::Mnemonic;

use crate::keystore::{Keystore, WalletWrapper};

impl Keystore {
    // 创建根Keystore，密钥随机生成，并且保存到文件
    pub(crate) fn create_root_keystore_with_path(
        self,
        path: &str,
        password: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let (pk_wallet, _) = PkWallet::new_keystore(path, &mut rng, password, None)?;
        // self.pk_wallet = Some(wallet);
        // self.wallet_wrapper = WalletWrapper::Root { pk_wallet, seed_wallet: () }
        Ok(self)
    }

    // 传入助记词、盐，生成密钥，创建根Keystore，并且保存到文件
    pub(crate) fn create_root_keystore_with_path_phrase(
        lang: &str,
        phrase: &str,
        salt: &str,
        path: &std::path::PathBuf,
        password: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let (master_key, seed) = Self::phrase_to_master_key(lang, phrase, salt)?;

        // let seed = mnemonic.to_seed(Some(salt))?;
        let seed_str = alloy::hex::encode(&seed);
        tracing::info!("种子：{seed_str}");
        // let chain = "m/44'/60'/0'/0/0";

        // let master_key = master_key.derive_path(chain)?;

        // let master_key = mnemonic.derive_key(chain, Some(salt))?;
        let signingkey: &coins_bip32::ecdsa::SigningKey = master_key.as_ref();
        let private_key = signingkey.to_bytes();

        // let key: &coins_bip32::prelude::SigningKey = master_key.as_ref();
        let key = alloy::hex::encode(private_key);

        tracing::info!("master key: {:#?}", key);

        // tracing::info!("十六进制主私钥: {:#?}", private_key);
        // let signer = alloy::signers::k256::schnorr::SigningKey::from_bytes(&key.to_bytes())?;

        // let address = secret_key_to_address(&signer);
        // Ok(Wallet::<SigningKey> { signer, address, chain_id: None })

        let address = alloy::signers::utils::secret_key_to_address(signingkey);
        let name = Self::from_address_to_name(&address, "pk");

        let (pk_wallet, _) = crate::wallet::pk_wallet::PkWallet::encrypt_keystore(
            &path,
            &mut rng,
            private_key,
            password,
            Some(&name),
        )?;
        tracing::info!("地址：{}", address);

        let seed_wallet = Keystore::save_seed_keystore(address, seed.as_slice(), path, password)?;
        // crate::wallet_tree::manager::WalletTreeManager::fresh()?;

        Ok(Self {
            wallet_wrapper: Some(WalletWrapper::Root {
                pk_wallet,
                // seed_wallet,
            }),
        })
    }

    // 传入助记词、盐，生成密钥，创建根Keystore，但不生成keystore文件
    pub(crate) fn create_root_keystore_with_phrase_no_path<W: coins_bip39::Wordlist>(
        phrase: &str,
        salt: &str,
    ) -> Result<Self, anyhow::Error> {
        // 从助记词和盐生成种子
        if salt.is_empty() {
            return Err(anyhow::anyhow!("salt should not be empty"));
        }
        let pk_wallet = crate::wallet::pk_wallet::MnemonicBuilder::<W>::default()
            .phrase(phrase)
            // Use this if your mnemonic is encrypted
            .password(salt)
            .build()?;

        // self.pk_wallet = Some(wallet);

        Ok(Self {
            wallet_wrapper: Some(WalletWrapper::Root {
                pk_wallet: pk_wallet,
                // seed_wallet: (),
            }),
        })
    }

    // 助记词->Mnemonic->root key
    pub(crate) fn phrase_to_master_key(
        lang: &str,
        phrase: &str,
        password: &str,
    ) -> Result<(coins_bip32::xkeys::XPriv, Vec<u8>), anyhow::Error> {
        let wordlist_wrapper = crate::utils::language::WordlistWrapper::new(lang)?;
        Ok(match wordlist_wrapper {
            crate::utils::language::WordlistWrapper::English(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                // let seed = seed;
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::ChineseSimplified(_) => {
                let mnemonic = Mnemonic::<coins_bip39::ChineseSimplified>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::ChineseTraditional(_) => {
                let mnemonic =
                    Mnemonic::<coins_bip39::ChineseTraditional>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::Czech(_) => {
                let mnemonic = Mnemonic::<coins_bip39::Czech>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::French(_) => {
                let mnemonic = Mnemonic::<coins_bip39::French>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::Italian(_) => {
                let mnemonic = Mnemonic::<coins_bip39::Italian>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::Japanese(_) => {
                let mnemonic = Mnemonic::<coins_bip39::Japanese>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::Korean(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::Portuguese(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
            crate::utils::language::WordlistWrapper::Spanish(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                let seed = mnemonic.to_seed(Some(password))?.to_vec();
                (mnemonic.master_key(Some(password))?, seed)
            }
        })
    }
}
