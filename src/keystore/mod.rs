pub mod derive;
pub mod seed;
pub mod signature;
pub mod transaction;

use std::path::{Path, PathBuf};

use alloy::{
    primitives::Address,
    signers::wallet::{MnemonicBuilder, Wallet},
};
use anyhow::anyhow;
use coins_bip39::Mnemonic;
use secp256k1::Secp256k1;

use crate::wallet::SeedWallet;

#[derive(Debug, Clone)]
pub(crate) struct Keystore {
    wallet_wrapper: Option<WalletWrapper>,
    _wordlist: crate::utils::language::WordlistWrapper,
}

#[derive(Debug, Clone)]
enum WalletWrapper {
    Root {
        pk_wallet: Wallet<alloy::signers::k256::ecdsa::SigningKey>,
        seed_wallet: SeedWallet,
    },
    Child {
        pk_wallet: Wallet<alloy::signers::k256::ecdsa::SigningKey>,
    },
}

impl Keystore {
    pub(crate) fn new(lang: &str) -> Result<Self, anyhow::Error> {
        let wordlist_wrapper = crate::utils::language::WordlistWrapper::new(lang);

        // tracing::info!("wordlist_wrapper: {wordlist_wrapper:#?}");
        Ok(Self {
            wallet_wrapper: None,
            _wordlist: wordlist_wrapper?,
        })
    }

    // pub(crate) fn get_name(&self) -> Result<String, anyhow::Error> {
    //     let Some(name) = &self.name else {
    //         return Err(anyhow!("No wallet"));
    //     };

    //     Ok(name.to_string())
    // }

    pub(crate) fn get_address(&self) -> Result<Address, anyhow::Error> {
        let Some(wallet) = &self.wallet_wrapper else {
            return Err(anyhow!("No wallet"));
        };

        let pk_wallet = match wallet {
            WalletWrapper::Root {
                pk_wallet,
                seed_wallet: _,
            } => pk_wallet,
            WalletWrapper::Child { pk_wallet } => pk_wallet,
        };

        Ok(pk_wallet.address())
    }

    // 创建根Keystore，密钥随机生成，并且保存到文件
    pub(crate) fn create_root_keystore_with_path(
        self,
        path: &str,
        password: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let (pk_wallet, _) = Wallet::new_keystore(path, &mut rng, password, None)?;
        // self.pk_wallet = Some(wallet);
        // self.wallet_wrapper = WalletWrapper::Root { pk_wallet, seed_wallet: () }
        Ok(self)
    }

    // 传入助记词、盐，生成密钥，创建根Keystore，并且保存到文件
    pub(crate) fn create_root_keystore_with_path_phrase(
        mut self,
        phrase: &str,
        salt: &str,
        path: &PathBuf,
        password: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let (master_key, seed) = self.phrase_to_master_key(phrase, salt)?;

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

        let (pk_wallet, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
            &path,
            &mut rng,
            private_key,
            password,
            Some(&name),
        )?;
        tracing::info!("地址：{}", address);

        let seed_wallet = Keystore::save_seed_keystore(address, seed.as_slice(), path, password)?;
        // crate::wallet_tree::manager::WalletTreeManager::fresh()?;

        self.wallet_wrapper = Some(WalletWrapper::Root {
            pk_wallet,
            seed_wallet,
        });
        Ok(self)
    }

    /// 验证助记词和盐生成的根私钥是否对应给定的地址。
    ///
    /// 该方法使用助记词和盐生成根私钥，并从根私钥派生出公钥地址，然后与提供的地址进行比较。
    ///
    /// # 参数
    ///
    /// * `phrase` - 助记词，用于生成根私钥。
    /// * `salt` - 盐，用于增加生成根私钥的复杂度。
    /// * `address` - 要验证的目标地址。
    ///
    /// # 返回值
    ///
    /// 如果生成的地址与提供的地址匹配，返回 `Ok(())`。否则，返回包含错误信息的 `Err`。
    ///
    /// # 错误
    ///
    /// 如果助记词或盐不正确，导致生成的地址与提供的地址不匹配，则返回包含错误信息的 `Err`。
    ///
    /// # 示例
    ///
    /// ```
    /// use your_crate::Keystore;
    /// use your_crate::Address;
    /// use anyhow::Result;
    ///
    /// fn example() -> Result<()> {
    ///     let keystore = Keystore::new("english")?;
    ///     let phrase = "shaft love depth mercy defy cargo strong control eye machine night test";
    ///     let salt = "salt";
    ///     let address = Address::from_str("0x...")?;
    ///
    ///     keystore.check_address(phrase, salt, address)?;
    ///     Ok(())
    /// }
    /// ```
    pub(crate) fn check_address(
        self,
        phrase: &str,
        salt: &str,
        address: Address,
    ) -> Result<(), anyhow::Error> {
        let (master_key, _) = self.phrase_to_master_key(phrase, salt)?;
        let signingkey: &coins_bip32::ecdsa::SigningKey = master_key.as_ref();
        // let private_key = signingkey.to_bytes();
        let wallet = Wallet::from_signing_key(signingkey.to_owned());
        let _address = wallet.address();

        tracing::info!("Generated address: {}", _address);
        tracing::info!("Provided address: {}", address);
        if _address.ne(&address) {
            return Err(anyhow!("Phrase or salt incorrect"));
        }
        Ok(())
    }

    pub(crate) fn from_address_to_name(
        address: &Address,
        // derivation_path: &str,
        suffix: &str,
    ) -> String {
        tracing::info!("from_signingkey_to_name: {:#?}", address);
        // let hash_name = Self::generate_hashed_filename(address, derivation_path);
        let name = format!("{}-{}", address.to_string(), suffix);
        name
    }

    pub(crate) fn from_address_and_derivation_path_to_name(
        address: Address,
        raw_derivation_path: &str,
        suffix: &str,
    ) -> String {
        tracing::info!("from_signingkey_to_name: {:#?}", address);
        // let hash_name = Self::generate_hashed_filename(address, derivation_path);
        // let name = format!("{}-{}", address.to_string(), suffix);

        let derivation_path =
            crate::utils::derivation::derivation_path_percent_encode(raw_derivation_path);

        let name = format!("{}-{}-{}", address, derivation_path, suffix);
        name
    }

    // 设置密码
    pub(crate) fn set_password(
        root_dir: PathBuf,
        subs_dir: PathBuf,
        wallet_tree: crate::wallet_tree::WalletTree,
        wallet_name: &str,
        address: Address,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), anyhow::Error> {
        let wallet = wallet_tree.get_wallet_branch(wallet_name)?;
        let account = wallet
            .get_account_with_address(&address)
            .ok_or(anyhow::anyhow!("No wallet"))?;

        tracing::info!("[set_password] account: {:?}", account);

        match &account {
            crate::wallet_tree::Account::Root(address) => {
                let pk = Keystore::get_pk(&account, old_password, &root_dir)?;
                let seed = Keystore::get_seed_with_password(address, old_password, &root_dir)?;

                let pk_filename = wallet.get_root_pk_filename();
                let seed_filename = wallet.get_root_seed_filename();

                let mut rng = rand::thread_rng();
                let (_, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
                    &root_dir,
                    &mut rng,
                    pk.as_slice(),
                    new_password,
                    Some(&pk_filename),
                )?;

                let (_, _) = SeedWallet::encrypt_keystore(
                    &root_dir,
                    &mut rng,
                    seed.as_slice(),
                    new_password,
                    Some(&seed_filename),
                )?;
            }
            crate::wallet_tree::Account::Sub(address, chain_code) => {
                let pk = Keystore::get_pk(&account, old_password, &subs_dir)?;

                let pk_filename = wallet.get_sub_pk_filename(address, &chain_code)?;

                let mut rng = rand::thread_rng();
                let (_, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
                    &subs_dir,
                    &mut rng,
                    pk.as_slice(),
                    new_password,
                    Some(&pk_filename),
                )?;
            }
        }
        // crate::wallet_tree::manager::WalletTreeManager::fresh()?;

        Ok(())
    }

    // 传入助记词、盐，生成密钥，创建根Keystore，但不生成keystore文件
    pub(crate) fn create_root_keystore_with_phrase_no_path<W: coins_bip39::Wordlist>(
        self,
        phrase: &str,
        salt: &str,
    ) -> Result<Self, anyhow::Error> {
        // 从助记词和盐生成种子
        if salt.is_empty() {
            return Err(anyhow!("salt should not be empty"));
        }
        let pk_wallet = MnemonicBuilder::<W>::default()
            .phrase(phrase)
            // Use this if your mnemonic is encrypted
            .password(salt)
            .build()?;

        // self.pk_wallet = Some(wallet);
        Ok(self)
    }

    // 助记词->Mnemonic->root key
    pub(crate) fn phrase_to_master_key(
        &self,
        phrase: &str,
        password: &str,
    ) -> Result<(coins_bip32::xkeys::XPriv, Vec<u8>), anyhow::Error> {
        Ok(match self._wordlist {
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

    // 获取密钥
    // TODO: 不用self
    pub(crate) fn get_private(self) -> Result<String, crate::Error> {
        let private_key = if let Some(wallet) = self.wallet_wrapper {
            let pk_wallet = match wallet {
                WalletWrapper::Root {
                    pk_wallet,
                    seed_wallet: _,
                } => pk_wallet,
                WalletWrapper::Child { pk_wallet } => pk_wallet,
            };
            pk_wallet
                .signer()
                .to_bytes()
                .iter()
                .map(|&i| format!("{:x}", i))
                .collect::<Vec<String>>()
                .join("")
        } else {
            String::new()
        };

        tracing::info!("打印出私钥：{:?}", private_key);
        Ok(private_key)
    }

    pub(crate) fn get_seed_with_password<P: AsRef<Path>>(
        address: &Address,
        password: &str,
        path: P,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let filename = Keystore::from_address_to_name(address, "seed");
        let path = path.as_ref().join(filename);
        let recovered_wallet = SeedWallet::decrypt_keystore(path, password)?;
        Ok(recovered_wallet.into_seed())
    }

    // 输入密码打开钱包
    pub(crate) fn get_pk<P: AsRef<Path>>(
        account: &crate::wallet_tree::Account,
        password: &str,
        path: P,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // let secret = eth_keystore::decrypt_key(path, password)?;
        let filename = account.generate_pk_filename();

        let path = path.as_ref().join(filename);

        tracing::info!("[get_pk_with_password] path: {path:?}");
        tracing::info!("[get_pk_with_password] password: {password:?}");

        let recovered_wallet = Wallet::decrypt_keystore(path, password)?;

        let key = recovered_wallet.signer().to_bytes();
        let private_key = key.to_vec();
        // let private_key = alloy::hex::encode(secret);
        // tracing::info!("十六进制主私钥: {:#?}", private_key);
        // let recovered_wallet = Wallet::decrypt_keystore(path, password)?;
        Ok(private_key)
    }

    /// 判断派生路径是否为根密钥路径
    ///
    /// # 参数
    /// - `derivation_path`: 派生路径
    ///
    /// # 返回
    /// 如果是根路径，返回 `true`，否则返回 `false`
    fn is_root_derivation_path(derivation_path: &str) -> bool {
        // BIP44 根路径格式: m/44'/coin_type'/account'/change/address_index
        let root_pattern = regex::Regex::new(r"^m/44'/\d+'/\d+'/?$").unwrap();
        root_pattern.is_match(derivation_path)
    }

    /// 根据地址和派生路径生成文件名
    ///
    /// # 参数
    /// - `address`: 以太坊地址
    /// - `derivation_path`: 派生路径
    ///
    /// # 返回
    /// 返回生成的文件名
    pub(crate) fn generate_hashed_filename(address: Address, derivation_path: &str) -> String {
        use sha2::{Digest, Sha256};
        // let input = format!("{}_{}", address.to_string(), derivation_path);
        let input = format!("{}", address.to_string());
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        hex::encode(result)
    }

    // 输入密码打开钱包
    pub(crate) fn open_with_password(
        password: &str,
        path: &PathBuf,
    ) -> Result<Wallet<alloy::signers::k256::ecdsa::SigningKey>, crate::Error> {
        let recovered_wallet = Wallet::decrypt_keystore(path, password)?;
        Ok(recovered_wallet)
    }

    // 检查本地根钱包的地址和所选的地址是否一致
    fn _check_root_wallet(self, address: &str) -> Result<(), anyhow::Error> {
        let address = address.parse::<Address>()?;
        let Some(wallet_wrapper) = &self.wallet_wrapper else {
            return Err(anyhow!("No wallet"));
        };

        let pk_wallet = match wallet_wrapper {
            WalletWrapper::Root {
                pk_wallet,
                seed_wallet: _,
            } => pk_wallet,
            WalletWrapper::Child { pk_wallet } => pk_wallet,
        };
        let local_address = pk_wallet.address();

        if address.ne(&local_address) {
            return Err(anyhow!(
                "The selected address is inconsistent with the root address of the local store"
            ));
        }

        Ok(())
    }

    pub(crate) fn listen() {}

    pub(crate) fn derive() {}

    pub(crate) fn gen_private_key() {
        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
        tracing::info!("sk: {sk:#?}");
    }
}

impl Keystore {}

#[cfg(test)]
mod test {
    use std::{
        fs::{self, read_to_string},
        path::PathBuf,
    };

    use alloy::{hex, primitives::Address, signers::wallet::Wallet};
    use coins_bip39::English;
    // use hdwallet::{traits::Serialize as _, KeyChain as _};
    use rand::thread_rng;
    use secp256k1::Secp256k1;
    use tempfile::tempdir;

    use crate::{
        init_log,
        keystore::WalletWrapper,
        wallet_manager::handler::tests::{
            print_dir_structure, setup_test_environment, TestData, TestEnv,
        },
    };

    use super::Keystore;

    /// 准备测试环境并生成根密钥库。
    fn setup_test_environment_and_create_keystore(
    ) -> Result<(TestData, Keystore, PathBuf), anyhow::Error> {
        let TestData {
            wallet_manager,
            env,
        } = setup_test_environment(Some("测试钱包".to_string()), 0, false)?;
        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type: _,
            account_index: _,
            password,
        } = &env;

        // 构建存储路径
        let path = wallet_manager.get_root_dir(wallet_name);
        let wallet_tree = wallet_manager.traverse_directory_structure()?;

        // 如果路径存在，清空目录
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;

        // 创建 Keystore 对象
        tracing::info!("path: {path:?}");
        let keystore = Keystore::new(&lang)?
            .create_root_keystore_with_path_phrase(&phrase, &salt, &path, &password)?;

        let subs_dir = wallet_manager.get_subs_dir(wallet_name);
        let derivation_path = "m/44'/60'/0'/0/1";
        crate::wallet_manager::handler::derive_subkey(
            path.clone(),
            subs_dir,
            wallet_tree,
            derivation_path,
            wallet_name,
            password,
            password,
        )?;
        let test_data = TestData {
            wallet_manager,
            env,
        };
        Ok((test_data, keystore, path))
    }

    #[test]
    fn test_gen_phrase() {
        let phrase = crate::wallet_manager::handler::gen_phrase("english").unwrap();
        tracing::info!("phrase: {}", phrase);
    }

    #[test]
    fn test_create_keystore_with_phrase_no_path() {
        // coins_bip32
        let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
        let salt = "";
        let lang = "english";
        let _res = Keystore::new(lang)
            .unwrap()
            .create_root_keystore_with_phrase_no_path::<English>(phrase, &salt)
            .unwrap();
    }

    #[test]
    fn test_create_root_keystore_with_path_phrase() -> Result<(), anyhow::Error> {
        // let derivation_path = "m/44'/60'/0'/0/0";
        // let derivation_path = "m/44'/60'/0'";

        // 调用公共函数设置测试环境并创建密钥库
        let (_, keystore, path) = setup_test_environment_and_create_keystore()?;

        // 检查返回值
        assert!(keystore.wallet_wrapper.is_some());

        // 打印生成的地址
        if let Some(WalletWrapper::Root { pk_wallet, .. }) = keystore.wallet_wrapper {
            tracing::info!("生成的地址: {}", pk_wallet.address());
        }

        // 打印生成的目录结构
        tracing::info!("Directory structure of '{}':", path.display());
        print_dir_structure(&path, 0);

        Ok(())
    }

    #[test]
    fn test_check_pk() -> Result<(), anyhow::Error> {
        // 测试参数
        let lang = "english";
        let phrase = "shaft love depth mercy defy cargo strong control eye machine night test";
        let salt = "";
        // let derivation_path = "m/44'/60'/0'/0/1";

        // 调用公共函数设置测试环境并创建密钥库
        let (_, keystore, _) = setup_test_environment_and_create_keystore()?;

        let address = keystore.get_address()?;

        // 验证生成的地址是否与提供的地址匹配
        Keystore::new(lang)?.check_address(phrase, salt, address)?;

        Ok(())
    }

    #[test]
    fn test_get_seed_keystore() {
        let address = "0x2A47C7a76Ea6994B16eEEDBfD75845B2bC591fDF";
        let address = address.parse::<Address>().unwrap();
        let _derivation_path = "m/44'/60'/0'/0/1";
        let password = "test";
        let dir = PathBuf::new().join("");
        let seed = Keystore::get_seed_keystore(address, &dir, password).unwrap();
        let seed = hex::encode(seed.seed());
        tracing::info!("seed: {seed}");
    }

    #[test]
    // TODO: 使其通过测试
    fn test_set_password() -> Result<(), anyhow::Error> {
        init_log();
        let (
            TestData {
                wallet_manager,
                env,
            },
            keystore,
            _path,
        ) = setup_test_environment_and_create_keystore()?;

        let TestEnv {
            lang: _,
            phrase: _,
            salt: _,
            wallet_name,
            coin_type: _,
            account_index: _,
            password,
        } = env;

        let wallet_tree = wallet_manager.traverse_directory_structure().unwrap();
        tracing::info!("[test_set_password] wallet_tree after: {wallet_tree:#?}");

        let wallet = wallet_tree.get_wallet_branch(&wallet_name).unwrap();
        let root_address = keystore.get_address().unwrap();

        let (chain_code, sub_address) = wallet.accounts.clone().pop_first().unwrap();

        let root_account = wallet.get_account_with_address(&root_address).unwrap();
        let sub_account = wallet.get_account_with_address(&sub_address).unwrap();

        let root_pk_file = wallet.get_root_pk_filename();
        let sub_pk_file = wallet
            .get_sub_pk_filename(&sub_address, &chain_code)
            .unwrap();
        tracing::info!("[test_set_password] root_pk_file: {root_pk_file}");
        tracing::info!("[test_set_password] sub_pk_file: {sub_pk_file}");
        let root_dir = wallet_manager.get_root_dir(&wallet_name);
        let subs_dir = wallet_manager.get_subs_dir(&wallet_name);

        tracing::info!("[test_set_password] root_dir: {root_dir:#?}");
        tracing::info!("[test_set_password] subs_dir: {subs_dir:#?}");

        //0xA933b676bE829a8203d8AA7501BD2A3671C77587-m%2F44%27%2F60%27%2F0%27%2F0%2F1-pk
        //0xA933b676bE829a8203d8AA7501BD2A3671C77587-m%252F44%2527%252F60%2527%252F0%2527%252F0%252F1-pk
        let old_root_pk = Keystore::get_pk(&root_account, &password, &root_dir).unwrap();
        let old_sub_pk = Keystore::get_pk(&sub_account, &password, &subs_dir).unwrap();

        let old_root_pk_str = alloy::hex::encode(old_root_pk);
        let old_sub_pk_str = alloy::hex::encode(old_sub_pk);
        tracing::info!("取出旧的根密钥： {old_root_pk_str}");
        tracing::info!("取出旧的子密钥： {old_sub_pk_str}");
        // let path = "7dcc4fe1-ea67-48d5-b086-b37cc93e4f32";
        // let old_password = "example_password";
        let new_password = "new_password";

        tracing::info!("[test_set_password] root_address: {root_address:#?}");
        tracing::info!("[test_set_password] sub_address: {sub_address:#?}");
        // 设置根密码
        wallet_manager.set_password(
            wallet_name.clone(),
            root_address.to_string(),
            password.clone(),
            new_password.to_owned(),
        );

        // 设置子密码
        wallet_manager.set_password(
            wallet_name,
            sub_address.to_string(),
            password,
            new_password.to_owned(),
        );

        // let path = "new_keystore";

        let root_pk = Keystore::get_pk(&root_account, new_password, root_dir).unwrap();
        tracing::info!("[test_set_password] sub_account: {sub_account:#?}, subs_dir: {subs_dir:?}");

        let sub_pk = Keystore::get_pk(&sub_account, new_password, subs_dir).unwrap();
        let root_pk_str = alloy::hex::encode(root_pk);
        let sub_pk_str = alloy::hex::encode(sub_pk);
        tracing::info!("设置根成功，取出密钥： {root_pk_str}");
        tracing::info!("设置子成功，取出密钥： {sub_pk_str}");

        Ok(())
    }

    #[test]
    fn test_derive_child_with_seed_and_chain_code_save() {
        // let phrase = "slam orient base razor trumpet swift second peasant amateur tape sweet enjoy";
        let seed = "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570";
        let seed = hex::decode(seed).unwrap();
        // let address = address!("2A47C7a76Ea6994B16eEEDBfD75845B2bC591fDF");

        let chain = "m/44'/60'/0'/0/1";
        // let lang = "english";
        // let _res = Keystore::new(lang)
        Keystore::derive_child_with_seed_and_chain_code_save(seed, chain, "", "test").unwrap();
    }

    #[test]
    fn test_derive_child_with_phrase_no_save() {
        // let phrase = "slam orient base razor trumpet swift second peasant amateur tape sweet enjoy";
        let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
        let chain = "m/44'/60'/0'/0/1";
        let lang = "english";
        let _res = Keystore::new(lang)
            .unwrap()
            ._derive_child_with_phrase_and_salt_no_save::<English>(phrase, "", chain)
            .unwrap();
    }

    #[test]
    fn test_gen() {
        let _mnemonic_phrase =
            "culture false mystery scrub kind pizza finger kit document fire debate cake";
        let seed_hex = "e61b56077fd615fa661b720d3021627d37bee396dcebd11a31f51355259712fe3b92f4cbd923dca32d6a80dfafbc0dd8f25a59aff331749c9afeef097a29d5d6";

        // 使用助记词生成种子
        // let mnemonic = coins_bip39::Mnemonic::<English>::new_from_phrase(mnemonic_phrase).unwrap();
        // let seed = Seed::new(&mnemonic, "");

        // 使用种子生成根私钥
        let _secp = Secp256k1::new();
        let mut private_key_bytes: [u8; 64] = [0; 64];
        let seed_slice = hex::decode(seed_hex).unwrap();
        private_key_bytes.copy_from_slice(&seed_slice);
        let secret_key = secp256k1::SecretKey::from_slice(&private_key_bytes).unwrap();
        // let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // 输出根私钥
        tracing::info!("Root Private Key: {:?}", secret_key);
    }

    #[test]
    fn test_hex() {
        let private_key = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        tracing::info!("private_key: {:#?}", private_key);
    }

    #[tokio::test]
    async fn test_sign_message() {
        let signer = alloy::signers::wallet::LocalWallet::random();
        let wallet = Keystore {
            wallet_wrapper: Some(crate::keystore::WalletWrapper::Child { pk_wallet: signer }),
            _wordlist: crate::utils::language::WordlistWrapper::English(English),
        };

        let res = wallet.sign_message("asd").await.unwrap();
        tracing::info!("private_key: {:#?}", res);
    }

    #[tokio::test]
    async fn add_money() {}

    #[tokio::test]
    async fn test_transaction() {
        let anvil = alloy::node_bindings::Anvil::new()
            .block_time(1)
            .try_spawn()
            .unwrap();

        let rpc_url = anvil.endpoint().parse().unwrap();
        let to = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let value = 100;
        let keystore_file_path =
            std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        tracing::info!("path: {:?}", keystore_file_path);
        let keystore_file_path = keystore_file_path
            // .join("6dab0ec3-ce31-4d24-ac4a-d4109446eca4")
            .join("alice.json");

        tracing::info!("keystore_file_path: {:?}", keystore_file_path);
        let lang = "english";
        let res = Keystore::new(lang)
            .unwrap()
            .transaction("test", &keystore_file_path, rpc_url, to, value)
            .await
            .unwrap();
        tracing::info!("private_key: {:#?}", res);
    }

    #[test]
    fn test_gen_private_key() {
        // let phrase = "culture false mystery scrub kind pizza finger kit document fire debate cake";
        // let password = "123";
        let _res = Keystore::gen_private_key();
    }

    #[test]
    fn test_create_keystore() -> Result<(), anyhow::Error> {
        let dir = tempdir()?;
        let mut rng = thread_rng();

        // Private key of Alice, the first default Anvil account.
        let private_key = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        // Password to encrypt the keystore file with.
        let password = "test";

        // Create a keystore file from the private key of Alice, returning a [Wallet] instance.
        let (wallet, file_path) =
            Wallet::encrypt_keystore(&dir, &mut rng, private_key, password, None)?;

        tracing::info!("file_path: {file_path}");
        let keystore_file_path = dir.path().join(file_path);

        tracing::info!(
            "Wrote keystore for {:?} to {:?}",
            wallet.address(),
            keystore_file_path
        );

        // Read the keystore file back.
        let recovered_wallet = Wallet::decrypt_keystore(keystore_file_path.clone(), password)?;

        tracing::info!(
            "Read keystore from {:?}, recovered address: {:?}",
            keystore_file_path,
            recovered_wallet.address()
        );

        // Assert that the address of the original key and the recovered key are the same.
        assert_eq!(wallet.address(), recovered_wallet.address());

        // Display the contents of the keystore file.
        let keystore_contents = read_to_string(keystore_file_path)?;

        tracing::info!("Keystore file contents: {keystore_contents:?}");
        Ok(())
    }
}

#[cfg(test)]
mod other_tests {

    // #[test]
    // fn test_hdwallet_gen_extended_privkey() {
    //     let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
    //     let mnemonic = Keystore::phrase_to_mnemonic(phrase).unwrap();

    // let seed = mnemonic.to_seed(None).unwrap();

    //     let root_key = hdwallet::ExtendedPrivKey::with_seed(&seed).unwrap();
    //     let key_chain = hdwallet::DefaultKeyChain::new(root_key);
    //     let (extended_key, _derivation) = key_chain
    //         .derive_private_key(hdwallet::ChainPath::from("m/44'/60'/0'/0/0"))
    //         .expect("fetch key");

    //     // let hardened_key_index = hdwallet::KeyIndex::from_index(0).unwrap();
    //     // let root_key = root_key.derive_private_key(hardened_key_index)?;
    //     tracing::info!(
    //         "Private key 0x{}\n",
    //         alloy::hex::encode(extended_key.serialize())
    //     );
    // }

    // #[test]
    // fn test_gen_master_key() {
    //     let provided_master_key_hex =
    //         "8b09ab2bfb613458f9362c4b79ff5ac8b8c6da10f25017807aa08cea969cd1ca";
    //         let provided_master_key_bytes = hex::decode(provided_master_key_hex).unwrap();
    //         let provided_master_key_bytes = provided_master_key_bytes.as_slice();
    //         let sign :coins_bip32::ecdsa::SigningKey= provided_master_key_bytes.try_into().unwrap();
    //     // 将提供的根私钥转换为XPriv类型
    //     let provided_master_key =
    //         coins_bip32::xkeys::XPriv::from_str(provided_master_key_hex).unwrap();
    // }

    // #[test]
    // fn test_create() {
    //     let phrase = Keystore::gen_phrase::<coins_bip39::English>();
    //     let salt = "Salt";
    //     let res = Keystore::create(&phrase, bip39::Language::English, salt);
    //     tracing::info!("res: {:#?}", res);
    // }

    // #[test]
    // fn test_create_root_keystore_with_path_phrase() {
    //     // let phrase = "slam orient base razor trumpet swift second peasant amateur tape sweet enjoy";
    //     let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
    //     // let chain = "m/44'/60'/0'/0/0";
    //     let lang = "english";
    //     let password = "test";
    //     let dir = PathBuf::new().join("");
    //     let keystore = Keystore::new(lang)
    //         .unwrap()
    //         .create_root_keystore_with_path_phrase(phrase, "", &dir, password)
    //         .unwrap();

    //     let address = keystore.get_address().unwrap();

    //     let seed = Keystore::get_seed_keystore(address, &dir, password).unwrap();
    //     let seed = hex::encode(seed.seed());
    //     tracing::info!("seed: {seed}");
    // }
}
