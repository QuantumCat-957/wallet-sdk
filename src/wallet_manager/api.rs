use crate::response::Response;

impl super::WalletManager {
    /// Initializes the global wallet tree resource.
    ///
    /// This function sets up the global wallet tree by traversing the directory structure
    /// specified by the given root path. It ensures that the wallet tree is initialized
    /// only once. If the wallet tree has already been initialized, subsequent calls to this
    /// function will have no effect.
    ///
    /// # Arguments
    ///
    /// * `root` - A string slice that holds the path to the root directory containing the wallet structure.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the wallet tree was successfully initialized.
    /// * `Err` if there was an error during initialization.
    ///
    /// # Errors
    ///
    /// This function will return an error if there is a problem reading the directory structure,
    /// or if any of the required files are missing or cannot be processed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anyhow::Error;
    ///
    /// fn main() -> Result<(), Error> {
    ///     init_resource("/path/to/wallet/root")?;
    ///     // Now the wallet tree is initialized and ready to use.
    ///     Ok(())
    /// }
    /// ```
    // pub fn init_resource(root: &str) -> Response<()> {
    //     crate::wallet_manager::handler::init_resource(root)?.into()
    // }

    /// Generates a mnemonic phrase in the specified language.
    ///
    /// This function generates a mnemonic phrase for a specified language. The language
    /// is provided as a string, and the function converts it to the appropriate `Language`
    /// enum variant before generating the phrase.
    ///
    /// # Arguments
    ///
    /// * `lang` - A string slice that specifies the language for the mnemonic phrase.
    ///            The string should be a valid language code that the `Language` enum recognizes.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` containing the generated mnemonic phrase if the language conversion and phrase generation succeed.
    /// * `Err(anyhow::Error)` if an error occurs during the language conversion or phrase generation.
    ///
    /// # Errors
    ///
    /// This function will return an error if the provided language string is invalid or
    /// if there is an issue generating the mnemonic phrase.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Error;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let phrase = gen_phrase("en")?;
    ///     tracing::info!("Generated mnemonic phrase: {}", phrase);
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not explicitly panic. However, if the underlying implementation of
    /// `Language::from_str` or `Language::gen_phrase` panics, those panics will propagate.
    #[cfg(feature = "result")]
    pub fn gen_phrase(&self, lang: String) -> Result<String, crate::Error> {
        crate::wallet_manager::handler::gen_phrase(&lang)
    }
    #[cfg(not(feature = "result"))]
    pub fn gen_phrase(&self, lang: String) -> Response<String> {
        crate::wallet_manager::handler::gen_phrase(&lang)?.into()
    }
    /// Generates a root keystore based on the provided mnemonic phrase, salt, and password.
    ///
    /// This function creates a new root keystore using the specified mnemonic phrase, salt,
    /// and password. It constructs a storage path based on the wallet name and derivation path,
    /// removes any existing keystore at that path, and creates a new keystore.
    ///
    /// # Arguments
    ///
    /// * `lang` - A string slice that specifies the language for the mnemonic phrase.
    /// * `phrase` - A string slice representing the mnemonic phrase.
    /// * `salt` - A string slice used as a salt in the key derivation process.
    /// * `wallet_name` - A string slice representing the name of the wallet.
    /// * `password` - A string slice used to encrypt the keystore.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` containing the name of the created keystore if the process is successful.
    /// * `Err(anyhow::Error)` if an error occurs during the keystore creation process.
    ///
    /// # Errors
    ///
    /// This function will return an error if there are issues with the provided arguments,
    /// the storage path, or the keystore creation process.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Error;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let lang = "en";
    ///     let phrase = "example mnemonic phrase";
    ///     let salt = "random_salt";
    ///     let wallet_name = "my_wallet";
    ///     let password = "secure_password";
    ///     
    ///     let keystore_name = generate_root(lang, phrase, salt, wallet_name, password)?;
    ///     tracing::info!("Generated keystore: {}", keystore_name);
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not explicitly panic. However, if the underlying implementations of
    /// `Keystore::build_storage_path`, `fs::remove_dir_all`, or `Keystore::create_root_keystore_with_path_phrase` panic, those panics will propagate.
    #[cfg(feature = "result")]
    pub fn generate_root(
        &self,
        lang: String,
        phrase: String,
        salt: String,
        wallet_name: String,
        password: String,
    ) -> Result<alloy::primitives::Address, crate::Error> {
        let storage_path = self.get_root_dir(&wallet_name);
        crate::wallet_manager::handler::generate_root(
            storage_path,
            &lang,
            &phrase,
            &salt,
            &password,
        )
    }
    #[cfg(not(feature = "result"))]
    pub fn generate_root(
        &self,
        lang: String,
        phrase: String,
        salt: String,
        wallet_name: String,
        password: String,
    ) -> Response<alloy::primitives::Address> {
        let storage_path = self.get_root_dir(&wallet_name);
        crate::wallet_manager::handler::generate_root(
            storage_path,
            &lang,
            &phrase,
            &salt,
            &password,
        )?
        .into()
    }

    /// Resets the root keystore using the provided mnemonic phrase, salt, and new password.
    ///
    /// This function verifies the provided address against the mnemonic phrase and salt,
    /// clears any existing keystore at the derived storage path, and creates a new root keystore
    /// with the new password.
    ///
    /// # Arguments
    ///
    /// * `lang` - A string slice that specifies the language for the mnemonic phrase.
    /// * `phrase` - A string slice representing the mnemonic phrase.
    /// * `salt` - A string slice used as a salt in the key derivation process.
    /// * `address` - A string slice representing the expected address derived from the mnemonic phrase and salt.
    /// * `wallet_name` - A string slice representing the name of the wallet.
    /// * `new_password` - A string slice used to encrypt the new keystore.
    ///
    /// # Returns
    ///
    /// * `Ok(Address)` containing the address of the created keystore if the process is successful.
    /// * `Err(anyhow::Error)` if an error occurs during the keystore creation process or if the address verification fails.
    ///
    /// # Errors
    ///
    /// This function will return an error if there are issues with the provided arguments,
    /// the storage path, or the keystore creation process.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Error;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let lang = "en";
    ///     let phrase = "example mnemonic phrase";
    ///     let salt = "random_salt";
    ///     let address = "expected_address";
    ///     let wallet_name = "my_wallet";
    ///     let new_password = "new_secure_password";
    ///
    ///     let new_address = reset_root(lang, phrase, salt, address, wallet_name, new_password)?;
    ///     tracing::info!("New keystore address: {}", new_address);
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not explicitly panic. However, if the underlying implementations of
    /// `Keystore::build_storage_path`, `fs::remove_dir_all`, or `Keystore::create_root_keystore_with_path_phrase` panic, those panics will propagate.
    #[cfg(feature = "result")]
    pub fn reset_root(
        &self,
        lang: String,
        phrase: String,
        salt: String,
        address: String,
        wallet_name: String,
        new_password: String,
    ) -> Result<alloy::primitives::Address, crate::Error> {
        let storage_path = self.get_root_dir(&wallet_name);
        crate::wallet_manager::handler::reset_root(
            storage_path,
            &lang,
            &phrase,
            &salt,
            &address,
            &new_password,
        )
    }
    #[cfg(not(feature = "result"))]
    pub fn reset_root(
        &self,
        lang: String,
        phrase: String,
        salt: String,
        address: String,
        wallet_name: String,
        new_password: String,
    ) -> Response<alloy::primitives::Address> {
        let storage_path = self.get_root_dir(&wallet_name);
        crate::wallet_manager::handler::reset_root(
            storage_path,
            &lang,
            &phrase,
            &salt,
            &address,
            &new_password,
        )?
        .into()
    }

    /// Changes the password of the keystore associated with a specific address in a wallet.
    ///
    /// This function locates the keystore file associated with the given address within the specified wallet,
    /// verifies the old password, and updates it to the new password.
    ///
    /// # Arguments
    ///
    /// * `wallet_name` - A string slice representing the name of the wallet.
    /// * `address` - The `Address` associated with the keystore that needs a password change.
    /// * `old_password` - A string slice containing the current password of the keystore.
    /// * `new_password` - A string slice containing the new password to set for the keystore.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the password change is successful.
    /// * `Err(anyhow::Error)` if an error occurs during the password change process.
    ///
    /// # Errors
    ///
    /// This function will return an error if there are issues with locating the keystore,
    /// verifying the old password, or updating it to the new password.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Error;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let wallet_name = "my_wallet";
    ///     let address: Address = "0x1234...".parse()?;
    ///     let old_password = "old_password";
    ///     let new_password = "new_password";
    ///
    ///     set_password(wallet_name, address, old_password, new_password)?;
    ///     tracing::info!("Password changed successfully");
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not explicitly panic. However, if the underlying implementations of
    /// `Keystore::set_password` panic, those panics will propagate.
    #[cfg(feature = "result")]
    pub fn set_password(
        &self,
        wallet_name: String,
        address: String,
        old_password: String,
        new_password: String,
    ) -> Result<(), crate::Error> {
        let root_dir = self.get_root_dir(&wallet_name);
        let subs_path = self.get_subs_dir(&wallet_name);
        let wallet_tree = self.traverse_directory_structure()?;
        crate::wallet_manager::handler::set_password(
            root_dir,
            subs_path,
            wallet_tree,
            &wallet_name,
            &address,
            &old_password,
            &new_password,
        )
    }
    #[cfg(not(feature = "result"))]
    pub fn set_password(
        &self,
        wallet_name: String,
        address: String,
        old_password: String,
        new_password: String,
    ) -> Response<()> {
        let root_dir = self.get_root_dir(&wallet_name);
        let subs_path = self.get_subs_dir(&wallet_name);
        let wallet_tree = self.traverse_directory_structure()?;
        crate::wallet_manager::handler::set_password(
            root_dir,
            subs_path,
            wallet_tree,
            &wallet_name,
            &address,
            &old_password,
            &new_password,
        )?
        .into()
    }

    /// Derives a subkey from the root key of the specified wallet, saves it with a new password, and returns its address.
    ///
    /// This function locates the specified wallet, retrieves the root keystore using the provided root password,
    /// derives a new subkey using a chain code, saves the derived subkey with the specified derive password,
    /// and returns the address of the newly created subkey.
    ///
    /// # Arguments
    ///
    /// * `wallet_name` - A string slice representing the name of the wallet.
    /// * `root_password` - A string slice used to decrypt the root keystore.
    /// * `derive_password` - A string slice used to encrypt the derived subkey keystore.
    ///
    /// # Returns
    ///
    /// * `Ok(Address)` containing the address of the derived subkey if the process is successful.
    /// * `Err(anyhow::Error)` if an error occurs during the keystore retrieval, derivation, or saving process.
    ///
    /// # Errors
    ///
    /// This function will return an error if there are issues with locating the wallet,
    /// decrypting the root keystore, deriving the subkey, or saving the derived keystore.
    ///
    /// # Examples
    ///
    /// ```
    /// use anyhow::Error;
    ///
    /// fn main() -> Result<(), Error> {
    ///     let wallet_name = "my_wallet";
    ///     let root_password = "root_password";
    ///     let derive_password = "derive_password";
    ///
    ///     let address = derive_subkey(wallet_name, root_password, derive_password)?;
    ///     tracing::info!("Derived subkey address: {}", address);
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not explicitly panic. However, if the underlying implementations of
    /// `Keystore::get_seed_keystore`, `Keystore::derive_child_with_seed_and_chain_code_save`, or file system operations panic, those panics will propagate.
    #[cfg(feature = "result")]
    pub fn derive_subkey(
        &self,
        derivation_path: String,
        wallet_name: String,
        root_password: String,
        derive_password: String,
    ) -> Result<(alloy::primitives::Address, crate::wallet_tree::WalletTree), crate::Error> {
        let root_dir = self.get_root_dir(&wallet_name);
        let subs_path = self.get_subs_dir(&wallet_name);
        let wallet_tree = self.traverse_directory_structure()?;
        let address = crate::wallet_manager::handler::derive_subkey(
            root_dir,
            subs_path,
            wallet_tree,
            &derivation_path,
            &wallet_name,
            &root_password,
            &derive_password,
        )?;
        let wallet_tree = self.traverse_directory_structure()?;
        Ok((address, wallet_tree))
    }
    #[cfg(not(feature = "result"))]
    pub fn derive_subkey(
        &self,
        derivation_path: String,
        wallet_name: String,
        root_password: String,
        derive_password: String,
    ) -> Response<(alloy::primitives::Address, crate::wallet_tree::WalletTree)> {
        let root_dir = self.get_root_dir(&wallet_name);
        let subs_path = self.get_subs_dir(&wallet_name);
        let wallet_tree = self.traverse_directory_structure()?;
        let address = crate::wallet_manager::handler::derive_subkey(
            root_dir,
            subs_path,
            wallet_tree,
            &derivation_path,
            &wallet_name,
            &root_password,
            &derive_password,
        )?;
        let wallet_tree = self.traverse_directory_structure()?;
        Ok((address, wallet_tree)).into()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::init_log;
    use crate::keystore::Keystore;
    use crate::WalletManager;

    use anyhow::Result;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};

    pub(crate) fn print_dir_structure(dir: &Path, level: usize) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    for _ in 0..level {
                        print!("  ");
                    }
                    if path.is_dir() {
                        tracing::info!("{}/", path.file_name().unwrap().to_string_lossy());
                        print_dir_structure(&path, level + 1);
                    } else {
                        tracing::info!("{}", path.file_name().unwrap().to_string_lossy());
                    }
                }
            }
        }
    }

    pub(crate) struct TestData {
        pub(crate) wallet_manager: WalletManager,
        pub(crate) env: TestEnv,
    }

    pub(crate) struct TestEnv {
        // pub(crate) storage_dir: PathBuf,
        pub(crate) lang: String,
        pub(crate) phrase: String,
        pub(crate) salt: String,
        pub(crate) wallet_name: String,
        pub(crate) coin_type: u32,
        pub(crate) account_index: u32,
        pub(crate) password: String,
    }

    fn setup_some_test_environment() -> Result<Vec<TestData>, anyhow::Error> {
        let test_data = vec![
            setup_test_environment(Some("钱包A".to_string()), 1, false)?,
            setup_test_environment(Some("钱包B".to_string()), 1, false)?,
            setup_test_environment(Some("钱包C".to_string()), 1, false)?,
        ];
        Ok(test_data)
    }

    pub(crate) fn setup_test_environment(
        mut wallet_name: Option<String>,
        account_index: u32,
        temp: bool,
    ) -> Result<TestData, anyhow::Error> {
        // 获取项目根目录
        let storage_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("test_data");

        // 创建测试目录
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir)?;
        }

        // 测试参数
        let lang = "english".to_string();
        let phrase =
            "shaft love depth mercy defy cargo strong control eye machine night test".to_string();
        let salt = "".to_string();
        if temp {
            tracing::info!("storage_dir: {storage_dir:?}");
            // 创建临时目录结构
            let temm_dir = tempfile::tempdir_in(&storage_dir)?;
            wallet_name = temm_dir
                .path()
                .file_name()
                .map(|name| name.to_string_lossy().to_string());
        }
        let wallet_name = wallet_name.unwrap_or("example_wallet".to_string());
        let coin_type = 60; // 60 是以太坊的 coin_type
        let password = "example_password".to_string();
        tracing::info!("[setup_test_environment] storage_dir: {storage_dir:?}");
        let wallet_manager = WalletManager::new(storage_dir.to_string_lossy().to_string());
        let env = TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type,
            account_index,
            password,
        };
        Ok(TestData {
            wallet_manager,
            env,
        })
    }

    #[test]
    fn test_setup_some_test_environment() -> Result<()> {
        for test_data in setup_some_test_environment()? {
            let TestData {
                wallet_manager,
                env,
            } = test_data;

            let TestEnv {
                // storage_dir,
                lang,
                phrase,
                salt,
                wallet_name,
                coin_type: _,
                account_index: _,
                password,
            } = env;

            // 调用 generate_root 函数
            wallet_manager.generate_root(
                lang,
                phrase,
                salt,
                // &storage_dir.to_string_lossy().to_string(),
                wallet_name,
                password,
            );
        }
        Ok(())
    }

    #[test]
    fn test_generate_root() -> Result<()> {
        init_log();
        let test_data = setup_test_environment(None, 0, false)?;

        let TestData {
            wallet_manager,
            env,
        } = test_data;

        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type: _,
            account_index: _,
            password,
        } = env;

        // 调用 generate_root 函数
        let address = wallet_manager
            .generate_root(
                lang,
                phrase,
                salt,
                // &storage_dir.to_string_lossy().to_string(),
                wallet_name.clone(),
                password,
            )
            .result
            .unwrap();
        tracing::info!("Generated address: {}", address);

        // 构建预期路径
        let expected_path = wallet_manager.get_root_dir(&wallet_name);
        tracing::info!("expected_path: {:?}", expected_path);

        // 确认目录存在
        assert!(expected_path.exists());
        assert!(expected_path.is_dir());

        // 确认keystore文件存在
        let name = Keystore::from_address_to_name(&address, "pk");
        let keystore_file = expected_path.join(name);
        assert!(keystore_file.exists());
        assert!(keystore_file.is_file());

        // 打印目录结构
        tracing::info!("Directory structure of '{}':", expected_path.display());
        print_dir_structure(&expected_path, 0);

        // 清理测试目录
        // fs::remove_dir_all(&expected_path)?;

        Ok(())
    }

    #[test]
    fn test_reset_root() -> Result<(), anyhow::Error> {
        init_log();
        let TestData {
            wallet_manager,
            env,
        } = setup_test_environment(None, 0, false)?;

        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type: _,
            account_index: _,
            password,
        } = env;

        // 先生成一个根密钥库
        let address = wallet_manager
            .generate_root(
                lang.clone(),
                phrase.clone(),
                salt.clone(),
                // &storage_dir.to_string_lossy().to_string(),
                wallet_name.clone(),
                password.clone(),
            )
            .result
            .unwrap();
        tracing::info!("Generated keystore_name for reset: {}", address);
        let root_path = wallet_manager.get_root_dir(&wallet_name);
        let name = Keystore::from_address_to_name(&address, "pk");
        let storage_path = root_path.join(&name);

        let root_wallet = Keystore::open_with_password(&password, &storage_path).unwrap();

        let address = root_wallet.address();

        // 重新设置新的密码并重置根密钥库
        let new_password = "new_example_password";
        let new_address = crate::wallet_manager::handler::reset_root(
            root_path.clone(),
            &lang,
            &phrase,
            &salt,
            &address.to_string(),
            // &storage_dir.to_string_lossy().to_string(),
            new_password,
        )?;
        tracing::info!("New generated address: {}", new_address);
        assert_eq!(address, new_address);

        // 构建预期路径
        let expected_path = root_path;
        tracing::info!("expected_path: {:?}", expected_path);

        // 确认目录存在
        assert!(expected_path.exists());
        assert!(expected_path.is_dir());

        // 确认新的keystore文件存在
        let keystore_file = expected_path.join(name);
        assert!(keystore_file.exists());
        assert!(keystore_file.is_file());

        // 打印目录结构
        tracing::info!("Directory structure of '{}':", expected_path.display());
        print_dir_structure(&expected_path, 0);

        // 使用新密码打开keystore文件
        let new_root_wallet = Keystore::open_with_password(new_password, &keystore_file)?;
        assert_eq!(new_root_wallet.address(), new_address);

        Ok(())
    }

    #[test]
    fn test_derive_subkey() -> Result<(), anyhow::Error> {
        let TestData {
            wallet_manager,
            env,
        } = setup_test_environment(None, 0, true)?;
        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type: _,
            account_index: _,
            password,
        } = env;
        let storage_dir = wallet_manager.get_wallet_dir();
        // // 创建临时目录结构
        // let storage_dir = tempfile::tempdir_in(wallet_dir)?;
        // let storage_dir = storage_dir.path();

        tracing::info!("storage_dir: {storage_dir:#?}");

        let keystore_name = wallet_manager
            .generate_root(
                lang,
                phrase,
                salt,
                // &storage_dir.to_string_lossy().to_string(),
                wallet_name.clone(),
                password.clone(),
            )
            .result
            .unwrap();

        tracing::info!("keystore_name: {keystore_name}");
        // 执行目录结构遍历
        print_dir_structure(&storage_dir, 0);

        let derivation_path = "m/44'/60'/0'/0/1";
        // 测试派生子密钥
        let root_path = wallet_manager.get_root_dir(&wallet_name);
        let subs_path = wallet_manager.get_subs_dir(&wallet_name);
        let wallet_tree = wallet_manager.traverse_directory_structure()?;
        let address = crate::wallet_manager::handler::derive_subkey(
            root_path,
            subs_path,
            wallet_tree,
            derivation_path,
            &wallet_name,
            &password,
            "password123",
        )?;

        // 验证派生的地址是否符合预期
        assert_eq!(
            address.to_string(),
            "0xA933b676bE829a8203d8AA7501BD2A3671C77587"
        );
        Ok(())
    }
}