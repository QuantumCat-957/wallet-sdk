use crate::response::Response;

impl super::WalletManager {
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
    pub fn generate_phrase(
        &self,
        lang: String,
        count: usize,
    ) -> Result<super::response_struct::GeneratePhraseRes, crate::Error> {
        crate::wallet_manager::handler::generate_phrase(language_code, count)
    }
    #[cfg(not(feature = "result"))]
    pub fn generate_phrase(
        &self,
        language_code: u8,
        count: usize,
    ) -> Response<super::response_struct::GeneratePhraseRes> {
        crate::wallet_manager::handler::generate_phrase(language_code, count)?.into()
    }

    /// 查询助记词短语。
    ///
    /// # 参数
    ///
    /// * `lang` - 指定语言的字符串。
    /// * `keyword` - 要查询的关键字字符串。
    /// * `mode` - 查询模式，0表示只匹配以关键字开头的短语，1表示匹配包含关键字的短语。
    ///
    /// # 返回
    ///
    /// 返回包含查询结果的响应结构体。
    ///
    /// # 错误
    ///
    /// 如果查询过程中出现任何错误，则返回相应的错误响应。
    #[cfg(feature = "result")]
    pub fn query_phrases(
        &self,
        language_code: u8,
        keyword: String,
        mode: u8,
    ) -> Result<super::response_struct::QueryPhraseRes, crate::Error> {
        crate::wallet_manager::handler::query_phrases(language_code, &keyword, mode)
    }
    #[cfg(not(feature = "result"))]
    pub fn query_phrases(
        &self,
        language_code: u8,
        keyword: String,
        mode: u8,
    ) -> Response<super::response_struct::QueryPhraseRes> {
        crate::wallet_manager::handler::query_phrases(language_code, &keyword, mode)?.into()
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
    ) -> Result<super::response_struct::GenerateRootRes, crate::Error> {
        let storage_path = self.get_root_dir(&wallet_name);
        crate::wallet_manager::handler::generate_root(
            storage_path,
            language_code,
            &phrase,
            &salt,
            &password,
        )
    }
    #[cfg(not(feature = "result"))]
    pub fn generate_root(
        &self,
        language_code: u8,
        phrase: String,
        salt: String,
        wallet_name: String,
        password: String,
    ) -> Response<super::response_struct::GenerateRootRes> {
        let storage_path = self.get_root_dir(&wallet_name);
        crate::wallet_manager::handler::generate_root(
            storage_path,
            language_code,
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
        subkey_password: Option<String>,
    ) -> Result<super::response_struct::ResetRootRes, crate::Error> {
        let root_path = self.get_root_dir(&wallet_name);
        let subs_path = self.get_subs_dir(&wallet_name);
        let wallet_tree = self.traverse_directory_structure()?;
        crate::wallet_manager::handler::reset_root(
            root_path,
            subs_path,
            wallet_tree,
            &wallet_name,
            language_code,
            &phrase,
            &salt,
            &address,
            &new_password,
            subkey_password,
        )
    }
    #[cfg(not(feature = "result"))]
    pub fn reset_root(
        &self,
        language_code: u8,
        phrase: String,
        salt: String,
        address: String,
        wallet_name: String,
        new_password: String,
        subkey_password: Option<String>,
    ) -> Response<super::response_struct::ResetRootRes> {
        let root_path = self.get_root_dir(&wallet_name);
        let subs_path = self.get_subs_dir(&wallet_name);
        let wallet_tree = self.traverse_directory_structure()?;
        crate::wallet_manager::handler::reset_root(
            root_path,
            subs_path,
            wallet_tree,
            &wallet_name,
            language_code,
            &phrase,
            &salt,
            &address,
            &new_password,
            subkey_password,
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
    ) -> Result<super::response_struct::DeriveSubkeyRes, crate::Error> {
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
    ) -> Response<super::response_struct::DeriveSubkeyRes> {
        let root_dir = self.get_root_dir(&wallet_name);
        let subs_path = self.get_subs_dir(&wallet_name);
        if !root_dir.exists() {
            std::fs::create_dir_all(&root_dir).map_err(|e| crate::Error::System(e.into()))?;
        }
        if !subs_path.exists() {
            std::fs::create_dir_all(&subs_path).map_err(|e| crate::Error::System(e.into()))?;
        }
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

        Ok(super::response_struct::DeriveSubkeyRes {
            address,
            wallet_tree,
        })
        .into()
    }
}

#[cfg(test)]
mod test {
    use crate::wallet_manager::handler::tests::{setup_test_environment, TestData, TestEnv};

    #[test]
    fn test_reset_root() -> Result<(), anyhow::Error> {
        let TestData {
            wallet_manager,
            env,
        } = setup_test_environment(None, 0, false)?;
        let TestEnv {
            // storage_dir,
            language_code,
            phrase,
            salt,
            wallet_name,
            password,
        } = env;
        let storage_dir = wallet_manager.get_wallet_dir();
        let keystore_name = wallet_manager
            .generate_root(
                1,
                "shaft love depth mercy defy cargo strong control eye machine night test"
                    .to_string(),
                "".to_string(),
                // &storage_dir.to_string_lossy().to_string(),
                "test".to_string(),
                "passwd".to_string(),
            )
            .result
            .unwrap();
        let new_passwd = "new_passwd".to_string();
        let address = wallet_manager
            .reset_root(
                1,
                "shaft love depth mercy defy cargo strong control eye machine night test"
                    .to_string(),
                "".to_string(),
                "0xfc6A4Ed634335cde2701553B7dbB2C362510FBd9".to_string(),
                "example_wallet".to_string(),
                new_passwd,
                None,
            )
            .result
            .unwrap();

        Ok(())
    }

    #[test]
    fn test_derive_subkey() -> Result<(), anyhow::Error> {
        let TestData {
            wallet_manager,
            env,
        } = setup_test_environment(None, 0, false)?;
        let TestEnv {
            // storage_dir,
            language_code: lang,
            phrase,
            salt,
            wallet_name,
            password,
        } = env;
        let storage_dir = wallet_manager.get_wallet_dir();
        let keystore_name = wallet_manager
            .generate_root(
                1,
                "shaft love depth mercy defy cargo strong control eye machine night test"
                    .to_string(),
                "".to_string(),
                // &storage_dir.to_string_lossy().to_string(),
                "test".to_string(),
                "passwd".to_string(),
            )
            .result
            .unwrap();
        let derive_passwd = "passwd".to_string();
        let address = wallet_manager
            .derive_subkey(
                "m/44'/60'/0'/0/1".to_string(),
                "test".to_string(),
                "passwd".to_string(),
                "passwd".to_string(),
            )
            .result
            .unwrap();

        Ok(())
    }
}
