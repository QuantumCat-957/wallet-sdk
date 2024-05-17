use std::{fs, path::Path};

use alloy::primitives::Address;

use crate::keystore::Keystore;

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
pub fn init_resource(root: &str) -> Result<(), anyhow::Error> {
    let root = Path::new(root);
    crate::wallet_tree::manager::WALLET_TREE_MANAGER.get_or_try_init(|| {
        // let wallet_tree = crate::traverse_directory_structure(root)?;
        let manager = crate::wallet_tree::manager::WalletTreeManager::new();
        manager.init_resource(root)
    })?;
    Ok(())
}

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
pub fn gen_phrase(lang: &str) -> Result<String, anyhow::Error> {
    let lang = crate::utils::language::Language::from_str(lang)?;
    Ok(lang.gen_phrase())
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
pub fn generate_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    wallet_name: &str,
    password: &str,
) -> Result<String, anyhow::Error> {
    let derivation_path = "m/44'/60'/0'";

    // Construct the storage path based on the wallet name and derivation path
    let storage_path = Keystore::build_storage_path(wallet_name, derivation_path)?;

    tracing::info!("storage_path: {storage_path:?}");

    // Clear any existing keystore at the storage path
    if storage_path.exists() {
        fs::remove_dir_all(&storage_path)?; // Remove the directory and its contents
    }
    fs::create_dir_all(&storage_path)?; // Recreate the directory

    // Create a new root keystore
    let keystore = Keystore::new(lang)?.create_root_keystore_with_path_phrase(
        phrase,
        salt,
        &storage_path,
        password,
    )?;

    Ok(keystore.get_name()?)
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
pub fn reset_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    address: &str,
    wallet_name: &str,
    new_password: &str,
) -> Result<Address, anyhow::Error> {
    // Parse the provided address
    let address: Address = address.parse()?;

    // Verify that the provided mnemonic phrase and salt generate the expected address
    Keystore::new(lang)?.check_address(phrase, salt, address)?;

    let derivation_path = "m/44'/60'/0'";
    // Construct the storage path based on the wallet name and derivation path
    let storage_path = Keystore::build_storage_path(wallet_name, derivation_path)?;

    tracing::info!("storage_path: {storage_path:?}");

    // Clear any existing keystore at the storage path
    if storage_path.exists() {
        fs::remove_dir_all(&storage_path)?; // Remove the directory and its contents
    }
    fs::create_dir_all(&storage_path)?; // Recreate the directory

    // Create a new root keystore with the new password
    let wallet = Keystore::new(lang)?.create_root_keystore_with_path_phrase(
        phrase,
        salt,
        &storage_path,
        new_password,
    )?;

    // Return the address of the newly created keystore
    Ok(wallet.get_address()?)
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
pub fn set_password(
    wallet_name: &str,
    address: Address,
    old_password: &str,
    new_password: &str,
) -> Result<(), anyhow::Error> {
    // Set the password for the keystore associated with the specified address
    Keystore::set_password(wallet_name, address, old_password, new_password)?;

    Ok(())
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
pub fn derive_subkey(
    wallet_name: &str,
    root_password: &str,
    derive_password: &str,
) -> Result<Address, anyhow::Error> {
    // Retrieve the directory where the wallet data is stored
    let wallet_dir = crate::wallet_tree::manager::WalletTreeManager::get_wallet_dir()?;

    // Initialize an empty WalletTree structure
    let mut wallet_tree = crate::wallet_tree::WalletTree::default();

    // Traverse the directory structure to populate the wallet tree
    crate::wallet_tree::manager::WalletTreeManager::traverse_directory_structure(
        &mut wallet_tree,
        &wallet_dir,
    )?;

    // Get the root and subs directory paths for the specified wallet
    let root_dir = wallet_tree.get_root_dir(wallet_name);
    let subs_dir = wallet_tree.get_subs_dir(wallet_name);

    // Retrieve the wallet branch for the specified wallet
    let wallet = wallet_tree.get_wallet_branch(wallet_name)?;

    // Get the root keystore using the root password
    let seed_wallet = Keystore::get_seed_keystore(wallet.root_address, &root_dir, root_password)?;
    tracing::info!("seed_wallet: {seed_wallet:#?}");

    // Generate the next derivation path
    let chain_code = wallet.get_next_derivation_path();

    // Derive a new subkey using the seed and chain code, and save it with the derive password
    let seed_wallet = Keystore::derive_child_with_seed_and_chain_code_save(
        seed_wallet.seed,
        &chain_code,
        subs_dir.to_string_lossy().to_string().as_str(),
        derive_password,
    )?;

    // Return the address of the newly created subkey
    let address = seed_wallet.address();

    Ok(address)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::init_log;

    use super::*;
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

    fn setup_some_test_environment() -> Result<Vec<TestEnv>, anyhow::Error> {
        let env = vec![
            setup_test_environment(Some("钱包A".to_string()), 1, false)?,
            setup_test_environment(Some("钱包B".to_string()), 1, false)?,
            setup_test_environment(Some("钱包C".to_string()), 1, false)?,
        ];
        Ok(env)
    }

    pub(crate) fn setup_test_environment(
        mut wallet_name: Option<String>,
        account_index: u32,
        temp: bool,
    ) -> Result<TestEnv, anyhow::Error> {
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
        init_resource(&storage_dir.to_string_lossy().to_string())?;
        Ok(TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type,
            account_index,
            password,
        })
    }

    #[test]
    fn test_setup_some_test_environment() -> Result<()> {
        for env in setup_some_test_environment()? {
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
            generate_root(
                &lang,
                &phrase,
                &salt,
                // &storage_dir.to_string_lossy().to_string(),
                &wallet_name,
                &password,
            )?;
        }
        Ok(())
    }

    #[test]
    fn test_generate_root() -> Result<()> {
        init_log();
        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type: _,
            account_index: _,
            password,
        } = setup_test_environment(None, 0, false)?;

        // 调用 generate_root 函数
        let address = generate_root(
            &lang,
            &phrase,
            &salt,
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            &password,
        )?;
        tracing::info!("Generated address: {}", address);

        // 构建预期路径
        let expected_path = Keystore::build_storage_path(
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            "m/44'/60'/0'",
        )?;
        tracing::info!("expected_path: {:?}", expected_path);

        // 确认目录存在
        assert!(expected_path.exists());
        assert!(expected_path.is_dir());

        // 确认keystore文件存在
        let keystore_file = expected_path.join(address);
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
        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type: _,
            account_index: _,
            password,
        } = setup_test_environment(None, 0, false)?;

        let derivation_path = "m/44'/60'/0'";
        // 先生成一个根密钥库
        let keystore_name = generate_root(
            &lang,
            &phrase,
            &salt,
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            &password,
        )?;
        tracing::info!("Generated keystore_name for reset: {}", keystore_name);
        let storage_path = Keystore::build_storage_path(
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            derivation_path,
        )?
        .join(&keystore_name);

        let root_wallet = Keystore::open_with_password(&password, &storage_path)?;

        let address = root_wallet.address();

        // 重新设置新的密码并重置根密钥库
        let new_password = "new_example_password";
        let new_address = reset_root(
            &lang,
            &phrase,
            &salt,
            &address.to_string(),
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            new_password,
        )?;
        tracing::info!("New generated address: {}", new_address);
        assert_eq!(address, new_address);

        // 构建预期路径
        let expected_path = Keystore::build_storage_path(
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            "m/44'/60'/0'",
        )?;
        tracing::info!("expected_path: {:?}", expected_path);

        // 确认目录存在
        assert!(expected_path.exists());
        assert!(expected_path.is_dir());

        // 确认新的keystore文件存在
        let keystore_file = expected_path.join(keystore_name);
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
        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type: _,
            account_index: _,
            password,
        } = setup_test_environment(None, 0, true)?;

        let storage_dir = crate::wallet_tree::manager::WalletTreeManager::get_wallet_dir()?;
        // // 创建临时目录结构
        // let storage_dir = tempfile::tempdir_in(wallet_dir)?;
        // let storage_dir = storage_dir.path();

        tracing::info!("storage_dir: {storage_dir:#?}");

        let keystore_name = generate_root(
            &lang,
            &phrase,
            &salt,
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            &password,
        )?;

        tracing::info!("keystore_name: {keystore_name}");
        // 执行目录结构遍历
        let wallet_dir = crate::wallet_tree::manager::WalletTreeManager::get_wallet_dir()?;
        print_dir_structure(&wallet_dir, 0);

        // 测试派生子密钥
        let address = derive_subkey(&wallet_name, &password, "password123")?;

        // 验证派生的地址是否符合预期
        assert_eq!(
            address.to_string(),
            "0xA933b676bE829a8203d8AA7501BD2A3671C77587"
        );
        Ok(())
    }
}
