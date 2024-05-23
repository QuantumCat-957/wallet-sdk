// pub fn init_resource(root: &str) -> Result<(), crate::Error> {
//     let root = std::path::Path::new(root);
//     crate::wallet_tree::manager::WALLET_TREE_MANAGER
//         .get_or_try_init(|| {
//             // let wallet_tree = crate::traverse_directory_structure(root)?;
//             let manager = crate::wallet_tree::manager::WalletTreeManager::new();
//             manager.init_resource(root)
//         })
//         .map_err(|e| crate::SystemError::Service(e.to_string()))?;

//     Ok(())
// }

pub fn generate_phrase(
    language_code: u8,
    count: usize,
) -> Result<super::response_struct::GeneratePhraseRes, crate::Error> {
    let lang = crate::utils::language::Language::from_u8(language_code)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    let phrases = lang
        .gen_phrase(count)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    Ok(super::response_struct::GeneratePhraseRes { phrases })
}

pub fn query_phrases(
    language_code: u8,
    keyword: &str,
    mode: u8,
) -> Result<super::response_struct::QueryPhraseRes, crate::Error> {
    let wordlist_wrapper = crate::utils::language::WordlistWrapper::new(language_code)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;
    let mode = crate::utils::language::QueryMode::from_u8(mode)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    let phrases = wordlist_wrapper.query_phrase(keyword, mode);

    Ok(super::response_struct::QueryPhraseRes { phrases })
}

pub fn generate_root(
    storage_path: std::path::PathBuf,
    language_code: u8,
    phrase: &str,
    salt: &str,
    password: &str,
) -> Result<super::response_struct::GenerateRootRes, crate::Error> {
    tracing::info!("storage_path: {storage_path:?}");
    // Clear any existing keystore at the storage path
    if storage_path.exists() {
        std::fs::remove_dir_all(&storage_path)
            .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Remove the directory and its contents
    }
    std::fs::create_dir_all(&storage_path)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Recreate the directory

    // Create a new root keystore
    let keystore = crate::keystore::Keystore::create_root_keystore_with_path_phrase(
        language_code,
        phrase,
        salt,
        &storage_path,
        password,
    )
    .map_err(|e| crate::SystemError::Service(e.to_string()))?;
    let address = keystore
        .get_address()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    Ok(crate::wallet_manager::response_struct::GenerateRootRes { address })
}

pub fn reset_root(
    root_dir: std::path::PathBuf,
    subs_dir: std::path::PathBuf,
    wallet_tree: crate::wallet_tree::WalletTree,
    wallet_name: &str,
    language_code: u8,
    phrase: &str,
    salt: &str,
    root_address: &str,
    new_password: &str,
    subkey_password: Option<String>,
) -> Result<super::response_struct::ResetRootRes, crate::Error> {
    // Parse the provided address
    let root_address = root_address
        .parse::<alloy::primitives::Address>()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Verify that the provided mnemonic phrase and salt generate the expected address
    crate::keystore::Keystore::check_address(language_code, phrase, salt, root_address)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    tracing::info!("storage_path: {root_dir:?}");

    // Clear any existing keystore at the storage path
    if root_dir.exists() {
        std::fs::remove_dir_all(&root_dir)
            .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Remove the directory and its contents
    }
    std::fs::create_dir_all(&root_dir).map_err(|e| crate::SystemError::Service(e.to_string()))?; // Recreate the directory

    if subs_dir.exists() {
        if let Some(subkey_password) = subkey_password {
            // TODO: 批量设置子密钥密码
            // crate::keystore::Keystore::set_password(
            //     root_dir,
            //     subs_dir,
            //     wallet_tree,
            //     wallet_name,
            //     address,
            //     old_password,
            //     new_password,
            // )
            // .map_err(|e| crate::SystemError::Service(e.to_string()))?
        } else {
            crate::keystore::Keystore::deprecate_subkeys(
                wallet_tree,
                wallet_name,
                root_address,
                subs_dir,
            )
            .map_err(|e| crate::SystemError::Service(e.to_string()))?;
        }
    }

    // Create a new root keystore with the new password
    let wallet = crate::keystore::Keystore::create_root_keystore_with_path_phrase(
        language_code,
        phrase,
        salt,
        &root_dir,
        new_password,
    )
    .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Return the address of the newly created keystore
    let address = wallet
        .get_address()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    Ok(crate::wallet_manager::response_struct::ResetRootRes { address })
}

pub fn set_password(
    root_dir: std::path::PathBuf,
    subs_dir: std::path::PathBuf,
    wallet_tree: crate::wallet_tree::WalletTree,
    wallet_name: &str,
    address: &str,
    old_password: &str,
    new_password: &str,
) -> Result<(), crate::Error> {
    // Parse the provided address
    let address = address
        .parse::<alloy::primitives::Address>()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Set the password for the keystore associated with the specified address
    Ok(crate::keystore::Keystore::set_password(
        root_dir,
        subs_dir,
        wallet_tree,
        wallet_name,
        address,
        old_password,
        new_password,
    )
    .map_err(|e| crate::SystemError::Service(e.to_string()))?)
}

pub fn derive_subkey(
    root_dir: std::path::PathBuf,
    subs_dir: std::path::PathBuf,
    wallet_tree: crate::wallet_tree::WalletTree,
    derivation_path: &str,
    wallet_name: &str,
    root_password: &str,
    derive_password: &str,
) -> Result<alloy::primitives::Address, crate::Error> {
    // Retrieve the wallet branch for the specified wallet
    let wallet = wallet_tree
        .get_wallet_branch(wallet_name)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;
    let root_info = &wallet.root_info;
    // Get the root keystore using the root password
    tracing::info!("[derive_subkey] root_address: {root_info:?}, root_dir: {root_dir:?}, root_password: {root_password}");
    let seed_wallet =
        crate::keystore::Keystore::get_seed_keystore(&root_info.address, &root_dir, root_password)
            .map_err(|e| crate::SystemError::Service(e.to_string()))?;
    tracing::info!("seed_wallet: {seed_wallet:#?}");

    // Derive a new subkey using the seed and chain code, and save it with the derive password
    let seed_wallet = crate::keystore::Keystore::derive_child_with_seed_and_chain_code_save(
        seed_wallet.seed,
        derivation_path,
        subs_dir.to_string_lossy().to_string().as_str(),
        derive_password,
    )
    .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Return the address of the newly created subkey
    let address = seed_wallet.address();

    Ok(address)
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::init_log;
    use crate::keystore::Keystore;
    use crate::wallet_tree::KeystoreInfo;
    use crate::WalletManager;

    use anyhow::Result;
    use coins_bip39::English;
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
        pub(crate) language_code: u8,
        pub(crate) phrase: String,
        pub(crate) salt: String,
        pub(crate) wallet_name: String,
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
        let language_code = 1;
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

        let password = "example_password".to_string();
        tracing::info!("[setup_test_environment] storage_dir: {storage_dir:?}");
        let wallet_manager = WalletManager::new(storage_dir.to_string_lossy().to_string());
        let env = TestEnv {
            // storage_dir,
            language_code,
            phrase,
            salt,
            wallet_name,
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
                language_code,
                phrase,
                salt,
                wallet_name,
                password,
            } = env;

            // 调用 generate_root 函数
            wallet_manager.generate_root(
                language_code,
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
    fn query_phrase() -> Result<()> {
        let language_code = 1;
        let keyword = "ap";
        let mode = crate::utils::language::QueryMode::StartsWith;
        // 调用被测函数
        let result = crate::utils::language::WordlistWrapper::new(language_code)?
            .query_phrase(keyword, mode);
        println!("StartsWith result: {result:?}");

        let mode = crate::utils::language::QueryMode::Contains;
        // 调用被测函数
        let result = crate::utils::language::WordlistWrapper::new(language_code)?
            .query_phrase(keyword, mode);
        println!("Contains result: {result:?}");
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
            language_code: lang,
            phrase,
            salt,
            wallet_name,
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
        tracing::info!("Generated address: {}", address.address);

        // 构建预期路径
        let expected_path = wallet_manager.get_root_dir(&wallet_name);
        tracing::info!("expected_path: {:?}", expected_path);

        // 确认目录存在
        assert!(expected_path.exists());
        assert!(expected_path.is_dir());

        // 确认keystore文件存在
        let name = KeystoreInfo::new(crate::utils::file::Suffix::pk(), address.address)
            .from_address_to_name();
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
            language_code,
            phrase,
            salt,
            wallet_name,
            password,
        } = env;

        // 先生成一个根密钥库
        let address = wallet_manager
            .generate_root(
                language_code,
                phrase.clone(),
                salt.clone(),
                // &storage_dir.to_string_lossy().to_string(),
                wallet_name.clone(),
                password.clone(),
            )
            .result
            .unwrap();
        tracing::info!("Generated keystore_name for reset: {}", address.address);
        let root_path = wallet_manager.get_root_dir(&wallet_name);
        let subs_path = wallet_manager.get_subs_dir(&wallet_name);
        let wallet_tree = wallet_manager.traverse_directory_structure()?;

        let name = KeystoreInfo::new(crate::utils::file::Suffix::pk(), address.address)
            .from_address_to_name();
        let storage_path = root_path.join(&name);

        let root_wallet = Keystore::open_with_password(&password, &storage_path).unwrap();

        let address = root_wallet.address();

        // 重新设置新的密码并重置根密钥库
        let new_password = "new_example_password";
        let new_address = crate::wallet_manager::handler::reset_root(
            root_path.clone(),
            subs_path.clone(),
            wallet_tree,
            &wallet_name,
            language_code,
            &phrase,
            &salt,
            &address.to_string(),
            // &storage_dir.to_string_lossy().to_string(),
            new_password,
            None, // None,
        )?;
        tracing::info!("New generated address: {}", new_address.address);
        assert_eq!(address, new_address.address);

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
        assert_eq!(new_root_wallet.address(), new_address.address);

        Ok(())
    }

    #[test]
    fn test_derive_subkey() -> Result<(), anyhow::Error> {
        init_log();
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

        tracing::info!("keystore_name: {:?}", keystore_name.address);
        // 执行目录结构遍历
        print_dir_structure(&storage_dir, 0);

        derive_some_subkey(&wallet_manager, &wallet_name, &password)?;
        Ok(())
    }

    fn derive_subkey(
        wallet_manager: &WalletManager,
        wallet_name: &str,
        root_password: &str,
    ) -> Result<()> {
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
            &root_password,
            "password123",
        )?;

        // 验证派生的地址是否符合预期
        assert_eq!(
            address.to_string(),
            "0xA933b676bE829a8203d8AA7501BD2A3671C77587"
        );

        Ok(())
    }

    fn derive_some_subkey(
        wallet_manager: &WalletManager,
        wallet_name: &str,
        root_password: &str,
    ) -> Result<()> {
        let derivation_path = "m/44'/60'/0'/0/";
        for i in 1..5 {
            let path = format!("{derivation_path}{i}");
            // 测试派生子密钥
            let root_path = wallet_manager.get_root_dir(&wallet_name);
            let subs_path = wallet_manager.get_subs_dir(&wallet_name);
            let wallet_tree = wallet_manager.traverse_directory_structure()?;
            let address = crate::wallet_manager::handler::derive_subkey(
                root_path,
                subs_path,
                wallet_tree,
                &path,
                &wallet_name,
                root_password,
                "password123",
            )?;
        }

        Ok(())
    }
}
