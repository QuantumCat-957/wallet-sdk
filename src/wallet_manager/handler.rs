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
    lang: &str,
    count: usize,
) -> Result<super::response_struct::GeneratePhraseRes, crate::Error> {
    let lang = crate::utils::language::Language::from_str(lang)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    let phrases = lang
        .gen_phrase(count)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    Ok(super::response_struct::GeneratePhraseRes { phrases })
}

pub fn generate_root(
    storage_path: std::path::PathBuf,
    lang: &str,
    phrase: &str,
    salt: &str,
    password: &str,
) -> Result<alloy::primitives::Address, crate::Error> {
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
        lang,
        phrase,
        salt,
        &storage_path,
        password,
    )
    .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    Ok(keystore
        .get_address()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?)
}

pub fn reset_root(
    storage_path: std::path::PathBuf,
    lang: &str,
    phrase: &str,
    salt: &str,
    address: &str,
    new_password: &str,
) -> Result<alloy::primitives::Address, crate::Error> {
    // Parse the provided address
    let address = address
        .parse::<alloy::primitives::Address>()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Verify that the provided mnemonic phrase and salt generate the expected address
    crate::keystore::Keystore::check_address(lang, phrase, salt, address)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    tracing::info!("storage_path: {storage_path:?}");

    // Clear any existing keystore at the storage path
    if storage_path.exists() {
        std::fs::remove_dir_all(&storage_path)
            .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Remove the directory and its contents
    }
    std::fs::create_dir_all(&storage_path)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Recreate the directory

    // Create a new root keystore with the new password
    let wallet = crate::keystore::Keystore::create_root_keystore_with_path_phrase(
        lang,
        phrase,
        salt,
        &storage_path,
        new_password,
    )
    .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Return the address of the newly created keystore
    Ok(wallet
        .get_address()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?)
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
    let root_address = wallet.root_address;
    // Get the root keystore using the root password
    tracing::info!("[derive_subkey] root_address: {root_address:?}, root_dir: {root_dir:?}, root_password: {root_password}");
    let seed_wallet =
        crate::keystore::Keystore::get_seed_keystore(root_address, &root_dir, root_password)
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
        } = setup_test_environment(None, 0, false)?;
        let TestEnv {
            // storage_dir,
            lang,
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
