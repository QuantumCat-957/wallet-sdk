use std::{fs, path::Path};

use alloy::primitives::Address;

use crate::keystore::Keystore;

/// 初始化资源并生成 `WalletTree`
///
/// 该函数会遍历指定目录结构，生成 `WalletTree` 并将其存储在全局静态变量 `WALLET_TREE` 中。
/// 如果 `WALLET_TREE` 已经初始化，则直接返回现有的 `WalletTree`。
///
/// # 参数
///
/// * `root` - 包含钱包数据的根目录路径。
///
/// # 返回
///
/// 如果成功，返回对 `WalletTree` 的不可变引用。
///
/// # 错误
///
/// 如果遍历目录结构时出错，或者 `WalletTree` 初始化失败，会返回一个 `anyhow::Error`。
///
/// # 示例
///
/// ```rust
/// let wallet_tree = init_resource("/path/to/wallets")?;
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

/// 生成助记词。
///
/// 该函数根据指定的语言生成一个助记词字符串。
///
/// # 参数
///
/// - `lang`: 指定生成助记词的语言，如 "english"。
///
/// # 返回
///
/// 如果成功生成助记词，则返回包含助记词的 `Ok(String)`。
/// 如果出现错误，则返回 `Err(anyhow::Error)`。
///
/// # 示例
///
/// ```rust
/// # use your_crate_name::gen_phrase;
/// # fn main() -> Result<(), anyhow::Error> {
/// let phrase = gen_phrase("english")?;
/// println!("Generated phrase: {}", phrase);
/// # Ok(())
/// # }
/// ```
pub fn gen_phrase(lang: &str) -> Result<String, anyhow::Error> {
    let lang = crate::utils::language::Language::from_str(lang)?;
    Ok(lang.gen_phrase())
}

/// 生成根密钥库
///
/// 这个函数根据提供的语言、助记词、盐、存储目录、钱包名称、账户索引和密码生成一个新的根密钥库。
///
/// # 参数
/// - `lang`: 语言，用于生成助记词的语言，如 "english"。
/// - `phrase`: 助记词，用于生成根密钥的助记词字符串。
/// - `salt`: 盐，用于生成根密钥的盐值。
/// - `storage_dir`: 存储目录，根密钥库的存储路径。
/// - `wallet_name`: 钱包名称，用于标识不同的钱包。
/// - `password`: 密码，用于加密根密钥库。
///
/// # 返回
/// 返回一个 `Result<String, anyhow::Error>`，表示生成的根密钥库的名称或生成过程中发生的错误。
///
/// # 示例
/// ```
/// let keystore_name = generate_root(
///     "english",
///     "shaft love depth mercy defy cargo strong control eye machine night test",
///     "salt",
///     "/path/to/storage",
///     "example_wallet",
///     "example_password"
/// )?;
/// println!("Generated keystore name: {}", keystore_name);
/// ```
///
/// # 错误
/// 如果在生成过程中发生任何错误，将返回相应的 `anyhow::Error`。
pub fn generate_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    wallet_name: &str,
    password: &str,
) -> Result<String, anyhow::Error> {
    let derivation_path = "m/44'/60'/0'";
    // 构建存储路径
    let storage_path = Keystore::build_storage_path(wallet_name, derivation_path)?;

    println!("storage_path: {storage_path:?}");
    // 清空该存储路径下的keystore
    if storage_path.exists() {
        fs::remove_dir_all(&storage_path)?; // 删除目录及其内容
    }
    fs::create_dir_all(&storage_path)?; // 重新创建目录

    // 重新创建root
    // let bip44_path = format!("m/44'/{}'/{}'/0/0", coin_type, account_index);
    let keystore = Keystore::new(lang)?.create_root_keystore_with_path_phrase(
        phrase,
        salt,
        &storage_path,
        // derivation_path,
        password,
    )?;

    Ok(keystore.get_name()?)
}

/// 通过验证提供的助记词和盐来重置根密钥库，并在指定的存储路径上用新密码重新创建密钥库。
///
/// # 参数
///
/// * `lang` - 助记词的语言。
/// * `phrase` - 助记词。
/// * `salt` - 用于密钥派生的盐值。
/// * `address` - 从助记词和盐派生的预期地址。
/// * `storage_dir` - 存储密钥库的基础目录。
/// * `wallet_name` - 钱包名称。
/// * `coin_type` - 币种类型（例如，以太坊的 coin_type 是 60）。
/// * `account_index` - 账户索引。
/// * `new_password` - 用于加密密钥库的新密码。
///
/// # 返回值
///
/// * `Result<Address, anyhow::Error>` - 成功时返回新创建的密钥库的地址，失败时返回错误。
///
/// # 错误
///
/// 如果出现以下情况，该函数将返回错误：
/// * 提供的助记词和盐不能生成预期的地址。
/// * 解析提供的地址时出错。
/// * 清空或创建存储目录时出错。
/// * 创建新密钥库时出错。
pub fn reset_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    address: &str,
    wallet_name: &str,
    new_password: &str,
) -> Result<Address, anyhow::Error> {
    // 解析提供的地址
    let address: Address = address.parse()?;

    // 验证提供的助记词和盐生成预期的地址
    Keystore::new(lang)?.check_address(phrase, salt, address)?;

    let derivation_path = "m/44'/60'/0'";
    // 构建存储路径
    let storage_path = Keystore::build_storage_path(wallet_name, derivation_path)?;

    println!("storage_path: {storage_path:?}");

    // 如果存储路径存在，清空该路径下的密钥库
    if storage_path.exists() {
        fs::remove_dir_all(&storage_path)?; // 删除目录及其内容
    }
    fs::create_dir_all(&storage_path)?; // 重新创建目录

    // 用新密码重新创建根密钥库
    let wallet = Keystore::new(lang)?.create_root_keystore_with_path_phrase(
        phrase,
        salt,
        &storage_path,
        // derivation_path,
        new_password,
    )?;

    // 返回新创建的密钥库的地址
    Ok(wallet.get_address()?)
}

/// 修改根密码
pub fn set_root_password(
    lang: &str,
    path: &str,
    old_password: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    Ok(())
}

/// 修改密码
pub fn set_password(
    wallet_name: &str,
    address: Address,
    old_password: &str,
    new_password: &str,
) -> Result<(), anyhow::Error> {
    Keystore::set_password(wallet_name, address, old_password, new_password)?;

    // let file_path = address.to_string();
    // let pk = Keystore::get_pk_with_password(old_password, &file_path)?;
    // TODO: 删除旧keystore
    // let secret = eth_keystore::decrypt_key(keypath, password)?;

    // let pk_filename =

    Ok(())
}

/// 派生子密钥
pub fn derive_subkey(
    wallet_name: &str,
    root_password: &str,
    derive_password: &str,
) -> Result<Address, anyhow::Error> {
    // if let Some(wallet_brach) = wallet_tree.get(wallet_name){
    //     let root_seed =
    // }
    let wallet_dir = crate::wallet_tree::manager::WalletTreeManager::get_wallet_dir()?;
    let mut wallet_tree = crate::wallet_tree::WalletTree::default();
    crate::wallet_tree::manager::WalletTreeManager::traverse_directory_structure(
        &mut wallet_tree,
        &wallet_dir,
    )?;

    let root_dir = wallet_tree.get_root_dir(wallet_name);
    let subs_dir = wallet_tree.get_subs_dir(wallet_name);
    let wallet = wallet_tree.get_wallet_branch(wallet_name)?;

    // let pk_filename = wallet.get_root_pk_filename();
    let seed_wallet = Keystore::get_seed_keystore(wallet.root_address, &root_dir, root_password)?;
    println!("seed_wallet: {seed_wallet:#?}");

    let chain_code = wallet.get_next_derivation_path();

    let seed_wallet = Keystore::derive_child_with_seed_and_chain_code_save(
        seed_wallet.seed,
        &chain_code,
        subs_dir.to_string_lossy().to_string().as_str(),
        derive_password,
    )?;

    let address = seed_wallet.address();

    Ok(address)
}

#[cfg(test)]
pub(crate) mod tests {
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
                        println!("{}/", path.file_name().unwrap().to_string_lossy());
                        print_dir_structure(&path, level + 1);
                    } else {
                        println!("{}", path.file_name().unwrap().to_string_lossy());
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
            println!("storage_dir: {storage_dir:?}");
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
        println!("[setup_test_environment] storage_dir: {storage_dir:?}");
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
                coin_type,
                account_index,
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
        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type,
            account_index,
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
        println!("Generated address: {}", address);

        // 构建预期路径
        let expected_path = Keystore::build_storage_path(
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            "m/44'/60'/0'",
        )?;
        println!("expected_path: {:?}", expected_path);

        // 确认目录存在
        assert!(expected_path.exists());
        assert!(expected_path.is_dir());

        // 确认keystore文件存在
        let keystore_file = expected_path.join(address);
        assert!(keystore_file.exists());
        assert!(keystore_file.is_file());

        // 打印目录结构
        println!("Directory structure of '{}':", expected_path.display());
        print_dir_structure(&expected_path, 0);

        // 清理测试目录
        // fs::remove_dir_all(&expected_path)?;

        Ok(())
    }

    #[test]
    fn test_reset_root() -> Result<(), anyhow::Error> {
        let TestEnv {
            // storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type,
            account_index,
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
        println!("Generated keystore_name for reset: {}", keystore_name);
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
        println!("New generated address: {}", new_address);
        assert_eq!(address, new_address);

        // 构建预期路径
        let expected_path = Keystore::build_storage_path(
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            "m/44'/60'/0'",
        )?;
        println!("expected_path: {:?}", expected_path);

        // 确认目录存在
        assert!(expected_path.exists());
        assert!(expected_path.is_dir());

        // 确认新的keystore文件存在
        let keystore_file = expected_path.join(keystore_name);
        assert!(keystore_file.exists());
        assert!(keystore_file.is_file());

        // 打印目录结构
        println!("Directory structure of '{}':", expected_path.display());
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
            coin_type,
            account_index,
            password,
        } = setup_test_environment(None, 0, true)?;

        let storage_dir = crate::wallet_tree::manager::WalletTreeManager::get_wallet_dir()?;
        // // 创建临时目录结构
        // let storage_dir = tempfile::tempdir_in(wallet_dir)?;
        // let storage_dir = storage_dir.path();

        println!("storage_dir: {storage_dir:#?}");

        let keystore_name = generate_root(
            &lang,
            &phrase,
            &salt,
            // &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            &password,
        )?;

        println!("keystore_name: {keystore_name}");
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
