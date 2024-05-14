use std::{fs, path::PathBuf};

use alloy::primitives::Address;

use crate::{keystore::Keystore, language::WordlistWrapper};

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
    let lang = crate::language::Language::from_str(lang)?;
    Ok(lang.gen_phrase())
}

/// 生成根密钥。
///
/// 该函数用于生成根密钥，并重新创建根密钥存储。
///
/// # 参数
///
/// - `lang`: 使用的语言，如英语或中文。
/// - `phrase`: 用于生成根密钥的助记词。
/// - `salt`: 用于加密助记词的盐。
/// - `storage_dir`: 存储根密钥的路径，由调用者指定的目录。
/// - `wallet_name`: 钱包名称。
/// - `coin_type`: 币种类型，比如0代表比特币，60代表以太坊。
/// - `account_index`: 账户索引，用于生成不同的子地址。
/// - `password`: 用于加密根密钥的密码。
///
/// # 返回
///
/// 如果成功生成并存储根密钥，则返回`Ok(keystore_name)`，其中`keystore_name`是生成的keystore的名称；
/// 否则返回错误。
///
/// # 注意
///
/// 在生成新的根密钥前，该存储路径下现有的keystore将被清空。
///
/// # 示例
///
/// ```rust
/// # use your_crate_name::generate_root;
/// # use std::path::Path;
/// # fn main() -> Result<(), anyhow::Error> {
/// let lang = "english";
/// let phrase = "example phrase";
/// let salt = "example salt";
/// let storage_dir = "/path/to/storage";
/// let wallet_name = "example_wallet";
/// let coin_type = 60; // 60 是以太坊的 coin_type
/// let account_index = 0;
/// let password = "example_password";
///
/// let keystore_name = generate_root(
///     lang,
///     phrase,
///     salt,
///     storage_dir,
///     wallet_name,
///     coin_type,
///     account_index,
///     password
/// )?;
///
/// println!("Keystore created with name: {}", keystore_name);
/// # Ok(())
/// # }
/// ```
pub fn generate_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    storage_dir: &str,
    wallet_name: &str,
    coin_type: u32,
    account_index: u32,
    password: &str,
) -> Result<String, anyhow::Error> {
    // 构建存储路径
    let storage_path =
        Keystore::build_storage_path(storage_dir, wallet_name, coin_type, account_index);

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
    storage_dir: &str,
    wallet_name: &str,
    coin_type: u32,
    account_index: u32,
    new_password: &str,
) -> Result<Address, anyhow::Error> {
    // 解析提供的地址
    let address: Address = address.parse()?;

    // 验证提供的助记词和盐生成预期的地址
    Keystore::new(lang)?.check_address(phrase, salt, address)?;

    // 构建存储路径
    let storage_path =
        Keystore::build_storage_path(storage_dir, wallet_name, coin_type, account_index);

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
    address: Address,
    old_password: &str,
    new_password: &str,
    name: &str,
) -> Result<(), anyhow::Error> {
    let file_path = address.to_string();
    let pk = Keystore::get_pk_with_password(old_password, &file_path)?;

    Keystore::set_password(pk, &file_path, new_password, name)?;
    // TODO: 删除旧keystore
    // let secret = eth_keystore::decrypt_key(keypath, password)?;
    Ok(())
}

/// 派生子密钥
// pub fn derive(password: &str) -> Result<Address, anyhow::Error> {
//     // 找到根keystore文件，根密钥只用来派生
//     let root_path = "";
//     let address = "";
//     let address = address.parse::<Address>()?;

//     let seed_wallet = Keystore::get_seed_keystore(address, root_path, password)?;

//     let chain_code = "";
//     // 获取根seed
//     let seed_wallet = Keystore::derive_child_with_seed_and_chain_code_save(
//         seed_wallet.seed,
//         chain_code,
//         root_path,
//         password,
//     )?;

//     let address = seed_wallet.address();

//     Ok(address)
// }

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn print_dir_structure(dir: &Path, level: usize) {
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

    fn setup_test_environment(
    ) -> Result<(PathBuf, String, String, String, String, u32, u32, String), anyhow::Error> {
        // 获取项目根目录
        let storage_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);

        // 创建测试目录
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir)?;
        }

        // 测试参数
        let lang = "english".to_string();
        let phrase =
            "shaft love depth mercy defy cargo strong control eye machine night test".to_string();
        let salt = "salt".to_string();
        let wallet_name = "example_wallet".to_string();
        let coin_type = 60; // 60 是以太坊的 coin_type
        let account_index = 0;
        let password = "example_password".to_string();

        Ok((
            storage_dir,
            lang,
            phrase,
            salt,
            wallet_name,
            coin_type,
            account_index,
            password,
        ))
    }

    #[test]
    fn test_generate_root() -> Result<()> {
        let (storage_dir, lang, phrase, salt, wallet_name, coin_type, account_index, password) =
            setup_test_environment()?;

        // 调用 generate_root 函数
        let address = generate_root(
            &lang,
            &phrase,
            &salt,
            &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            coin_type,
            account_index,
            &password,
        )?;
        println!("Generated address: {}", address);

        // 构建预期路径
        let mut expected_path = PathBuf::from(&storage_dir);
        expected_path.push(wallet_name);
        expected_path.push(format!("coin_{}", coin_type));
        expected_path.push(format!("account_{}", account_index));

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
        let (storage_dir, lang, phrase, salt, wallet_name, coin_type, account_index, password) =
            setup_test_environment()?;

        // 先生成一个根密钥库
        let keystore_name = generate_root(
            &lang,
            &phrase,
            &salt,
            &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            coin_type,
            account_index,
            &password,
        )?;
        println!("Generated keystore_name for reset: {}", keystore_name);
        let storage_path = Keystore::build_storage_path(
            &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            coin_type,
            account_index,
        )
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
            &storage_dir.to_string_lossy().to_string(),
            &wallet_name,
            coin_type,
            account_index,
            new_password,
        )?;
        println!("New generated address: {}", new_address);
        assert_eq!(address, new_address);

        // 构建预期路径
        let mut expected_path = PathBuf::from(&storage_dir);
        expected_path.push(&wallet_name);
        expected_path.push(format!("coin_{}", coin_type));
        expected_path.push(format!("account_{}", account_index));

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
}
