use std::{fs, path::PathBuf};

use alloy::primitives::Address;

use crate::{keystore::Keystore, language::WordlistWrapper};

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
/// - `storage_dir`: 存储根密钥的路径，由调用者指定。
/// - `wallet_name`: 钱包名称。
/// - `coin_type`: 币种类型，比如0代表比特币，60代表以太坊。
/// - `account_index`: 账户索引，用于生成不同的子地址。
/// - `password`: 用于加密根密钥的密码。
///
/// # 返回
///
/// 如果成功生成并存储根密钥，则返回`Ok(())`，否则返回错误。
///
/// # 注意
///
/// 在生成新的根密钥前，该存储路径下现有的keystore将被清空。
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
    let mut storage_path = PathBuf::from(storage_dir);
    storage_path.push(wallet_name);
    storage_path.push(format!("coin_{}", coin_type));
    storage_path.push(format!("account_{}", account_index));

    println!("storage_path: {storage_path:?}");
    // 清空该存储路径下的keystore
    if storage_path.exists() {
        // fs::remove_dir_all(&storage_path)?; // 删除目录及其内容
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

/// 重置根密码
/// 相当于忘记密码
// pub fn reset_root(
//     lang: &str,
//     phrase: &str,
//     salt: &str,
//     path: &str,
//     password: &str,
// ) -> Result<Address, anyhow::Error> {
//     // TODO: 清空keystore

//     // 重新创建root
//     let wordlist_wrapper = WordlistWrapper::new(lang)?;

//     let wallet =
//         Keystore::new(lang)?.create_root_keystore_with_path_phrase(phrase, salt, path, password)?;

//     Ok(wallet.get_address()?)
// }

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
    use std::env;
    use std::fs::{self, ReadDir};
    use std::path::Path;

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

    #[test]
    fn test_generate_root() -> Result<(), anyhow::Error> {
        let storage_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);

        // 创建测试目录
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir)?;
        }

        let lang = "english";
        let phrase = "shaft love depth mercy defy cargo strong control eye machine night test";
        let salt = "salt";
        let wallet_name = "example_wallet";
        let coin_type = 60; // 60 是以太坊的 coin_type
        let account_index = 0;
        let password = "example_password";

        // 调用 generate_root 函数
        let name = generate_root(
            lang,
            phrase,
            salt,
            &storage_dir.to_string_lossy().to_string(),
            wallet_name,
            coin_type,
            account_index,
            password,
        )?;
        println!("name: {}", name);

        // 检查生成的路径
        let mut expected_path = PathBuf::from(&storage_dir);
        expected_path.push(wallet_name);
        expected_path.push(format!("coin_{}", coin_type));
        expected_path.push(format!("account_{}", account_index));

        println!("expected_path: {expected_path:?}");
        // 确认目录存在
        assert!(expected_path.exists());
        assert!(expected_path.is_dir());

        // 确认keystore文件存在
        let keystore_file = expected_path.join(name);
        assert!(keystore_file.exists());
        assert!(keystore_file.is_file());

        // 打印目录结构
        println!("Directory structure of '{}':", expected_path.display());
        print_dir_structure(&expected_path, 0);

        // 清理测试目录
        // fs::remove_dir_all(&expected_path)?;

        Ok(())
    }
}
