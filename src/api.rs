use alloy::primitives::Address;

use crate::{keystore::Keystore, language::WordlistWrapper};

pub fn gen_phrase(lang: &str) -> Result<String, anyhow::Error> {
    let lang = crate::language::Language::from_str(lang)?;
    Ok(lang.gen_phrase())
}

/// 生成根密钥
/// 先不分组
pub fn gen_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    path: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    // TODO: 清空该分组下的keystore

    // 重新创建root

    Keystore::new(lang)?.create_root_keystore_with_path_phrase(phrase, salt, path, password)?;

    Ok(())
}

/// 重置根密码
/// 相当于忘记密码
pub fn reset_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    path: &str,
    password: &str,
) -> Result<Address, anyhow::Error> {
    // TODO: 清空keystore

    // 重新创建root
    let wordlist_wrapper = WordlistWrapper::new(lang)?;

    let wallet =
        Keystore::new(lang)?.create_root_keystore_with_path_phrase(phrase, salt, path, password)?;

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
    path: &str,
    old_password: &str,
    new_password: &str,
    name: &str,
) -> Result<(), anyhow::Error> {
    let pk = Keystore::get_pk_with_password(old_password, path)?;

    Keystore::set_password(pk, path, new_password, name)?;
    // TODO: 删除旧keystore
    // let secret = eth_keystore::decrypt_key(keypath, password)?;
    Ok(())
}

// /// 派生子密钥
// pub fn derive(password: &str) -> Result<Address, anyhow::Error> {
//     // 找到根keystore文件，根密钥只用来派生
//     let root_path = "";

//     let wallet = Keystore::open_with_password(password, root_path)?;

//     let _res = Keystore::<coins_bip39::English>::new()
//         .create_root_keystore_with_phrase_no_path(phrase, &salt)
//         .unwrap();

//     Ok(())
// }
