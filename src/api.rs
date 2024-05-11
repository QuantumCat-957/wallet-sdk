use alloy::primitives::Address;

use crate::{
    keystore::Keystore,
    language::{Language, WordlistWrapper},
};

pub fn gen_phrase(lang: &str) -> String {
    let lang: crate::language::Language = serde_json::from_str(lang).unwrap();
    lang.gen_phrase()
}

/// 重置根
/// 相当于忘记密码
pub fn reset_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    path: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    // TODO: 清空keystore

    // 重新创建root
    let wordlist_wrapper = WordlistWrapper::new(lang)?;

    Keystore::new(wordlist_wrapper)
        .create_root_keystore_with_path_phrase(phrase, salt, path, password)?;

    Ok(())
}

/// 修改密码
pub fn set_password(
    lang: &str,
    path: &str,
    old_password: &str,
    password: &str,
) -> Result<(), anyhow::Error> {
    let wordlist_wrapper = WordlistWrapper::new(lang)?;

    let wallet = Keystore::open_with_password(old_password, path)?;



    Ok(())
}

// pub fn derive(address: &str) -> Address {
//     // 找到keystore文件
//     let root_path = "";

//     let _res = Keystore::<coins_bip39::English>::new()
//         .create_root_keystore_with_phrase_no_path(phrase, &salt)
//         .unwrap();
// }
