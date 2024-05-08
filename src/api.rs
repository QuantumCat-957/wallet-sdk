use bip39::{Mnemonic, Seed};
use hdwallet::ExtendedPrivKey;
use secp256k1::Secp256k1;

const RSA_PRIVATE_KEY: &str = "";

pub struct Keystone {}

impl Keystone {
    pub fn gen_phrase(lang: bip39::Language) -> String {
        let w24 = bip39::MnemonicType::Words24;
        let mnemonic = Mnemonic::new(w24, lang);
        mnemonic.phrase().to_string()
    }

    pub fn create(
        phrase: &str,
        lang: bip39::Language,
        salt: &str,
    ) -> Result<hdwallet::secp256k1::SecretKey, anyhow::Error> {
        // 从助记词和盐生成种子
        // let wallet = MnemonicBuilder::<English>::default()
        //     .phrase(phrase)
        //     .password(salt)
        //     .build()?;

        let mnemonic = Mnemonic::from_phrase(phrase, lang)?;

        let seed = Seed::new(&mnemonic, salt);
        // 使用种子生成主私钥
        let secp = Secp256k1::new();
        let master_key = ExtendedPrivKey::with_seed(seed.as_bytes())?;

        // let dir = "./";
        // let mut rng = rand::thread_rng();
        // 将主私钥转换为十六进制字符串
        let private_key_hex = master_key.private_key;
        // std::fs::File::create(dir);
        // let (wallet, file_path) =
        //     Wallet::encrypt_keystore(&dir, &mut rng, private_key, password, None)?;

        // wallet
        Ok(private_key_hex)
    }

    // fn gen_priv_key(phrase: &str, password: &str) -> Result<Self, crate::Error> {
    //     let mnemonic = Mnemonic::from_phrase(phrase, bip39::Language::English)
    //         .map_err(|e| crate::Error::Bip39(e.to_string()))?;

    //     let seed = Seed::new(&mnemonic, password);

    //     let ext_priv_key = Extend

    //     let wallet = hdwallet::Wallet::from_seed(seed.as_bytes()).unwrap();

    // }

    // pub fn open(password: String) -> Result<Keystone, crate::Error> {
    //     let recovered_wallet = Wallet::decrypt_keystore(keystore_file_path.clone(), password)?;
    //     // recovered_wallet.
    //     let keystore_contents = read_to_string(keystore_file_path)?;
    // }

    pub fn open_with_key(priv_key: &str, password: String) -> Result<String, anyhow::Error> {
        let der_encoded = RSA_PRIVATE_KEY
            .lines()
            .filter(|line| !line.starts_with("-"))
            .fold(String::new(), |mut data, line| {
                data.push_str(&line);
                data
            });
        let der_bytes = base64::decode(&der_encoded).expect("failed to decode base64 content");
        let private_key = rsa::RSAPrivateKey::from_pkcs1(&der_bytes)?;
        let decrypted_data =
            private_key.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, priv_key.as_bytes())?;

        let decrypted_str = String::from_utf8(decrypted_data)?;
        Ok(decrypted_str)
    }

    // pub fn get_private(&self) -> Result<Private, crate::Error> {}
}

#[cfg(test)]
mod test {
    use super::Keystone;

    #[test]
    fn test_gen_phrase() {
        let phrase = Keystone::gen_phrase(bip39::Language::English);
        println!("phrase: {}", phrase);
    }

    #[test]
    fn test_create() {
        let phrase = Keystone::gen_phrase(bip39::Language::English);
        let salt = "Salt";
        let res = Keystone::create(&phrase, bip39::Language::English, salt);
        println!("res: {:#?}", res);
    }
}
