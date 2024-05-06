// use alloy::signers::wallet::{coins_bip39::English, MnemonicBuilder, Wallet};
// use bip39::{Mnemonic, Seed};

// pub struct Keystone {}

// impl Keystone {

//     pub fn gen_phrase() -> String {
//         let w24 = bip39::MnemonicType::Words24;
//         let mnemonic = Mnemonic::new(w24, bip39::Language::English);
//         mnemonic.phrase().to_string()
//     }

//     pub fn create(phrase: &str, salt: &str, password: &str) -> Result<Self, crate::Error> {
//         //
//         let wallet = MnemonicBuilder::<English>::default()
//             .phrase(phrase)
//             .password(password)
//             .build()?;

//         let dir = "./";
//         let mut rng = rand::thread_rng();

//         std::fs::File::create(dir);
//         let (wallet, file_path) =
//             Wallet::encrypt_keystore(&dir, &mut rng, private_key, password, None)?;

//         wallet
//     }

//     fn gen_priv_key(phrase: &str, password: &str) -> Result<Self, crate::Error> {
//         let mnemonic = Mnemonic::from_phrase(phrase, bip39::Language::English)
//             .map_err(|e| crate::Error::Bip39(e.to_string()))?;

//         let seed = Seed::new(&mnemonic, password);

//         let ext_priv_key = Extend

//         let wallet = hdwallet::Wallet::from_seed(seed.as_bytes()).unwrap();
        
//     }

//     pub fn open(password: String) -> Result<Keystone, crate::Error> {
//         let recovered_wallet = Wallet::decrypt_keystore(keystore_file_path.clone(), password)?;
//         recovered_wallet.
//         let keystore_contents = read_to_string(keystore_file_path)?;
//     }



//     pub fn get_private(&self) -> Result<Private, crate::Error> {}
// }

// pub struct Private {}
