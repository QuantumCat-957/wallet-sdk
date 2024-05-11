use std::any::Any;

use alloy::{
    network::{EthereumSigner, TransactionBuilder},
    primitives::Address,
    providers::Provider as _,
    signers::wallet::{MnemonicBuilder, Wallet},
};
use anyhow::anyhow;
use coins_bip39::Mnemonic;
use secp256k1::Secp256k1;

#[derive(Debug, Clone)]
pub struct Keystore {
    wallet: Option<Wallet<alloy::signers::k256::ecdsa::SigningKey>>,
    _wordlist: crate::language::WordlistWrapper,
}

// pub struct  KeystoreBuilder{

// }

// impl KeystoreBuilder{
//     pub fn new(word: *mut ()) -> KeystoreBuilder {
//         let word = unsafe{
//             &mut *word.cast::<W>()
//         };
//         Self {
//             wallet: None,
//             _wordlist: word,
//         }
//     }
// }

impl Keystore {
    pub fn new(word: crate::language::WordlistWrapper) -> Self {
        Self {
            wallet: None,
            _wordlist: word,
        }
    }

    // pub fn gen_phrase(self) -> String {
    //     let mut rng = rand::thread_rng();
    //     match
    //     let mnemonic = coins_bip39::Mnemonic::<W>::new(&mut rng);
    //     mnemonic.to_phrase()
    // }

    // pub fn get_root(path: &str) -> Self{

    // }

    // 创建根Keystore，密钥随机生成，并且保存到文件
    pub(crate) fn create_root_keystore_with_path(
        mut self,
        path: &str,
        password: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let (wallet, _) = Wallet::new_keystore(path, &mut rng, password, None)?;
        self.wallet = Some(wallet);
        Ok(self)
    }

    // 传入助记词、盐，生成密钥，创建根Keystore，并且保存到文件
    pub fn create_root_keystore_with_path_phrase(
        mut self,
        phrase: &str,
        salt: &str,
        path: &str,
        password: &str,
    ) -> Result<Self, anyhow::Error> {
        let mut rng = rand::thread_rng();
        let master_key = self.phrase_to_master_key(phrase, salt)?;

        // let seed = mnemonic.to_seed(Some(salt))?;
        // let seed_str = alloy::hex::encode(seed);
        // println!("种子：{seed_str}");
        // let chain = "m/44'/60'/0'/0/0";

        // let master_key = master_key.derive_path(chain)?;

        // let master_key = mnemonic.derive_key(chain, Some(salt))?;
        let signingkey: &coins_bip32::ecdsa::SigningKey = master_key.as_ref();
        let private_key = signingkey.to_bytes();

        // let key: &coins_bip32::prelude::SigningKey = master_key.as_ref();
        // let private_key = alloy::hex::encode(key);

        // println!("master key: {:#?}", master_key);

        // println!("十六进制主私钥: {:#?}", private_key);
        // let signer = alloy::signers::k256::schnorr::SigningKey::from_bytes(&key.to_bytes())?;

        // let address = secret_key_to_address(&signer);
        // Ok(Wallet::<SigningKey> { signer, address, chain_id: None })

        let (wallet, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
            path,
            &mut rng,
            private_key,
            password,
            None,
        )?;

        let address = wallet.address();
        println!("地址：{}", address);

        self.wallet = Some(wallet);
        Ok(self)
    }

    // 传入助记词、盐，生成密钥，创建根Keystore，但不生成keystore文件
    pub fn create_root_keystore_with_phrase_no_path<W: coins_bip39::Wordlist>(
        mut self,
        phrase: &str,
        salt: &str,
    ) -> Result<Self, anyhow::Error> {
        // 从助记词和盐生成种子
        if salt.is_empty() {
            return Err(anyhow!("salt should not be empty"));
        }
        let wallet = MnemonicBuilder::<W>::default()
            .phrase(phrase)
            // Use this if your mnemonic is encrypted
            .password(salt)
            .build()?;

        self.wallet = Some(wallet);
        Ok(self)
    }

    // 传入助记词、盐、chain_code，由根私钥派生出子私钥，创建子Keystore，并生成keystore文件
    // pub fn derive_child_with_address_and_save(
    //     mut self,
    //     chain: &str,
    //     root_path: &str,
    //     root_password: &str,
    //     child_password: &str,
    // ) -> Result<Self, anyhow::Error> {

    //     // let master_key = mnemonic.derive_key(chain, Some(salt))?;
    //     let root_wallet = Wallet::decrypt_keystore(root_path, root_password)?;

    //     let root_signer = root_wallet.signer();
    //     root_signer


    //     let signingkey: &coins_bip32::ecdsa::SigningKey = derive_key.as_ref();
    //     let private_key = signingkey.to_bytes();

    //     let key = alloy::hex::encode(private_key);
    //     println!("十六进制派生私钥: {:#?}", key);

    //     let (wallet, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
    //         path,
    //         &mut rng,
    //         private_key,
    //         password,
    //         None,
    //     )?;

    //     self.wallet = Some(wallet);
    //     Ok(self)
    // }

    // 传入助记词、盐、chain_code，由根私钥派生出子私钥，创建子Keystore，并生成keystore文件
    // pub fn derive_child_with_phrase_and_salt_save(
    //     mut self,
    //     phrase: &str,
    //     salt: &str,
    //     chain: &str,
    //     path: &str,
    //     password: &str,
    // ) -> Result<Self, anyhow::Error> {
    //     let mut rng = rand::thread_rng();
    //     let master_key = self.phrase_to_master_key(phrase, salt)?;
    //     let derive_key = mnemonic.derive_key(chain, Some(salt))?;

    //     let mnemonic = Self::phrase_to_master_key(phrase, chain, Some(salt))?;
    //     // let master_key = mnemonic.derive_key(chain, Some(salt))?;

    //     let signingkey: &coins_bip32::ecdsa::SigningKey = derive_key.as_ref();
    //     let private_key = signingkey.to_bytes();

    //     let key = alloy::hex::encode(private_key);
    //     println!("十六进制派生私钥: {:#?}", key);

    //     let (wallet, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
    //         path,
    //         &mut rng,
    //         private_key,
    //         password,
    //         None,
    //     )?;

    //     self.wallet = Some(wallet);
    //     Ok(self)
    // }

    // 传入助记词、盐、派生路径，由根私钥派生出子私钥，创建子Keystore，不生成keystore文件
    pub fn derive_child_with_phrase_and_salt_no_save<W: coins_bip39::Wordlist>(
        mut self,
        phrase: &str,
        salt: &str,
        chain: &str,
    ) -> Result<Self, anyhow::Error> {
        let wallet = MnemonicBuilder::<W>::default()
            .phrase(phrase)
            .derivation_path(chain)?
            // Use this if your mnemonic is encrypted
            .password(salt)
            .build()?;

        let key = self.clone().get_private()?;
        println!("key: {key}");
        self.wallet = Some(wallet);
        Ok(self)
    }

    // 助记词->Mnemonic->root key
    pub fn phrase_to_master_key(
        &self,
        phrase: &str,
        password: &str,
    ) -> Result<coins_bip32::xkeys::XPriv, anyhow::Error> {
        Ok(match self._wordlist {
            crate::language::WordlistWrapper::English(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::ChineseSimplified(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::ChineseTraditional(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::Czech(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::French(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::Italian(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::Japanese(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::Korean(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::Portuguese(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
            crate::language::WordlistWrapper::Spanish(_) => {
                let mnemonic = Mnemonic::<coins_bip39::English>::new_from_phrase(phrase)?;
                mnemonic.master_key(Some(password))?
            }
        })
    }

    // 获取密钥
    // TODO: 不用self
    pub fn get_private(self) -> Result<String, crate::Error> {
        let private_key = if let Some(wallet) = self.wallet {
            wallet
                .signer()
                .to_bytes()
                .iter()
                .map(|&i| format!("{:x}", i))
                .collect::<Vec<String>>()
                .join("")
        } else {
            String::new()
        };

        println!("打印出私钥：{:?}", private_key);
        Ok(private_key)
    }

    // 输入密码打开钱包
    pub(crate) fn open_with_password(password: &str, path: &str) -> Result<Wallet<alloy::signers::k256::ecdsa::SigningKey>, crate::Error> {
        let recovered_wallet = Wallet::decrypt_keystore(path, password)?;
        Ok(   recovered_wallet)
    }

    // 签名
    pub async fn sign_message(
        &self,
        message: &str,
    ) -> Result<alloy::primitives::Signature, anyhow::Error> {
        use alloy::signers::Signer;

        let Some(signer) = &self.wallet else {
            return Err(anyhow!("No wallet"));
        };
        let signature = signer.sign_message(message.as_bytes()).await?;

        println!(
            "Signature produced by {:?}: {:?}",
            signer.address(),
            signature
        );
        println!(
            "Signature recovered address: {:?}",
            signature.recover_address_from_msg(message)?
        );

        Ok(signature)
    }

    // 传入密码、keystore文件路径，交易
    pub async fn transaction(
        self,
        password: &str,
        path: &str,
        rpc_url: url::Url,
        to: &str,
        value: usize,
    ) -> Result<(), anyhow::Error> {
        let signer = Keystore::open_with_password(password, path)?;
        let to = to.parse::<Address>()?;

        let address = signer.address();
        // Create a provider with the signer.
        let provider = alloy::providers::ProviderBuilder::new()
            .with_recommended_fillers()
            .signer(EthereumSigner::from(signer))
            .on_http(rpc_url);

        let tx = alloy::rpc::types::eth::TransactionRequest::default()
            .with_from(address)
            .with_to(to)
            .with_value(alloy::primitives::U256::from(value));

        // Send the transaction and wait for the receipt.
        let receipt = provider.send_transaction(tx).await?.get_receipt().await?;

        println!("Send transaction: {:?}", receipt.transaction_hash);

        Ok(())
    }

    // 检查本地根钱包的地址和所选的地址是否一致
    fn _check_root_wallet(self, address: &str) -> Result<(), anyhow::Error> {
        let address = address.parse::<Address>()?;
        let Some(signer) = self.wallet else {
            return Err(anyhow!("No wallet"));
        };
        let local_address = signer.address();

        if address.ne(&local_address) {
            return Err(anyhow!(
                "The selected address is inconsistent with the root address of the local store"
            ));
        }

        Ok(())
    }

    pub fn listen() {}

    pub fn derive() {}

    pub fn gen_private_key() {
        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
        println!("sk: {sk:#?}");
    }
}

// #[cfg(test)]
// mod test {
//     use std::fs::read_to_string;

//     use alloy::{hex, signers::wallet::Wallet};
//     use hdwallet::{traits::Serialize as _, KeyChain as _};
//     use rand::thread_rng;
//     use secp256k1::Secp256k1;
//     use tempfile::tempdir;

//     use super::Keystore;

//     #[test]
//     fn test_gen_phrase() {
//         let phrase = Keystore::<coins_bip39::English>::gen_phrase();
//         println!("phrase: {}", phrase);
//     }

//     #[test]
//     fn test_create_keystore_with_phrase_no_path() {
//         // coins_bip32
//         let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
//         let salt = "";
//         let _res = Keystore::<coins_bip39::English>::new()
//             .create_root_keystore_with_phrase_no_path(phrase, &salt)
//             .unwrap();
//     }

//     #[test]
//     fn test_hdwallet_gen_extended_privkey() {
//         let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
//         let mnemonic = Keystore::<coins_bip39::English>::phrase_to_mnemonic(phrase).unwrap();

//         let seed = mnemonic.to_seed(None).unwrap();

//         let root_key = hdwallet::ExtendedPrivKey::with_seed(&seed).unwrap();
//         let key_chain = hdwallet::DefaultKeyChain::new(root_key);
//         let (extended_key, _derivation) = key_chain
//             .derive_private_key(hdwallet::ChainPath::from("m/44'/60'/0'/0/0"))
//             .expect("fetch key");

//         // let hardened_key_index = hdwallet::KeyIndex::from_index(0).unwrap();
//         // let root_key = root_key.derive_private_key(hardened_key_index)?;
//         println!(
//             "Private key 0x{}\n",
//             alloy::hex::encode(extended_key.serialize())
//         );
//     }

//     // #[test]
//     // fn test_gen_master_key() {
//     //     let provided_master_key_hex =
//     //         "8b09ab2bfb613458f9362c4b79ff5ac8b8c6da10f25017807aa08cea969cd1ca";
//     //         let provided_master_key_bytes = hex::decode(provided_master_key_hex).unwrap();
//     //         let provided_master_key_bytes = provided_master_key_bytes.as_slice();
//     //         let sign :coins_bip32::ecdsa::SigningKey= provided_master_key_bytes.try_into().unwrap();
//     //     // 将提供的根私钥转换为XPriv类型
//     //     let provided_master_key =
//     //         coins_bip32::xkeys::XPriv::from_str(provided_master_key_hex).unwrap();
//     // }

//     // #[test]
//     // fn test_create() {
//     //     let phrase = Keystore::gen_phrase::<coins_bip39::English>();
//     //     let salt = "Salt";
//     //     let res = Keystore::create(&phrase, bip39::Language::English, salt);
//     //     println!("res: {:#?}", res);
//     // }

//     #[test]
//     fn test_create_root_keystore_with_path_phrase() {
//         // let phrase = "slam orient base razor trumpet swift second peasant amateur tape sweet enjoy";
//         let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
//         // let chain = "m/44'/60'/0'/0/0";
//         let _res = Keystore::<coins_bip39::English>::new()
//             .create_root_keystore_with_path_phrase(phrase, "", "", "test")
//             .unwrap();
//     }

//     #[test]
//     fn test_derive_child_with_phrase_and_save() {
//         // let phrase = "slam orient base razor trumpet swift second peasant amateur tape sweet enjoy";
//         let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
//         let chain = "m/44'/60'/0'/0/1";
//         let _res = Keystore::<coins_bip39::English>::new()
//             .derive_child_with_phrase_and_salt_save(phrase, "", chain, "", "test")
//             .unwrap();
//     }

//     #[test]
//     fn test_derive_child_with_phrase_no_save() {
//         // let phrase = "slam orient base razor trumpet swift second peasant amateur tape sweet enjoy";
//         let phrase = "army van defense carry jealous true garbage claim echo media make crunch";
//         let chain = "m/44'/60'/0'/0/1";
//         let _res = Keystore::<coins_bip39::English>::new()
//             .derive_child_with_phrase_and_salt_no_save(phrase, "", chain)
//             .unwrap();
//     }

//     #[test]
//     fn test_gen() {
//         let _mnemonic_phrase =
//             "culture false mystery scrub kind pizza finger kit document fire debate cake";
//         let seed_hex = "e61b56077fd615fa661b720d3021627d37bee396dcebd11a31f51355259712fe3b92f4cbd923dca32d6a80dfafbc0dd8f25a59aff331749c9afeef097a29d5d6";

//         // 使用助记词生成种子
//         // let mnemonic = coins_bip39::Mnemonic::<English>::new_from_phrase(mnemonic_phrase).unwrap();
//         // let seed = Seed::new(&mnemonic, "");

//         // 使用种子生成根私钥
//         let _secp = Secp256k1::new();
//         let mut private_key_bytes: [u8; 64] = [0; 64];
//         let seed_slice = hex::decode(seed_hex).unwrap();
//         private_key_bytes.copy_from_slice(&seed_slice);
//         let secret_key = secp256k1::SecretKey::from_slice(&private_key_bytes).unwrap();
//         // let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

//         // 输出根私钥
//         println!("Root Private Key: {:?}", secret_key);
//     }

//     #[test]
//     fn test_hex() {
//         let private_key = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
//         println!("private_key: {:#?}", private_key);
//     }

//     #[tokio::test]
//     async fn test_sign_message() {
//         let signer = alloy::signers::wallet::LocalWallet::random();
//         let wallet = Keystore::<coins_bip39::English> {
//             wallet: Some(signer),
//             _wordlist: std::marker::PhantomData,
//         };

//         let res = wallet.sign_message("asd").await.unwrap();
//         println!("private_key: {:#?}", res);
//     }

//     #[tokio::test]
//     async fn add_money() {}

//     #[tokio::test]
//     async fn test_transaction() {
//         let anvil = alloy::node_bindings::Anvil::new()
//             .block_time(1)
//             .try_spawn()
//             .unwrap();

//         let rpc_url = anvil.endpoint().parse().unwrap();
//         let to = "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
//         let value = 100;
//         let keystore_file_path =
//             std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
//         println!("path: {:?}", keystore_file_path);
//         let keystore_file_path = keystore_file_path
//             // .join("6dab0ec3-ce31-4d24-ac4a-d4109446eca4")
//             .join("alice.json")
//             .to_string_lossy()
//             .to_string();

//         println!("keystore_file_path: {:?}", keystore_file_path);
//         let res = Keystore::<coins_bip39::English>::new()
//             .transaction("test", &keystore_file_path, rpc_url, to, value)
//             .await
//             .unwrap();
//         println!("private_key: {:#?}", res);
//     }

//     #[test]
//     fn test_gen_private_key() {
//         // let phrase = "culture false mystery scrub kind pizza finger kit document fire debate cake";
//         // let password = "123";
//         let _res = Keystore::<coins_bip39::English>::gen_private_key();
//     }

//     #[test]
//     fn test_create_keystore() -> Result<(), anyhow::Error> {
//         let dir = tempdir()?;
//         let mut rng = thread_rng();

//         // Private key of Alice, the first default Anvil account.
//         let private_key = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
//         // Password to encrypt the keystore file with.
//         let password = "test";

//         // Create a keystore file from the private key of Alice, returning a [Wallet] instance.
//         let (wallet, file_path) =
//             Wallet::encrypt_keystore(&dir, &mut rng, private_key, password, None)?;

//         println!("file_path: {file_path}");
//         let keystore_file_path = dir.path().join(file_path);

//         println!(
//             "Wrote keystore for {:?} to {:?}",
//             wallet.address(),
//             keystore_file_path
//         );

//         // Read the keystore file back.
//         let recovered_wallet = Wallet::decrypt_keystore(keystore_file_path.clone(), password)?;

//         println!(
//             "Read keystore from {:?}, recovered address: {:?}",
//             keystore_file_path,
//             recovered_wallet.address()
//         );

//         // Assert that the address of the original key and the recovered key are the same.
//         assert_eq!(wallet.address(), recovered_wallet.address());

//         // Display the contents of the keystore file.
//         let keystore_contents = read_to_string(keystore_file_path)?;

//         println!("Keystore file contents: {keystore_contents:?}");
//         Ok(())
//     }
// }