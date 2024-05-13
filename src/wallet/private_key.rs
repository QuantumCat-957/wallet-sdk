//! [`k256`] wallet implementation.

use super::{SeedWallet, WalletError};
use alloy::primitives::{hex, B256};
use alloy::signers::k256::{
    ecdsa::{self, SigningKey},
    FieldBytes, NonZeroScalar, SecretKey as K256SecretKey,
};
use alloy::signers::utils::secret_key_to_address;
use coins_bip32::xkeys::XPriv;
use coins_bip39::{mnemonic, Mnemonic, Wordlist};
use rand::{CryptoRng, Rng};
use std::str::FromStr;

// #[cfg(feature = "keystore")]
use {elliptic_curve::rand_core, std::path::Path};

impl SeedWallet {
    /// Creates a new Wallet instance from a [`SigningKey`].
    ///
    /// This can also be used to create a Wallet from a [`SecretKey`](K256SecretKey).
    /// See also the `From` implementations.
    #[inline]
    pub fn from_seed(seed: Vec<u8>) -> Result<Self, WalletError> {
        let pri_key = XPriv::root_from_seed(seed.as_slice(), None)?;
        let signingkey: &coins_bip32::ecdsa::SigningKey = pri_key.as_ref();

        let address = secret_key_to_address(signingkey);
        Ok(Self::new_with_seed(seed, address))
    }
}

// #[cfg(feature = "keystore")]
impl SeedWallet {
    // /// Creates a new random encrypted JSON with the provided password and stores it in the
    // /// provided directory. Returns a tuple (Wallet, String) of the wallet instance for the
    // /// keystore with its random UUID. Accepts an optional name for the keystore file. If `None`,
    // /// the keystore is stored as the stringified UUID.
    // #[inline]
    // pub fn new_keystore<P, R, S>(
    //     dir: P,
    //     rng: &mut R,
    //     password: S,
    //     name: Option<&str>,
    // ) -> Result<(Self, String), WalletError>
    // where
    //     P: AsRef<Path>,
    //     R: Rng + CryptoRng + rand_core::CryptoRng,
    //     S: AsRef<[u8]>,
    // {
    //     let (secret, uuid) = eth_keystore::new(dir, rng, password, name)?;
    //     let mnemonic = Mnemonic::
    //     Ok((Self::from_slice(&secret)?, uuid))
    // }

    /// Decrypts an encrypted JSON from the provided path to construct a Wallet instance
    #[inline]
    pub fn decrypt_keystore<P, S>(keypath: P, password: S) -> Result<Self, WalletError>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
    {
        let seed = crate::eth_keystore::decrypt_data(keypath, password)?;
        Ok(Self::from_seed(seed)?)
    }

    /// Creates a new encrypted JSON with the provided private key and password and stores it in the
    /// provided directory. Returns a tuple (Wallet, String) of the wallet instance for the
    /// keystore with its random UUID. Accepts an optional name for the keystore file. If `None`,
    /// the keystore is stored as the stringified UUID.
    #[inline]
    pub fn encrypt_keystore<P, R, B, S>(
        keypath: P,
        rng: &mut R,
        data: B,
        password: S,
        name: Option<&str>,
    ) -> Result<(Self, String), WalletError>
    where
        P: AsRef<Path>,
        R: Rng + CryptoRng,
        B: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let data = data.as_ref();
        let uuid = crate::eth_keystore::encrypt_data(keypath, rng, data, password, name)?;
        Ok((Self::from_seed(data.to_vec())?, uuid))
    }

    // pub fn derive_path_to_wallet<E, P>(&self, p: P)-> Result<Self, WalletError>
    // where
    // E: Into<coins_bip32::Bip32Error>,
    // P: TryInto<coins_bip32::path::DerivationPath, Error = E>,{
    //     let derive_key = self.derive_path(p)?;

    //     let mut rng = rand::thread_rng();
    //     let signingkey: &coins_bip32::ecdsa::SigningKey = derive_key.as_ref();
    //     let private_key = signingkey.to_bytes();

    //     // let key = alloy::hex::encode(private_key);
    //     // println!("十六进制派生私钥: {:#?}", key);

    //     let (wallet, _) = alloy::signers::wallet::Wallet::encrypt_keystore(
    //         path,
    //         &mut rng,
    //         private_key,
    //         password,
    //         None,
    //     )?;
    // }

    pub fn derive_path<E, P>(&self, p: P) -> Result<XPriv, WalletError>
    where
        E: Into<coins_bip32::Bip32Error>,
        P: TryInto<coins_bip32::path::DerivationPath, Error = E>,
    {
        let pri_key = XPriv::root_from_seed(self.seed.as_slice(), None)?;
        let derive_key = pri_key.derive_path(p)?;

        Ok(derive_key)
    }
}

impl PartialEq for SeedWallet {
    fn eq(&self, other: &Self) -> bool {
        self.seed.eq(&other.seed) && self.address == other.address
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use alloy::primitives::{address, b256};
    // use alloy::signers::{wallet::LocalWallet, SignerSync};

    // #[cfg(feature = "keystore")]
    // use tempfile::tempdir;

    // #[test]
    // fn parse_pk() {
    //     let s = "6f142508b4eea641e33cb2a0161221105086a84584c74245ca463a49effea30b";
    //     let _pk: Wallet<SigningKey> = s.parse().unwrap();
    // }

    // #[test]
    // fn parse_short_key() {
    //     let s = "6f142508b4eea641e33cb2a0161221105086a84584c74245ca463a49effea3";
    //     assert!(s.len() < 64);
    //     let pk = s.parse::<LocalWallet>().unwrap_err();
    //     match pk {
    //         WalletError::HexError(hex::FromHexError::InvalidStringLength) => {}
    //         _ => panic!("Unexpected error"),
    //     }
    // }

    // #[cfg(feature = "keystore")]
    // fn test_encrypted_json_keystore(key: Wallet<SigningKey>, uuid: &str, dir: &Path) {
    //     // sign a message using the given key
    //     let message = "Some data";
    //     let signature = key.sign_message_sync(message.as_bytes()).unwrap();

    //     // read from the encrypted JSON keystore and decrypt it, while validating that the
    //     // signatures produced by both the keys should match
    //     let path = Path::new(dir).join(uuid);
    //     let key2 = Wallet::<SigningKey>::decrypt_keystore(path.clone(), "randpsswd").unwrap();

    //     let signature2 = key2.sign_message_sync(message.as_bytes()).unwrap();
    //     assert_eq!(signature, signature2);

    //     std::fs::remove_file(&path).unwrap();
    // }

    // #[test]
    // #[cfg(feature = "keystore")]
    // fn encrypted_json_keystore_new() {
    //     // create and store an encrypted JSON keystore in this directory
    //     let dir = tempdir().unwrap();
    //     let mut rng = rand::thread_rng();
    //     let (key, uuid) =
    //         Wallet::<SigningKey>::new_keystore(&dir, &mut rng, "randpsswd", None).unwrap();

    //     test_encrypted_json_keystore(key, &uuid, dir.path());
    // }

    // #[test]
    // #[cfg(feature = "keystore")]
    // fn encrypted_json_keystore_from_pk() {
    //     // create and store an encrypted JSON keystore in this directory
    //     let dir = tempdir().unwrap();
    //     let mut rng = rand::thread_rng();

    //     let private_key =
    //         hex::decode("6f142508b4eea641e33cb2a0161221105086a84584c74245ca463a49effea30b")
    //             .unwrap();

    //     let (key, uuid) =
    //         Wallet::<SigningKey>::encrypt_keystore(&dir, &mut rng, private_key, "randpsswd", None)
    //             .unwrap();

    //     test_encrypted_json_keystore(key, &uuid, dir.path());
    // }

    // #[test]
    // fn signs_msg() {
    //     let message = "Some data";
    //     let hash = alloy::primitives::utils::eip191_hash_message(message);
    //     let key = Wallet::<SigningKey>::random_with(&mut rand::thread_rng());
    //     let address = key.address;

    //     // sign a message
    //     let signature = key.sign_message_sync(message.as_bytes()).unwrap();

    //     // ecrecover via the message will hash internally
    //     let recovered = signature.recover_address_from_msg(message).unwrap();
    //     assert_eq!(recovered, address);

    //     // if provided with a hash, it will skip hashing
    //     let recovered2 = signature.recover_address_from_prehash(&hash).unwrap();
    //     assert_eq!(recovered2, address);
    // }

    // #[test]
    // #[cfg(feature = "eip712")]
    // fn typed_data() {
    //     use alloy_dyn_abi::eip712::TypedData;
    //     use alloy_primitives::{keccak256, Address, I256, U256};
    //     use alloy_sol_types::{eip712_domain, sol, SolStruct};
    //     use serde::Serialize;

    //     sol! {
    //         #[derive(Debug, Serialize)]
    //         struct FooBar {
    //             int256 foo;
    //             uint256 bar;
    //             bytes fizz;
    //             bytes32 buzz;
    //             string far;
    //             address out;
    //         }
    //     }

    //     let domain = eip712_domain! {
    //         name: "Eip712Test",
    //         version: "1",
    //         chain_id: 1,
    //         verifying_contract: address!("0000000000000000000000000000000000000001"),
    //         salt: keccak256("eip712-test-75F0CCte"),
    //     };
    //     let foo_bar = FooBar {
    //         foo: I256::try_from(10u64).unwrap(),
    //         bar: U256::from(20u64),
    //         fizz: b"fizz".to_vec(),
    //         buzz: keccak256("buzz"),
    //         far: String::from("space"),
    //         out: Address::ZERO,
    //     };
    //     let wallet = Wallet::random();
    //     let hash = foo_bar.eip712_signing_hash(&domain);
    //     let sig = wallet.sign_typed_data_sync(&foo_bar, &domain).unwrap();
    //     assert_eq!(
    //         sig.recover_address_from_prehash(&hash).unwrap(),
    //         wallet.address()
    //     );
    //     assert_eq!(wallet.sign_hash_sync(&hash).unwrap(), sig);
    //     let foo_bar_dynamic = TypedData::from_struct(&foo_bar, Some(domain));
    //     let dynamic_hash = foo_bar_dynamic.eip712_signing_hash().unwrap();
    //     let sig_dynamic = wallet
    //         .sign_dynamic_typed_data_sync(&foo_bar_dynamic)
    //         .unwrap();
    //     assert_eq!(
    //         sig_dynamic
    //             .recover_address_from_prehash(&dynamic_hash)
    //             .unwrap(),
    //         wallet.address()
    //     );
    //     assert_eq!(wallet.sign_hash_sync(&dynamic_hash).unwrap(), sig_dynamic);
    // }

    // #[test]
    // fn key_to_address() {
    //     let wallet: Wallet<SigningKey> =
    //         "0000000000000000000000000000000000000000000000000000000000000001"
    //             .parse()
    //             .unwrap();
    //     assert_eq!(
    //         wallet.address,
    //         address!("7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
    //     );

    //     let wallet: Wallet<SigningKey> =
    //         "0000000000000000000000000000000000000000000000000000000000000002"
    //             .parse()
    //             .unwrap();
    //     assert_eq!(
    //         wallet.address,
    //         address!("2B5AD5c4795c026514f8317c7a215E218DcCD6cF")
    //     );

    //     let wallet: Wallet<SigningKey> =
    //         "0000000000000000000000000000000000000000000000000000000000000003"
    //             .parse()
    //             .unwrap();
    //     assert_eq!(
    //         wallet.address,
    //         address!("6813Eb9362372EEF6200f3b1dbC3f819671cBA69")
    //     );
    // }

    // #[test]
    // fn conversions() {
    //     let key = b256!("0000000000000000000000000000000000000000000000000000000000000001");

    //     let wallet_b256: Wallet<SigningKey> = LocalWallet::from_bytes(&key).unwrap();
    //     assert_eq!(
    //         wallet_b256.address,
    //         address!("7E5F4552091A69125d5DfCb7b8C2659029395Bdf")
    //     );
    //     assert_eq!(wallet_b256.chain_id, None);
    //     assert_eq!(
    //         wallet_b256.signer,
    //         SigningKey::from_bytes((&key.0).into()).unwrap()
    //     );

    //     let wallet_str =
    //         Wallet::from_str("0000000000000000000000000000000000000000000000000000000000000001")
    //             .unwrap();
    //     assert_eq!(wallet_str.address, wallet_b256.address);
    //     assert_eq!(wallet_str.chain_id, wallet_b256.chain_id);
    //     assert_eq!(wallet_str.signer, wallet_b256.signer);
    //     assert_eq!(wallet_str.to_bytes(), key);
    //     assert_eq!(wallet_str.to_field_bytes(), key.0.into());

    //     let wallet_slice = Wallet::from_slice(&key[..]).unwrap();
    //     assert_eq!(wallet_slice.address, wallet_b256.address);
    //     assert_eq!(wallet_slice.chain_id, wallet_b256.chain_id);
    //     assert_eq!(wallet_slice.signer, wallet_b256.signer);
    //     assert_eq!(wallet_slice.to_bytes(), key);
    //     assert_eq!(wallet_slice.to_field_bytes(), key.0.into());

    //     let wallet_field_bytes = Wallet::from_field_bytes((&key.0).into()).unwrap();
    //     assert_eq!(wallet_field_bytes.address, wallet_b256.address);
    //     assert_eq!(wallet_field_bytes.chain_id, wallet_b256.chain_id);
    //     assert_eq!(wallet_field_bytes.signer, wallet_b256.signer);
    //     assert_eq!(wallet_field_bytes.to_bytes(), key);
    //     assert_eq!(wallet_field_bytes.to_field_bytes(), key.0.into());
    // }

    // #[test]
    // fn key_from_str() {
    //     let wallet: Wallet<SigningKey> =
    //         "0000000000000000000000000000000000000000000000000000000000000001"
    //             .parse()
    //             .unwrap();

    //     // Check FromStr and `0x`
    //     let wallet_0x: Wallet<SigningKey> =
    //         "0x0000000000000000000000000000000000000000000000000000000000000001"
    //             .parse()
    //             .unwrap();
    //     assert_eq!(wallet.address, wallet_0x.address);
    //     assert_eq!(wallet.chain_id, wallet_0x.chain_id);
    //     assert_eq!(wallet.signer, wallet_0x.signer);

    //     // Must fail because of `0z`
    //     "0z0000000000000000000000000000000000000000000000000000000000000001"
    //         .parse::<Wallet<SigningKey>>()
    //         .unwrap_err();
    // }
}
