#![cfg_attr(docsrs, feature(doc_cfg))]
//! A minimalist library to interact with encrypted JSON keystores as per the
//! [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).

use aes::{
    cipher::{self, InnerIvInit, KeyInit, StreamCipherCore},
    Aes128,
};
use digest::{Digest, Update};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{CryptoRng, Rng};
use rust_decimal::prelude::*;
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;
use sha3::Keccak256;
use uuid::Uuid;

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

mod keystore;
mod utils;

#[cfg(feature = "geth-compat")]
use utils::geth_compat::address_from_pk;

pub use eth_keystore::KeystoreError;
pub use keystore::{CipherparamsJson, CryptoJson, EthKeystore, KdfType, KdfparamsType};

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

/// Creates a new JSON keystore using the [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// key derivation function. The keystore is encrypted by a key derived from the provided `password`
/// and stored in the provided directory with either the user-provided filename, or a generated
/// Uuid `id`.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::new;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = Path::new("./keys");
/// let mut rng = rand::thread_rng();
/// // here `None` signifies we don't specify a filename for the keystore.
/// // the default filename is a generated Uuid for the keystore.
/// let (private_key, name) = new(&dir, &mut rng, "password_to_keystore", None)?;
///
/// // here `Some("my_key")` denotes a custom filename passed by the caller.
/// let (private_key, name) = new(&dir, &mut rng, "password_to_keystore", Some("my_key"))?;
/// # Ok(())
/// # }
/// ```
pub fn new<P, R, S>(
    dir: P,
    rng: &mut R,
    password: S,
    name: Option<&str>,
) -> Result<(Vec<u8>, String), KeystoreError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
{
    // Generate a random private key.
    let mut pk = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(pk.as_mut_slice());

    let name = encrypt_data(dir, rng, &pk, password, name)?;
    Ok((pk, name))
}

/// Decrypts an encrypted JSON keystore at the provided `path` using the provided `password`.
/// Decryption supports the [Scrypt](https://tools.ietf.org/html/rfc7914.html) and
/// [PBKDF2](https://ietf.org/rfc/rfc2898.txt) key derivation functions.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::decrypt_key;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let keypath = Path::new("./keys/my-key");
/// let private_key = decrypt_key(&keypath, "password_to_keystore")?;
/// # Ok(())
/// # }
/// ```
pub fn decrypt_data<P, S>(path: P, password: S) -> Result<Vec<u8>, KeystoreError>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    // Read the file contents as string and deserialize it.
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let keystore: EthKeystore = serde_json::from_str(&contents)?;

    // Derive the key.
    let key = match keystore.crypto.kdfparams {
        KdfparamsType::Pbkdf2 {
            c,
            dklen,
            prf: _,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            pbkdf2::<Hmac<Sha256>>(password.as_ref(), &salt, c, key.as_mut_slice());
            key
        }
        KdfparamsType::Scrypt {
            dklen,
            n,
            p,
            r,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            // let log_n = (n as f32).log2();
            let n_decimal = rust_decimal::Decimal::from(n);
            let log2_decomal = n_decimal.log10() / Decimal::from(2).log10();

            let log_n = log2_decomal.to_u8().unwrap();
            // let log_n = (n as f32).log2();
            // tracing::info!("[decrypt_data] log_n: {log_n}");
            // let log_n = log_n as u8;
            tracing::info!("[decrypt_data] n: {n}, log_n: {log_n}");
            let scrypt_params = ScryptParams::new(log_n, r, p)?;
            tracing::info!("[decrypt_data] scrypt_params: {scrypt_params:?}");
            tracing::info!("[decrypt_data] salt: {salt:?}");
            scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;
            key
        }
    };

    tracing::info!("[decrypt_data] key: {key:?}");
    tracing::info!(
        "[decrypt_data] ciphertext: {:?}",
        keystore.crypto.ciphertext
    );

    // Derive the MAC from the derived key and ciphertext.
    let derived_mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&keystore.crypto.ciphertext)
        .finalize();

    tracing::info!("[decrypt_data] derived_mac: {:?}", derived_mac.as_slice());
    tracing::info!(
        "[decrypt_data] keystore.crypto.mac: {:?}",
        keystore.crypto.mac.as_slice()
    );
    if derived_mac.as_slice() != keystore.crypto.mac.as_slice() {
        return Err(KeystoreError::MacMismatch);
    }

    // Decrypt the private key bytes using AES-128-CTR
    let decryptor =
        Aes128Ctr::new(&key[..16], &keystore.crypto.cipherparams.iv[..16]).expect("invalid length");

    let mut data = keystore.crypto.ciphertext;

    tracing::info!("[decrypt_data] data: {data:?}");

    decryptor.apply_keystream(&mut data);
    tracing::info!("[decrypt_data] apply_keystream data: {data:?}");

    Ok(data)
}

/// Encrypts the given private key using the [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// password-based key derivation function, and stores it in the provided directory. On success, it
/// returns the `id` (Uuid) generated for this keystore.
///
/// # Example
///
/// ```no_run
/// use eth_keystore::encrypt_key;
/// use rand::RngCore;
/// use std::path::Path;
///
/// # async fn foobar() -> Result<(), Box<dyn std::error::Error>> {
/// let dir = Path::new("./keys");
/// let mut rng = rand::thread_rng();
///
/// // Construct a 32-byte random private key.
/// let mut private_key = vec![0u8; 32];
/// rng.fill_bytes(private_key.as_mut_slice());
///
/// // Since we specify a custom filename for the keystore, it will be stored in `$dir/my-key`
/// let name = encrypt_key(&dir, &mut rng, &private_key, "password_to_keystore", Some("my-key"))?;
/// # Ok(())
/// # }
/// ```
pub fn encrypt_data<P, R, B, S>(
    dir: P,
    rng: &mut R,
    data: B,
    password: S,
    name: Option<&str>,
) -> Result<String, KeystoreError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    B: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    // Generate a random salt.
    let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(salt.as_mut_slice());

    // Derive the key.
    let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
    let scrypt_params = ScryptParams::new(
        DEFAULT_KDF_PARAMS_LOG_N,
        DEFAULT_KDF_PARAMS_R,
        DEFAULT_KDF_PARAMS_P,
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    // Encrypt the private key using AES-128-CTR.
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());

    let encryptor = Aes128Ctr::new(&key[..16], &iv[..16]).expect("invalid length");

    let mut ciphertext = data.as_ref().to_vec();

    tracing::info!("[encrypt_key] ciphertext: {ciphertext:?}");
    encryptor.apply_keystream(&mut ciphertext);
    tracing::info!("[encrypt_key] apply_keystream ciphertext: {ciphertext:?}");

    // Calculate the MAC.
    let mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&ciphertext)
        .finalize();

    // If a file name is not specified for the keystore, simply use the strigified uuid.
    let id = Uuid::new_v4();
    let name = if let Some(name) = name {
        name.to_string()
    } else {
        id.to_string()
    };

    // Construct and serialize the encrypted JSON keystore.
    let keystore = EthKeystore {
        id,
        version: 3,
        crypto: CryptoJson {
            cipher: String::from(DEFAULT_CIPHER),
            cipherparams: CipherparamsJson { iv },
            ciphertext: ciphertext.to_vec(),
            kdf: KdfType::Scrypt,
            kdfparams: KdfparamsType::Scrypt {
                dklen: DEFAULT_KDF_PARAMS_DKLEN,
                n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                p: DEFAULT_KDF_PARAMS_P,
                r: DEFAULT_KDF_PARAMS_R,
                salt,
            },
            mac: mac.to_vec(),
        },
    };

    tracing::info!("[encrypt_data] keystore: {:?}", keystore);
    let contents = serde_json::to_string(&keystore)?;

    // Create a file in write-only mode, to store the encrypted JSON keystore.
    let mut file = File::create(dir.as_ref().join(&name))?;
    file.write_all(contents.as_bytes())?;

    Ok(id.to_string())
}

struct Aes128Ctr {
    inner: ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
}

impl Aes128Ctr {
    fn new(key: &[u8], iv: &[u8]) -> Result<Self, cipher::InvalidLength> {
        let cipher = aes::Aes128::new_from_slice(key).unwrap();
        let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv).unwrap();
        Ok(Self { inner })
    }

    fn apply_keystream(self, buf: &mut [u8]) {
        self.inner.apply_keystream_partial(buf.into());
    }
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_encrypt_key() {
        let dir = Path::new("");
        let mut rng = rand::thread_rng();

        // let provided_master_key_hex =
        //     "8b09ab2bfb613458f9362c4b79ff5ac8b8c6da10f25017807aa08cea969cd1ca";
        let seed_hex = "e61b56077fd615fa661b720d3021627d37bee396dcebd11a31f51355259712fe3b92f4cbd923dca32d6a80dfafbc0dd8f25a59aff331749c9afeef097a29d5d6";
        let provided_master_key_bytes = hex::decode(seed_hex).unwrap();
        let data_to_encrypt = provided_master_key_bytes.as_slice();

        // // let data_to_encrypt = b"Hello, world!";
        // // let data_to_encrypt = alloy::hex!("e61b56077fd615fa661b720d3021627d37bee396dcebd11a31f51355259712fe3b92f4cbd923dca32d6a80dfafbc0dd8f25a59aff331749c9afeef097a29d5d6");
        // let data_to_encrypt =
        //     alloy::hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        // // let data_to_encrypt = alloy::hex!("hellohellohellohellohello");

        let a = data_to_encrypt.as_ref().to_vec();
        tracing::info!("[test_encrypt_key] a: {a:?}");
        tracing::info!("[test_encrypt_key] data: {data_to_encrypt:?}");

        tracing::info!("");
        let password = "password_to_keystore";

        // Since we specify a custom filename for the keystore, it will be stored in `$dir/my-key`
        let _name =
            encrypt_data(&dir, &mut rng, &data_to_encrypt, password, Some("my-key")).unwrap();

        let path = "./my-key";
        let data = decrypt_data(path, password).unwrap();

        let data = hex::encode(data);

        // let wallet = Wallet::from_slice(&data).unwrap();
        // let key = wallet.signer().to_bytes();
        // let private_key = key.to_vec();
        // let private_key = alloy::hex::encode(private_key);
        // let data = alloy::hex::encode(&data);
        tracing::info!("data: {data}");
    }

    #[test]
    fn test_log_n() {
        let n = 8192;
        let n_decimal = rust_decimal::Decimal::from(n);
        let log2_decomal = n_decimal.log10() / Decimal::from(2).log10();

        let log_n = log2_decomal.to_u8().unwrap();

        println!("log_n: {log_n}");

        let mut log_n = 0;
        let mut value = n;
        while value > 1 {
            value >>= 1; // 右移一位，相当于除以2
            log_n += 1;
        }
        println!("log_n: {log_n}");
    }
}
