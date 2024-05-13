#![warn(unreachable_pub, clippy::missing_const_for_fn, rustdoc::all)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![deny(unused_must_use)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy::consensus::SignableTransaction;
use alloy::network::{TxSigner, TxSignerSync};
use alloy::primitives::{Address, ChainId, Signature, B256};
use alloy::signers::k256::ecdsa::{self, signature::hazmat::PrehashSigner, RecoveryId};
use alloy::signers::{k256, Result, Signer, SignerSync};
use async_trait::async_trait;
use coins_bip39::{Mnemonic, Wordlist};
use std::fmt;

pub use alloy::signers::wallet::WalletError;

// #[cfg(feature = "mnemonic")]
// mod mnemonic;
// #[cfg(feature = "mnemonic")]
// pub use mnemonic::MnemonicBuilder;

mod private_key;

// #[cfg(feature = "yubihsm")]
// mod yubi;

// #[cfg(feature = "yubihsm")]
// pub use yubihsm;

// #[cfg(feature = "mnemonic")]
// pub use coins_bip39;

/// A wallet instantiated with a locally stored private key
pub type LocalWallet = SeedWallet;

/// A wallet instantiated with a YubiHSM
// #[cfg(feature = "yubihsm")]
// pub type YubiWallet = Wallet<yubihsm::ecdsa::Signer<k256::Secp256k1>>;

/// An Ethereum private-public key pair which can be used for signing messages.
///
/// # Examples
///
/// ## Signing and Verifying a message
///
/// The wallet can be used to produce ECDSA [`Signature`] objects, which can be
/// then verified. Note that this uses
/// [`eip191_hash_message`](alloy_primitives::eip191_hash_message) under the hood which will
/// prefix the message being hashed with the `Ethereum Signed Message` domain separator.
///
/// ```
/// use alloy_signer::{Signer, SignerSync};
///
/// let wallet = alloy_signer_wallet::LocalWallet::random();
///
/// // Optionally, the wallet's chain id can be set, in order to use EIP-155
/// // replay protection with different chains
/// let wallet = wallet.with_chain_id(Some(1337));
///
/// // The wallet can be used to sign messages
/// let message = b"hello";
/// let signature = wallet.sign_message_sync(message)?;
/// assert_eq!(signature.recover_address_from_msg(&message[..]).unwrap(), wallet.address());
///
/// // LocalWallet is clonable:
/// let wallet_clone = wallet.clone();
/// let signature2 = wallet_clone.sign_message_sync(message)?;
/// assert_eq!(signature, signature2);
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct SeedWallet {
    /// The wallet's private key.
    pub(crate) seed: Vec<u8>,
    /// The wallet's address.
    pub(crate) address: Address,
}

impl SeedWallet {
    /// Construct a new wallet with an external [`PrehashSigner`].
    #[inline]
    pub const fn new_with_seed(seed: Vec<u8>, address: Address) -> Self {
        SeedWallet { seed, address }
    }

    /// Returns this wallet's signer.
    #[inline]
    pub const fn seed(&self) -> &Vec<u8> {
        &self.seed
    }

    /// Consumes this wallet and returns its signer.
    #[inline]
    pub fn into_seed(self) -> Vec<u8> {
        self.seed
    }

    /// Returns this wallet's chain ID.
    #[inline]
    pub const fn address(&self) -> Address {
        self.address
    }
}

// do not log the signer
impl fmt::Debug for SeedWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy::consensus::TxLegacy;
    use alloy::primitives::{address, U256};
}
