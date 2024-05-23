use std::f64::consts::E;

use serde::Serialize;

/// 钱包
///       根              子
///    pk    seed       pk  pk
///                      
/// 表示钱包的目录结构，将钱包名称映射到其下的账户目录结构。
#[derive(Debug, Default, PartialEq, Clone, Serialize)]
pub struct WalletTree {
    pub tree: std::collections::HashMap<String, WalletBranch>,
}

impl WalletTree {
    pub(crate) fn get_wallet_branch(
        &self,
        wallet_name: &str,
    ) -> Result<&WalletBranch, anyhow::Error> {
        self.tree
            .get(wallet_name)
            .ok_or(anyhow::anyhow!("No wallet"))
    }

    pub(crate) fn get_mut_wallet_branch(
        &mut self,
        wallet_name: &str,
    ) -> Result<&mut WalletBranch, anyhow::Error> {
        self.tree
            .get_mut(wallet_name)
            .ok_or(anyhow::anyhow!("No wallet"))
    }
}

#[derive(Debug)]
pub(crate) enum AccountInfo {
    Root(KeystoreInfo),
    Sub(String, KeystoreInfo),
}

impl AccountInfo {
    pub(crate) fn generate_pk_filename(&self) -> String {
        match self {
            AccountInfo::Root(keystore_info) => keystore_info.from_address_to_name(),
            AccountInfo::Sub(chain_code, keystore_info) => {
                keystore_info.from_derivation_path_to_name(&chain_code)
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct WalletBranch {
    // 根账户信息
    pub root_info: KeystoreInfo,
    // key: 派生路径 value: 子账户信息
    pub accounts: std::collections::BTreeMap<String, KeystoreInfo>,
}

impl Default for WalletBranch {
    fn default() -> Self {
        Self {
            root_info: KeystoreInfo {
                address: Default::default(),
                suffix: crate::utils::file::Suffix::Pk { deprecated: false },
            },
            accounts: Default::default(),
        }
    }
}

// pub struct

impl WalletBranch {
    // 根据文件名解析并添加密钥
    pub fn add_subkey_from_filename(&mut self, filename: &str) -> Result<(), anyhow::Error> {
        let (derivation_path, wallet_info) =
            crate::utils::file::extract_sub_address_and_derive_path_from_filename(filename)?;
        tracing::info!(
            "[add_key_from_filename] derivation_path: {derivation_path}, wallet_info: {wallet_info:#?}"
        );

        let derivation_path =
            crate::utils::derivation::derivation_path_percent_decode(&derivation_path);
        tracing::info!("[add_key_from_filename] accounts: {:#?}", self.accounts);
        self.accounts
            .insert(derivation_path.decode_utf8()?.to_string(), wallet_info);
        tracing::info!(
            "[add_key_from_filename] after accounts: {:#?}",
            self.accounts
        );

        Ok(())
    }

    // 根据文件名解析并添加密钥
    pub fn add_root_from_filename(&mut self, filename: &str) -> Result<(), anyhow::Error> {
        let wallet_info =
            crate::utils::file::extract_root_address_and_suffix_from_filename(filename)?;

        self.root_info = wallet_info;
        Ok(())
    }

    pub(crate) fn deprecate_subkeys(
        &mut self,
        root_address: &alloy::primitives::Address,
        subs_path: std::path::PathBuf,
    ) {
        if self.root_info.address == *root_address {
            for (raw_derivation_path, keystore_info) in self.accounts.iter_mut() {
                let old_pk_name = keystore_info.from_derivation_path_to_name(raw_derivation_path);
                let old_path = subs_path.join(old_pk_name);
                keystore_info.suffix = crate::utils::file::Suffix::deprecated_pk();
                let new_pk_name = keystore_info.from_derivation_path_to_name(raw_derivation_path);
                let new_path = subs_path.join(new_pk_name);
                if let Err(e) = std::fs::rename(&old_path, new_path) {
                    tracing::error!("[deprecate_subkeys] Rename {old_path:?} error: {e}");
                };
            }
        }
    }

    pub(crate) fn recover_subkey(
        &mut self,
        sub_address: &alloy::primitives::Address,
        subs_path: std::path::PathBuf,
    ) {
        if let Some((raw_derivation_path, keystore_info)) = self
            .accounts
            .iter_mut()
            .find(|(_, keystore_info)| keystore_info.address == *sub_address)
        {
            let old_pk_name = keystore_info.from_derivation_path_to_name(raw_derivation_path);
            let old_path = subs_path.join(old_pk_name);
            keystore_info.suffix = crate::utils::file::Suffix::pk();
            let new_pk_name = keystore_info.from_derivation_path_to_name(raw_derivation_path);
            let new_path = subs_path.join(new_pk_name);
            std::fs::rename(old_path, new_path);
        }
    }

    pub(crate) fn get_account_with_address(
        &self,
        address: &alloy::primitives::Address,
    ) -> Option<AccountInfo> {
        if &self.root_info.address == address {
            Some(AccountInfo::Root(self.root_info.to_owned()))
        } else if let Some((derivation_path, _)) =
            self.accounts.iter().find(|(_, a)| a.address == *address)
        {
            Some(AccountInfo::Sub(
                derivation_path.to_string(),
                self.root_info.to_owned(),
            ))
        } else {
            None
        }
    }

    pub(crate) fn get_root_pk_filename(&self) -> String {
        KeystoreInfo::new(crate::utils::file::Suffix::pk(), self.root_info.address)
            .from_address_to_name()
    }

    pub(crate) fn get_root_seed_filename(&self) -> String {
        KeystoreInfo::new(crate::utils::file::Suffix::seed(), self.root_info.address)
            .from_address_to_name()
    }

    pub(crate) fn get_sub_pk_filename(
        address: &alloy::primitives::Address,
        raw_derivation_path: &str,
    ) -> Result<String, anyhow::Error> {
        // let chain = self
        //     .accounts
        //     .iter()
        //     .find(|(_, a)| a == &&address)
        //     .map(|(chain, _)| chain)
        //     .ok_or(anyhow::anyhow!("File not found"))?;
        Ok(
            KeystoreInfo::new(crate::utils::file::Suffix::pk(), *address)
                .from_derivation_path_to_name(raw_derivation_path),
        )
    }
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct KeystoreInfo {
    pub address: alloy::primitives::Address,
    pub suffix: crate::utils::file::Suffix,
}

impl KeystoreInfo {
    pub(crate) fn new(
        suffix: crate::utils::file::Suffix,
        address: alloy::primitives::Address,
    ) -> Self {
        Self { address, suffix }
    }

    pub(crate) fn from_address_to_name(&self) -> String {
        // tracing::info!("from_signingkey_to_name: {:#?}", address);
        // let hash_name = Self::generate_hashed_filename(address, derivation_path);
        let name = format!("{}-{}", self.address.to_string(), self.suffix.to_string());
        name
    }

    pub(crate) fn from_derivation_path_to_name(&self, raw_derivation_path: &str) -> String {
        // tracing::info!("from_signingkey_to_name: {:#?}", address);
        // let hash_name = Self::generate_hashed_filename(address, derivation_path);
        // let name = format!("{}-{}", address.to_string(), suffix);

        let derivation_path =
            crate::utils::derivation::derivation_path_percent_encode(raw_derivation_path);

        let name = format!(
            "{}-{}-{}",
            self.address,
            derivation_path,
            self.suffix.to_string()
        );
        name
    }
}
