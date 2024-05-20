pub(crate) mod manager;

/// 钱包
///       根              子
///    pk    seed       pk  pk
///                      
/// 表示钱包的目录结构，将钱包名称映射到其下的账户目录结构。
#[derive(Debug, Default, PartialEq, Clone)]
pub struct WalletTree {
    dir: std::path::PathBuf,
    tree: std::collections::HashMap<String, WalletBranch>,
}

impl WalletTree {
    pub fn fresh() -> Result<(), anyhow::Error> {
        // let wallet_tree = crate::WALLET_TREE_MANAGER.get_mut();
        Ok(())
    }

    pub(crate) fn get_wallet_branch(
        &self,
        wallet_name: &str,
    ) -> Result<&WalletBranch, anyhow::Error> {
        self.tree
            .get(wallet_name)
            .ok_or(anyhow::anyhow!("No wallet"))
    }

    pub(crate) fn get_root_dir(&self, wallet_name: &str) -> std::path::PathBuf {
        self.dir.join(wallet_name).join("root")
    }

    pub(crate) fn get_subs_dir(&self, wallet_name: &str) -> std::path::PathBuf {
        self.dir.join(wallet_name).join("subs")
    }
}

#[derive(Debug)]
pub(crate) enum Account {
    Root(alloy::primitives::Address),
    Sub(alloy::primitives::Address, String),
}

impl Account {
    pub(crate) fn generate_pk_filename(&self) -> String {
        match self {
            Account::Root(address) => {
                crate::keystore::Keystore::from_address_to_name(address, "pk")
            }
            Account::Sub(address, chain_code) => {
                crate::keystore::Keystore::from_address_and_derivation_path_to_name(
                    *address,
                    &chain_code,
                    "pk",
                )
            }
        }
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct WalletBranch {
    // 根地址
    pub root_address: alloy::primitives::Address,
    // key: 派生路径 value: 地址
    pub accounts: std::collections::BTreeMap<String, alloy::primitives::Address>,
}

impl WalletBranch {
    // 根据文件名解析并添加密钥
    pub fn add_key_from_filename(&mut self, filename: &str) -> Result<(), anyhow::Error> {
        if let Some((address, derivation_path)) =
            crate::utils::file::extract_address_and_path_from_filename(filename)
        {
            tracing::info!(
                "[add_key_from_filename] derivation_path: {derivation_path}, address: {address}"
            );
            let address = address.parse()?;
            let derivation_path =
                crate::utils::derivation::derivation_path_percent_decode(&derivation_path);
            tracing::info!("[add_key_from_filename] accounts: {:#?}", self.accounts);
            self.accounts
                .insert(derivation_path.decode_utf8()?.to_string(), address);
            tracing::info!(
                "[add_key_from_filename] after accounts: {:#?}",
                self.accounts
            );
        }

        Ok(())
    }

    // 根据文件名解析并添加密钥
    pub fn add_root_from_filename(&mut self, filename: &str) -> Result<(), anyhow::Error> {
        if let Some(address) = crate::utils::file::extract_address_from_filename(filename) {
            let address: alloy::primitives::Address = address.parse()?;
            self.root_address = address;
        };
        Ok(())
    }

    pub(crate) fn get_account_with_address(
        &self,
        address: &alloy::primitives::Address,
    ) -> Option<Account> {
        if &self.root_address == address {
            Some(Account::Root(*address))
        } else if let Some((chain_code, _)) = self.accounts.iter().find(|(_, a)| a == &address) {
            Some(Account::Sub(*address, chain_code.to_string()))
        } else {
            None
        }
    }

    pub(crate) fn get_root_pk_filename(&self) -> String {
        crate::keystore::Keystore::from_address_to_name(&self.root_address, "pk")
    }

    pub(crate) fn get_root_seed_filename(&self) -> String {
        crate::keystore::Keystore::from_address_to_name(&self.root_address, "seed")
    }

    pub(crate) fn get_sub_pk_filename(
        &self,
        address: &alloy::primitives::Address,
        chain_code: &str,
    ) -> Result<String, anyhow::Error> {
        // let chain = self
        //     .accounts
        //     .iter()
        //     .find(|(_, a)| a == &&address)
        //     .map(|(chain, _)| chain)
        //     .ok_or(anyhow::anyhow!("File not found"))?;

        Ok(
            crate::keystore::Keystore::from_address_and_derivation_path_to_name(
                *address, chain_code, "pk",
            ),
        )
    }

    // pub(crate) fn get_next_derivation_path(&self) -> String {
    //     // 找到所有现有的派生路径
    //     let mut indices: Vec<u32> = self
    //         .accounts
    //         .values()
    //         .map(|address| address.to_string())
    //         .filter_map(|path| {
    //             tracing::info!("[get_next_derivation_path] path: {path}");
    //             if path.starts_with("m/44'/60'/0'/0/") {
    //                 path.split('/').last()?.parse::<u32>().ok()
    //             } else {
    //                 None
    //             }
    //         })
    //         .collect();

    //     // 找到最大的索引
    //     indices.sort();
    //     tracing::info!("indices: {indices:?}");
    //     let next_index = indices.last().cloned().unwrap_or(0) + 1;
    //     tracing::info!("next_index: {next_index}");

    //     format!("m/44'/60'/0'/0/{}", next_index)
    // }
}
