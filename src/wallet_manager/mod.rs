use std::path::PathBuf;

pub mod api;
pub mod handler;

#[derive(Debug, Clone)]
pub struct WalletManager {
    pub dir: String,
}

impl WalletManager {
    pub fn new(dir: String) -> WalletManager {
        // let dir = PathBuf::from(&dir);
        WalletManager { dir }
    }

    pub fn get_wallet_dir(&self) -> std::path::PathBuf {
        PathBuf::from(&self.dir)
    }

    pub(crate) fn get_root_dir(&self, wallet_name: &str) -> std::path::PathBuf {
        let path = PathBuf::from(&self.dir);
        path.join(wallet_name).join("root")
    }

    pub(crate) fn get_subs_dir(&self, wallet_name: &str) -> std::path::PathBuf {
        let path = PathBuf::from(&self.dir);
        path.join(wallet_name).join("subs")
    }

    /// 遍历指定目录结构，并将结果映射到数据结构中。
    ///
    /// # Arguments
    ///
    /// * `base_path` - 基础目录路径。
    ///
    /// # Returns
    ///
    /// 返回表示目录结构的数据结构，将钱包名称映射到其下的账户目录结构。
    ///
    /// # Example
    ///
    /// ```no_run
    /// let base_path = PathBuf::from("/path/to/wallets");
    /// let structure = traverse_directory_structure(base_path);
    /// tracing::info!("{:#?}", structure);
    /// ```
    pub fn traverse_directory_structure(
        // wallet_tree: &mut super::WalletTree,
        &self,
    ) -> Result<crate::wallet_tree::WalletTree, crate::Error> {
        let mut wallet_tree = crate::wallet_tree::WalletTree::default();
        // wallet_tree.dir = root.to_owned();
        let root = &self.dir;
        for entry in std::fs::read_dir(root).map_err(|e| crate::Error::System(e.into()))? {
            let mut wallet_branch = crate::wallet_tree::WalletBranch::default();
            let entry = entry.map_err(|e| crate::Error::System(e.into()))?;
            let path = entry.path();

            if path.is_dir() {
                let wallet_name = path.file_name().unwrap().to_string_lossy().to_string();
                let root_dir = path.join("root");
                let subs_dir = path.join("subs");
                if !root_dir.exists() {
                    std::fs::create_dir_all(&root_dir)
                        .map_err(|e| crate::Error::System(e.into()))?;
                }
                if !subs_dir.exists() {
                    std::fs::create_dir_all(&subs_dir)
                        .map_err(|e| crate::Error::System(e.into()))?;
                }

                tracing::info!("root_dir: {root_dir:?}");

                let Some(root_dir) = std::fs::read_dir(&root_dir)
                    .map_err(|e| crate::Error::System(e.into()))?
                    .filter_map(Result::ok)
                    .map(|e| e.file_name())
                    .find(|e| e.to_string_lossy().ends_with("-pk"))
                else {
                    continue;
                };

                let pk_filename = root_dir.to_string_lossy().to_string();

                // let seed_filename = fs::read_dir(&root_dir)?
                //     .filter_map(Result::ok)
                //     .find(|e| e.file_name().to_string_lossy().ends_with("-seed"))
                //     .map(|e| e.file_name().to_string_lossy().to_string())
                //     .ok_or_else(|| anyhow::anyhow!("No -seed file found in root directory"))?;

                // let root_address = Root {
                //     pk_filename,
                //     seed_filename,
                // };

                wallet_branch.add_root_from_filename(&pk_filename)?;

                for subs_entry in
                    std::fs::read_dir(subs_dir).map_err(|e| crate::Error::System(e.into()))?
                {
                    let subs_entry = subs_entry.map_err(|e| crate::Error::System(e.into()))?;
                    let subs_path = subs_entry.path();
                    tracing::info!("[traverse_directory_structure] subs_path: {subs_path:?}");

                    if subs_path.is_file()
                        && subs_path
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .ends_with("-pk")
                    {
                        if let Err(e) = wallet_branch.add_key_from_filename(
                            &subs_path.file_name().unwrap().to_string_lossy().to_string(),
                        ) {
                            tracing::error!("[traverse_directory_structure] subs error: {e}");
                            continue;
                        };
                        // let derivation_path =
                        //     subs_path.file_name().unwrap().to_string_lossy().to_string();
                        // accounts.insert(derivation_path, subs_path.to_string_lossy().to_string());
                    }
                }
                // wallet_branch.accounts = accounts;

                tracing::info!(
                    "[traverse_directory_structure] wallet_tree before: {:#?}",
                    wallet_tree
                );
                // 将钱包分支添加到钱包树中
                wallet_tree
                    .tree
                    .insert(wallet_name.to_string(), wallet_branch);
                tracing::info!(
                    "[traverse_directory_structure] wallet_tree after: {:#?}",
                    wallet_tree
                );
            }
        }

        Ok(wallet_tree)
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet_manager::api::tests::{
        print_dir_structure, setup_test_environment, TestData, TestEnv,
    };

    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_traverse_directory_structure() -> Result<(), anyhow::Error> {
        // 创建临时目录结构
        let temp_dir = tempdir()?;
        let root_dir = temp_dir.path();

        // 创建模拟钱包和账户目录结构
        let wallet_a_path = root_dir.join("钱包A");
        let wallet_a_root_path = wallet_a_path.join("root");
        let wallet_a_subs_path = wallet_a_path.join("subs");

        let wallet_b_path = root_dir.join("钱包B");
        let wallet_b_root_path = wallet_b_path.join("root");
        let wallet_b_subs_path = wallet_b_path.join("subs");

        fs::create_dir_all(&wallet_a_root_path)?;
        fs::create_dir_all(&wallet_a_subs_path)?;
        fs::create_dir_all(&wallet_b_root_path)?;
        fs::create_dir_all(&wallet_b_subs_path)?;

        // 创建钱包根密钥文件和种子文件
        let wallet_a_root_pk_file =
            wallet_a_root_path.join("0x296a3C6B001e163409D7df318799bD52B5e3b67d-pk");
        let wallet_a_root_seed_file =
            wallet_a_root_path.join("0x296a3C6B001e163409D7df318799bD52B5e3b67d-seed");
        let wallet_b_root_pk_file =
            wallet_b_root_path.join("0x21A640a53530Aee3feEc2487a01070971d66320f-pk");
        let wallet_b_root_seed_file =
            wallet_b_root_path.join("0x21A640a53530Aee3feEc2487a01070971d66320f-seed");

        File::create(&wallet_a_root_pk_file)?.write_all(b"walletA root pk")?;
        File::create(&wallet_a_root_seed_file)?.write_all(b"walletA root seed")?;
        File::create(&wallet_b_root_pk_file)?.write_all(b"walletB root pk")?;
        File::create(&wallet_b_root_seed_file)?.write_all(b"walletB root seed")?;

        // 创建派生密钥文件
        let wallet_a_sub_key_0 = wallet_a_subs_path.join("address1-m_44'_60'_0'_0_0-pk");
        let wallet_a_sub_key_1 = wallet_a_subs_path.join("address2-m_44'_60'_0'_0_1-pk");
        let wallet_a_sub_key_2 = wallet_a_subs_path.join("address3-m_44'_60'_1'_0_0-pk");

        File::create(&wallet_a_sub_key_0)?.write_all(b"walletA sub key 0")?;
        File::create(&wallet_a_sub_key_1)?.write_all(b"walletA sub key 1")?;
        File::create(&wallet_a_sub_key_2)?.write_all(b"walletA sub key 2")?;

        let dir = &root_dir.to_string_lossy().to_string();

        let manager = crate::WalletManager::new(dir.to_string());

        let wallet_tree = manager.traverse_directory_structure()?;
        // let wallet_tree = {
        //     let root = std::path::Path::new(dir);
        //     WALLET_TREE_MANAGER.get_or_try_init(|| {
        //         // let wallet_tree = crate::traverse_directory_structure(root)?;
        //         let manager = WalletTreeManager::new();
        //         manager.init_resource(root)
        //     })?;
        //     WalletTreeManager::get_wallet_tree()?
        // };
        // 执行目录结构遍历
        // let mut traverse_wallet_tree = crate::wallet_tree::WalletTree::default();
        // WalletTreeManager::traverse_directory_structure(&mut traverse_wallet_tree, root_dir)?;

        // 验证钱包A
        // let wallet_a_branch = wallet_tree.get("钱包A").unwrap();
        // assert_eq!(
        //     wallet_a_branch.wallet_root.pk_filename,
        //     wallet_a_root_pk_file.file_name().unwrap().to_string_lossy()
        // );
        // assert_eq!(
        //     wallet_a_branch.wallet_root.seed_filename,
        //     wallet_a_root_seed_file
        //         .file_name()
        //         .unwrap()
        //         .to_string_lossy()
        // );
        // assert_eq!(
        //     wallet_a_branch
        //         .accounts
        //         .get("address1-m_44'_60'_0'_0_0-pk")
        //         .unwrap(),
        //     &wallet_a_sub_key_0.to_string_lossy()
        // );
        // assert_eq!(
        //     wallet_a_branch
        //         .accounts
        //         .get("address2-m_44'_60'_0'_0_1-pk")
        //         .unwrap(),
        //     &wallet_a_sub_key_1.to_string_lossy()
        // );
        // assert_eq!(
        //     wallet_a_branch
        //         .accounts
        //         .get("address3-m_44'_60'_1'_0_0-pk")
        //         .unwrap(),
        //     &wallet_a_sub_key_2.to_string_lossy()
        // );

        // 验证钱包B
        // let wallet_b_branch = wallet_tree.get("钱包B").unwrap();
        // assert_eq!(
        //     wallet_b_branch.wallet_root.pk_filename,
        //     wallet_b_root_pk_file.file_name().unwrap().to_string_lossy()
        // );
        // assert_eq!(
        //     wallet_b_branch.wallet_root.seed_filename,
        //     wallet_b_root_seed_file
        //         .file_name()
        //         .unwrap()
        //         .to_string_lossy()
        // );
        // assert!(wallet_b_branch.accounts.is_empty());
        print_dir_structure(&root_dir, 0);
        tracing::info!("钱包树: {:#?}", wallet_tree);
        // assert_eq!(*wallet_tree, traverse_wallet_tree);
        Ok(())
    }
}
