pub mod api;
pub mod error;
pub mod eth_keystore;
pub mod keystore;
pub mod language;
pub mod signer;
pub mod wallet;

use crossbeam::atomic::AtomicCell;
use error::Error;

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicPtr, Ordering},
        Arc,
    },
};

pub static WALLET_TREE_MANAGER: once_cell::sync::Lazy<
    once_cell::sync::OnceCell<WalletTreeManager>,
> = once_cell::sync::Lazy::new(once_cell::sync::OnceCell::new);

// 使用 AtomicCell 管理 WalletTree 的 Arc 引用
pub struct WalletTreeManager {
    wallet_tree: AtomicPtr<WalletTree>,
}

impl WalletTreeManager {
    pub fn new() -> Self {
        WalletTreeManager {
            wallet_tree: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    pub fn init_resource(self, root: &Path) -> Result<Self, anyhow::Error> {
        let root_path = Path::new(root);
        let wallet_tree = Box::new(traverse_directory_structure(root_path)?);
        let wallet_tree_ptr = Box::into_raw(wallet_tree);
        self.wallet_tree.store(wallet_tree_ptr, Ordering::SeqCst);
        Ok(self)
    }

    pub fn get_wallet_tree() -> Result<Arc<WalletTree>, anyhow::Error> {
        let manager = WALLET_TREE_MANAGER
            .get()
            .ok_or(anyhow::anyhow!("Wallet tree not initialized"))?;
        let ptr = manager.wallet_tree.load(Ordering::SeqCst);
        if ptr.is_null() {
            Err(anyhow::anyhow!("Must init first"))
        } else {
            // 转换成 Arc 共享指针
            Ok(unsafe { Arc::from_raw(ptr) })
        }
    }

    pub fn get_wallet_dir() -> Result<PathBuf, anyhow::Error> {
        let manager = WALLET_TREE_MANAGER
            .get()
            .ok_or(anyhow::anyhow!("Wallet tree not initialized"))?;
        let ptr = manager.wallet_tree.load(Ordering::SeqCst);
        let wallet_tree = unsafe { Arc::from_raw(ptr) };
        Ok(wallet_tree.dir.clone())
    }

    pub fn clear_wallet_tree(&self) {
        let ptr = self
            .wallet_tree
            .swap(std::ptr::null_mut(), Ordering::SeqCst);
        if !ptr.is_null() {
            // 确保正确释放内存
            unsafe {
                Box::from_raw(ptr);
            }
        }
    }
}

/// 钱包
///       根              子
///    pk    seed       pk  pk
///                      
/// 表示钱包的目录结构，将钱包名称映射到其下的账户目录结构。
#[derive(Debug, Default, PartialEq, Clone)]
pub struct WalletTree {
    dir: PathBuf,
    tree: HashMap<String, WalletBranch>,
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

    pub(crate) fn get_root_dir(&self, wallet_name: &str) -> PathBuf {
        self.dir.join(wallet_name).join("root")
    }

    pub(crate) fn get_subs_dir(&self, wallet_name: &str) -> PathBuf {
        self.dir.join(wallet_name).join("subs")
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
pub struct WalletBranch {
    // 根地址
    pub root_address: alloy::primitives::Address,
    // key: 派生路径 value: 地址
    pub accounts: BTreeMap<String, alloy::primitives::Address>,
}

pub(crate) enum WalletType {
    Root(alloy::primitives::Address),
    Subs(alloy::primitives::Address),
}

impl WalletBranch {
    // 根据文件名解析并添加密钥
    pub fn add_key_from_filename(&mut self, filename: &str) -> Result<(), anyhow::Error> {
        if let Some((derivation_path, address)) = extract_address_and_path_from_filename(filename) {
            println!("derivation_path: {derivation_path}, address: {address}");
            let address = address.parse()?;
            self.accounts.insert(derivation_path, address);
        }

        Ok(())
    }

    // 根据文件名解析并添加密钥
    pub fn add_root_from_filename(&mut self, filename: &str) -> Result<(), anyhow::Error> {
        if let Some(address) = extract_address_from_filename(filename) {
            let address: alloy::primitives::Address = address.parse()?;
            self.root_address = address;
        };
        Ok(())
    }

    pub(crate) fn find_with_address(
        &self,
        address: alloy::primitives::Address,
    ) -> Option<WalletType> {
        if self.root_address == address {
            Some(WalletType::Root(address))
        } else if let Some(_) = self.accounts.values().find(|a| a == &&address) {
            Some(WalletType::Subs(address))
        } else {
            None
        }
    }

    pub(crate) fn get_root_pk_filename(&self) -> String {
        keystore::Keystore::from_address_to_name(self.root_address, "pk")
    }

    pub(crate) fn get_root_seed_filename(&self) -> String {
        keystore::Keystore::from_address_to_name(self.root_address, "seed")
    }

    pub(crate) fn get_next_derivation_path(&self) -> String {
        // 找到所有现有的派生路径
        let mut indices: Vec<u32> = self
            .accounts
            .values()
            .map(|address| address.to_string())
            .filter_map(|path| {
                println!("path: {path}");
                if path.starts_with("m/44'/60'/0'/0/") {
                    path.split('/').last()?.parse::<u32>().ok()
                } else {
                    None
                }
            })
            .collect();

        // 找到最大的索引
        indices.sort();
        println!("indices: {indices:?}");
        let next_index = indices.last().cloned().unwrap_or(0) + 1;
        println!("next_index: {next_index}");

        format!("m/44'/60'/0'/0/{}", next_index)
    }
}

// #[derive(Debug)]
// pub struct Root {
//     pub pk_filename: String,
//     pub seed_filename: String,
// }

// #[derive(Debug)]
// pub struct AccountBranch {
//     pub derived_keys: BTreeMap<String, String>,
// }

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
/// println!("{:#?}", structure);
/// ```
pub fn traverse_directory_structure(root: &Path) -> Result<WalletTree, anyhow::Error> {
    let mut wallet_tree: WalletTree = WalletTree::default();

    wallet_tree.dir = root.to_path_buf();

    for entry in fs::read_dir(root)? {
        let mut wallet_branch = WalletBranch::default();
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            let wallet_name = path.file_name().unwrap().to_string_lossy().to_string();
            let root_dir = path.join("root");
            let subs_dir = path.join("subs");
            if !root_dir.exists() {
                fs::create_dir_all(&root_dir)?;
            }
            if !subs_dir.exists() {
                fs::create_dir_all(&subs_dir)?;
            }

            println!("root_dir: {root_dir:?}");

            let Some(root_dir) = fs::read_dir(&root_dir)?
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

            for subs_entry in fs::read_dir(subs_dir)? {
                let subs_entry = subs_entry?;
                let subs_path = subs_entry.path();
                if subs_path.is_file()
                    && subs_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .ends_with("-pk")
                {
                    if let Err(_) = wallet_branch.add_key_from_filename(
                        &subs_path.file_name().unwrap().to_string_lossy().to_string(),
                    ) {
                        continue;
                    };
                    // let derivation_path =
                    //     subs_path.file_name().unwrap().to_string_lossy().to_string();
                    // accounts.insert(derivation_path, subs_path.to_string_lossy().to_string());
                }
            }
            // wallet_branch.accounts = accounts;

            // 将钱包分支添加到钱包树中
            wallet_tree
                .tree
                .insert(wallet_name.to_string(), wallet_branch);
        }
    }

    Ok(wallet_tree)
}

pub(crate) fn extract_address_from_filename(filename: &str) -> Option<String> {
    filename.split('-').next().map(|s| s.to_string())
}

pub(crate) fn extract_address_and_path_from_filename(filename: &str) -> Option<(String, String)> {
    println!("filename: {filename}");
    let parts: Vec<&str> = filename.split('-').collect();
    if parts.len() >= 3 {
        let address = parts[0].to_string();
        let derivation_path = parts[1..parts.len() - 1].join("-").replace("_", "/");
        Some((address, derivation_path))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
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

        let wallet_tree = {
            let root = Path::new(dir);
            crate::WALLET_TREE_MANAGER.get_or_try_init(|| {
                // let wallet_tree = crate::traverse_directory_structure(root)?;
                let manager = crate::WalletTreeManager::new();
                manager.init_resource(root)
            })?;
            WalletTreeManager::get_wallet_tree()?
        };
        // 执行目录结构遍历
        let traverse_wallet_tree = traverse_directory_structure(root_dir)?;

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
        api::tests::print_dir_structure(&root_dir, 0);
        println!("钱包树: {:#?}", wallet_tree);
        assert_eq!(*wallet_tree, traverse_wallet_tree);
        Ok(())
    }

    #[test]
    fn test_get_next_derivation_path() -> Result<(), anyhow::Error> {
        // 创建钱包分支
        let mut wallet_branch = WalletBranch {
            root_address: "0x296a3c6b001e163409d7df318799bd52b5e3b67d"
                .parse()
                .unwrap(),
            accounts: BTreeMap::new(),
        };

        // 添加一些派生路径
        wallet_branch.add_key_from_filename("address-m_44'_60'_0'_0_0-pk")?;
        wallet_branch.add_key_from_filename("address-m_44'_60'_0'_0_1-pk")?;

        // 检查生成的下一个派生路径
        let next_derivation_path = wallet_branch.get_next_derivation_path();
        assert_eq!(next_derivation_path, "m/44'/60'/0'/0/2");

        // 添加更多派生路径
        wallet_branch.add_key_from_filename("address-m_44'_60'_0'_0_2-pk")?;
        wallet_branch.add_key_from_filename("address-m_44'_60'_0'_0_4-pk")?;

        // 检查生成的下一个派生路径
        let next_derivation_path = wallet_branch.get_next_derivation_path();
        assert_eq!(next_derivation_path, "m/44'/60'/0'/0/5");

        Ok(())
    }
}
