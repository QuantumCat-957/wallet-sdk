pub mod api;
pub mod error;
pub mod eth_keystore;
pub mod keystore;
pub mod language;
pub mod signer;
pub mod wallet;

use error::Error;

// pub static RESOURCE_PATH: once_cell::sync::Lazy<once_cell::sync::OnceCell<String>> =
//     once_cell::sync::Lazy::new(once_cell::sync::OnceCell::new);

// pub fn init_resource(app: &tauri::App) {
//     crate::RESOURCE_PATH.get_or_init(|| {
//         let resource_path = app
//             .path_resolver()
//             .resolve_resource("wintun.dll")
//             .expect("failed to resolve resource")
//             .to_string_lossy()
//             .to_string();
//         resource_path
//     });
// }

use std::{collections::HashMap, fs, path::PathBuf};

/// 钱包账户目录结构的表示，包含根文件夹和子文件夹的名称。
pub type AccountDirectory = HashMap<String, (String, String)>;

/// 钱包目录结构的表示，将钱包名称映射到其下的账户目录结构。
// pub type WalletDirectory = HashMap<String, AccountDirectory>;

/// 遍历指定目录结构，并将结果映射到数据结构中。
///
/// # Returns
///
/// 返回表示目录结构的数据结构，将钱包名称映射到其下的账户目录结构。
///
/// # Example
///
/// ```no_run
/// let structure = traverse_directory_structure();
/// println!("{:#?}", structure);
/// ```
// pub fn traverse_directory_structure() -> WalletDirectory {
//     let mut directory_structure: WalletDirectory = HashMap::new();

//     // 模拟目录结构的遍历过程，这里使用示例数据
//     let wallets = vec![
//         (
//             "wallet1".to_string(),
//             vec![
//                 (
//                     "account1".to_string(),
//                     ("root1".to_string(), "sub1".to_string()),
//                 ),
//                 (
//                     "account2".to_string(),
//                     ("root2".to_string(), "sub2".to_string()),
//                 ),
//             ],
//         ),
//         (
//             "wallet2".to_string(),
//             vec![(
//                 "account3".to_string(),
//                 ("root3".to_string(), "sub3".to_string()),
//             )],
//         ),
//     ];

//     // 将遍历结果映射到数据结构中
//     for (wallet_name, accounts) in wallets {
//         let mut account_directory: AccountDirectory = HashMap::new();
//         for (account_name, folders) in accounts {
//             account_directory.insert(account_name, folders);
//         }
//         directory_structure.insert(wallet_name, account_directory);
//     }

//     directory_structure
// }

/// 钱包
///    账户
///       根              子
///    pk    seed         pk  

// pub fn print_files_in_directory(dir: &std::path::Path) {
//     let mut wallet_tree = WalletDirectory::new();

//     if let Ok(wallet_dirs) = std::fs::read_dir(dir) {
//         for Ok(wallet_dir) in wallet_dirs {
//             let wallet_dir_path = wallet_dir.path();
//             if wallet_dir_path.is_dir() {
//                 for account_dirs in std::fs::read_dir(wallet_dir_path) {
//                     for Ok(account_dir) in account_dirs{
//                         let account_dir_path = account_dir.path();
//                         if account_dir_path.is_dir(){
//                             account_dir_path.
//                         }
//                     }
//                     if account_dir
//                 }
//                 // 递归遍历账户目录
//                 print_files_in_directory(&path);
//             } else if let Some(file_name) = path.file_name() {
//                 println!("{}", file_name.to_string_lossy());
//             }
//         }
//     }
// }

/// 表示账户的目录结构，包含根文件夹和子文件夹的名称。
#[derive(Debug)]
pub struct Account {
    root: String,
    subs: Vec<String>,
}

/// 表示钱包的目录结构，将钱包名称映射到其下的账户目录结构。
pub type WalletDirectory = HashMap<String, HashMap<String, Account>>;

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
pub fn traverse_directory_structure(base_path: PathBuf) -> WalletDirectory {
    let mut directory_structure: WalletDirectory = HashMap::new();

    if let Ok(wallets) = fs::read_dir(&base_path) {
        for wallet in wallets {
            if let Ok(wallet) = wallet {
                let wallet_name = wallet.file_name().into_string().unwrap();
                let wallet_path = wallet.path();
                let mut accounts = HashMap::new();

                if let Ok(account_entries) = fs::read_dir(&wallet_path) {
                    for account in account_entries {
                        if let Ok(account) = account {
                            let account_name = account.file_name().into_string().unwrap();
                            let account_path = account.path();
                            let root_path = account_path.join("root");
                            let subs_path = account_path.join("subs");

                            let root = root_path.to_string_lossy().to_string();
                            let mut subs = Vec::new();

                            if let Ok(sub_entries) = fs::read_dir(&subs_path) {
                                for sub in sub_entries {
                                    if let Ok(sub) = sub {
                                        subs.push(sub.file_name().into_string().unwrap());
                                    }
                                }
                            }

                            accounts.insert(account_name, Account { root, subs });
                        }
                    }
                }

                directory_structure.insert(wallet_name, accounts);
            }
        }
    }

    directory_structure
}
