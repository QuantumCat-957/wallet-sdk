// pub fn init_resource(root: &str) -> Result<(), crate::Error> {
//     let root = std::path::Path::new(root);
//     crate::wallet_tree::manager::WALLET_TREE_MANAGER
//         .get_or_try_init(|| {
//             // let wallet_tree = crate::traverse_directory_structure(root)?;
//             let manager = crate::wallet_tree::manager::WalletTreeManager::new();
//             manager.init_resource(root)
//         })
//         .map_err(|e| crate::SystemError::Service(e.to_string()))?;

//     Ok(())
// }

pub fn gen_phrase(lang: &str) -> Result<String, crate::Error> {
    let lang = crate::utils::language::Language::from_str(lang)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;
    Ok(lang.gen_phrase())
}

pub fn generate_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    wallet_name: &str,
    password: &str,
) -> Result<alloy::primitives::Address, crate::Error> {
    // Construct the storage path based on the wallet name and derivation path
    let storage_path = crate::keystore::Keystore::build_storage_path(wallet_name, true)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    tracing::info!("storage_path: {storage_path:?}");

    // Clear any existing keystore at the storage path
    if storage_path.exists() {
        std::fs::remove_dir_all(&storage_path)
            .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Remove the directory and its contents
    }
    std::fs::create_dir_all(&storage_path)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Recreate the directory

    // Create a new root keystore
    let keystore = crate::keystore::Keystore::new(lang)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?
        .create_root_keystore_with_path_phrase(phrase, salt, &storage_path, password)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    Ok(keystore
        .get_address()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?)
}

pub fn reset_root(
    lang: &str,
    phrase: &str,
    salt: &str,
    address: &str,
    wallet_name: &str,
    new_password: &str,
) -> Result<alloy::primitives::Address, crate::Error> {
    // Parse the provided address
    let address = address
        .parse::<alloy::primitives::Address>()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Verify that the provided mnemonic phrase and salt generate the expected address
    crate::keystore::Keystore::new(lang)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?
        .check_address(phrase, salt, address)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Construct the storage path based on the wallet name and derivation path
    let storage_path = crate::keystore::Keystore::build_storage_path(wallet_name, true)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    tracing::info!("storage_path: {storage_path:?}");

    // Clear any existing keystore at the storage path
    if storage_path.exists() {
        std::fs::remove_dir_all(&storage_path)
            .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Remove the directory and its contents
    }
    std::fs::create_dir_all(&storage_path)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?; // Recreate the directory

    // Create a new root keystore with the new password
    let wallet = crate::keystore::Keystore::new(lang)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?
        .create_root_keystore_with_path_phrase(phrase, salt, &storage_path, new_password)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Return the address of the newly created keystore
    Ok(wallet
        .get_address()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?)
}

pub fn set_password(
    wallet_name: &str,
    address: &str,
    old_password: &str,
    new_password: &str,
) -> Result<(), crate::Error> {
    // Parse the provided address
    let address = address
        .parse::<alloy::primitives::Address>()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;
    // Set the password for the keystore associated with the specified address
    Ok(
        crate::keystore::Keystore::set_password(wallet_name, address, old_password, new_password)
            .map_err(|e| crate::SystemError::Service(e.to_string()))?,
    )
}

pub fn derive_subkey(
    derivation_path: &str,
    wallet_name: &str,
    root_password: &str,
    derive_password: &str,
) -> Result<alloy::primitives::Address, crate::Error> {
    // Retrieve the directory where the wallet data is stored
    let wallet_dir = crate::wallet_tree::manager::WalletTreeManager::get_wallet_dir()
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Initialize an empty WalletTree structure
    let mut wallet_tree = crate::wallet_tree::WalletTree::default();

    // Traverse the directory structure to populate the wallet tree
    crate::wallet_tree::manager::WalletTreeManager::traverse_directory_structure(
        &mut wallet_tree,
        &wallet_dir,
    )
    .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Get the root and subs directory paths for the specified wallet
    let root_dir = wallet_tree.get_root_dir(wallet_name);
    let subs_dir = wallet_tree.get_subs_dir(wallet_name);

    // Retrieve the wallet branch for the specified wallet
    let wallet = wallet_tree
        .get_wallet_branch(wallet_name)
        .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Get the root keystore using the root password
    let seed_wallet =
        crate::keystore::Keystore::get_seed_keystore(wallet.root_address, &root_dir, root_password)
            .map_err(|e| crate::SystemError::Service(e.to_string()))?;
    tracing::info!("seed_wallet: {seed_wallet:#?}");

    // Derive a new subkey using the seed and chain code, and save it with the derive password
    let seed_wallet = crate::keystore::Keystore::derive_child_with_seed_and_chain_code_save(
        seed_wallet.seed,
        derivation_path,
        subs_dir.to_string_lossy().to_string().as_str(),
        derive_password,
    )
    .map_err(|e| crate::SystemError::Service(e.to_string()))?;

    // Return the address of the newly created subkey
    let address = seed_wallet.address();

    Ok(address)
}
