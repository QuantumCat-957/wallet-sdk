pub(crate) fn extract_address_from_filename(filename: &str) -> Option<String> {
    filename.split('-').next().map(|s| s.to_string())
}

pub(crate) fn extract_address_and_path_from_filename(filename: &str) -> Option<(String, String)> {
    tracing::info!("filename: {filename}");
    let parts: Vec<&str> = filename.split('-').collect();
    if parts.len() >= 3 {
        let address = parts[0].to_string();
        let derivation_path = parts[1..parts.len() - 1].join("-");

        tracing::info!(
            "[extract_address_and_path_from_filename] derivation_path: {derivation_path}"
        );
        Some((address, derivation_path))
    } else {
        None
    }
}
