pub(crate) fn extract_root_address_and_suffix_from_filename(
    filename: &str,
) -> Result<crate::wallet_tree::KeystoreInfo, anyhow::Error> {
    let parts: Vec<&str> = filename.split('-').collect();
    if parts.len() >= 2 {
        let address = parts[0].to_string();
        let address = address.parse()?;
        let suffix = parts[1];
        let deprecated = suffix.starts_with("deprecated");

        let suffix = if suffix.ends_with("pk") {
            if deprecated {
                Suffix::deprecated_pk()
            } else {
                Suffix::pk()
            }
        } else if suffix.ends_with("seed") {
            Suffix::seed()
        } else {
            return Err(anyhow::anyhow!("Filename invalid"));
        };

        Ok(crate::wallet_tree::KeystoreInfo { address, suffix })
    } else {
        Err(anyhow::anyhow!("Filename invalid"))
    }
}

pub(crate) fn extract_sub_address_and_derive_path_from_filename(
    filename: &str,
) -> Result<(String, crate::wallet_tree::KeystoreInfo), anyhow::Error> {
    tracing::info!("filename: {filename}");
    let parts: Vec<&str> = filename.split('-').collect();
    if parts.len() >= 3 {
        let address = parts[0].to_string();
        let address = address.parse()?;
        let derivation_path = parts[1].to_string();
        let suffix = parts[2];

        tracing::info!(
            "[extract_address_and_path_from_filename] derivation_path: {derivation_path}"
        );
        let deprecated = suffix.starts_with("deprecated");
        let suffix = if suffix.ends_with("pk") {
            if deprecated {
                Suffix::deprecated_pk()
            } else {
                Suffix::pk()
            }
        } else {
            return Err(anyhow::anyhow!("Filename invalid"));
        };

        Ok((
            derivation_path,
            crate::wallet_tree::KeystoreInfo { address, suffix },
        ))
    } else {
        Err(anyhow::anyhow!("Filename invalid"))
    }
}

#[derive(Debug, PartialEq, Clone, serde::Serialize)]
pub enum Suffix {
    Pk { deprecated: bool },
    Seed,
}

impl Suffix {
    pub(crate) fn pk() -> Suffix {
        Suffix::Pk { deprecated: false }
    }

    pub(crate) fn deprecated_pk() -> Suffix {
        Suffix::Pk { deprecated: true }
    }

    pub(crate) fn seed() -> Suffix {
        Suffix::Seed
    }

    pub(crate) fn to_string(&self) -> String {
        match self {
            Suffix::Pk { deprecated } => {
                if *deprecated {
                    "deprecated_pk".to_string()
                } else {
                    "pk".to_string()
                }
            }
            Suffix::Seed => "seed".to_string(),
        }
    }
}
