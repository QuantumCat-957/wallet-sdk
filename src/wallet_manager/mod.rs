pub mod api;
pub mod handler;

pub struct WalletManager {
    dir: String,
}

impl WalletManager {
    pub fn new(dir: String) -> WalletManager {
        WalletManager { dir }
    }
}
