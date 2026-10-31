use crate::crypto::{CryptoEngine, CryptoError};
use crate::models::{AuthSettings, VaultData};
use directories::ProjectDirs;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub const VAULT_FILENAME: &str = "vault.vult";
pub const CONFIG_FILENAME: &str = "config.json";

#[derive(Debug)]
pub enum StorageError {
    IoError(std::io::Error),
    CryptoError(CryptoError),
    SerializationError(serde_json::Error),
    VaultNotFound,
    DirectoryError(String),
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::IoError(e)
    }
}

impl From<CryptoError> for StorageError {
    fn from(e: CryptoError) -> Self {
        StorageError::CryptoError(e)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::SerializationError(e)
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "I/O error: {}", e),
            StorageError::CryptoError(e) => write!(f, "Cryptographic error: {}", e),
            StorageError::SerializationError(e) => write!(f, "JSON error: {}", e),
            StorageError::VaultNotFound => write!(f, "No vault found on system"),
            StorageError::DirectoryError(s) => write!(f, "Directory error: {}", s),
        }
    }
}

impl std::error::Error for StorageError {}

pub struct StorageManager {
    base_dir: PathBuf,
}

impl StorageManager {
    pub fn new() -> Result<Self, StorageError> {
        let base_dir = Self::resolve_default_dir()?;
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir)?;
        }
        Ok(Self { base_dir })
    }

    pub fn with_custom_dir(dir: PathBuf) -> Result<Self, StorageError> {
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        Ok(Self { base_dir: dir })
    }

    fn resolve_default_dir() -> Result<PathBuf, StorageError> {
        if let Some(proj_dirs) = ProjectDirs::from("com", "vult", "Vult") {
            Ok(proj_dirs.data_dir().to_path_buf())
        } else {
            // Fallback to local ./vult_data
            let fallback = PathBuf::from("./vult_data");
            Ok(fallback)
        }
    }

    pub fn get_vault_path(&self) -> PathBuf {
        self.base_dir.join(VAULT_FILENAME)
    }

    pub fn get_config_path(&self) -> PathBuf {
        self.base_dir.join(CONFIG_FILENAME)
    }

    pub fn vault_exists(&self) -> bool {
        self.get_vault_path().exists()
    }

    /// Read non-sensitive configuration (e.g. auth mode, whether Windows Hello is enabled)
    pub fn read_config(&self) -> Result<AuthSettings, StorageError> {
        let config_path = self.get_config_path();
        if !config_path.exists() {
            return Ok(AuthSettings::default());
        }
        let mut file = File::open(config_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let settings: AuthSettings = serde_json::from_str(&contents)?;
        Ok(settings)
    }

    /// Save non-sensitive configuration to config.json
    pub fn write_config(&self, settings: &AuthSettings) -> Result<(), StorageError> {
        let config_path = self.get_config_path();
        let json = serde_json::to_string_pretty(settings)?;
        let temp_path = config_path.with_extension("tmp");
        {
            let mut file = File::create(&temp_path)?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        Self::atomic_replace_file(&temp_path, &config_path)?;
        Ok(())
    }

    /// Resilient atomic replace with retries and fallback to handle Windows file locking / antivirus scanners
    fn atomic_replace_file(from: &Path, to: &Path) -> Result<(), StorageError> {
        let mut attempts = 0;
        loop {
            match fs::rename(from, to) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    attempts += 1;
                    if attempts < 6 {
                        let delay_ms = 25 * (1 << (attempts - 1).min(4));
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    } else {
                        if fs::copy(from, to).is_ok() {
                            let _ = fs::remove_file(from);
                            return Ok(());
                        }
                        return Err(StorageError::IoError(e));
                    }
                }
            }
        }
    }

    /// Save encrypted vault using atomic write (write to tmp -> sync -> rename)
    pub fn save_vault(&self, data: &VaultData, password: &[u8], crypto: &CryptoEngine) -> Result<(), StorageError> {
        let vault_path = self.get_vault_path();
        let mut plaintext_json = serde_json::to_vec(data)?;

        // Encrypt with AES-256-GCM + Argon2id
        let encrypted_res = crypto.encrypt_vault(password, &plaintext_json);
        plaintext_json.zeroize();
        let encrypted_bytes = encrypted_res?;

        // Atomic write to avoid file corruption
        let temp_path = vault_path.with_extension("tmp");
        {
            let mut file = File::create(&temp_path)?;
            file.write_all(&encrypted_bytes)?;
            file.sync_all()?;
        }
        Self::atomic_replace_file(&temp_path, &vault_path)?;

        // Also update config.json with current auth settings
        self.write_config(&data.settings)?;

        Ok(())
    }

    /// Load and decrypt vault data
    pub fn load_vault(&self, password: &[u8], crypto: &CryptoEngine) -> Result<VaultData, StorageError> {
        let vault_path = self.get_vault_path();
        if !vault_path.exists() {
            return Err(StorageError::VaultNotFound);
        }

        let mut file = File::open(&vault_path)?;
        let mut encrypted_bytes = Vec::new();
        file.read_to_end(&mut encrypted_bytes)?;

        // Decrypt and verify integrity
        let mut decrypted_json = crypto.decrypt_vault(password, &encrypted_bytes)?;

        let vault_data_res: Result<VaultData, serde_json::Error> = serde_json::from_slice(&decrypted_json);
        decrypted_json.zeroize();
        let vault_data = vault_data_res?;
        Ok(vault_data)
    }

    /// Export raw encrypted vault or backup to path
    pub fn export_vault_file(&self, destination_path: &Path) -> Result<(), StorageError> {
        let vault_path = self.get_vault_path();
        if !vault_path.exists() {
            return Err(StorageError::VaultNotFound);
        }
        fs::copy(&vault_path, destination_path)?;
        Ok(())
    }

    /// Import vault file replacing current vault
    pub fn import_vault_file(&self, source_path: &Path) -> Result<(), StorageError> {
        if !source_path.exists() {
            return Err(StorageError::VaultNotFound);
        }
        let vault_path = self.get_vault_path();
        fs::copy(source_path, &vault_path)?;
        Ok(())
    }

    /// Wipe all vault files completely
    pub fn wipe(&self) -> Result<(), StorageError> {
        let vault_path = self.get_vault_path();
        if vault_path.exists() {
            fs::remove_file(vault_path)?;
        }
        let config_path = self.get_config_path();
        if config_path.exists() {
            fs::remove_file(config_path)?;
        }
        let hello_path = self.get_vault_path().with_extension("hello");
        if hello_path.exists() {
            let _ = fs::remove_file(hello_path);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_storage_save_load_roundtrip() {
        let temp_dir = env::temp_dir().join(format!("vult_test_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let password = b"TestMasterPassword!";

        let mut vault = VaultData::default();
        vault.entries.push(crate::models::VaultEntry {
            id: "entry-1".to_string(),
            category: "login".to_string(),
            title: "Test Login".to_string(),
            fields: serde_json::json!({ "username": "admin", "password": "123" }),
            notes: None,
            tags: vec![],
            favorite: false,
            created_at: "".to_string(),
            modified_at: "".to_string(),
            accessed_at: "".to_string(),
        });

        // Save
        storage.save_vault(&vault, password, &crypto).unwrap();
        assert!(storage.vault_exists());

        // Load
        let loaded = storage.load_vault(password, &crypto).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].title, "Test Login");

        // Wipe
        storage.wipe().unwrap();
        assert!(!storage.vault_exists());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
