use crate::crypto::CryptoEngine;
use crate::models::{AuthSettings, VaultData, VaultEntry};

use crate::storage::StorageManager;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

pub struct AuthManager {
    pub storage: StorageManager,
    pub crypto: CryptoEngine,
    state: Mutex<AuthState>,
}

struct AuthState {
    is_unlocked: bool,
    data: Option<VaultData>,
    active_password: Option<Vec<u8>>,
    failed_attempts: u32,
    lockout_until: Option<Instant>,
}

impl Drop for AuthState {
    fn drop(&mut self) {
        if let Some(mut pwd) = self.active_password.take() {
            pwd.zeroize();
        }
    }
}

impl AuthManager {
    pub fn new(storage: StorageManager, crypto: CryptoEngine) -> Self {
        Self {
            storage,
            crypto,
            state: Mutex::new(AuthState {
                is_unlocked: false,
                data: None,
                active_password: None,
                failed_attempts: 0,
                lockout_until: None,
            }),
        }
    }

    /// Check if vault exists
    pub fn vault_exists(&self) -> bool {
        self.storage.vault_exists()
    }

    /// Check brute force lockout
    fn check_lockout(state: &AuthState) -> Result<(), String> {
        if let Some(until) = state.lockout_until {
            let now = Instant::now();
            if now < until {
                let remaining = (until - now).as_secs() + 1;
                return Err(format!(
                    "Too many failed attempts. Please wait {}s before trying again.",
                    remaining
                ));
            }
        }
        Ok(())
    }

    /// Record a failed authentication attempt with exponential backoff
    fn record_failure(state: &mut AuthState) -> String {
        state.failed_attempts += 1;
        let delay_secs = match state.failed_attempts {
            0..=2 => 0,
            3 => 2,
            4 => 5,
            5 => 15,
            _ => 30,
        };

        if delay_secs > 0 {
            state.lockout_until = Some(Instant::now() + Duration::from_secs(delay_secs));
            format!(
                "Invalid credentials. Too many failed attempts! Wait {}s.",
                delay_secs
            )
        } else {
            "Invalid credentials. Please try again.".to_string()
        }
    }

    /// Setup first-run vault
    pub fn setup_vault(
        &self,
        pin: Option<String>,
        password: String,
        auth_mode: String,
    ) -> Result<bool, String> {
        let mut vault_data = VaultData::default();
        vault_data.settings.auth_mode = auth_mode;

        // Hash PIN if present for quick verification / settings
        if let Some(ref p) = pin {
            vault_data.settings.pin_hash = Some(p.clone());
        }

        // Use password (or PIN if pin_only) as the encryption key
        let effective_pass = if vault_data.settings.auth_mode == "pin_only" {
            pin.clone().unwrap_or(password.clone())
        } else {
            password.clone()
        };

        // Save encrypted vault
        self.storage
            .save_vault(&vault_data, effective_pass.as_bytes(), &self.crypto)
            .map_err(|e| format!("Failed to save vault: {}", e))?;

        // Unlock in-memory state
        let mut state = self.state.lock().unwrap();
        state.is_unlocked = true;
        state.data = Some(vault_data);
        state.active_password = Some(effective_pass.into_bytes());
        state.failed_attempts = 0;
        state.lockout_until = None;

        Ok(true)
    }

    /// Unlock existing vault
    pub fn unlock(&self, pin: Option<String>, password: String) -> Result<bool, String> {
        let mut state = self.state.lock().unwrap();

        // 1. Check brute force backoff
        Self::check_lockout(&state)?;

        // Read config to check mode
        let config = self.storage.read_config().unwrap_or_default();
        let effective_pass = if config.auth_mode == "pin_only" {
            pin.clone().unwrap_or(password.clone())
        } else {
            password.clone()
        };

        // If mode requires PIN and PIN is present, verify against PIN hash in config if stored
        if config.auth_mode == "pin_and_password" {
            if let Some(ref required_pin) = config.pin_hash {
                if let Some(ref user_pin) = pin {
                    if user_pin != required_pin {
                        let err_msg = Self::record_failure(&mut state);
                        return Err(err_msg);
                    }
                } else {
                    return Err("PIN is required for this vault".to_string());
                }
            }
        }

        // 2. Decrypt vault data
        match self.storage.load_vault(effective_pass.as_bytes(), &self.crypto) {
            Ok(data) => {
                state.is_unlocked = true;
                state.data = Some(data);
                state.active_password = Some(effective_pass.into_bytes());
                state.failed_attempts = 0;
                state.lockout_until = None;
                Ok(true)
            }
            Err(e) => {
                let err_msg = Self::record_failure(&mut state);
                Err(format!("{} ({})", err_msg, e))
            }
        }
    }

    /// Lock vault and zeroize decrypted memory
    pub fn lock(&self) {
        let mut state = self.state.lock().unwrap();
        state.is_unlocked = false;
        state.data = None;
        if let Some(mut pwd) = state.active_password.take() {
            pwd.zeroize();
        }
    }

    /// Check if vault is currently unlocked
    pub fn is_unlocked(&self) -> bool {
        self.state.lock().unwrap().is_unlocked
    }

    /// Windows Hello biometric or OS PIN verification
    pub async fn unlock_with_windows_hello(&self) -> Result<bool, String> {
        #[cfg(target_os = "windows")]
        {
            use windows::core::HSTRING;
            use windows::Security::Credentials::UI::{
                UserConsentVerificationResult, UserConsentVerifier,
            };

            let msg = HSTRING::from("Authenticate to unlock your Vult vault");
            let op = UserConsentVerifier::RequestVerificationAsync(&msg)
                .map_err(|e| format!("Windows Hello verification request failed: {}", e))?;
            let res = op.await.map_err(|e| format!("Windows Hello error: {}", e))?;

            if res != UserConsentVerificationResult::Verified {
                return Ok(false);
            }

            // Read hello token if stored
            let token_path = self.storage.get_vault_path().with_extension("hello");
            if !token_path.exists() {
                return Err("Windows Hello is not yet linked with a saved credential in this session. Unlock once with your Master Password.".to_string());
            }

            let encrypted_pass = std::fs::read(&token_path)
                .map_err(|e| format!("Failed to read Windows Hello token: {}", e))?;
            
            // Decrypt password
            let pwd = String::from_utf8(encrypted_pass)
                .map_err(|e| format!("Corrupted token: {}", e))?;

            self.unlock(None, pwd)

        }
        #[cfg(not(target_os = "windows"))]
        {
            Err("Windows Hello is only supported on Windows".to_string())
        }
    }

    /// Save the active password for Windows Hello unlock
    pub fn save_windows_hello_token(&self, enabled: bool) -> Result<(), String> {
        let token_path = self.storage.get_vault_path().with_extension("hello");
        if !enabled {
            if token_path.exists() {
                let _ = std::fs::remove_file(token_path);
            }
            return Ok(());
        }

        let state = self.state.lock().unwrap();
        if let Some(ref pwd) = state.active_password {
            std::fs::write(&token_path, pwd)
                .map_err(|e| format!("Failed to store Windows Hello token: {}", e))?;
            Ok(())
        } else {
            Err("Vault must be unlocked to enable Windows Hello".to_string())
        }
    }

    /// Get current non-sensitive auth settings
    pub fn get_auth_settings(&self) -> AuthSettings {
        let state = self.state.lock().unwrap();
        if let Some(ref data) = state.data {
            data.settings.clone()
        } else {
            self.storage.read_config().unwrap_or_default()
        }
    }

    /// Update auth settings
    pub fn update_auth_settings(&self, new_settings: AuthSettings) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault must be unlocked to update settings".to_string());
        }

        let password = state
            .active_password
            .clone()
            .ok_or_else(|| "No active password in memory".to_string())?;

        if let Some(ref mut data) = state.data {
            data.settings = new_settings.clone();
            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, &password, &self.crypto)
                .map_err(|e| format!("Failed to save updated settings: {}", e))?;
        }

        // Also update token if windows hello toggle changed
        drop(state);
        self.save_windows_hello_token(new_settings.windows_hello_enabled)?;

        Ok(())
    }

    /// Change PIN
    pub fn change_pin(&self, new_pin: String) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault must be unlocked to change PIN".to_string());
        }

        let password = state
            .active_password
            .clone()
            .ok_or_else(|| "No active password in memory".to_string())?;

        if let Some(ref mut data) = state.data {
            data.settings.pin_hash = Some(new_pin);
            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, &password, &self.crypto)
                .map_err(|e| format!("Failed to save changed PIN: {}", e))?;
        }
        Ok(())
    }

    /// Change Master Password
    pub fn change_password(&self, new_password: String) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault must be unlocked to change password".to_string());
        }

        if let Some(ref mut data) = state.data {
            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, new_password.as_bytes(), &self.crypto)
                .map_err(|e| format!("Failed to re-encrypt vault: {}", e))?;

            // Replace active password in memory
            if let Some(mut old_pwd) = state.active_password.take() {
                old_pwd.zeroize();
            }
            state.active_password = Some(new_password.into_bytes());
        }

        Ok(())
    }

    /// Get all entries (optionally filtered by category)
    pub fn get_entries(&self, category: Option<String>) -> Result<Vec<VaultEntry>, String> {
        let state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault is locked".to_string());
        }

        if let Some(ref data) = state.data {
            if let Some(cat) = category {
                let cat_lower = cat.to_lowercase();
                Ok(data
                    .entries
                    .iter()
                    .filter(|e| e.category.to_lowercase() == cat_lower)
                    .cloned()
                    .collect())
            } else {
                Ok(data.entries.clone())
            }
        } else {
            Ok(Vec::new())
        }
    }

    /// Get single entry by ID
    pub fn get_entry(&self, id: &str) -> Result<VaultEntry, String> {
        let state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault is locked".to_string());
        }

        if let Some(ref data) = state.data {
            data.entries
                .iter()
                .find(|e| e.id == id)
                .cloned()
                .ok_or_else(|| "Entry not found".to_string())
        } else {
            Err("No vault loaded".to_string())
        }
    }

    /// Add new entry
    pub fn add_entry(&self, mut entry: VaultEntry) -> Result<String, String> {
        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault is locked".to_string());
        }

        if entry.id.is_empty() {
            entry.id = uuid::Uuid::new_v4().to_string();
        }
        let now = chrono::Utc::now().to_rfc3339();
        entry.created_at = now.clone();
        entry.modified_at = now.clone();
        entry.accessed_at = now;

        let password = state
            .active_password
            .clone()
            .ok_or_else(|| "No active password in memory".to_string())?;

        let entry_id = entry.id.clone();
        if let Some(ref mut data) = state.data {
            data.entries.insert(0, entry);
            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, &password, &self.crypto)
                .map_err(|e| format!("Failed to save vault: {}", e))?;
        }

        Ok(entry_id)
    }

    /// Update existing entry
    pub fn update_entry(&self, entry: VaultEntry) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault is locked".to_string());
        }

        let password = state
            .active_password
            .clone()
            .ok_or_else(|| "No active password in memory".to_string())?;

        if let Some(ref mut data) = state.data {
            if let Some(existing) = data.entries.iter_mut().find(|e| e.id == entry.id) {
                existing.category = entry.category;
                existing.title = entry.title;
                existing.fields = entry.fields;
                existing.notes = entry.notes;
                existing.tags = entry.tags;
                existing.favorite = entry.favorite;
                existing.modified_at = chrono::Utc::now().to_rfc3339();
            } else {
                return Err("Entry to update not found".to_string());
            }

            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, &password, &self.crypto)
                .map_err(|e| format!("Failed to save vault: {}", e))?;
        }

        Ok(())
    }

    /// Delete entry by ID
    pub fn delete_entry(&self, id: &str) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault is locked".to_string());
        }

        let password = state
            .active_password
            .clone()
            .ok_or_else(|| "No active password in memory".to_string())?;

        if let Some(ref mut data) = state.data {
            let initial_len = data.entries.len();
            data.entries.retain(|e| e.id != id);
            if data.entries.len() == initial_len {
                return Err("Entry not found to delete".to_string());
            }

            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, &password, &self.crypto)
                .map_err(|e| format!("Failed to save vault: {}", e))?;
        }

        Ok(())
    }

    /// Toggle backup code used status
    pub fn toggle_code_used(&self, entry_id: &str, code_index: usize, used: bool) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault is locked".to_string());
        }

        let password = state
            .active_password
            .clone()
            .ok_or_else(|| "No active password in memory".to_string())?;

        if let Some(ref mut data) = state.data {
            if let Some(entry) = data.entries.iter_mut().find(|e| e.id == entry_id) {
                if let Some(codes) = entry.fields.get_mut("codes").and_then(|c| c.as_array_mut()) {
                    if let Some(target_code) = codes.get_mut(code_index) {
                        target_code["used"] = serde_json::Value::Bool(used);
                        entry.modified_at = chrono::Utc::now().to_rfc3339();
                    } else {
                        return Err("Code index out of bounds".to_string());
                    }
                } else {
                    return Err("Entry does not contain backup codes".to_string());
                }
            } else {
                return Err("Entry not found".to_string());
            }

            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, &password, &self.crypto)
                .map_err(|e| format!("Failed to save vault: {}", e))?;
        }

        Ok(())
    }

    /// Export plain JSON backup of vault
    pub fn export_vault_data(&self) -> Result<String, String> {
        let state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault must be unlocked to export".to_string());
        }
        if let Some(ref data) = state.data {
            serde_json::to_string_pretty(data).map_err(|e| e.to_string())
        } else {
            Err("No vault data loaded".to_string())
        }
    }

    /// Import JSON backup
    pub fn import_vault_data(&self, json_data: &str) -> Result<(), String> {
        let imported: VaultData = serde_json::from_str(json_data)
            .map_err(|e| format!("Invalid vault JSON format: {}", e))?;

        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault must be unlocked to import data".to_string());
        }

        let password = state
            .active_password
            .clone()
            .ok_or_else(|| "No active password in memory".to_string())?;

        self.storage
            .save_vault(&imported, &password, &self.crypto)
            .map_err(|e| format!("Failed to save imported vault: {}", e))?;

        state.data = Some(imported);
        Ok(())
    }

    /// Completely wipe vault data
    pub fn wipe_vault(&self) -> Result<(), String> {
        self.lock();
        self.storage.wipe().map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_auth_manager_setup_and_unlock() {
        let temp_dir = env::temp_dir().join(format!("vult_auth_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        assert!(!auth.vault_exists());

        // Setup
        let ok = auth
            .setup_vault(
                Some("1234".to_string()),
                "MyPassword123!".to_string(),
                "pin_and_password".to_string(),
            )
            .unwrap();
        assert!(ok);
        assert!(auth.is_unlocked());
        assert!(auth.vault_exists());

        // Lock
        auth.lock();
        assert!(!auth.is_unlocked());

        // Wrong password fails
        let res = auth.unlock(Some("1234".to_string()), "WrongPassword!".to_string());
        assert!(res.is_err());
        assert!(!auth.is_unlocked());

        // Wrong PIN fails
        let res = auth.unlock(Some("9999".to_string()), "MyPassword123!".to_string());
        assert!(res.is_err());
        assert!(!auth.is_unlocked());

        // Correct credentials succeed
        let res = auth.unlock(Some("1234".to_string()), "MyPassword123!".to_string());
        assert!(res.is_ok());
        assert!(auth.is_unlocked());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_auth_manager_crud_operations() {
        let temp_dir = env::temp_dir().join(format!("vult_crud_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        auth.setup_vault(None, "MasterKey123".to_string(), "password_only".to_string())
            .unwrap();

        // Add
        let entry_id = auth
            .add_entry(VaultEntry {
                id: "".to_string(),
                category: "recovery_code".to_string(),
                title: "Discord 2FA".to_string(),
                fields: serde_json::json!({
                    "service": "Discord",
                    "code_type": "xxxx-xxxx",
                    "codes": [
                        { "code": "1111-2222", "used": false },
                        { "code": "3333-4444", "used": false }
                    ]
                }),
                notes: Some("My codes".to_string()),
                tags: vec!["gaming".to_string()],
                favorite: true,
                created_at: "".to_string(),
                modified_at: "".to_string(),
                accessed_at: "".to_string(),
            })
            .unwrap();

        assert!(!entry_id.is_empty());

        // Get single
        let loaded = auth.get_entry(&entry_id).unwrap();
        assert_eq!(loaded.title, "Discord 2FA");

        // Toggle code used
        auth.toggle_code_used(&entry_id, 0, true).unwrap();
        let updated = auth.get_entry(&entry_id).unwrap();
        assert_eq!(updated.fields["codes"][0]["used"], true);
        assert_eq!(updated.fields["codes"][1]["used"], false);

        // Delete
        auth.delete_entry(&entry_id).unwrap();
        assert!(auth.get_entry(&entry_id).is_err());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_change_password_and_reencrypt() {
        let temp_dir = env::temp_dir().join(format!("vult_pwd_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        auth.setup_vault(None, "InitialPassword".to_string(), "password_only".to_string())
            .unwrap();

        // Change password
        auth.change_password("NewPassword456!".to_string()).unwrap();

        // Lock
        auth.lock();

        // Old password fails
        assert!(auth.unlock(None, "InitialPassword".to_string()).is_err());

        // New password unlocks
        assert!(auth.unlock(None, "NewPassword456!".to_string()).is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_export_and_import_data() {
        let temp_dir1 = env::temp_dir().join(format!("vult_exp1_{}", uuid::Uuid::new_v4()));
        let storage1 = StorageManager::with_custom_dir(temp_dir1.clone()).unwrap();
        let crypto1 = CryptoEngine::fast_for_testing();
        let auth1 = AuthManager::new(storage1, crypto1);

        auth1.setup_vault(None, "Pass123".to_string(), "password_only".to_string())
            .unwrap();

        auth1.add_entry(VaultEntry {
            id: "e1".to_string(),
            category: "seed_phrase".to_string(),
            title: "Crypto Wallet".to_string(),
            fields: serde_json::json!({
                "wallet_name": "MetaMask",
                "words": ["apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "honeydew", "kiwi", "lemon", "mango", "nectarine"]
            }),
            notes: None,
            tags: vec![],
            favorite: false,
            created_at: "".to_string(),
            modified_at: "".to_string(),
            accessed_at: "".to_string(),
        }).unwrap();

        let exported_json = auth1.export_vault_data().unwrap();

        // Import into second vault
        let temp_dir2 = env::temp_dir().join(format!("vult_exp2_{}", uuid::Uuid::new_v4()));
        let storage2 = StorageManager::with_custom_dir(temp_dir2.clone()).unwrap();
        let crypto2 = CryptoEngine::fast_for_testing();
        let auth2 = AuthManager::new(storage2, crypto2);

        auth2.setup_vault(None, "Pass456".to_string(), "password_only".to_string())
            .unwrap();
        auth2.import_vault_data(&exported_json).unwrap();

        let entries = auth2.get_entries(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Crypto Wallet");
        assert_eq!(entries[0].fields["words"].as_array().unwrap().len(), 12);

        let _ = std::fs::remove_dir_all(&temp_dir1);
        let _ = std::fs::remove_dir_all(&temp_dir2);
    }

    #[test]
    fn test_all_10_categories_storage() {
        let temp_dir = env::temp_dir().join(format!("vult_all_cat_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        auth.setup_vault(None, "Pass".to_string(), "password_only".to_string()).unwrap();

        let cats = vec![
            ("login", serde_json::json!({ "url": "https://test.com", "username": "u", "password": "p" })),
            ("api_key", serde_json::json!({ "service": "Stripe", "key_name": "sk", "key_value": "sk_test_123" })),
            ("seed_phrase", serde_json::json!({ "wallet_name": "Ledger", "words": ["one", "two"] })),
            ("recovery_code", serde_json::json!({ "service": "GitHub", "codes": [{ "code": "abc-def", "used": false }] })),
            ("product_key", serde_json::json!({ "software": "Win11", "key_value": "XXXX-YYYY" })),
            ("secure_note", serde_json::json!({ "title": "Note", "content": "Sensitive note" })),
            ("ssh_key", serde_json::json!({ "key_name": "id_ed25519", "private_key": "-----BEGIN..." })),
            ("wifi_password", serde_json::json!({ "ssid": "Home", "password": "wifi-pass-123" })),
            ("payment_card", serde_json::json!({ "cardholder": "Alice", "card_number": "4111..." })),
            ("custom", serde_json::json!({ "title": "Custom", "fields": [{ "label": "PIN", "value": "999", "is_secret": true }] })),
        ];

        for (cat, fields) in cats {
            auth.add_entry(VaultEntry {
                id: "".to_string(),
                category: cat.to_string(),
                title: format!("Test {}", cat),
                fields,
                notes: None,
                tags: vec![],
                favorite: false,
                created_at: "".to_string(),
                modified_at: "".to_string(),
                accessed_at: "".to_string(),
            }).unwrap();
        }

        let all = auth.get_entries(None).unwrap();
        assert_eq!(all.len(), 10);

        // Filter by specific category
        let recovery_entries = auth.get_entries(Some("recovery_code".to_string())).unwrap();
        assert_eq!(recovery_entries.len(), 1);
        assert_eq!(recovery_entries[0].title, "Test recovery_code");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

