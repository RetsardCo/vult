use crate::crypto::CryptoEngine;
use crate::models::{AuthSettings, VaultData, VaultEntry};
use crate::storage::StorageManager;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[cfg(target_os = "windows")]
pub mod dpapi {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };

    pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB::default();

        unsafe {
            CryptProtectData(
                &data_in,
                None,
                None,
                None,
                None,
                0,
                &mut data_out,
            )
            .map_err(|e| format!("DPAPI encryption failed: {}", e))?;

            let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
            let result = slice.to_vec();
            let _ = LocalFree(Some(HLOCAL(data_out.pbData as _)));
            Ok(result)
        }
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
        let data_in = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut data_out = CRYPT_INTEGER_BLOB::default();

        unsafe {
            CryptUnprotectData(
                &data_in,
                None,
                None,
                None,
                None,
                0,
                &mut data_out,
            )
            .map_err(|e| format!("DPAPI decryption failed: {}", e))?;

            let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
            let result = slice.to_vec();
            let _ = LocalFree(Some(HLOCAL(data_out.pbData as _)));
            Ok(result)
        }
    }
}

pub fn base64_encode(data: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(CHARSET[(b0 >> 2) as usize] as char);
        out.push(CHARSET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARSET[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARSET[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 4 != 0 {
        return Err("Invalid base64 length".to_string());
    }
    let decode_val = |b: u8| -> Result<u8, String> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => Err(format!("Invalid base64 character: {}", b as char)),
        }
    };
    let bytes = clean.as_bytes();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let c0 = decode_val(chunk[0])?;
        let c1 = decode_val(chunk[1])?;
        let c2 = decode_val(chunk[2])?;
        let c3 = decode_val(chunk[3])?;
        out.push((c0 << 2) | (c1 >> 4));
        if chunk[2] != b'=' {
            out.push(((c1 & 0x0F) << 4) | (c2 >> 2));
        }
        if chunk[3] != b'=' {
            out.push(((c2 & 0x03) << 6) | c3);
        }
    }
    Ok(out)
}

fn compute_effective_pass(auth_mode: &str, pin: Option<&str>, password: &str) -> String {
    match auth_mode {
        "pin_only" => pin.unwrap_or(password).to_string(),
        "password_only" => password.to_string(),
        _ => {
            // "pin_and_password" requires both
            if let Some(p) = pin {
                format!("{}:{}", password, p)
            } else {
                password.to_string()
            }
        }
    }
}

pub struct AuthManager {
    pub storage: StorageManager,
    pub crypto: CryptoEngine,
    state: Mutex<AuthState>,
}

struct AuthState {
    is_unlocked: bool,
    data: Option<VaultData>,
    active_password: Option<Vec<u8>>,
    active_pin: Option<String>,
    active_master_pwd: Option<String>,
    failed_attempts: u32,
    lockout_until: Option<Instant>,
}

impl Drop for AuthState {
    fn drop(&mut self) {
        if let Some(mut data) = self.data.take() {
            data.zeroize();
        }
        if let Some(mut pwd) = self.active_password.take() {
            pwd.zeroize();
        }
        if let Some(mut pin) = self.active_pin.take() {
            pin.zeroize();
        }
        if let Some(mut master) = self.active_master_pwd.take() {
            master.zeroize();
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
                active_pin: None,
                active_master_pwd: None,
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
        vault_data.settings.auth_mode = auth_mode.clone();
        vault_data.settings.pin_hash = None; // Never store plain PIN on disk!
        vault_data.settings.pin_length = if auth_mode == "password_only" {
            None
        } else {
            pin.as_ref().map(|p| p.len())
        };

        let effective_pass = compute_effective_pass(&auth_mode, pin.as_deref(), &password);

        // Save encrypted vault
        self.storage
            .save_vault(&vault_data, effective_pass.as_bytes(), &self.crypto)
            .map_err(|e| format!("Failed to save vault: {}", e))?;

        // Unlock in-memory state
        let mut state = self.state.lock().unwrap();
        state.is_unlocked = true;
        state.data = Some(vault_data);
        state.active_password = Some(effective_pass.into_bytes());
        state.active_pin = pin;
        state.active_master_pwd = Some(password);
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

        if config.auth_mode == "pin_and_password" {
            if pin.as_ref().map(|p| p.trim().is_empty()).unwrap_or(true) {
                return Err("PIN is required for this vault".to_string());
            }
        }

        let effective_pass = compute_effective_pass(&config.auth_mode, pin.as_deref(), &password);

        // 2. Decrypt vault data
        match self.storage.load_vault(effective_pass.as_bytes(), &self.crypto) {
            Ok(mut data) => {
                // If legacy vault didn't have pin_length recorded in settings, self-heal now:
                if data.settings.pin_length.is_none() && pin.is_some() && config.auth_mode != "password_only" {
                    data.settings.pin_length = pin.as_ref().map(|p| p.len());
                    let _ = self.storage.save_vault(&data, effective_pass.as_bytes(), &self.crypto);
                }

                state.is_unlocked = true;
                state.data = Some(data);
                state.active_password = Some(effective_pass.into_bytes());
                state.active_pin = pin;
                state.active_master_pwd = Some(password);
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
        if let Some(mut data) = state.data.take() {
            data.zeroize();
        }
        if let Some(mut pwd) = state.active_password.take() {
            pwd.zeroize();
        }
        if let Some(mut pin) = state.active_pin.take() {
            pin.zeroize();
        }
        if let Some(mut master) = state.active_master_pwd.take() {
            master.zeroize();
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

            let encrypted_token = std::fs::read(&token_path)
                .map_err(|e| format!("Failed to read Windows Hello token: {}", e))?;
            
            let decrypted_pwd_bytes = dpapi::unprotect(&encrypted_token)
                .map_err(|e| format!("Failed to decrypt Windows Hello token via DPAPI: {}", e))?;

            let effective_pass = String::from_utf8(decrypted_pwd_bytes)
                .map_err(|e| format!("Corrupted token: {}", e))?;

            let mut state = self.state.lock().unwrap();
            match self.storage.load_vault(effective_pass.as_bytes(), &self.crypto) {
                Ok(data) => {
                    state.is_unlocked = true;
                    state.active_password = Some(effective_pass.into_bytes());
                    state.data = Some(data);
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
        #[cfg(not(target_os = "windows"))]
        {
            Err("Windows Hello is only supported on Windows".to_string())
        }
    }

    /// Save the active password for Windows Hello unlock (encrypted via DPAPI)
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
            #[cfg(target_os = "windows")]
            {
                let encrypted_bytes = dpapi::protect(pwd)?;
                std::fs::write(&token_path, encrypted_bytes)
                    .map_err(|e| format!("Failed to store Windows Hello token: {}", e))?;
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            {
                Err("Windows Hello is only supported on Windows".to_string())
            }
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

        let old_mode = state.data.as_ref().map(|d| d.settings.auth_mode.clone()).unwrap_or_default();
        let mode_changed = old_mode != new_settings.auth_mode;

        let pin = state.active_pin.clone();
        let master = state.active_master_pwd.clone().unwrap_or_default();

        let active_pin_len = state.active_pin.as_ref().map(|p| p.len());
        let new_effective = if mode_changed {
            compute_effective_pass(&new_settings.auth_mode, pin.as_deref(), &master)
        } else {
            String::from_utf8(state.active_password.clone().unwrap_or_default()).unwrap_or_default()
        };

        if let Some(ref mut data) = state.data {
            let preserved_pin_len = data.settings.pin_length.or(active_pin_len);
            data.settings = new_settings.clone();
            if data.settings.pin_length.is_none() && new_settings.auth_mode != "password_only" {
                data.settings.pin_length = preserved_pin_len;
            } else if new_settings.auth_mode == "password_only" {
                data.settings.pin_length = None;
            }
            data.settings.pin_hash = None; // Never store plain PIN on disk
            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, new_effective.as_bytes(), &self.crypto)
                .map_err(|e| format!("Failed to save updated settings: {}", e))?;

            if mode_changed {
                if let Some(mut old_pwd) = state.active_password.take() {
                    old_pwd.zeroize();
                }
                state.active_password = Some(new_effective.into_bytes());
            }
        }

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

        let config = state
            .data
            .as_ref()
            .map(|d| d.settings.clone())
            .unwrap_or_default();

        let master = state.active_master_pwd.clone().unwrap_or_default();
        let new_effective = compute_effective_pass(&config.auth_mode, Some(&new_pin), &master);

        if let Some(ref mut data) = state.data {
            data.settings.pin_length = Some(new_pin.len());
            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, new_effective.as_bytes(), &self.crypto)
                .map_err(|e| format!("Failed to re-encrypt vault with new PIN: {}", e))?;

            if let Some(mut old_pwd) = state.active_password.take() {
                old_pwd.zeroize();
            }
            state.active_password = Some(new_effective.into_bytes());
            state.active_pin = Some(new_pin);
        }

        let hello_enabled = config.windows_hello_enabled;
        drop(state);

        if hello_enabled {
            self.save_windows_hello_token(true)?;
        }

        Ok(())
    }

    /// Change Master Password
    pub fn change_password(&self, new_password: String) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault must be unlocked to change password".to_string());
        }

        let config = state
            .data
            .as_ref()
            .map(|d| d.settings.clone())
            .unwrap_or_default();

        let pin = state.active_pin.clone();
        let new_effective = compute_effective_pass(&config.auth_mode, pin.as_deref(), &new_password);

        if let Some(ref mut data) = state.data {
            data.modified_at = chrono::Utc::now().to_rfc3339();
            self.storage
                .save_vault(data, new_effective.as_bytes(), &self.crypto)
                .map_err(|e| format!("Failed to re-encrypt vault with new password: {}", e))?;

            if let Some(mut old_pwd) = state.active_password.take() {
                old_pwd.zeroize();
            }
            state.active_password = Some(new_effective.into_bytes());
            state.active_master_pwd = Some(new_password);
        }

        let hello_enabled = config.windows_hello_enabled;
        drop(state);

        if hello_enabled {
            self.save_windows_hello_token(true)?;
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

    /// Search entries
    pub fn search_entries(&self, query: &str) -> Result<Vec<VaultEntry>, String> {
        let state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault is locked".to_string());
        }
        let q = query.trim().to_lowercase();
        if let Some(ref data) = state.data {
            if q.is_empty() {
                return Ok(data.entries.clone());
            }
            let filtered = data
                .entries
                .iter()
                .filter(|e| {
                    e.title.to_lowercase().contains(&q)
                        || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
                        || e.notes.as_deref().unwrap_or("").to_lowercase().contains(&q)
                        || e.fields.to_string().to_lowercase().contains(&q)
                })
                .cloned()
                .collect();
            Ok(filtered)
        } else {
            Ok(Vec::new())
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

    /// Export raw encrypted binary vault encoded as Base64 (.vult backup)
    pub fn export_vault_encrypted(&self) -> Result<String, String> {
        let state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault must be unlocked to export".to_string());
        }
        let vault_path = self.storage.get_vault_path();
        if !vault_path.exists() {
            return Err("No vault file found to export".to_string());
        }
        let bytes = std::fs::read(&vault_path)
            .map_err(|e| format!("Failed to read vault file: {}", e))?;
        Ok(base64_encode(&bytes))
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

    /// Import vault backup (supports both encrypted .vult base64/binary and plain JSON)
    pub fn import_vault_data(&self, input: &str, password: Option<String>) -> Result<(), String> {
        let trimmed = input.trim();

        // 1. Try if JSON format
        let mut imported: Option<VaultData> = if trimmed.starts_with('{') {
            serde_json::from_str(trimmed).ok()
        } else {
            None
        };

        // 2. If not JSON, try binary VULT1 or base64 VULT1
        if imported.is_none() {
            let binary_bytes = if trimmed.as_bytes().starts_with(crate::crypto::MAGIC_BYTES) {
                trimmed.as_bytes().to_vec()
            } else if let Ok(decoded) = base64_decode(trimmed) {
                decoded
            } else {
                return Err("Unsupported file format: expected valid Vult backup (.vult) or JSON format".to_string());
            };

            if !binary_bytes.starts_with(crate::crypto::MAGIC_BYTES) {
                return Err("Invalid vault file: missing VULT1 magic header".to_string());
            }

            let state = self.state.lock().unwrap();
            let active_pwd = state.active_password.clone().map(|p| String::from_utf8_lossy(&p).to_string());
            drop(state);

            let decrypt_pass = password
                .or(active_pwd)
                .ok_or_else(|| "Password is required to decrypt this backup file".to_string())?;

            let plaintext = self.crypto
                .decrypt_vault(decrypt_pass.as_bytes(), &binary_bytes)
                .map_err(|e| format!("Failed to decrypt backup: {}", e))?;

            imported = Some(serde_json::from_slice(&plaintext)
                .map_err(|e| format!("Corrupted vault data in backup: {}", e))?);
        }

        let mut vault_data = imported.ok_or_else(|| "Failed to parse imported vault data".to_string())?;

        // Sanitize imported entries
        for entry in &mut vault_data.entries {
            if entry.id.is_empty() {
                entry.id = uuid::Uuid::new_v4().to_string();
            }
            if entry.created_at.is_empty() {
                entry.created_at = chrono::Utc::now().to_rfc3339();
            }
            if entry.modified_at.is_empty() {
                entry.modified_at = entry.created_at.clone();
            }
            if entry.accessed_at.is_empty() {
                entry.accessed_at = entry.created_at.clone();
            }
        }

        let mut state = self.state.lock().unwrap();
        if !state.is_unlocked {
            return Err("Vault must be unlocked to import data".to_string());
        }

        let active_pass = state
            .active_password
            .clone()
            .ok_or_else(|| "No active password in memory".to_string())?;

        // Preserve current active vault auth settings and pin_length when importing entries
        if let Some(ref current_data) = state.data {
            vault_data.settings = current_data.settings.clone();
        }

        // Save imported vault encrypted with current active vault key
        self.storage
            .save_vault(&vault_data, &active_pass, &self.crypto)
            .map_err(|e| format!("Failed to save imported vault: {}", e))?;

        state.data = Some(vault_data);
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
    fn test_export_and_import_encrypted_vault() {
        let temp_dir1 = env::temp_dir().join(format!("vult_enc_exp1_{}", uuid::Uuid::new_v4()));
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

        // Export encrypted base64
        let exported_b64 = auth1.export_vault_encrypted().unwrap();

        // Import into second vault
        let temp_dir2 = env::temp_dir().join(format!("vult_enc_exp2_{}", uuid::Uuid::new_v4()));
        let storage2 = StorageManager::with_custom_dir(temp_dir2.clone()).unwrap();
        let crypto2 = CryptoEngine::fast_for_testing();
        let auth2 = AuthManager::new(storage2, crypto2);

        auth2.setup_vault(None, "Pass456".to_string(), "password_only".to_string())
            .unwrap();
        
        // Import encrypted backup decrypted with original password Pass123
        auth2.import_vault_data(&exported_b64, Some("Pass123".to_string())).unwrap();

        let entries = auth2.get_entries(None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Crypto Wallet");

        // Re-lock second vault and verify it unlocks with Pass456 (not Pass123)
        auth2.lock();
        assert!(auth2.unlock(None, "Pass456".to_string()).is_ok());

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

        // Search test
        let search_res = auth.search_entries("Stripe").unwrap();
        assert_eq!(search_res.len(), 1);
        assert_eq!(search_res[0].category, "api_key");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_dpapi_protect_unprotect() {
        let secret = b"VerySecretMasterPasswordToCache";
        let protected = dpapi::protect(secret).unwrap();
        assert_ne!(protected, secret);

        let unprotected = dpapi::unprotect(&protected).unwrap();
        assert_eq!(unprotected, secret);
    }

    #[test]
    fn test_brute_force_lockout_delays() {
        let temp_dir = env::temp_dir().join(format!("vult_lockout_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        auth.setup_vault(None, "Pass123".to_string(), "password_only".to_string()).unwrap();
        auth.lock();

        // 1st failed attempt
        let res1 = auth.unlock(None, "Wrong1".to_string());
        assert!(res1.is_err());

        // 2nd failed attempt
        let res2 = auth.unlock(None, "Wrong2".to_string());
        assert!(res2.is_err());

        // 3rd failed attempt triggers 2s delay
        let res3 = auth.unlock(None, "Wrong3".to_string());
        assert!(res3.is_err());
        assert!(res3.unwrap_err().contains("Too many failed attempts"));

        // Attempting immediately again is blocked by lockout
        let res_locked = auth.unlock(None, "Pass123".to_string());
        assert!(res_locked.is_err());
        assert!(res_locked.unwrap_err().contains("Too many failed attempts"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pin_change_reencrypts_correctly() {
        let temp_dir = env::temp_dir().join(format!("vult_pin_chg_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        auth.setup_vault(Some("1111".to_string()), "Pass123".to_string(), "pin_and_password".to_string()).unwrap();
        assert_eq!(auth.get_auth_settings().pin_length, Some(4));

        // Change PIN to 222222 (6 digits)
        auth.change_pin("222222".to_string()).unwrap();
        assert_eq!(auth.get_auth_settings().pin_length, Some(6));
        auth.lock();

        // Old PIN 1111 fails
        assert!(auth.unlock(Some("1111".to_string()), "Pass123".to_string()).is_err());

        // New PIN 222222 succeeds
        assert!(auth.unlock(Some("222222".to_string()), "Pass123".to_string()).is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_dynamic_pin_length_persisted_in_config() {
        let temp_dir = env::temp_dir().join(format!("vult_pin_cfg_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        // Setup 4-digit PIN vault
        auth.setup_vault(Some("4321".to_string()), "SecretPass".to_string(), "pin_only".to_string()).unwrap();
        auth.lock();

        // When locked, read_config should still reflect 4-digit PIN length for UI unlock rendering
        let settings = auth.get_auth_settings();
        assert_eq!(settings.pin_length, Some(4));
        assert_eq!(settings.auth_mode, "pin_only");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mode_switch_reencrypts_correctly() {
        let temp_dir = env::temp_dir().join(format!("vult_mode_chg_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        auth.setup_vault(Some("1234".to_string()), "Pass123".to_string(), "pin_and_password".to_string()).unwrap();

        // Switch to password_only
        let mut settings = auth.get_auth_settings();
        settings.auth_mode = "password_only".to_string();
        auth.update_auth_settings(settings).unwrap();

        auth.lock();

        // In password_only mode, unlocking with just password succeeds
        assert!(auth.unlock(None, "Pass123".to_string()).is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_corrupted_backup_rejected() {
        let temp_dir = env::temp_dir().join(format!("vult_bad_bkp_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        auth.setup_vault(None, "Pass123".to_string(), "password_only".to_string()).unwrap();

        // Malformed JSON
        let bad_json = r#"{"entries": [{"id": "bad", "incomplete": true"#;
        assert!(auth.import_vault_data(bad_json, None).is_err());

        // Bad base64
        assert!(auth.import_vault_data("not-valid-base64!!!", None).is_err());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_unlock_self_heals_missing_pin_length() {
        let temp_dir = env::temp_dir().join(format!("vult_heal_{}", uuid::Uuid::new_v4()));
        let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
        let crypto = CryptoEngine::fast_for_testing();
        let auth = AuthManager::new(storage, crypto);

        // Setup vault with 4-digit PIN
        auth.setup_vault(Some("9876".to_string()), "Pass123".to_string(), "pin_only".to_string()).unwrap();

        // Simulate a legacy vault where pin_length was None
        {
            let mut state = auth.state.lock().unwrap();
            let active = state.active_password.clone().unwrap();
            if let Some(ref mut d) = state.data {
                d.settings.pin_length = None;
                auth.storage.save_vault(d, &active, &auth.crypto).unwrap();
            }
        }
        auth.lock();

        // Initially in legacy state, settings in config.json have pin_length = None
        assert_eq!(auth.get_auth_settings().pin_length, None);

        // Unlock with the 4-digit PIN
        assert!(auth.unlock(Some("9876".to_string()), "".to_string()).is_ok());

        // Now settings should be self-healed to Some(4)
        assert_eq!(auth.get_auth_settings().pin_length, Some(4));

        // Lock again and check that config.json was persisted with Some(4)
        auth.lock();
        assert_eq!(auth.get_auth_settings().pin_length, Some(4));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_various_pin_lengths_setup_and_persist() {
        for len in [4, 5, 7, 8] {
            let temp_dir = env::temp_dir().join(format!("vult_pin_len_{}_{}", len, uuid::Uuid::new_v4()));
            let storage = StorageManager::with_custom_dir(temp_dir.clone()).unwrap();
            let crypto = CryptoEngine::fast_for_testing();
            let auth = AuthManager::new(storage, crypto);

            let pin = "1".repeat(len);
            auth.setup_vault(Some(pin.clone()), "Pass123".to_string(), "pin_and_password".to_string()).unwrap();
            assert_eq!(auth.get_auth_settings().pin_length, Some(len));

            auth.lock();
            // In locked state, config should still accurately reflect configured length
            assert_eq!(auth.get_auth_settings().pin_length, Some(len));

            // Verify unlock works with this exact PIN
            assert!(auth.unlock(Some(pin), "Pass123".to_string()).is_ok());

            let _ = std::fs::remove_dir_all(&temp_dir);
        }
    }

    #[test]
    fn test_import_vault_preserves_active_auth_settings() {
        let temp_dir1 = env::temp_dir().join(format!("vult_imp_src_{}", uuid::Uuid::new_v4()));
        let storage1 = StorageManager::with_custom_dir(temp_dir1.clone()).unwrap();
        let crypto1 = CryptoEngine::fast_for_testing();
        let auth1 = AuthManager::new(storage1, crypto1);

        // Vault 1: PIN Only, 4-digit PIN
        auth1.setup_vault(Some("1234".to_string()), "".to_string(), "pin_only".to_string()).unwrap();
        let exported_b64 = auth1.export_vault_encrypted().unwrap();

        // Vault 2: Password Only
        let temp_dir2 = env::temp_dir().join(format!("vult_imp_dst_{}", uuid::Uuid::new_v4()));
        let storage2 = StorageManager::with_custom_dir(temp_dir2.clone()).unwrap();
        let crypto2 = CryptoEngine::fast_for_testing();
        let auth2 = AuthManager::new(storage2, crypto2);

        auth2.setup_vault(None, "PassMaster99".to_string(), "password_only".to_string()).unwrap();

        // Import Vault 1 backup into Vault 2 (decrypted using Vault 1's key "1234")
        auth2.import_vault_data(&exported_b64, Some("1234".to_string())).unwrap();

        // Vault 2 must STILL be in password_only mode, not corrupted into pin_only!
        let s2 = auth2.get_auth_settings();
        assert_eq!(s2.auth_mode, "password_only");
        assert_eq!(s2.pin_length, None);

        // Lock Vault 2 and verify it unlocks with PassMaster99
        auth2.lock();
        assert!(auth2.unlock(None, "PassMaster99".to_string()).is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir1);
        let _ = std::fs::remove_dir_all(&temp_dir2);
    }
}
