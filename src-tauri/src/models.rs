use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSettings {
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String, // "pin_and_password", "password_only", "pin_only"

    #[serde(default)]
    pub pin_hash: Option<String>,

    #[serde(default = "default_win_hello")]
    pub windows_hello_enabled: bool,

    #[serde(default = "default_auto_lock")]
    pub auto_lock_minutes: u32,

    #[serde(default = "default_clipboard_clear")]
    pub clipboard_clear_seconds: u32,
}

fn default_auth_mode() -> String {
    "pin_and_password".to_string()
}
fn default_win_hello() -> bool {
    false
}
fn default_auto_lock() -> u32 {
    5
}
fn default_clipboard_clear() -> u32 {
    30
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            auth_mode: default_auth_mode(),
            pin_hash: None,
            windows_hello_enabled: default_win_hello(),
            auto_lock_minutes: default_auto_lock(),
            clipboard_clear_seconds: default_clipboard_clear(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub category: String,
    pub title: String,
    pub fields: serde_json::Value,

    #[serde(default)]
    pub notes: Option<String>,

    #[serde(default)]
    pub tags: Vec<String>,

    #[serde(default)]
    pub favorite: bool,

    #[serde(default)]
    pub created_at: String,

    #[serde(default)]
    pub modified_at: String,

    #[serde(default)]
    pub accessed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,
    pub entries: Vec<VaultEntry>,
    pub settings: AuthSettings,
    pub created_at: String,
    pub modified_at: String,
}

impl Default for VaultData {
    fn default() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            version: 1,
            entries: Vec::new(),
            settings: AuthSettings::default(),
            created_at: now.clone(),
            modified_at: now,
        }
    }
}

impl zeroize::Zeroize for VaultEntry {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.category.zeroize();
        self.title.zeroize();
        if let Some(ref mut n) = self.notes {
            n.zeroize();
        }
        for tag in &mut self.tags {
            tag.zeroize();
        }
        zeroize_json_value(&mut self.fields);
    }
}

pub fn zeroize_json_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => {
            s.zeroize();
            *s = String::new();
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                zeroize_json_value(item);
            }
            arr.clear();
        }
        serde_json::Value::Object(map) => {
            for (_, val) in map.iter_mut() {
                zeroize_json_value(val);
            }
            map.clear();
        }
        _ => {}
    }
}

impl zeroize::Zeroize for VaultData {
    fn zeroize(&mut self) {
        for entry in &mut self.entries {
            entry.zeroize();
        }
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_data_serialization() {
        let mut vault = VaultData::default();
        let entry = VaultEntry {
            id: "uuid-1234".to_string(),
            category: "recovery_code".to_string(),
            title: "Discord Backup".to_string(),
            fields: serde_json::json!({
                "service": "Discord",
                "codes": [
                    { "code": "xxxx-xxxx", "used": false },
                    { "code": "yyyy-yyyy", "used": true }
                ]
            }),
            notes: Some("Keep safe".to_string()),
            tags: vec!["2fa".to_string(), "discord".to_string()],
            favorite: true,
            created_at: "2026-10-31T00:00:00Z".to_string(),
            modified_at: "2026-10-31T00:00:00Z".to_string(),
            accessed_at: "2026-10-31T00:00:00Z".to_string(),
        };
        vault.entries.push(entry);

        let json = serde_json::to_string(&vault).unwrap();
        let deserialized: VaultData = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.entries.len(), 1);
        assert_eq!(deserialized.entries[0].title, "Discord Backup");
        assert_eq!(deserialized.entries[0].category, "recovery_code");
    }

    #[test]
    fn test_zeroize_vault_data() {
        let mut vault = VaultData::default();
        let entry = VaultEntry {
            id: "uuid-sensitive".to_string(),
            category: "login".to_string(),
            title: "SuperSecretSite".to_string(),
            fields: serde_json::json!({
                "password": "MySuperSecretPassword123!",
                "api_key": "sk-1234567890abcdef"
            }),
            notes: Some("Confidential note".to_string()),
            tags: vec!["critical".to_string()],
            favorite: false,
            created_at: "".to_string(),
            modified_at: "".to_string(),
            accessed_at: "".to_string(),
        };
        vault.entries.push(entry);

        assert_eq!(vault.entries.len(), 1);
        vault.zeroize();
        assert_eq!(vault.entries.len(), 0);
    }
}

