use crate::auth::AuthManager;
use crate::models::{AuthSettings, VaultEntry};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;

#[tauri::command]
pub async fn check_vault_exists(auth: State<'_, Arc<AuthManager>>) -> Result<bool, String> {
    Ok(auth.vault_exists())
}

#[tauri::command]
pub async fn setup_vault(
    auth: State<'_, Arc<AuthManager>>,
    pin: Option<String>,
    password: String,
    auth_mode: String,
) -> Result<bool, String> {
    auth.setup_vault(pin, password, auth_mode)
}

#[tauri::command]
pub async fn unlock_vault(
    auth: State<'_, Arc<AuthManager>>,
    pin: Option<String>,
    password: String,
) -> Result<bool, String> {
    auth.unlock(pin, password)
}

#[tauri::command]
pub async fn unlock_with_windows_hello(
    auth: State<'_, Arc<AuthManager>>,
) -> Result<bool, String> {
    auth.unlock_with_windows_hello().await
}

#[tauri::command]
pub async fn lock_vault(auth: State<'_, Arc<AuthManager>>) -> Result<(), String> {
    auth.lock();
    Ok(())
}

#[tauri::command]
pub async fn get_auth_settings(auth: State<'_, Arc<AuthManager>>) -> Result<AuthSettings, String> {
    Ok(auth.get_auth_settings())
}

#[tauri::command]
pub async fn update_auth_settings(
    auth: State<'_, Arc<AuthManager>>,
    settings: AuthSettings,
) -> Result<(), String> {
    auth.update_auth_settings(settings)
}

#[tauri::command]
pub async fn change_pin(
    auth: State<'_, Arc<AuthManager>>,
    new_pin: String,
) -> Result<(), String> {
    auth.change_pin(new_pin)
}

#[tauri::command]
pub async fn change_password(
    auth: State<'_, Arc<AuthManager>>,
    new_password: String,
) -> Result<(), String> {
    auth.change_password(new_password)
}

#[tauri::command]
pub async fn get_entries(
    auth: State<'_, Arc<AuthManager>>,
    category: Option<String>,
) -> Result<Vec<VaultEntry>, String> {
    auth.get_entries(category)
}

#[tauri::command]
pub async fn get_entry(
    auth: State<'_, Arc<AuthManager>>,
    id: String,
) -> Result<VaultEntry, String> {
    auth.get_entry(&id)
}

#[tauri::command]
pub async fn add_entry(
    auth: State<'_, Arc<AuthManager>>,
    entry: VaultEntry,
) -> Result<String, String> {
    auth.add_entry(entry)
}

#[tauri::command]
pub async fn update_entry(
    auth: State<'_, Arc<AuthManager>>,
    entry: VaultEntry,
) -> Result<(), String> {
    auth.update_entry(entry)
}

#[tauri::command]
pub async fn delete_entry(
    auth: State<'_, Arc<AuthManager>>,
    id: String,
) -> Result<(), String> {
    auth.delete_entry(&id)
}

#[tauri::command]
pub async fn toggle_code_used(
    auth: State<'_, Arc<AuthManager>>,
    entry_id: String,
    code_index: usize,
    used: bool,
) -> Result<(), String> {
    auth.toggle_code_used(&entry_id, code_index, used)
}

#[tauri::command]
pub async fn export_vault_data(
    auth: State<'_, Arc<AuthManager>>,
) -> Result<String, String> {
    auth.export_vault_data()
}

#[tauri::command]
pub async fn import_vault_data(
    auth: State<'_, Arc<AuthManager>>,
    json_data: String,
) -> Result<(), String> {
    auth.import_vault_data(&json_data)
}

#[tauri::command]
pub async fn wipe_vault(auth: State<'_, Arc<AuthManager>>) -> Result<(), String> {
    auth.wipe_vault()
}

#[tauri::command]
pub async fn copy_to_clipboard(
    app: AppHandle,
    text: String,
    auto_clear_seconds: u32,
) -> Result<(), String> {
    let clipboard = app.clipboard();
    clipboard
        .write_text(&text)
        .map_err(|e| format!("Clipboard write failed: {}", e))?;

    if auto_clear_seconds > 0 {
        let app_clone = app.clone();
        let expected_text = text.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(auto_clear_seconds as u64));
            if let Ok(current_text) = app_clone.clipboard().read_text() {
                if current_text == expected_text {
                    let _ = app_clone.clipboard().write_text("");
                }
            }
        });
    }


    Ok(())
}
