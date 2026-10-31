pub mod auth;
pub mod commands;
pub mod crypto;
pub mod models;
pub mod storage;

use auth::AuthManager;
use crypto::CryptoEngine;
use storage::StorageManager;
use std::sync::Arc;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let storage = StorageManager::new().expect("Failed to initialize vault storage directory");
    let crypto = CryptoEngine::default();
    let auth_manager = Arc::new(AuthManager::new(storage, crypto));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(auth_manager)
        .invoke_handler(tauri::generate_handler![
            commands::check_vault_exists,
            commands::setup_vault,
            commands::unlock_vault,
            commands::unlock_with_windows_hello,
            commands::lock_vault,
            commands::get_auth_settings,
            commands::update_auth_settings,
            commands::change_pin,
            commands::change_password,
            commands::get_entries,
            commands::get_entry,
            commands::search_entries,
            commands::add_entry,
            commands::update_entry,
            commands::delete_entry,
            commands::toggle_code_used,
            commands::export_vault_encrypted,
            commands::export_vault_data,
            commands::import_vault_data,
            commands::wipe_vault,
            commands::copy_to_clipboard,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vult application");
}
