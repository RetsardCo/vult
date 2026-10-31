import { invokeCommand } from "../utils/tauri-bridge.js";
import { showToast } from "../components/toast.js";
import { showConfirmModal } from "../components/modal.js";

export function initSettingsScreen({
  onBack,
  onVaultWiped,
  onLockVault,
  onSettingsUpdated = null
}) {
  const container = document.getElementById("screen-settings");
  let currentSettings = {};

  container.innerHTML = `
    <header class="app-header">
      <div class="header-left">
        <button id="set-back-btn" class="btn-icon" data-tooltip="Back to Dashboard">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="15 18 9 12 15 6"></polyline>
          </svg>
        </button>
        <div class="header-title">Settings</div>
      </div>
    </header>

    <div class="settings-content">
      <div class="settings-group">
        <div class="section-title">Security & Unlock</div>
        <div class="settings-card">
          <div class="settings-row" data-tooltip="Configure how you authenticate to unlock your vault">
            <div class="settings-row-label">
              <span class="settings-row-icon">🔐</span>
              <span>Auth Mode</span>
            </div>
            <div class="settings-row-control">
              <select id="set-auth-mode" class="settings-select">
                <option value="pin_and_password">PIN + Password</option>
                <option value="password_only">Password Only</option>
                <option value="pin_only">PIN Only</option>
              </select>
            </div>
          </div>

          <div class="settings-row clickable" id="set-change-pin-row" data-tooltip="Change your 4-8 digit numeric PIN">
            <div class="settings-row-label">
              <span class="settings-row-icon">🔢</span>
              <span>Change PIN</span>
            </div>
            <div class="settings-row-control">→</div>
          </div>

          <div class="settings-row clickable" id="set-change-pwd-row" data-tooltip="Change your Master Encryption Password">
            <div class="settings-row-label">
              <span class="settings-row-icon">🔑</span>
              <span>Change Master Password</span>
            </div>
            <div class="settings-row-control">→</div>
          </div>

          <div class="settings-row" data-tooltip="Enable Windows Hello biometric fingerprint, face, or OS PIN unlock">
            <div class="settings-row-label">
              <span class="settings-row-icon">🪟</span>
              <span>Windows Hello Unlock</span>
            </div>
            <div class="settings-row-control">
              <label class="toggle-switch">
                <input type="checkbox" id="set-win-hello-toggle">
                <span class="slider-round"></span>
              </label>
            </div>
          </div>

          <div class="settings-row" data-tooltip="Automatically lock the vault after a period of user inactivity">
            <div class="settings-row-label">
              <span class="settings-row-icon">⏱️</span>
              <span>Auto-Lock After</span>
            </div>
            <div class="settings-row-control">
              <select id="set-autolock-select" class="settings-select">
                <option value="1">1 minute</option>
                <option value="5">5 minutes</option>
                <option value="15">15 minutes</option>
                <option value="30">30 minutes</option>
                <option value="0">Never</option>
              </select>
            </div>
          </div>

          <div class="settings-row" data-tooltip="Clear copied passwords and sensitive secrets from clipboard after a delay">
            <div class="settings-row-label">
              <span class="settings-row-icon">📋</span>
              <span>Clipboard Auto-Clear</span>
            </div>
            <div class="settings-row-control">
              <select id="set-clipboard-select" class="settings-select">
                <option value="10">10 seconds</option>
                <option value="30">30 seconds</option>
                <option value="60">60 seconds</option>
                <option value="0">Never</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <div class="settings-group">
        <div class="section-title">Vault Backup & Data</div>
        <div class="settings-card">
          <div class="settings-row clickable" id="set-export-row" data-tooltip="Export authenticated encrypted vault backup file (.vult)">
            <div class="settings-row-label">
              <span class="settings-row-icon">💾</span>
              <span>Export Encrypted Backup</span>
            </div>
            <div class="settings-row-control">→</div>
          </div>

          <div class="settings-row clickable" id="set-import-row" data-tooltip="Import an existing vault backup (.vult or JSON)">
            <div class="settings-row-label">
              <span class="settings-row-icon">📥</span>
              <span>Import Vault Backup</span>
            </div>
            <div class="settings-row-control">→</div>
          </div>
        </div>
      </div>

      <div class="settings-group">
        <div class="section-title">Danger Zone</div>
        <div class="settings-card">
          <div class="settings-row clickable" id="set-wipe-row" data-tooltip="Permanently delete entire vault and all stored secrets">
            <div class="settings-row-label" style="color:var(--destructive);">
              <span class="settings-row-icon" style="color:var(--destructive);">⚠️</span>
              <span>Wipe All Data</span>
            </div>
            <div class="settings-row-control" style="color:var(--destructive);">Wipe</div>
          </div>
        </div>
      </div>

      <div class="about-box">
        <div class="about-logo">🔐</div>
        <div class="about-title">Vult</div>
        <div class="about-version">Version 1.0.0 • Local-First Vault</div>
        <div class="about-desc">
          Protected by AES-256-GCM authenticated encryption and Argon2id key derivation. No analytics, no cloud telemetry.
        </div>
      </div>
    </div>
  `;

  const backBtn = container.querySelector("#set-back-btn");
  const authModeSelect = container.querySelector("#set-auth-mode");
  const winHelloToggle = container.querySelector("#set-win-hello-toggle");
  const autoLockSelect = container.querySelector("#set-autolock-select");
  const clipSelect = container.querySelector("#set-clipboard-select");

  backBtn.onclick = onBack;

  async function loadSettings() {
    try {
      currentSettings = await invokeCommand("get_auth_settings");
      authModeSelect.value = currentSettings.auth_mode || "pin_and_password";
      winHelloToggle.checked = !!currentSettings.windows_hello_enabled;
      autoLockSelect.value = String(currentSettings.auto_lock_minutes ?? 5);
      clipSelect.value = String(currentSettings.clipboard_clear_seconds ?? 30);
    } catch (e) {
      console.error("Failed to load settings:", e);
    }
  }

  async function saveUpdatedSettings() {
    const newMode = authModeSelect.value;
    if (newMode !== "password_only" && currentSettings.auth_mode === "password_only" && !currentSettings.pin_length) {
      const pin = prompt("Enter a 4-8 digit numeric PIN for the new authentication mode:");
      if (!pin || !/^\d{4,8}$/.test(pin)) {
        showToast("A valid 4 to 8 digit PIN is required", "error");
        authModeSelect.value = currentSettings.auth_mode || "password_only";
        return;
      }
      try {
        await invokeCommand("change_pin", { newPin: pin });
        currentSettings.pin_length = pin.length;
      } catch (err) {
        showToast(typeof err === "string" ? err : "Failed to set PIN", "error");
        authModeSelect.value = currentSettings.auth_mode || "password_only";
        return;
      }
    }

    const updated = {
      ...currentSettings,
      auth_mode: newMode,
      windows_hello_enabled: winHelloToggle.checked,
      auto_lock_minutes: parseInt(autoLockSelect.value, 10),
      clipboard_clear_seconds: parseInt(clipSelect.value, 10)
    };
    try {
      await invokeCommand("update_auth_settings", { settings: updated });
      currentSettings = updated;
      showToast("Settings updated");
      if (onSettingsUpdated) onSettingsUpdated(updated);
    } catch (err) {
      showToast(typeof err === "string" ? err : "Failed to update settings", "error");
    }
  }

  authModeSelect.onchange = saveUpdatedSettings;
  winHelloToggle.onchange = saveUpdatedSettings;
  autoLockSelect.onchange = saveUpdatedSettings;
  clipSelect.onchange = saveUpdatedSettings;

  // Change PIN modal
  container.querySelector("#set-change-pin-row").onclick = () => {
    const newPin = prompt("Enter new 4-8 digit numeric PIN:");
    if (!newPin) return;
    if (!/^\d{4,8}$/.test(newPin)) {
      showToast("PIN must be 4 to 8 digits", "error");
      return;
    }
    invokeCommand("change_pin", { newPin })
      .then(() => {
        showToast("PIN successfully updated");
        currentSettings.pin_length = newPin.length;
      })
      .catch(err => showToast(typeof err === "string" ? err : "Failed to update PIN", "error"));
  };

  // Change Password modal
  container.querySelector("#set-change-pwd-row").onclick = () => {
    const newPassword = prompt("Enter new Master Password (min 6 characters):");
    if (!newPassword) return;
    if (newPassword.length < 6) {
      showToast("Password must be at least 6 characters", "error");
      return;
    }
    const confirm = prompt("Confirm new Master Password:");
    if (confirm !== newPassword) {
      showToast("Passwords do not match", "error");
      return;
    }
    invokeCommand("change_password", { newPassword })
      .then(() => showToast("Master Password updated"))
      .catch(err => showToast(typeof err === "string" ? err : "Failed to update password", "error"));
  };

  // Export
  container.querySelector("#set-export-row").onclick = async () => {
    try {
      const exportB64 = await invokeCommand("export_vault_encrypted");
      const byteChars = atob(exportB64);
      const byteNumbers = new Array(byteChars.length);
      for (let i = 0; i < byteChars.length; i++) {
        byteNumbers[i] = byteChars.charCodeAt(i);
      }
      const byteArray = new Uint8Array(byteNumbers);
      const blob = new Blob([byteArray], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vult-backup-${new Date().toISOString().slice(0, 10)}.vult`;
      a.click();
      URL.revokeObjectURL(url);
      showToast("Encrypted backup exported (.vult)");
    } catch (e) {
      showToast(typeof e === "string" ? e : "Export failed", "error");
    }
  };

  // Import
  container.querySelector("#set-import-row").onclick = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".vult,.json";
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const isJson = file.name.endsWith(".json");
      const reader = new FileReader();

      if (isJson) {
        reader.onload = async (event) => {
          try {
            const rawData = event.target.result;
            await invokeCommand("import_vault_data", { data: rawData, password: null });
            showToast("JSON Vault imported successfully");
            loadSettings();
          } catch (err) {
            showToast(typeof err === "string" ? err : "Import failed", "error");
          }
        };
        reader.readAsText(file);
      } else {
        reader.onload = async (event) => {
          try {
            const arrayBuffer = event.target.result;
            const bytes = new Uint8Array(arrayBuffer);
            let binary = "";
            for (let i = 0; i < bytes.byteLength; i++) {
              binary += String.fromCharCode(bytes[i]);
            }
            const b64Data = btoa(binary);

            const pwdPrompt = prompt("Enter password for this backup (Leave blank to use current Master Password):");
            const backupPassword = pwdPrompt && pwdPrompt.trim() ? pwdPrompt.trim() : null;

            await invokeCommand("import_vault_data", { data: b64Data, password: backupPassword });
            showToast("Encrypted backup imported successfully");
            loadSettings();
          } catch (err) {
            showToast(typeof err === "string" ? err : "Import failed", "error");
          }
        };
        reader.readAsArrayBuffer(file);
      }
    };
    input.click();
  };

  // Wipe All Data
  container.querySelector("#set-wipe-row").onclick = () => {
    showConfirmModal({
      title: "Wipe All Data?",
      description: "WARNING: This will permanently delete your entire vault and all stored secrets. There is NO recovery.",
      confirmText: "Wipe Everything",
      confirmDestructive: true,
      onConfirm: async () => {
        try {
          await invokeCommand("wipe_vault");
          showToast("Vault completely wiped");
          onVaultWiped();
        } catch (err) {
          showToast(typeof err === "string" ? err : "Failed to wipe vault", "error");
        }
      }
    });
  };

  return {
    loadSettings
  };
}
