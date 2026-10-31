// Tauri IPC Bridge with safe fallback for browser testing
export async function invokeCommand(cmd, args = {}) {
  if (window.__TAURI__ && window.__TAURI__.core && typeof window.__TAURI__.core.invoke === "function") {
    return await window.__TAURI__.core.invoke(cmd, args);
  }
  // Try dynamic import if Tauri bundle
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    return await invoke(cmd, args);
  } catch (err) {
    console.warn(`[Tauri Bridge] Falling back or failed invoking "${cmd}":`, err);
    throw err;
  }
}

let clipboardClearTimer = null;

export async function copySecret(text, label = "Secret", autoClearSeconds = 30) {
  if (!text) return false;
  try {
    // Invoke Rust clipboard command which also handles auto-clear
    await invokeCommand("copy_to_clipboard", {
      text,
      autoClearSeconds
    });
  } catch (e) {
    // Browser fallback
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
      if (autoClearSeconds > 0) {
        clipboardClearTimer = setTimeout(async () => {
          try {
            await navigator.clipboard.writeText("");
          } catch (_) {}
        }, autoClearSeconds * 1000);
      }
    }
  }
  return true;
}
