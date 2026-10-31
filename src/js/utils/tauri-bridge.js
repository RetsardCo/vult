// Tauri IPC Bridge with safe fallback for browser testing and timeout protection
export async function invokeCommand(cmd, args = {}, timeoutMs = 15000) {
  let invoker = null;

  // 1. Check window.__TAURI__ variants (Tauri v2 core, Tauri v1, Tauri internals)
  if (typeof window !== "undefined") {
    if (window.__TAURI__?.core?.invoke && typeof window.__TAURI__.core.invoke === "function") {
      invoker = window.__TAURI__.core.invoke;
    } else if (window.__TAURI__?.invoke && typeof window.__TAURI__.invoke === "function") {
      invoker = window.__TAURI__.invoke;
    } else if (window.__TAURI_INTERNALS__?.invoke && typeof window.__TAURI_INTERNALS__.invoke === "function") {
      invoker = window.__TAURI_INTERNALS__.invoke;
    }
  }

  // 2. Try dynamic import if Tauri bundle with package bundler
  if (!invoker) {
    try {
      const api = await import("@tauri-apps/api/core");
      if (api && typeof api.invoke === "function") {
        invoker = api.invoke;
      }
    } catch (_) {
      // Dynamic import not available
    }
  }

  if (!invoker) {
    const err = new Error(`Tauri IPC not available. Cannot execute command "${cmd}".`);
    console.warn(`[Tauri Bridge] ${err.message}`);
    throw err;
  }

  // 3. Timeout guard to guarantee UI never hangs indefinitely on stuck IPC calls
  const effectiveTimeout = cmd === "unlock_with_windows_hello" ? Math.max(timeoutMs, 120000) : timeoutMs;
  let timerId = null;
  const timeoutPromise = new Promise((_, reject) => {
    timerId = setTimeout(() => {
      reject(new Error(`Command "${cmd}" timed out after ${effectiveTimeout / 1000}s`));
    }, effectiveTimeout);
  });

  try {
    const result = await Promise.race([
      invoker(cmd, args),
      timeoutPromise
    ]);
    return result;
  } catch (err) {
    console.error(`[Tauri Bridge] Command "${cmd}" failed:`, err);
    throw (typeof err === "string" ? new Error(err) : err);
  } finally {
    if (timerId) clearTimeout(timerId);
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
