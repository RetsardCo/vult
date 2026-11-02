import { calculatePasswordStrength, escapeHtml } from "../utils/helpers.js";

// Modal confirmation and dialog utility
export function showConfirmModal({
  title,
  description,
  confirmText = "Confirm",
  confirmDestructive = false,
  cancelText = "Cancel",
  onConfirm = () => {},
  onCancel = () => {}
}) {
  const modal = document.getElementById("confirm-modal");
  if (!modal) return;

  const titleEl = modal.querySelector(".modal-title");
  const descEl = modal.querySelector(".modal-description");
  const confirmBtn = modal.querySelector("#modal-confirm-btn");
  const cancelBtn = modal.querySelector("#modal-cancel-btn");

  if (titleEl) titleEl.textContent = title;
  if (descEl) descEl.textContent = description;
  if (confirmBtn) {
    confirmBtn.textContent = confirmText;
    confirmBtn.className = confirmDestructive ? "btn btn-destructive" : "btn btn-primary";
  }
  if (cancelBtn) cancelBtn.textContent = cancelText;

  modal.classList.add("active");

  const cleanup = () => {
    modal.classList.remove("active");
    confirmBtn.onclick = null;
    cancelBtn.onclick = null;
  };

  confirmBtn.onclick = () => {
    cleanup();
    onConfirm();
  };

  cancelBtn.onclick = () => {
    cleanup();
    onCancel();
  };
}

export function closeModal() {
  const modal = document.getElementById("confirm-modal");
  if (modal) modal.classList.remove("active");
}

function mountModal(overlayEl, onDismiss, defaultDismissResult = null) {
  const app = document.getElementById("app") || document.body;
  app.appendChild(overlayEl);

  void overlayEl.offsetHeight;
  overlayEl.classList.add("active");

  const onKeydown = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      cleanup(defaultDismissResult);
    }
  };
  window.addEventListener("keydown", onKeydown);

  overlayEl.onclick = (e) => {
    if (e.target === overlayEl) {
      cleanup(defaultDismissResult);
    }
  };

  let cleaned = false;
  function cleanup(result) {
    if (cleaned) return;
    cleaned = true;
    window.removeEventListener("keydown", onKeydown);
    overlayEl.classList.remove("active");
    setTimeout(() => {
      if (overlayEl.parentNode) {
        overlayEl.parentNode.removeChild(overlayEl);
      }
    }, 200);
    onDismiss(result);
  }

  return cleanup;
}

function setupEyeToggle(container) {
  const toggleButtons = container.querySelectorAll(".password-toggle-btn");
  toggleButtons.forEach(btn => {
    btn.onclick = (e) => {
      e.preventDefault();
      const group = btn.closest(".password-input-group");
      if (!group) return;
      const input = group.querySelector("input");
      if (!input) return;
      if (input.type === "password") {
        input.type = "text";
        btn.style.color = "var(--accent)";
      } else {
        input.type = "password";
        btn.style.color = "";
      }
    };
  });
}

/**
 * Custom macOS-styled Change / Set PIN modal
 * @returns {Promise<string|null>} PIN or null if cancelled
 */
export function showPinModal({
  title = "Change PIN",
  subtitle = "Enter a 4 to 8 digit numeric PIN.",
  confirmText = "Update PIN"
} = {}) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.innerHTML = `
      <div class="modal-dialog">
        <div class="modal-title">${escapeHtml(title)}</div>
        ${subtitle ? `<div class="modal-description">${escapeHtml(subtitle)}</div>` : ""}
        
        <div class="modal-form-group">
          <label for="modal-new-pin">New PIN (4–8 digits)</label>
          <div class="password-input-group">
            <input type="password" id="modal-new-pin" class="input-text input-mono" maxlength="8" inputmode="numeric" placeholder="Enter PIN">
            <button type="button" class="password-toggle-btn" tabindex="-1" title="Show/Hide PIN">👁</button>
          </div>
        </div>

        <div class="modal-form-group">
          <label for="modal-confirm-pin">Confirm PIN</label>
          <div class="password-input-group">
            <input type="password" id="modal-confirm-pin" class="input-text input-mono" maxlength="8" inputmode="numeric" placeholder="Confirm PIN">
            <button type="button" class="password-toggle-btn" tabindex="-1" title="Show/Hide PIN">👁</button>
          </div>
        </div>

        <div class="modal-error" id="modal-pin-error" style="display: none;"></div>

        <div class="modal-actions">
          <button id="modal-pin-cancel-btn" class="btn btn-secondary btn-sm" type="button">Cancel</button>
          <button id="modal-pin-submit-btn" class="btn btn-primary btn-sm" type="button">${escapeHtml(confirmText)}</button>
        </div>
      </div>
    `;

    const cleanup = mountModal(overlay, resolve, null);
    setupEyeToggle(overlay);

    const newPinInput = overlay.querySelector("#modal-new-pin");
    const confirmPinInput = overlay.querySelector("#modal-confirm-pin");
    const errorEl = overlay.querySelector("#modal-pin-error");
    const submitBtn = overlay.querySelector("#modal-pin-submit-btn");
    const cancelBtn = overlay.querySelector("#modal-pin-cancel-btn");

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.style.display = "block";
    }

    cancelBtn.onclick = () => cleanup(null);

    submitBtn.onclick = () => {
      const pin = newPinInput.value.trim();
      const confirm = confirmPinInput.value.trim();

      if (!pin) {
        showError("Please enter a PIN.");
        newPinInput.focus();
        return;
      }
      if (!/^\d{4,8}$/.test(pin)) {
        showError("PIN must be 4 to 8 numeric digits.");
        newPinInput.focus();
        return;
      }
      if (pin !== confirm) {
        showError("PINs do not match.");
        confirmPinInput.focus();
        return;
      }

      cleanup(pin);
    };

    [newPinInput, confirmPinInput].forEach(inp => {
      inp.addEventListener("input", () => {
        inp.value = inp.value.replace(/\D/g, "");
        errorEl.style.display = "none";
      });
    });

    newPinInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        if (!confirmPinInput.value) {
          confirmPinInput.focus();
        } else {
          submitBtn.click();
        }
      }
    });

    confirmPinInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submitBtn.click();
      }
    });

    setTimeout(() => newPinInput.focus(), 50);
  });
}

/**
 * Custom macOS-styled Change Master Password modal with real-time strength meter
 * @returns {Promise<string|null>} Password or null if cancelled
 */
export function showPasswordModal({
  title = "Change Master Password",
  subtitle = "Enter a new Master Password (minimum 6 characters).",
  confirmText = "Update Password"
} = {}) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.innerHTML = `
      <div class="modal-dialog">
        <div class="modal-title">${escapeHtml(title)}</div>
        ${subtitle ? `<div class="modal-description">${escapeHtml(subtitle)}</div>` : ""}

        <div class="modal-form-group">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:var(--space-2xs);">
            <label for="modal-new-pwd" style="margin-bottom:0;">New Master Password</label>
            <span id="modal-pwd-strength-label" style="font-size:11px; color:var(--text-tertiary);">Empty</span>
          </div>
          <div class="password-input-group">
            <input type="password" id="modal-new-pwd" class="input-text input-mono" placeholder="New Password">
            <button type="button" class="password-toggle-btn" tabindex="-1" title="Show/Hide Password">👁</button>
          </div>
          <div class="modal-entropy-bar">
            <div id="modal-pwd-entropy-fill" class="modal-entropy-fill weak" style="width: 0%;"></div>
          </div>
        </div>

        <div class="modal-form-group">
          <label for="modal-confirm-pwd">Confirm Master Password</label>
          <div class="password-input-group">
            <input type="password" id="modal-confirm-pwd" class="input-text input-mono" placeholder="Confirm Password">
            <button type="button" class="password-toggle-btn" tabindex="-1" title="Show/Hide Password">👁</button>
          </div>
        </div>

        <div class="modal-error" id="modal-pwd-error" style="display: none;"></div>

        <div class="modal-actions">
          <button id="modal-pwd-cancel-btn" class="btn btn-secondary btn-sm" type="button">Cancel</button>
          <button id="modal-pwd-submit-btn" class="btn btn-primary btn-sm" type="button">${escapeHtml(confirmText)}</button>
        </div>
      </div>
    `;

    const cleanup = mountModal(overlay, resolve, null);
    setupEyeToggle(overlay);

    const newPwdInput = overlay.querySelector("#modal-new-pwd");
    const confirmPwdInput = overlay.querySelector("#modal-confirm-pwd");
    const strengthLabel = overlay.querySelector("#modal-pwd-strength-label");
    const entropyFill = overlay.querySelector("#modal-pwd-entropy-fill");
    const errorEl = overlay.querySelector("#modal-pwd-error");
    const submitBtn = overlay.querySelector("#modal-pwd-submit-btn");
    const cancelBtn = overlay.querySelector("#modal-pwd-cancel-btn");

    function showError(msg) {
      errorEl.textContent = msg;
      errorEl.style.display = "block";
    }

    newPwdInput.addEventListener("input", () => {
      errorEl.style.display = "none";
      const val = newPwdInput.value;
      const strength = calculatePasswordStrength(val);
      entropyFill.className = `modal-entropy-fill ${strength.class}`;
      entropyFill.style.width = `${strength.percent}%`;
      strengthLabel.textContent = `${strength.label}${val.length ? ` (${val.length} chars)` : ""}`;
    });

    confirmPwdInput.addEventListener("input", () => {
      errorEl.style.display = "none";
    });

    cancelBtn.onclick = () => cleanup(null);

    submitBtn.onclick = () => {
      const pwd = newPwdInput.value;
      const confirm = confirmPwdInput.value;

      if (!pwd) {
        showError("Please enter a password.");
        newPwdInput.focus();
        return;
      }
      if (pwd.length < 6) {
        showError("Password must be at least 6 characters.");
        newPwdInput.focus();
        return;
      }
      if (pwd !== confirm) {
        showError("Passwords do not match.");
        confirmPwdInput.focus();
        return;
      }

      cleanup(pwd);
    };

    newPwdInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        if (!confirmPwdInput.value) {
          confirmPwdInput.focus();
        } else {
          submitBtn.click();
        }
      }
    });

    confirmPwdInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submitBtn.click();
      }
    });

    setTimeout(() => newPwdInput.focus(), 50);
  });
}

/**
 * Custom macOS-styled Import Backup Password modal
 * @returns {Promise<{cancelled: boolean, password: string|null}>}
 */
export function showBackupPasswordModal({
  title = "Backup Password",
  subtitle = "Enter the password used when creating this backup (or leave blank to use your current Master Password).",
  confirmText = "Import"
} = {}) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.innerHTML = `
      <div class="modal-dialog">
        <div class="modal-title">${escapeHtml(title)}</div>
        ${subtitle ? `<div class="modal-description">${escapeHtml(subtitle)}</div>` : ""}

        <div class="modal-form-group">
          <label for="modal-backup-pwd">Backup Password</label>
          <div class="password-input-group">
            <input type="password" id="modal-backup-pwd" class="input-text input-mono" placeholder="Leave blank for Master Password">
            <button type="button" class="password-toggle-btn" tabindex="-1" title="Show/Hide Password">👁</button>
          </div>
        </div>

        <div class="modal-actions">
          <button id="modal-backup-cancel-btn" class="btn btn-secondary btn-sm" type="button">Cancel</button>
          <button id="modal-backup-submit-btn" class="btn btn-primary btn-sm" type="button">${escapeHtml(confirmText)}</button>
        </div>
      </div>
    `;

    const cleanup = mountModal(overlay, resolve, { cancelled: true, password: null });
    setupEyeToggle(overlay);

    const pwdInput = overlay.querySelector("#modal-backup-pwd");
    const submitBtn = overlay.querySelector("#modal-backup-submit-btn");
    const cancelBtn = overlay.querySelector("#modal-backup-cancel-btn");

    cancelBtn.onclick = () => cleanup({ cancelled: true, password: null });

    submitBtn.onclick = () => {
      const val = pwdInput.value;
      const password = val && val.trim().length > 0 ? val : null;
      cleanup({ cancelled: false, password });
    };

    pwdInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submitBtn.click();
      }
    });

    setTimeout(() => pwdInput.focus(), 50);
  });
}
