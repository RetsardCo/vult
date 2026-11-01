import { invokeCommand } from "../utils/tauri-bridge.js";
import { showToast } from "../components/toast.js";

export function initLockScreen({ onUnlocked }) {
  const container = document.getElementById("screen-lock");
  let vaultExists = false;
  let currentAuthMode = "pin_and_password";
  let enteredPin = "";
  let lockoutTimer = null;
  let lockoutSecondsRemaining = 0;

  async function checkStatus() {
    try {
      vaultExists = await invokeCommand("check_vault_exists");
      if (vaultExists) {
        const settings = await invokeCommand("get_auth_settings");
        currentAuthMode = settings.auth_mode || "pin_and_password";
        renderUnlockView(settings);
      } else {
        renderSetupView();
      }
    } catch (e) {
      console.error("Failed to check vault status:", e);
      renderSetupView();
    }
  }

  function renderSetupView() {
    window.onkeydown = null;
    container.innerHTML = `
      <div class="auth-container">
        <div class="auth-header">
          <div class="auth-logo">
            <img src="assets/logo.png" alt="Vult Logo" class="auth-logo-img">
          </div>
          <div class="auth-title">Vult</div>
          <div class="auth-subtitle">Create Your Secure Vault</div>
        </div>

        <div class="setup-wizard">
          <div class="form-group">
            <label class="form-label">Authentication Mode</label>
            <div class="auth-mode-selector">
              <div class="auth-mode-option selected" data-mode="pin_and_password">PIN + Password</div>
              <div class="auth-mode-option" data-mode="password_only">Password Only</div>
              <div class="auth-mode-option" data-mode="pin_only">PIN Only</div>
            </div>
          </div>

          <div class="form-group" id="setup-pin-group">
            <label class="form-label">Create PIN (4-8 digits)</label>
            <input type="password" id="setup-pin" class="input-text input-mono" placeholder="e.g. 1234" maxlength="8" pattern="[0-9]*" inputmode="numeric">
          </div>

          <div class="form-group" id="setup-password-group">
            <label class="form-label">Master Password</label>
            <div class="password-input-group">
              <input type="password" id="setup-password" class="input-text" placeholder="Enter strong password">
              <button class="password-toggle-btn" type="button" data-tooltip="Show / Hide Password">👁</button>
            </div>
          </div>

          <div class="form-group" id="setup-confirm-group">
            <label class="form-label">Confirm Master Password</label>
            <input type="password" id="setup-password-confirm" class="input-text" placeholder="Confirm password">
          </div>

          <div class="auth-error" id="setup-error"></div>

          <button id="setup-submit-btn" class="btn btn-primary" style="width:100%; margin-top:12px;">
            Create Vault & Unlock
          </button>
        </div>
      </div>
    `;

    let selectedMode = "pin_and_password";
    const modeOptions = container.querySelectorAll(".auth-mode-option");
    const pinGroup = container.querySelector("#setup-pin-group");
    const pwdGroup = container.querySelector("#setup-password-group");
    const confGroup = container.querySelector("#setup-confirm-group");
    const errorEl = container.querySelector("#setup-error");
    const submitBtn = container.querySelector("#setup-submit-btn");

    modeOptions.forEach(opt => {
      opt.onclick = () => {
        modeOptions.forEach(o => o.classList.remove("selected"));
        opt.classList.add("selected");
        selectedMode = opt.dataset.mode;
        if (selectedMode === "pin_only") {
          pinGroup.style.display = "block";
          pwdGroup.style.display = "none";
          confGroup.style.display = "none";
        } else if (selectedMode === "password_only") {
          pinGroup.style.display = "none";
          pwdGroup.style.display = "block";
          confGroup.style.display = "block";
        } else {
          pinGroup.style.display = "block";
          pwdGroup.style.display = "block";
          confGroup.style.display = "block";
        }
      };
    });

    const toggleBtn = container.querySelector(".password-toggle-btn");
    const pwdInput = container.querySelector("#setup-password");
    if (toggleBtn && pwdInput) {
      toggleBtn.onclick = () => {
        pwdInput.type = pwdInput.type === "password" ? "text" : "password";
      };
    }

    submitBtn.onclick = async () => {
      errorEl.textContent = "";
      const pinVal = container.querySelector("#setup-pin")?.value.trim() || "";
      const pwdVal = container.querySelector("#setup-password")?.value || "";
      const confVal = container.querySelector("#setup-password-confirm")?.value || "";

      if (selectedMode !== "password_only") {
        if (!pinVal || pinVal.length < 4 || !/^\d+$/.test(pinVal)) {
          errorEl.textContent = "PIN must be between 4 and 8 digits.";
          return;
        }
      }

      if (selectedMode !== "pin_only") {
        if (!pwdVal || pwdVal.length < 6) {
          errorEl.textContent = "Master password must be at least 6 characters.";
          return;
        }
        if (pwdVal !== confVal) {
          errorEl.textContent = "Passwords do not match.";
          return;
        }
      }

      try {
        submitBtn.disabled = true;
        submitBtn.textContent = "Initializing Encryption...";
        await invokeCommand("setup_vault", {
          pin: selectedMode === "password_only" ? null : pinVal,
          password: selectedMode === "pin_only" ? pinVal : pwdVal,
          authMode: selectedMode
        });
        showToast("Vault successfully created!");
        onUnlocked();
      } catch (err) {
        errorEl.textContent = typeof err === "string" ? err : err.message || "Failed to create vault";
        submitBtn.disabled = false;
        submitBtn.textContent = "Create Vault & Unlock";
      }
    };
  }

  function renderUnlockView(settings) {
    const hasPin = settings.auth_mode !== "password_only";
    const hasPassword = settings.auth_mode !== "pin_only";
    const hasWinHello = settings.windows_hello_enabled;
    const pinLength = settings.pin_length && settings.pin_length >= 4 && settings.pin_length <= 8
      ? settings.pin_length
      : 6;
    enteredPin = "";

    container.innerHTML = `
      <div class="auth-container">
        <div class="auth-header">
          <div class="auth-logo">
            <img src="assets/logo.png" alt="Vult Logo" class="auth-logo-img">
          </div>
          <div class="auth-title">Vult</div>
          <div class="auth-subtitle">Enter credentials to unlock</div>
        </div>

        <div id="unlock-card" style="width:100%;">
          ${hasPin ? `
            <div class="pin-wrapper">
              <div class="pin-label">PIN Code</div>
              <div class="pin-dots">
                ${Array.from({ length: pinLength }, (_, i) => `
                  <div class="pin-dot" id="dot-${i}"></div>
                `).join("")}
              </div>

              <div class="pin-keypad">
                ${[1, 2, 3, 4, 5, 6, 7, 8, 9].map(n => `
                  <button type="button" class="pin-key" data-key="${n}">${n}</button>
                `).join("")}
                <button type="button" class="pin-key ghost" data-key="clear" data-tooltip="Clear PIN">✕</button>
                <button type="button" class="pin-key" data-key="0">0</button>
                <button type="button" class="pin-key ghost" data-key="backspace" data-tooltip="Delete last digit">⌫</button>
              </div>
            </div>
          ` : ""}

          ${hasPassword ? `
            <div class="form-group" style="text-align:left;">
              <label class="form-label">Master Password</label>
              <div class="password-input-group">
                <input type="password" id="unlock-password" class="input-text" placeholder="Enter master password">
                <button class="password-toggle-btn" type="button" data-tooltip="Show / Hide Password">👁</button>
              </div>
            </div>
          ` : ""}

          <div class="auth-error" id="unlock-error"></div>

          <div class="auth-actions">
            <button id="unlock-submit-btn" class="btn btn-primary">
              Unlock Vault
            </button>

            ${hasWinHello ? `
              <div class="auth-divider">or</div>
              <button id="win-hello-btn" type="button" class="btn btn-win-hello" data-tooltip="Unlock using Windows biometric or OS credentials">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M0 0h11v11H0zM13 0h11v11H13zM0 13h11v11H0zM13 13h11v11H13z"/>
                </svg>
                Unlock with Windows Hello
              </button>
            ` : ""}
          </div>
        </div>
      </div>
    `;

    const unlockCard = container.querySelector("#unlock-card");
    const errorEl = container.querySelector("#unlock-error");
    const submitBtn = container.querySelector("#unlock-submit-btn");
    const pwdInput = container.querySelector("#unlock-password");
    const winHelloBtn = container.querySelector("#win-hello-btn");

    function updateDots() {
      for (let i = 0; i < pinLength; i++) {
        const dot = container.querySelector(`#dot-${i}`);
        if (dot) {
          if (i < enteredPin.length) {
            dot.classList.add("filled");
          } else {
            dot.classList.remove("filled");
          }
        }
      }
    }

    // Keypad listeners
    container.querySelectorAll(".pin-key").forEach(btn => {
      btn.onclick = () => {
        if (lockoutSecondsRemaining > 0) return;
        const key = btn.dataset.key;
        if (key === "clear") {
          enteredPin = "";
        } else if (key === "backspace") {
          enteredPin = enteredPin.slice(0, -1);
        } else if (enteredPin.length < pinLength) {
          enteredPin += key;
        }
        updateDots();
        // Auto trigger unlock if PIN only and reached full configured PIN length
        if (!hasPassword && enteredPin.length === pinLength) {
          triggerUnlock();
        }
      };
    });

    // Keyboard support for PIN and Enter
    window.onkeydown = (e) => {
      if (!container.classList.contains("active")) return;
      if (e.target && (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA")) {
        if (e.target.id === "unlock-password" && e.key === "Enter") {
          triggerUnlock();
        }
        return;
      }
      if (lockoutSecondsRemaining > 0) return;
      if (hasPin && /^[0-9]$/.test(e.key)) {
        if (enteredPin.length < pinLength) {
          enteredPin += e.key;
          updateDots();
          if (!hasPassword && enteredPin.length === pinLength) {
            triggerUnlock();
          }
        }
      } else if (hasPin && e.key === "Backspace") {
        enteredPin = enteredPin.slice(0, -1);
        updateDots();
      } else if (e.key === "Enter") {
        triggerUnlock();
      }
    };

    const toggleBtn = container.querySelector(".password-toggle-btn");
    if (toggleBtn && pwdInput) {
      toggleBtn.onclick = () => {
        pwdInput.type = pwdInput.type === "password" ? "text" : "password";
      };
    }

    if (winHelloBtn) {
      winHelloBtn.onclick = async () => {
        try {
          errorEl.textContent = "";
          const ok = await invokeCommand("unlock_with_windows_hello");
          if (ok) {
            showToast("Windows Hello verified");
            onUnlocked();
          } else {
            shakeCard("Windows Hello verification cancelled or failed");
          }
        } catch (err) {
          shakeCard(typeof err === "string" ? err : err.message || "Windows Hello error");
        }
      };
    }

    function shakeCard(errMsg) {
      errorEl.textContent = errMsg;
      unlockCard.classList.remove("shake");
      void unlockCard.offsetWidth; // re-flow
      unlockCard.classList.add("shake");
      enteredPin = "";
      updateDots();
    }

    function startLockoutCountdown(seconds) {
      lockoutSecondsRemaining = seconds;
      submitBtn.disabled = true;
      if (lockoutTimer) clearInterval(lockoutTimer);
      lockoutTimer = setInterval(() => {
        lockoutSecondsRemaining--;
        if (lockoutSecondsRemaining <= 0) {
          clearInterval(lockoutTimer);
          submitBtn.disabled = false;
          submitBtn.textContent = "Unlock Vault";
          errorEl.textContent = "";
        } else {
          errorEl.textContent = `Too many failed attempts. Wait ${lockoutSecondsRemaining}s`;
          submitBtn.textContent = `Locked (${lockoutSecondsRemaining}s)`;
        }
      }, 1000);
    }

    async function triggerUnlock() {
      if (lockoutSecondsRemaining > 0) return;
      errorEl.textContent = "";

      const pin = hasPin ? enteredPin : null;
      const pwd = hasPassword ? (pwdInput?.value || "") : "";

      if (hasPin && !pin) {
        shakeCard("Please enter your PIN");
        return;
      }
      if (hasPassword && !pwd) {
        shakeCard("Please enter your Master Password");
        return;
      }

      try {
        submitBtn.disabled = true;
        submitBtn.textContent = "Decrypting...";
        const ok = await invokeCommand("unlock_vault", {
          pin,
          password: hasPassword ? pwd : pin
        });
        if (ok) {
          showToast("Vault unlocked");
          onUnlocked();
        } else {
          shakeCard("Invalid credentials. Please try again.");
          submitBtn.disabled = false;
          submitBtn.textContent = "Unlock Vault";
        }
      } catch (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = "Unlock Vault";
        const msg = typeof err === "string" ? err : err.message || "Decryption failed";
        if (msg.includes("Too many failed attempts") || msg.includes("Wait")) {
          // Extract seconds if present
          const match = msg.match(/(\d+)\s*s/);
          startLockoutCountdown(match ? parseInt(match[1]) : 10);
        } else {
          shakeCard(msg);
        }
      }
    }

    submitBtn.onclick = triggerUnlock;
  }

  return {
    checkStatus,
    reset: checkStatus
  };
}
