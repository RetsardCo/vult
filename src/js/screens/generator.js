import { copySecret } from "../utils/tauri-bridge.js";
import { calculatePasswordStrength } from "../utils/helpers.js";
import { showToast } from "../components/toast.js";

export function initGeneratorScreen({
  onBack,
  onUsePassword = null
}) {
  const container = document.getElementById("screen-generator");
  let onSelectCallback = null;

  container.innerHTML = `
    <header class="app-header">
      <div class="header-left">
        <button id="gen-back-btn" class="btn-icon" data-tooltip="Back">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="15 18 9 12 15 6"></polyline>
          </svg>
        </button>
        <div class="header-title">Password Generator</div>
      </div>
      <div class="header-right">
        <button id="gen-use-btn" class="btn btn-primary btn-sm" style="display:none;" data-tooltip="Insert password into active form">Use</button>
      </div>
    </header>

    <div class="gen-container">
      <div class="gen-display-card">
        <div class="gen-password-text" id="gen-pwd-display"></div>
        <div class="gen-entropy-bar">
          <div class="gen-entropy-fill" id="gen-entropy-fill"></div>
        </div>
        <div class="gen-display-actions">
          <span class="gen-strength-label" id="gen-strength-label">Strong</span>
          <div style="display:flex; gap:6px;">
            <button id="gen-refresh-btn" class="btn-icon" data-tooltip="Generate New Password">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="23 4 23 10 17 10"></polyline>
                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
              </svg>
            </button>
            <button id="gen-copy-btn" class="btn btn-secondary btn-sm" data-tooltip="Copy Generated Password">Copy</button>
          </div>
        </div>
      </div>

      <div class="slider-group">
        <div class="slider-header">
          <span class="form-label" style="margin-bottom:0;">Length</span>
          <span class="slider-val" id="gen-length-val">20</span>
        </div>
        <input type="range" id="gen-length-slider" class="range-input" min="8" max="64" value="20">
      </div>

      <div class="gen-options-list">
        <label class="toggle-row">
          <span class="toggle-label">Uppercase Letters (A-Z)</span>
          <label class="toggle-switch">
            <input type="checkbox" id="gen-opt-upper" checked>
            <span class="slider-round"></span>
          </label>
        </label>

        <label class="toggle-row">
          <span class="toggle-label">Lowercase Letters (a-z)</span>
          <label class="toggle-switch">
            <input type="checkbox" id="gen-opt-lower" checked>
            <span class="slider-round"></span>
          </label>
        </label>

        <label class="toggle-row">
          <span class="toggle-label">Numbers (0-9)</span>
          <label class="toggle-switch">
            <input type="checkbox" id="gen-opt-nums" checked>
            <span class="slider-round"></span>
          </label>
        </label>

        <label class="toggle-row">
          <span class="toggle-label">Symbols (!@#$%^&*)</span>
          <label class="toggle-switch">
            <input type="checkbox" id="gen-opt-syms" checked>
            <span class="slider-round"></span>
          </label>
        </label>

        <label class="toggle-row">
          <span class="toggle-label">Avoid Ambiguous (1, l, I, 0, O)</span>
          <label class="toggle-switch">
            <input type="checkbox" id="gen-opt-ambig" checked>
            <span class="slider-round"></span>
          </label>
        </label>
      </div>
    </div>
  `;

  const pwdDisplay = container.querySelector("#gen-pwd-display");
  const entropyFill = container.querySelector("#gen-entropy-fill");
  const strengthLabel = container.querySelector("#gen-strength-label");
  const lengthSlider = container.querySelector("#gen-length-slider");
  const lengthVal = container.querySelector("#gen-length-val");
  const refreshBtn = container.querySelector("#gen-refresh-btn");
  const copyBtn = container.querySelector("#gen-copy-btn");
  const useBtn = container.querySelector("#gen-use-btn");
  const backBtn = container.querySelector("#gen-back-btn");

  const optUpper = container.querySelector("#gen-opt-upper");
  const optLower = container.querySelector("#gen-opt-lower");
  const optNums = container.querySelector("#gen-opt-nums");
  const optSyms = container.querySelector("#gen-opt-syms");
  const optAmbig = container.querySelector("#gen-opt-ambig");

  let currentPassword = "";

  function generate() {
    const len = parseInt(lengthSlider.value, 10);
    let charset = "";

    let upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    let lower = "abcdefghijkmnopqrstuvwxyz";
    let nums = "23456789";
    let syms = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    if (!optAmbig.checked) {
      upper += "IO";
      lower += "l";
      nums += "01";
    }

    if (optUpper.checked) charset += upper;
    if (optLower.checked) charset += lower;
    if (optNums.checked) charset += nums;
    if (optSyms.checked) charset += syms;

    if (!charset) {
      charset = lower + nums;
      optLower.checked = true;
    }

    // Cryptographically secure random values via crypto.getRandomValues
    const randomVals = new Uint32Array(len);
    window.crypto.getRandomValues(randomVals);

    let result = "";
    for (let i = 0; i < len; i++) {
      result += charset[randomVals[i] % charset.length];
    }

    currentPassword = result;
    pwdDisplay.textContent = currentPassword;

    const strength = calculatePasswordStrength(currentPassword);
    entropyFill.className = `gen-entropy-fill ${strength.class}`;
    strengthLabel.textContent = `${strength.label} (${len} chars)`;
  }

  lengthSlider.oninput = () => {
    lengthVal.textContent = lengthSlider.value;
    generate();
  };

  [optUpper, optLower, optNums, optSyms, optAmbig].forEach(el => {
    el.onchange = generate;
  });

  refreshBtn.onclick = generate;

  copyBtn.onclick = async () => {
    if (!currentPassword) return;
    await copySecret(currentPassword, "Generated Password");
    showToast("Password copied to clipboard");
  };

  useBtn.onclick = () => {
    if (onSelectCallback && currentPassword) {
      onSelectCallback(currentPassword);
      onBack();
    }
  };

  backBtn.onclick = onBack;

  function open(callback = null) {
    onSelectCallback = callback;
    useBtn.style.display = callback ? "inline-flex" : "none";
    generate();
  }

  return {
    open,
    generate
  };
}
