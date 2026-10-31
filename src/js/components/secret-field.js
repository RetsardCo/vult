import { copySecret } from "../utils/tauri-bridge.js";
import { showToast } from "./toast.js";

export function renderSecretField({
  label,
  value,
  isMono = true,
  maskedByDefault = true,
  canCopy = true,
  onCopy = null
}) {
  const container = document.createElement("div");
  container.className = "field-card";

  let isRevealed = !maskedByDefault;

  container.innerHTML = `
    <div class="field-card-header">
      <span class="field-label">${label}</span>
      <div style="display:flex; gap:4px; align-items:center;">
        ${maskedByDefault ? `
          <button class="btn-icon reveal-btn" title="Toggle visibility">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          </button>
        ` : ""}
        ${canCopy ? `
          <button class="btn-icon copy-btn" title="Copy to clipboard">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
        ` : ""}
      </div>
    </div>
    <div class="field-value-row">
      <div class="field-value ${isMono ? "mono" : ""} ${maskedByDefault ? "masked" : ""}">
        ${maskedByDefault ? "••••••••••••••••" : (value || "None")}
      </div>
    </div>
  `;

  const valueEl = container.querySelector(".field-value");
  const revealBtn = container.querySelector(".reveal-btn");
  const copyBtn = container.querySelector(".copy-btn");

  if (revealBtn) {
    revealBtn.onclick = () => {
      isRevealed = !isRevealed;
      if (isRevealed) {
        valueEl.textContent = value || "None";
        valueEl.classList.remove("masked");
        revealBtn.innerHTML = `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
            <line x1="1" y1="1" x2="23" y2="23"></line>
          </svg>
        `;
      } else {
        valueEl.textContent = "••••••••••••••••";
        valueEl.classList.add("masked");
        revealBtn.innerHTML = `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
        `;
      }
    };
  }

  if (copyBtn) {
    copyBtn.onclick = async () => {
      if (!value) return;
      await copySecret(value, label);
      showToast(`${label} copied (auto-clears in 30s)`);
      if (onCopy) onCopy();
    };
  }

  return container;
}
