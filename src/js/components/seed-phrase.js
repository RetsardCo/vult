import { copySecret } from "../utils/tauri-bridge.js";
import { showToast } from "./toast.js";

export function renderSeedPhrase({
  words = [],
  passphrase = null,
  derivationPath = null
}) {
  const container = document.createElement("div");
  container.className = "seed-phrase-container";

  let isRevealed = false;

  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <span class="field-label">Recovery Words (${words.length})</span>
      <div style="display:flex; gap:6px;">
        <button class="btn btn-secondary btn-sm toggle-reveal-btn">Reveal Words</button>
        <button class="btn btn-secondary btn-sm copy-seed-btn">Copy All</button>
      </div>
    </div>
    <div class="seed-grid"></div>
    ${passphrase ? `
      <div class="field-card" style="margin-top:6px;">
        <span class="field-label">Optional Passphrase (13th / 25th word)</span>
        <div class="field-value mono">${passphrase}</div>
      </div>
    ` : ""}
    ${derivationPath ? `
      <div class="field-card" style="margin-top:6px;">
        <span class="field-label">Derivation Path</span>
        <div class="field-value mono">${derivationPath}</div>
      </div>
    ` : ""}
  `;

  const gridEl = container.querySelector(".seed-grid");
  const toggleBtn = container.querySelector(".toggle-reveal-btn");
  const copyBtn = container.querySelector(".copy-seed-btn");

  function renderGrid() {
    gridEl.innerHTML = "";
    words.forEach((w, idx) => {
      const pill = document.createElement("div");
      pill.className = "seed-word-pill";
      pill.innerHTML = `
        <span class="seed-word-num">${idx + 1}.</span>
        <span class="seed-word-text">${isRevealed ? w : "••••••"}</span>
      `;
      gridEl.appendChild(pill);
    });
  }

  renderGrid();

  toggleBtn.onclick = () => {
    isRevealed = !isRevealed;
    toggleBtn.textContent = isRevealed ? "Hide Words" : "Reveal Words";
    renderGrid();
  };

  copyBtn.onclick = async () => {
    await copySecret(words.join(" "), "Seed Phrase");
    showToast("Seed phrase copied to clipboard");
  };

  return container;
}
