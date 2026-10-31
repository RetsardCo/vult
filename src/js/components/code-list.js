import { copySecret } from "../utils/tauri-bridge.js";
import { showToast } from "./toast.js";

export function renderCodeList({
  codes = [],
  entryId,
  onToggleCode = null
}) {
  const container = document.createElement("div");
  container.className = "backup-codes-container";

  const total = codes.length;
  const remaining = codes.filter(c => !c.used).length;

  container.innerHTML = `
    <div class="backup-codes-stats">
      <span class="badge badge-accent">${remaining} / ${total} remaining</span>
      <button class="btn btn-secondary btn-sm copy-all-btn">Copy Remaining</button>
    </div>
    <div class="backup-codes-list"></div>
  `;

  const listEl = container.querySelector(".backup-codes-list");
  const copyAllBtn = container.querySelector(".copy-all-btn");

  copyAllBtn.onclick = async () => {
    const activeCodes = codes.filter(c => !c.used).map(c => c.code).join("\n");
    if (!activeCodes) {
      showToast("No unused codes remaining", "error");
      return;
    }
    await copySecret(activeCodes, "Backup Codes");
    showToast(`Copied ${remaining} backup codes`);
  };

  codes.forEach((item, index) => {
    const row = document.createElement("div");
    row.className = `backup-code-item ${item.used ? "used" : ""}`;

    row.innerHTML = `
      <input type="checkbox" class="code-checkbox" ${item.used ? "checked" : ""} title="Mark as used">
      <span class="code-text">${item.code}</span>
      <button class="btn-icon copy-single-btn" title="Copy code">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
      </button>
    `;

    const checkbox = row.querySelector(".code-checkbox");
    const copySingleBtn = row.querySelector(".copy-single-btn");

    checkbox.onchange = (e) => {
      const isUsed = e.target.checked;
      item.used = isUsed;
      if (isUsed) {
        row.classList.add("used");
      } else {
        row.classList.remove("used");
      }
      if (onToggleCode) {
        onToggleCode(entryId, index, isUsed);
      }
    };

    copySingleBtn.onclick = async () => {
      await copySecret(item.code, "Backup Code");
      showToast("Backup code copied");
    };

    listEl.appendChild(row);
  });

  return container;
}
