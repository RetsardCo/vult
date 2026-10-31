/**
 * Elegant macOS-style long-hover tooltip system for Vult.
 * Appears after a deliberate hover delay (~450ms) to provide helpful details
 * without visual clutter during swift cursor navigation.
 */

export function initTooltipSystem() {
  let tooltipEl = document.getElementById("vult-tooltip");
  if (!tooltipEl) {
    tooltipEl = document.createElement("div");
    tooltipEl.id = "vult-tooltip";
    tooltipEl.className = "vult-tooltip";
    tooltipEl.setAttribute("role", "tooltip");
    tooltipEl.setAttribute("aria-hidden", "true");
    document.body.appendChild(tooltipEl);
  }

  let hoverTimer = null;
  let currentTarget = null;
  const HOVER_DELAY = 450; // ms: deliberate long-hover like macOS native tooltips

  function getTooltipText(el) {
    if (!el || !(el instanceof Element)) return null;

    // 1. Direct explicit data-tooltip attribute
    if (el.dataset && el.dataset.tooltip) {
      return el.dataset.tooltip.trim();
    }

    // 2. Title attribute (migrate to data-tooltip to prevent native ugly OS tooltip from showing)
    if (el.hasAttribute("title")) {
      const title = el.getAttribute("title");
      if (title && title.trim()) {
        const text = title.trim();
        el.dataset.tooltip = text;
        el.removeAttribute("title");
        return text;
      }
    }

    // 3. Fallback to aria-label if present
    if (el.hasAttribute("aria-label")) {
      const aria = el.getAttribute("aria-label");
      if (aria && aria.trim()) return aria.trim();
    }

    // 4. Contextual fallbacks for known action buttons & interactive rows
    const id = el.id || "";
    if (id === "dash-settings-btn") return "Settings & Preferences";
    if (id === "dash-lock-btn") return "Lock Vault";
    if (id === "dash-gen-btn") return "Password Generator";
    if (id === "dash-fab-btn") return "Add New Secret";
    if (id === "dash-search-clear") return "Clear Search";
    if (id === "set-back-btn" || id === "cat-back-btn" || id === "detail-back-btn" || id === "form-back-btn" || id === "gen-back-btn") return "Back";
    if (id === "set-change-pin-row") return "Change your 4-8 digit numeric PIN";
    if (id === "set-change-pwd-row") return "Change Master Encryption Password";
    if (id === "set-export-row") return "Export Encrypted Vault Backup (.vult)";
    if (id === "set-import-row") return "Import Vault Backup (.vult or JSON)";
    if (id === "set-wipe-row") return "Permanently erase all vault data";
    if (id === "win-hello-btn") return "Unlock with Windows Hello biometric or OS credentials";
    if (id === "gen-refresh-btn") return "Generate New Password";
    if (id === "gen-copy-btn") return "Copy Password";
    if (id === "cat-add-btn") return "Add Secret";
    if (id === "detail-edit-btn") return "Edit Secret";
    if (id === "detail-delete-btn") return "Delete Secret";
    if (id === "detail-fav-btn") return "Toggle Favorite";
    if (id === "gen-pwd-quick-btn") return "Generate strong password";
    if (id === "add-custom-field-btn") return "Add custom field";
    if (id === "form-save-btn") return "Save secret to vault";

    if (el.classList.contains("password-toggle-btn")) return "Show / Hide Password";
    if (el.classList.contains("copy-btn") || el.classList.contains("copy-single-btn") || el.classList.contains("copy-quick-btn") || el.classList.contains("copy-note-btn")) {
      return "Copy to Clipboard";
    }
    if (el.classList.contains("copy-all-btn")) return "Copy all remaining recovery codes";
    if (el.classList.contains("copy-seed-btn")) return "Copy all recovery seed words";
    if (el.classList.contains("toggle-reveal-btn")) return "Show / Hide seed phrase words";
    if (el.classList.contains("c-del")) return "Remove custom field";
    if (el.classList.contains("reveal-btn")) return "Show / Hide Secret";
    if (el.classList.contains("pin-key")) {
      const key = el.dataset.key;
      if (key === "clear") return "Clear PIN";
      if (key === "backspace") return "Delete Last Digit";
    }

    return null;
  }

  function showTooltip(target, text) {
    if (!target || !text || !document.body.contains(target)) return;

    tooltipEl.textContent = text;
    tooltipEl.classList.remove("visible");
    tooltipEl.style.display = "block";

    const rect = target.getBoundingClientRect();
    const tipWidth = tooltipEl.offsetWidth || tooltipEl.getBoundingClientRect().width;
    const tipHeight = tooltipEl.offsetHeight || tooltipEl.getBoundingClientRect().height;

    // Center horizontally over target element
    let left = rect.left + (rect.width / 2) - (tipWidth / 2);
    // Keep within window horizontal boundaries (400px app width with safe 8px gutter)
    left = Math.max(8, Math.min(left, window.innerWidth - tipWidth - 8));

    // Position vertically: prefer below button, flip above if close to bottom
    let top = rect.bottom + 6;
    if (top + tipHeight > window.innerHeight - 8) {
      top = rect.top - tipHeight - 6;
    }
    top = Math.max(8, Math.min(top, window.innerHeight - tipHeight - 8));

    tooltipEl.style.left = `${Math.round(left)}px`;
    tooltipEl.style.top = `${Math.round(top)}px`;
    tooltipEl.setAttribute("aria-hidden", "false");

    requestAnimationFrame(() => {
      tooltipEl.classList.add("visible");
    });
  }

  function hideTooltip() {
    if (hoverTimer) {
      clearTimeout(hoverTimer);
      hoverTimer = null;
    }
    currentTarget = null;
    if (tooltipEl) {
      tooltipEl.classList.remove("visible");
      tooltipEl.setAttribute("aria-hidden", "true");
    }
  }

  // Global mouseover delegation
  document.addEventListener("mouseover", (e) => {
    const target = e.target.closest(
      "button, .btn, .btn-icon, .settings-row.clickable, [data-tooltip], [title], .pin-key, .password-toggle-btn"
    );
    if (!target) return;

    const text = getTooltipText(target);
    if (!text) return;

    if (currentTarget === target) return;
    hideTooltip();
    currentTarget = target;

    hoverTimer = setTimeout(() => {
      showTooltip(target, text);
    }, HOVER_DELAY);
  }, { passive: true });

  // Dismiss on mouse leave
  document.addEventListener("mouseout", (e) => {
    if (!currentTarget) return;
    const related = e.relatedTarget;
    if (related && (currentTarget === related || currentTarget.contains(related))) return;
    hideTooltip();
  }, { passive: true });

  // Dismiss immediately on interactions
  document.addEventListener("mousedown", hideTooltip, { passive: true });
  document.addEventListener("scroll", hideTooltip, { capture: true, passive: true });
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideTooltip();
  }, { passive: true });

  return {
    hide: hideTooltip
  };
}
