import { invokeCommand, copySecret } from "../utils/tauri-bridge.js";
import { getCategoryMeta, formatRelativeTime } from "../utils/helpers.js";
import { renderSecretField } from "../components/secret-field.js";
import { renderCodeList } from "../components/code-list.js";
import { renderSeedPhrase } from "../components/seed-phrase.js";
import { showToast } from "../components/toast.js";
import { showConfirmModal } from "../components/modal.js";

export function initEntryDetailScreen({
  onBack,
  onNavigateEdit,
  onDeleted
}) {
  const container = document.getElementById("screen-entry-detail");
  let currentEntry = null;

  container.innerHTML = `
    <header class="app-header">
      <div class="header-left">
        <button id="detail-back-btn" class="btn-icon" title="Back">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="15 18 9 12 15 6"></polyline>
          </svg>
        </button>
        <div class="header-title" id="detail-header-title">Detail</div>
      </div>
      <div class="header-right">
        <button id="detail-edit-btn" class="btn-icon" title="Edit Secret">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 20h9"></path>
            <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
          </svg>
        </button>
        <button id="detail-delete-btn" class="btn-icon destructive" title="Delete Secret">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          </svg>
        </button>
      </div>
    </header>

    <div class="entry-scroll-content" id="detail-body"></div>
  `;

  container.querySelector("#detail-back-btn").onclick = onBack;
  container.querySelector("#detail-edit-btn").onclick = () => {
    if (currentEntry) onNavigateEdit(currentEntry);
  };

  container.querySelector("#detail-delete-btn").onclick = () => {
    if (!currentEntry) return;
    showConfirmModal({
      title: "Delete Secret?",
      description: `Are you sure you want to permanently delete "${currentEntry.title}"? This cannot be undone.`,
      confirmText: "Delete",
      confirmDestructive: true,
      onConfirm: async () => {
        try {
          await invokeCommand("delete_entry", { id: currentEntry.id });
          showToast("Secret deleted");
          onDeleted();
        } catch (e) {
          showToast("Failed to delete secret", "error");
        }
      }
    });
  };

  async function loadEntry(id) {
    try {
      currentEntry = await invokeCommand("get_entry", { id });
      renderEntry();
    } catch (e) {
      console.error("Failed to load entry:", e);
      showToast("Secret not found", "error");
      onBack();
    }
  }

  function renderEntry() {
    const body = container.querySelector("#detail-body");
    body.innerHTML = "";
    if (!currentEntry) return;

    const meta = getCategoryMeta(currentEntry.category);
    container.querySelector("#detail-header-title").textContent = currentEntry.title;

    // Header info card
    const headerCard = document.createElement("div");
    headerCard.innerHTML = `
      <div class="entry-meta-header">
        <span class="entry-item-icon" style="background:var(--bg-card);">${meta.icon}</span>
        <div>
          <span class="badge badge-accent">${meta.label}</span>
          <div class="entry-title-display">${currentEntry.title}</div>
        </div>
      </div>
    `;
    body.appendChild(headerCard);

    const f = currentEntry.fields || {};

    // Render by Category
    if (currentEntry.category === "login") {
      if (f.username) body.appendChild(renderSecretField({ label: "Username", value: f.username, isMono: false, maskedByDefault: false }));
      if (f.email) body.appendChild(renderSecretField({ label: "Email", value: f.email, isMono: false, maskedByDefault: false }));
      if (f.password) body.appendChild(renderSecretField({ label: "Password", value: f.password, isMono: true, maskedByDefault: true }));
      if (f.url) body.appendChild(renderSecretField({ label: "Website / URL", value: f.url, isMono: false, maskedByDefault: false }));
      if (f.totp_secret) body.appendChild(renderSecretField({ label: "TOTP Secret Key", value: f.totp_secret, isMono: true, maskedByDefault: true }));
    } else if (currentEntry.category === "api_key") {
      if (f.service) body.appendChild(renderSecretField({ label: "Service", value: f.service, isMono: false, maskedByDefault: false }));
      if (f.key_name) body.appendChild(renderSecretField({ label: "Key Identifier / Name", value: f.key_name, isMono: false, maskedByDefault: false }));
      if (f.key_value) body.appendChild(renderSecretField({ label: "API Key", value: f.key_value, isMono: true, maskedByDefault: true }));
      if (f.secret) body.appendChild(renderSecretField({ label: "API Secret / Token", value: f.secret, isMono: true, maskedByDefault: true }));
      if (f.endpoint) body.appendChild(renderSecretField({ label: "API Endpoint URL", value: f.endpoint, isMono: false, maskedByDefault: false }));
      if (f.expiry) body.appendChild(renderSecretField({ label: "Expiration Date", value: f.expiry, isMono: false, maskedByDefault: false }));
    } else if (currentEntry.category === "seed_phrase") {
      if (f.wallet_name) body.appendChild(renderSecretField({ label: "Wallet Name / Network", value: f.wallet_name, isMono: false, maskedByDefault: false }));
      if (f.words && f.words.length > 0) {
        body.appendChild(renderSeedPhrase({
          words: f.words,
          passphrase: f.passphrase,
          derivationPath: f.derivation_path
        }));
      }
    } else if (currentEntry.category === "recovery_code") {
      if (f.service) body.appendChild(renderSecretField({ label: "Service / Platform", value: f.service, isMono: false, maskedByDefault: false }));
      if (f.code_type) body.appendChild(renderSecretField({ label: "Format / Code Type", value: f.code_type, isMono: false, maskedByDefault: false }));
      if (f.codes) {
        body.appendChild(renderCodeList({
          codes: f.codes,
          entryId: currentEntry.id,
          onToggleCode: async (entryId, index, used) => {
            try {
              await invokeCommand("toggle_code_used", {
                entryId,
                codeIndex: index,
                used
              });
            } catch (err) {
              console.error("Failed to toggle code:", err);
            }
          }
        }));
      }
    } else if (currentEntry.category === "product_key") {
      if (f.software) body.appendChild(renderSecretField({ label: "Software / Game", value: f.software, isMono: false, maskedByDefault: false }));
      if (f.key_value) body.appendChild(renderSecretField({ label: "License / Serial Key", value: f.key_value, isMono: true, maskedByDefault: true }));
      if (f.activation_url) body.appendChild(renderSecretField({ label: "Activation Portal", value: f.activation_url, isMono: false, maskedByDefault: false }));
      if (f.purchase_date) body.appendChild(renderSecretField({ label: "Purchase Date", value: f.purchase_date, isMono: false, maskedByDefault: false }));
      if (f.expiry) body.appendChild(renderSecretField({ label: "Expiration / Maintenance", value: f.expiry, isMono: false, maskedByDefault: false }));
    } else if (currentEntry.category === "secure_note") {
      const noteCard = document.createElement("div");
      noteCard.className = "field-card";
      noteCard.innerHTML = `
        <div class="field-card-header">
          <span class="field-label">Encrypted Note Content</span>
          <button class="btn-icon copy-note-btn" title="Copy note">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
        </div>
        <div class="field-value" style="white-space: pre-wrap; margin-top:6px;">${f.content || ""}</div>
      `;
      noteCard.querySelector(".copy-note-btn").onclick = async () => {
        await copySecret(f.content, "Secure Note");
        showToast("Note content copied");
      };
      body.appendChild(noteCard);
    } else if (currentEntry.category === "ssh_key") {
      if (f.key_name) body.appendChild(renderSecretField({ label: "Key Identifier", value: f.key_name, isMono: false, maskedByDefault: false }));
      if (f.key_type) body.appendChild(renderSecretField({ label: "Algorithm / Type", value: f.key_type, isMono: false, maskedByDefault: false }));
      if (f.private_key) body.appendChild(renderSecretField({ label: "Private Key", value: f.private_key, isMono: true, maskedByDefault: true }));
      if (f.public_key) body.appendChild(renderSecretField({ label: "Public Key", value: f.public_key, isMono: true, maskedByDefault: false }));
      if (f.passphrase) body.appendChild(renderSecretField({ label: "Key Passphrase", value: f.passphrase, isMono: true, maskedByDefault: true }));
      if (f.fingerprint) body.appendChild(renderSecretField({ label: "Fingerprint", value: f.fingerprint, isMono: true, maskedByDefault: false }));
    } else if (currentEntry.category === "wifi_password") {
      if (f.ssid) body.appendChild(renderSecretField({ label: "Network Name (SSID)", value: f.ssid, isMono: false, maskedByDefault: false }));
      if (f.security_type) body.appendChild(renderSecretField({ label: "Security Protocol", value: f.security_type, isMono: false, maskedByDefault: false }));
      if (f.password) body.appendChild(renderSecretField({ label: "Wi-Fi Password", value: f.password, isMono: true, maskedByDefault: true }));
    } else if (currentEntry.category === "payment_card") {
      if (f.cardholder) body.appendChild(renderSecretField({ label: "Cardholder Name", value: f.cardholder, isMono: false, maskedByDefault: false }));
      if (f.card_number) body.appendChild(renderSecretField({ label: "Card Number", value: f.card_number, isMono: true, maskedByDefault: true }));
      if (f.expiry) body.appendChild(renderSecretField({ label: "Expiration (MM/YY)", value: f.expiry, isMono: true, maskedByDefault: false }));
      if (f.cvv) body.appendChild(renderSecretField({ label: "CVV / CVC Code", value: f.cvv, isMono: true, maskedByDefault: true }));
      if (f.billing_address) body.appendChild(renderSecretField({ label: "Billing Address", value: f.billing_address, isMono: false, maskedByDefault: false }));
    } else if (currentEntry.category === "custom") {
      if (f.fields && Array.isArray(f.fields)) {
        f.fields.forEach(cField => {
          body.appendChild(renderSecretField({
            label: cField.label || "Custom Field",
            value: cField.value,
            isMono: !!cField.is_secret,
            maskedByDefault: !!cField.is_secret
          }));
        });
      }
    }

    // Additional Notes Card
    if (currentEntry.notes) {
      const notesCard = document.createElement("div");
      notesCard.className = "field-card";
      notesCard.innerHTML = `
        <span class="field-label">Additional Notes</span>
        <div class="field-value" style="white-space: pre-wrap; margin-top:4px;">${currentEntry.notes}</div>
      `;
      body.appendChild(notesCard);
    }

    // Metadata Footer
    const footer = document.createElement("div");
    footer.style.cssText = "font-size:var(--font-size-xs); color:var(--text-tertiary); text-align:center; padding:12px 0;";
    footer.innerHTML = `
      Updated ${formatRelativeTime(currentEntry.modified_at)} • Created ${formatRelativeTime(currentEntry.created_at)}
    `;
    body.appendChild(footer);
  }

  return {
    loadEntry
  };
}
