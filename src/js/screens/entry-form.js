import { invokeCommand } from "../utils/tauri-bridge.js";
import { CATEGORIES, getCategoryMeta } from "../utils/helpers.js";
import { showToast } from "../components/toast.js";

export function initEntryFormScreen({
  onBack,
  onSaved,
  onOpenGenerator
}) {
  const container = document.getElementById("screen-entry-form");
  let editEntryId = null;
  let selectedCategory = null;
  let customFieldsList = [];
  let existingCodesMap = new Map();
  let existingEntryFields = {};

  container.innerHTML = `
    <header class="app-header">
      <div class="header-left">
        <button id="form-back-btn" class="btn-icon" data-tooltip="Cancel and Go Back">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="15 18 9 12 15 6"></polyline>
          </svg>
        </button>
        <div class="header-title" id="form-header-title">Add Secret</div>
      </div>
      <div class="header-right">
        <button id="form-save-btn" class="btn btn-primary btn-sm" data-tooltip="Save Secret to Vault">Save</button>
      </div>
    </header>

    <div id="form-type-picker" class="type-picker-grid" style="display:none;"></div>
    <div id="form-fields-container" class="entry-scroll-content" style="display:none;"></div>
  `;

  const typePicker = container.querySelector("#form-type-picker");
  const fieldsContainer = container.querySelector("#form-fields-container");
  const headerTitle = container.querySelector("#form-header-title");
  const saveBtn = container.querySelector("#form-save-btn");

  container.querySelector("#form-back-btn").onclick = onBack;

  function renderTypePicker() {
    typePicker.innerHTML = `
      <div style="font-size:var(--font-size-xs); font-weight:700; text-transform:uppercase; color:var(--text-secondary); margin-bottom:4px;">
        Choose Secret Category
      </div>
    `;
    typePicker.style.display = "flex";
    fieldsContainer.style.display = "none";
    headerTitle.textContent = "Select Category";
    saveBtn.style.display = "none";

    for (const [key, meta] of Object.entries(CATEGORIES)) {
      const card = document.createElement("div");
      card.className = "type-picker-card";
      card.innerHTML = `
        <div class="type-picker-icon">${meta.icon}</div>
        <div class="type-picker-info">
          <div class="type-picker-title">${meta.label}</div>
        </div>
      `;
      card.onclick = () => {
        setupFormForCategory(key);
      };
      typePicker.appendChild(card);
    }
  }

  function setupNew(preselectedCategory = null) {
    editEntryId = null;
    existingCodesMap.clear();
    existingEntryFields = {};
    customFieldsList = [{ label: "Key", value: "", is_secret: false }];
    if (preselectedCategory && CATEGORIES[preselectedCategory]) {
      setupFormForCategory(preselectedCategory);
    } else {
      renderTypePicker();
    }
  }

  function setupEdit(entry) {
    editEntryId = entry.id;
    selectedCategory = entry.category;
    existingCodesMap.clear();
    existingEntryFields = entry.fields || {};
    if (entry.category === "recovery_code" && Array.isArray(entry.fields?.codes)) {
      entry.fields.codes.forEach(c => {
        if (c && c.code) existingCodesMap.set(c.code.trim(), !!c.used);
      });
    }
    customFieldsList = entry.category === "custom" && entry.fields?.fields 
      ? JSON.parse(JSON.stringify(entry.fields.fields)) 
      : [{ label: "Key", value: "", is_secret: false }];
    setupFormForCategory(entry.category, entry);
  }

  function setupFormForCategory(catKey, existingEntry = null) {
    selectedCategory = catKey;
    const meta = getCategoryMeta(catKey);
    typePicker.style.display = "none";
    fieldsContainer.style.display = "flex";
    saveBtn.style.display = "inline-flex";
    headerTitle.textContent = existingEntry ? `Edit ${meta.label}` : `New ${meta.label}`;

    const ef = existingEntry?.fields || {};
    const titleVal = existingEntry?.title || "";
    const notesVal = existingEntry?.notes || "";

    let specificHtml = "";

    if (catKey === "login") {
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Username</label>
          <input type="text" id="f-username" class="input-text" placeholder="e.g. john_doe" value="${ef.username || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Email</label>
          <input type="email" id="f-email" class="input-text" placeholder="name@example.com" value="${ef.email || ""}">
        </div>
        <div class="form-group">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <label class="form-label">Password</label>
            <button type="button" class="btn-ghost btn-sm" id="gen-pwd-quick-btn" style="color:var(--accent); font-size:11px; padding:2px 6px;">
              ⚡ Generate
            </button>
          </div>
          <div class="password-input-group">
            <input type="password" id="f-password" class="input-text input-mono" placeholder="Password" value="${ef.password || ""}">
            <button type="button" class="password-toggle-btn" id="toggle-pwd-btn">👁</button>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Website URL</label>
          <input type="text" id="f-url" class="input-text" placeholder="https://example.com" value="${ef.url || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">TOTP Secret / Setup Key (Optional)</label>
          <input type="text" id="f-totp" class="input-text input-mono" placeholder="Base32 Key (e.g. JBSWY3DPEHPK3PXP)" value="${ef.totp_secret || ""}">
        </div>
      `;
    } else if (catKey === "api_key") {
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Service / Provider</label>
          <input type="text" id="f-service" class="input-text" placeholder="e.g. OpenAI, Stripe, AWS" value="${ef.service || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Key Name / Identifier</label>
          <input type="text" id="f-key-name" class="input-text" placeholder="e.g. Production Key, Server-1" value="${ef.key_name || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">API Key / Token Value</label>
          <input type="text" id="f-key-value" class="input-text input-mono" placeholder="sk-..." value="${ef.key_value || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">API Secret (Optional)</label>
          <input type="password" id="f-secret" class="input-text input-mono" placeholder="Secret / Private Key" value="${ef.secret || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Endpoint URL (Optional)</label>
          <input type="text" id="f-endpoint" class="input-text" placeholder="https://api.example.com/v1" value="${ef.endpoint || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Expiry Date (Optional)</label>
          <input type="text" id="f-expiry" class="input-text" placeholder="YYYY-MM-DD" value="${ef.expiry || ""}">
        </div>
      `;
    } else if (catKey === "seed_phrase") {
      const wordsText = ef.words ? ef.words.join(" ") : "";
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Wallet / Blockchain</label>
          <input type="text" id="f-wallet" class="input-text" placeholder="e.g. MetaMask, Ledger, Solana" value="${ef.wallet_name || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Recovery Words (12 or 24 words separated by space)</label>
          <textarea id="f-words" class="input-textarea input-mono" placeholder="word1 word2 word3 ... word12">${wordsText}</textarea>
        </div>
        <div class="form-group">
          <label class="form-label">Passphrase / 13th Word (Optional)</label>
          <input type="password" id="f-passphrase" class="input-text input-mono" placeholder="Optional extra passphrase" value="${ef.passphrase || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Derivation Path (Optional)</label>
          <input type="text" id="f-derivation" class="input-text input-mono" placeholder="m/44'/60'/0'/0/0" value="${ef.derivation_path || ""}">
        </div>
      `;
    } else if (catKey === "recovery_code") {
      const codesText = ef.codes ? ef.codes.map(c => c.code).join("\n") : "";
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Service / Platform</label>
          <input type="text" id="f-service" class="input-text" placeholder="e.g. Discord, GitHub, Google" value="${ef.service || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Code Format / Type</label>
          <input type="text" id="f-code-type" class="input-text" placeholder="e.g. 2FA Backup Codes (xxxx-xxxx)" value="${ef.code_type || "2FA Backup Codes"}">
        </div>
        <div class="form-group">
          <label class="form-label">Codes (Paste one per line)</label>
          <textarea id="f-codes" class="input-textarea input-mono" placeholder="2dj4-xbtz\n39wa-j5w2\n...">${codesText}</textarea>
        </div>
      `;
    } else if (catKey === "product_key") {
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Software / Product Name</label>
          <input type="text" id="f-software" class="input-text" placeholder="e.g. Windows 11 Pro, JetBrains, Ableton" value="${ef.software || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">License / Serial Key</label>
          <input type="text" id="f-key-value" class="input-text input-mono" placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX" value="${ef.key_value || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Activation Portal / URL</label>
          <input type="text" id="f-activation" class="input-text" placeholder="https://..." value="${ef.activation_url || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Purchase Date</label>
          <input type="text" id="f-purchase" class="input-text" placeholder="YYYY-MM-DD" value="${ef.purchase_date || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Expiry / Renewal</label>
          <input type="text" id="f-expiry" class="input-text" placeholder="Lifetime or YYYY-MM-DD" value="${ef.expiry || ""}">
        </div>
      `;
    } else if (catKey === "secure_note") {
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Encrypted Note Body</label>
          <textarea id="f-content" class="input-textarea" style="min-height:160px;" placeholder="Write sensitive notes, codes, instructions...">${ef.content || ""}</textarea>
        </div>
      `;
    } else if (catKey === "ssh_key") {
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Key Name / Identifier</label>
          <input type="text" id="f-key-name" class="input-text" placeholder="e.g. id_ed25519_prod" value="${ef.key_name || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Key Type</label>
          <input type="text" id="f-key-type" class="input-text" placeholder="e.g. Ed25519, RSA 4096" value="${ef.key_type || "Ed25519"}">
        </div>
        <div class="form-group">
          <label class="form-label">Private Key</label>
          <textarea id="f-private-key" class="input-textarea input-mono" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----...">${ef.private_key || ""}</textarea>
        </div>
        <div class="form-group">
          <label class="form-label">Public Key (Optional)</label>
          <textarea id="f-public-key" class="input-textarea input-mono" placeholder="ssh-ed25519 AAAAC3NzaC1...">${ef.public_key || ""}</textarea>
        </div>
        <div class="form-group">
          <label class="form-label">Passphrase (Optional)</label>
          <input type="password" id="f-passphrase" class="input-text input-mono" placeholder="Key Passphrase" value="${ef.passphrase || ""}">
        </div>
      `;
    } else if (catKey === "wifi_password") {
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Network Name (SSID)</label>
          <input type="text" id="f-ssid" class="input-text" placeholder="Home-WiFi-5G" value="${ef.ssid || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Security Type</label>
          <select id="f-security" class="input-select">
            <option value="WPA3-Personal" ${ef.security_type === "WPA3-Personal" ? "selected" : ""}>WPA3-Personal</option>
            <option value="WPA2-Personal" ${ef.security_type === "WPA2-Personal" || !ef.security_type ? "selected" : ""}>WPA2-Personal</option>
            <option value="WPA/WPA2 Enterprise" ${ef.security_type === "WPA/WPA2 Enterprise" ? "selected" : ""}>WPA/WPA2 Enterprise</option>
            <option value="WEP" ${ef.security_type === "WEP" ? "selected" : ""}>WEP</option>
            <option value="Open" ${ef.security_type === "Open" ? "selected" : ""}>Open (No password)</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Wi-Fi Password</label>
          <input type="password" id="f-password" class="input-text input-mono" placeholder="Network password" value="${ef.password || ""}">
        </div>
      `;
    } else if (catKey === "payment_card") {
      specificHtml = `
        <div class="form-group">
          <label class="form-label">Cardholder Name</label>
          <input type="text" id="f-cardholder" class="input-text" placeholder="JOHN DOE" value="${ef.cardholder || ""}">
        </div>
        <div class="form-group">
          <label class="form-label">Card Number</label>
          <input type="text" id="f-card-number" class="input-text input-mono" placeholder="4111 2222 3333 4444" value="${ef.card_number || ""}">
        </div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px;">
          <div class="form-group">
            <label class="form-label">Expiry (MM/YY)</label>
            <input type="text" id="f-expiry" class="input-text input-mono" placeholder="12/28" value="${ef.expiry || ""}">
          </div>
          <div class="form-group">
            <label class="form-label">CVV / CVC</label>
            <input type="password" id="f-cvv" class="input-text input-mono" placeholder="123" maxlength="4" value="${ef.cvv || ""}">
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Billing Address (Optional)</label>
          <input type="text" id="f-billing" class="input-text" placeholder="123 Main St..." value="${ef.billing_address || ""}">
        </div>
      `;
    } else if (catKey === "custom") {
      specificHtml = `
        <div class="form-group">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
            <label class="form-label" style="margin-bottom:0;">Custom Fields</label>
            <button type="button" class="btn-ghost btn-sm" id="add-custom-field-btn" style="color:var(--accent);">+ Add Field</button>
          </div>
          <div id="custom-fields-rows"></div>
        </div>
      `;
    }

    fieldsContainer.innerHTML = `
      <div class="form-group">
        <label class="form-label">Title / Name *</label>
        <input type="text" id="f-title" class="input-text" placeholder="e.g. My Secret Item" value="${titleVal}">
      </div>

      ${specificHtml}

      <div class="form-group">
        <label class="form-label">Tags (comma-separated)</label>
        <input type="text" id="f-tags" class="input-text" placeholder="work, personal, crypto" value="${(existingEntry?.tags || []).join(", ")}">
      </div>

      <div class="form-group">
        <label class="form-label">Notes (Optional)</label>
        <textarea id="f-notes" class="input-textarea" placeholder="Additional details...">${notesVal}</textarea>
      </div>
    `;

    // Hook up password generator quick button
    const quickGen = fieldsContainer.querySelector("#gen-pwd-quick-btn");
    if (quickGen) {
      quickGen.onclick = () => {
        onOpenGenerator((generatedPassword) => {
          const pwdField = fieldsContainer.querySelector("#f-password");
          if (pwdField) pwdField.value = generatedPassword;
        });
      };
    }

    // Hook up eye toggle
    const toggleEye = fieldsContainer.querySelector("#toggle-pwd-btn");
    if (toggleEye) {
      toggleEye.onclick = () => {
        const pwdField = fieldsContainer.querySelector("#f-password");
        if (pwdField) {
          pwdField.type = pwdField.type === "password" ? "text" : "password";
        }
      };
    }

    // Hook up custom fields list
    if (catKey === "custom") {
      const rowsContainer = fieldsContainer.querySelector("#custom-fields-rows");
      const addFieldBtn = fieldsContainer.querySelector("#add-custom-field-btn");

      function renderCustomRows() {
        rowsContainer.innerHTML = "";
        customFieldsList.forEach((cField, idx) => {
          const row = document.createElement("div");
          row.className = "custom-field-row";
          row.innerHTML = `
            <input type="text" class="input-text c-label" placeholder="Label" value="${cField.label}" style="width:30%;">
            <input type="${cField.is_secret ? "password" : "text"}" class="input-text c-value" placeholder="Value" value="${cField.value}" style="width:45%;">
            <label style="display:flex; align-items:center; gap:2px; font-size:11px; color:var(--text-secondary); cursor:pointer;">
              <input type="checkbox" class="c-secret" ${cField.is_secret ? "checked" : ""}> Secret
            </label>
            <button type="button" class="btn-icon c-del" title="Remove" style="width:24px; height:24px;">✕</button>
          `;

          row.querySelector(".c-label").oninput = (e) => { cField.label = e.target.value; };
          row.querySelector(".c-value").oninput = (e) => { cField.value = e.target.value; };
          row.querySelector(".c-secret").onchange = (e) => {
            cField.is_secret = e.target.checked;
            row.querySelector(".c-value").type = cField.is_secret ? "password" : "text";
          };
          row.querySelector(".c-del").onclick = () => {
            customFieldsList.splice(idx, 1);
            renderCustomRows();
          };
          rowsContainer.appendChild(row);
        });
      }

      renderCustomRows();

      addFieldBtn.onclick = () => {
        customFieldsList.push({ label: "", value: "", is_secret: false });
        renderCustomRows();
      };
    }
  }

  saveBtn.onclick = async () => {
    const title = fieldsContainer.querySelector("#f-title")?.value.trim();
    if (!title) {
      showToast("Please enter a title", "error");
      return;
    }

    const tagsVal = fieldsContainer.querySelector("#f-tags")?.value.trim();
    const tags = tagsVal ? tagsVal.split(",").map(t => t.trim()).filter(Boolean) : [];
    const notes = fieldsContainer.querySelector("#f-notes")?.value.trim() || null;

    let fields = {};

    if (selectedCategory === "login") {
      fields = {
        username: fieldsContainer.querySelector("#f-username")?.value.trim() || null,
        email: fieldsContainer.querySelector("#f-email")?.value.trim() || null,
        password: fieldsContainer.querySelector("#f-password")?.value || "",
        url: fieldsContainer.querySelector("#f-url")?.value.trim() || null,
        totp_secret: fieldsContainer.querySelector("#f-totp")?.value.trim() || null
      };
    } else if (selectedCategory === "api_key") {
      fields = {
        service: fieldsContainer.querySelector("#f-service")?.value.trim() || "",
        key_name: fieldsContainer.querySelector("#f-key-name")?.value.trim() || "",
        key_value: fieldsContainer.querySelector("#f-key-value")?.value.trim() || "",
        secret: fieldsContainer.querySelector("#f-secret")?.value.trim() || null,
        endpoint: fieldsContainer.querySelector("#f-endpoint")?.value.trim() || null,
        expiry: fieldsContainer.querySelector("#f-expiry")?.value.trim() || null
      };
    } else if (selectedCategory === "seed_phrase") {
      const wordsStr = fieldsContainer.querySelector("#f-words")?.value.trim() || "";
      const words = wordsStr.split(/\s+/).filter(Boolean);
      fields = {
        wallet_name: fieldsContainer.querySelector("#f-wallet")?.value.trim() || "",
        words,
        passphrase: fieldsContainer.querySelector("#f-passphrase")?.value || null,
        derivation_path: fieldsContainer.querySelector("#f-derivation")?.value.trim() || null
      };
    } else if (selectedCategory === "recovery_code") {
      const rawCodes = fieldsContainer.querySelector("#f-codes")?.value.trim() || "";
      const codeList = rawCodes.split("\n")
        .map(c => c.trim())
        .filter(Boolean)
        .map(code => ({
          code,
          used: existingCodesMap.has(code) ? existingCodesMap.get(code) : false
        }));
      fields = {
        service: fieldsContainer.querySelector("#f-service")?.value.trim() || "",
        code_type: fieldsContainer.querySelector("#f-code-type")?.value.trim() || "2FA Backup Codes",
        codes: codeList
      };
    } else if (selectedCategory === "product_key") {
      fields = {
        software: fieldsContainer.querySelector("#f-software")?.value.trim() || "",
        key_value: fieldsContainer.querySelector("#f-key-value")?.value.trim() || "",
        activation_url: fieldsContainer.querySelector("#f-activation")?.value.trim() || null,
        purchase_date: fieldsContainer.querySelector("#f-purchase")?.value.trim() || null,
        expiry: fieldsContainer.querySelector("#f-expiry")?.value.trim() || null
      };
    } else if (selectedCategory === "secure_note") {
      fields = {
        title,
        content: fieldsContainer.querySelector("#f-content")?.value || ""
      };
    } else if (selectedCategory === "ssh_key") {
      fields = {
        key_name: fieldsContainer.querySelector("#f-key-name")?.value.trim() || "",
        key_type: fieldsContainer.querySelector("#f-key-type")?.value.trim() || "Ed25519",
        private_key: fieldsContainer.querySelector("#f-private-key")?.value || "",
        public_key: fieldsContainer.querySelector("#f-public-key")?.value || null,
        passphrase: fieldsContainer.querySelector("#f-passphrase")?.value || null,
        fingerprint: existingEntryFields?.fingerprint || null
      };
    } else if (selectedCategory === "wifi_password") {
      fields = {
        ssid: fieldsContainer.querySelector("#f-ssid")?.value.trim() || "",
        security_type: fieldsContainer.querySelector("#f-security")?.value || "WPA2-Personal",
        password: fieldsContainer.querySelector("#f-password")?.value || ""
      };
    } else if (selectedCategory === "payment_card") {
      fields = {
        cardholder: fieldsContainer.querySelector("#f-cardholder")?.value.trim() || "",
        card_number: fieldsContainer.querySelector("#f-card-number")?.value.trim() || "",
        expiry: fieldsContainer.querySelector("#f-expiry")?.value.trim() || "",
        cvv: fieldsContainer.querySelector("#f-cvv")?.value.trim() || "",
        billing_address: fieldsContainer.querySelector("#f-billing")?.value.trim() || null
      };
    } else if (selectedCategory === "custom") {
      fields = {
        title,
        fields: customFieldsList.filter(f => f.label || f.value)
      };
    }

    const payload = {
      id: editEntryId || "",
      category: selectedCategory,
      title,
      fields,
      notes,
      tags,
      favorite: false
    };

    try {
      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      if (editEntryId) {
        await invokeCommand("update_entry", { entry: payload });
        showToast("Secret updated");
      } else {
        await invokeCommand("add_entry", { entry: payload });
        showToast("Secret saved to vault");
      }
      onSaved(editEntryId);
    } catch (err) {
      showToast(typeof err === "string" ? err : "Failed to save entry", "error");
      saveBtn.disabled = false;
      saveBtn.textContent = "Save";
    }
  };

  return {
    setupNew,
    setupEdit
  };
}
