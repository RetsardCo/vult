import { invokeCommand, copySecret } from "../utils/tauri-bridge.js";
import { CATEGORIES, getCategoryMeta, maskSecret } from "../utils/helpers.js";
import { showToast } from "../components/toast.js";

export function initDashboardScreen({
  onNavigateCategory,
  onNavigateDetail,
  onNavigateNew,
  onNavigateGenerator,
  onNavigateSettings,
  onLockVault
}) {
  const container = document.getElementById("screen-dashboard");
  let allEntries = [];

  container.innerHTML = `
    <header class="app-header">
      <div class="header-left">
        <div class="header-title">
          <span class="brand-icon">🔐</span>
          <span>Vult</span>
        </div>
      </div>
      <div class="header-right">
        <button id="dash-gen-btn" class="btn-icon" data-tooltip="Password Generator">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
            <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
            <line x1="12" y1="22.08" x2="12" y2="12"></line>
          </svg>
        </button>
        <button id="dash-settings-btn" class="btn-icon" data-tooltip="Settings & Preferences">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3"></circle>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
          </svg>
        </button>
        <button id="dash-lock-btn" class="btn-icon" data-tooltip="Lock Vault Immediately">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </button>
      </div>
    </header>

    <div class="dashboard-content">
      <div class="search-wrapper">
        <div class="search-icon">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
        </div>
        <input type="text" id="dash-search" class="search-input" placeholder="Search secrets, services, tags...">
        <button id="dash-search-clear" class="search-clear-btn" data-tooltip="Clear search">✕</button>
      </div>

      <div id="dash-categories-section">
        <div class="section-header">
          <span class="section-title">Categories</span>
        </div>
        <div class="category-grid" id="category-grid"></div>
      </div>

      <div id="dash-entries-section">
        <div class="section-header">
          <span class="section-title" id="entries-section-title">Recent Entries</span>
        </div>
        <div class="entry-list" id="entries-list"></div>
      </div>
    </div>

    <button id="dash-fab-btn" class="fab-btn" data-tooltip="Add New Secret">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="12" y1="5" x2="12" y2="19"></line>
        <line x1="5" y1="12" x2="19" y2="12"></line>
      </svg>
    </button>
  `;

  const searchInput = container.querySelector("#dash-search");
  const searchClear = container.querySelector("#dash-search-clear");
  const catGridEl = container.querySelector("#category-grid");
  const entriesListEl = container.querySelector("#entries-list");
  const sectionTitle = container.querySelector("#entries-section-title");
  const categoriesSection = container.querySelector("#dash-categories-section");

  container.querySelector("#dash-gen-btn").onclick = onNavigateGenerator;
  container.querySelector("#dash-settings-btn").onclick = onNavigateSettings;
  container.querySelector("#dash-lock-btn").onclick = onLockVault;
  container.querySelector("#dash-fab-btn").onclick = onNavigateNew;

  searchClear.onclick = () => {
    searchInput.value = "";
    searchClear.classList.remove("visible");
    renderDashboard();
  };

  searchInput.oninput = () => {
    const q = searchInput.value.trim().toLowerCase();
    searchClear.classList.toggle("visible", q.length > 0);
    renderDashboard(q);
  };

  async function loadData() {
    try {
      allEntries = await invokeCommand("get_entries");
      renderDashboard(searchInput.value.trim().toLowerCase());
    } catch (e) {
      console.error("Failed to load entries:", e);
      showToast("Error loading vault entries", "error");
    }
  }

  function renderDashboard(query = "") {
    // 1. Render Categories Grid with dynamic counts
    const catCounts = {};
    for (const key of Object.keys(CATEGORIES)) {
      catCounts[key] = 0;
    }
    allEntries.forEach(e => {
      const cat = (e.category || "").toLowerCase();
      if (catCounts[cat] !== undefined) catCounts[cat]++;
    });

    catGridEl.innerHTML = "";
    for (const [catKey, meta] of Object.entries(CATEGORIES)) {
      const count = catCounts[catKey] || 0;
      const tile = document.createElement("div");
      tile.className = "category-tile";
      tile.innerHTML = `
        <div class="category-tile-left">
          <span class="category-tile-icon">${meta.icon}</span>
          <span class="category-tile-name">${meta.label}</span>
        </div>
        <span class="badge ${count > 0 ? "badge-accent" : ""}">${count}</span>
      `;
      tile.onclick = () => onNavigateCategory(catKey);
      catGridEl.appendChild(tile);
    }

    // 2. Render Entries
    let filtered = allEntries;
    if (query) {
      categoriesSection.style.display = "none";
      sectionTitle.textContent = `Search Results (${query})`;
      filtered = allEntries.filter(e => {
        const titleMatch = (e.title || "").toLowerCase().includes(query);
        const tagsMatch = (e.tags || []).some(t => t.toLowerCase().includes(query));
        const notesMatch = (e.notes || "").toLowerCase().includes(query);
        // check fields string representation
        const fieldsStr = JSON.stringify(e.fields || {}).toLowerCase();
        return titleMatch || tagsMatch || notesMatch || fieldsStr.includes(query);
      });
    } else {
      categoriesSection.style.display = "block";
      sectionTitle.textContent = "Recent Entries";
    }

    entriesListEl.innerHTML = "";
    if (filtered.length === 0) {
      entriesListEl.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">📂</div>
          <div class="empty-state-text">${query ? "No matching secrets found" : "No secrets stored yet. Tap + to add one!"}</div>
        </div>
      `;
      return;
    }

    // Limit to latest 15 if on home without search
    const displayList = query ? filtered : filtered.slice(0, 15);

    displayList.forEach(item => {
      const meta = getCategoryMeta(item.category);
      const row = document.createElement("div");
      row.className = "entry-item";

      // Subtitle detection based on category
      let subtitle = "";
      let primarySecretToCopy = null;

      if (item.fields) {
        if (item.category === "login") {
          subtitle = item.fields.username || item.fields.email || item.fields.url || "";
          primarySecretToCopy = item.fields.password;
        } else if (item.category === "api_key") {
          subtitle = item.fields.service || item.fields.key_name || "";
          primarySecretToCopy = item.fields.key_value;
        } else if (item.category === "seed_phrase") {
          const count = item.fields.words ? item.fields.words.length : 0;
          subtitle = `${count} words mnemonic`;
          primarySecretToCopy = (item.fields.words || []).join(" ");
        } else if (item.category === "recovery_code") {
          const codes = item.fields.codes || [];
          const remaining = codes.filter(c => !c.used).length;
          subtitle = `${remaining}/${codes.length} remaining`;
          primarySecretToCopy = codes.filter(c => !c.used).map(c => c.code).join("\n");
        } else if (item.category === "product_key") {
          subtitle = item.fields.software || "";
          primarySecretToCopy = item.fields.key_value;
        } else if (item.category === "wifi_password") {
          subtitle = item.fields.ssid || "";
          primarySecretToCopy = item.fields.password;
        } else if (item.category === "payment_card") {
          subtitle = item.fields.cardholder || "";
          primarySecretToCopy = item.fields.card_number;
        } else if (item.category === "ssh_key") {
          subtitle = item.fields.key_type || "";
          primarySecretToCopy = item.fields.private_key;
        } else {
          subtitle = item.notes || "";
        }
      }

      row.innerHTML = `
        <div class="entry-item-left">
          <div class="entry-item-icon">${meta.icon}</div>
          <div class="entry-item-info">
            <div class="entry-item-title">${item.title}</div>
            <div class="entry-item-sub">${subtitle || meta.label}</div>
          </div>
        </div>
        <div class="entry-item-actions">
          ${primarySecretToCopy ? `
            <button class="btn-icon copy-quick-btn" data-tooltip="Copy to Clipboard">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
            </button>
          ` : ""}
        </div>
      `;

      row.querySelector(".entry-item-left").onclick = () => onNavigateDetail(item.id);

      const copyBtn = row.querySelector(".copy-quick-btn");
      if (copyBtn && primarySecretToCopy) {
        copyBtn.onclick = async (ev) => {
          ev.stopPropagation();
          await copySecret(primarySecretToCopy, item.title);
          showToast(`Copied secret for ${item.title}`);
        };
      }

      entriesListEl.appendChild(row);
    });
  }

  return {
    loadData
  };
}
