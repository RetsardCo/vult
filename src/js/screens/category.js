import { invokeCommand, copySecret } from "../utils/tauri-bridge.js";
import { getCategoryMeta } from "../utils/helpers.js";
import { showToast } from "../components/toast.js";

export function initCategoryScreen({
  onBack,
  onNavigateDetail,
  onNavigateNew
}) {
  const container = document.getElementById("screen-category");
  let currentCategory = "";
  let categoryEntries = [];

  container.innerHTML = `
    <header class="app-header">
      <div class="header-left">
        <button id="cat-back-btn" class="btn-icon" data-tooltip="Back to Dashboard">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="15 18 9 12 15 6"></polyline>
          </svg>
        </button>
        <div class="header-title" id="cat-header-title">
          <span id="cat-header-icon">📂</span>
          <span id="cat-header-text">Category</span>
        </div>
      </div>
      <div class="header-right">
        <button id="cat-add-btn" class="btn-icon" data-tooltip="Add New Secret to Category">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <line x1="12" y1="5" x2="12" y2="19"></line>
            <line x1="5" y1="12" x2="19" y2="12"></line>
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
        <input type="text" id="cat-search" class="search-input" placeholder="Search in this category...">
      </div>

      <div class="entry-list" id="cat-entries-list"></div>
    </div>
  `;

  container.querySelector("#cat-back-btn").onclick = onBack;
  container.querySelector("#cat-add-btn").onclick = () => onNavigateNew(currentCategory);

  const searchInput = container.querySelector("#cat-search");
  const entriesListEl = container.querySelector("#cat-entries-list");
  const headerIcon = container.querySelector("#cat-header-icon");
  const headerText = container.querySelector("#cat-header-text");

  searchInput.oninput = () => {
    renderList(searchInput.value.trim().toLowerCase());
  };

  async function loadCategory(catKey) {
    currentCategory = catKey;
    const meta = getCategoryMeta(catKey);
    headerIcon.textContent = meta.icon;
    headerText.textContent = meta.label;
    searchInput.value = "";

    try {
      categoryEntries = await invokeCommand("get_entries", { category: catKey });
      renderList();
    } catch (e) {
      console.error("Failed to load category entries:", e);
      showToast("Error loading category", "error");
    }
  }

  function renderList(query = "") {
    entriesListEl.innerHTML = "";
    const filtered = categoryEntries.filter(e => {
      if (!query) return true;
      const titleMatch = (e.title || "").toLowerCase().includes(query);
      const tagsMatch = (e.tags || []).some(t => t.toLowerCase().includes(query));
      const strMatch = JSON.stringify(e.fields || {}).toLowerCase().includes(query);
      return titleMatch || tagsMatch || strMatch;
    });

    if (filtered.length === 0) {
      entriesListEl.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">📭</div>
          <div class="empty-state-text">No entries in this category</div>
        </div>
      `;
      return;
    }

    filtered.forEach(item => {
      const meta = getCategoryMeta(item.category);
      const row = document.createElement("div");
      row.className = "entry-item";

      let subtitle = "";
      if (item.category === "recovery_code" && item.fields && item.fields.codes) {
        const remaining = item.fields.codes.filter(c => !c.used).length;
        subtitle = `${remaining} / ${item.fields.codes.length} remaining`;
      } else if (item.category === "login" && item.fields) {
        subtitle = item.fields.username || item.fields.email || "";
      } else if (item.category === "seed_phrase" && item.fields) {
        subtitle = `${item.fields.words?.length || 0} words`;
      } else {
        subtitle = item.notes || "";
      }

      row.innerHTML = `
        <div class="entry-item-left">
          <div class="entry-item-icon">${meta.icon}</div>
          <div class="entry-item-info">
            <div class="entry-item-title">${item.title}</div>
            <div class="entry-item-sub">${subtitle}</div>
          </div>
        </div>
        <div class="entry-item-actions">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color:var(--text-tertiary);">
            <polyline points="9 18 15 12 9 6"></polyline>
          </svg>
        </div>
      `;

      row.onclick = () => onNavigateDetail(item.id);
      entriesListEl.appendChild(row);
    });
  }

  return {
    loadCategory
  };
}
