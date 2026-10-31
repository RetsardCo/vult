import { initLockScreen } from "./screens/lock.js";
import { initDashboardScreen } from "./screens/dashboard.js";
import { initCategoryScreen } from "./screens/category.js";
import { initEntryDetailScreen } from "./screens/entry-detail.js";
import { initEntryFormScreen } from "./screens/entry-form.js";
import { initGeneratorScreen } from "./screens/generator.js";
import { initSettingsScreen } from "./screens/settings.js";
import { invokeCommand } from "./utils/tauri-bridge.js";

class VultApp {
  constructor() {
    this.currentScreen = null;
    this.screens = {};
    this.autoLockTimer = null;
    this.autoLockMinutes = 5;
    this.lastActivity = Date.now();
  }

  init() {
    // Collect screen elements
    this.screens = {
      lock: document.getElementById("screen-lock"),
      dashboard: document.getElementById("screen-dashboard"),
      category: document.getElementById("screen-category"),
      detail: document.getElementById("screen-entry-detail"),
      form: document.getElementById("screen-entry-form"),
      generator: document.getElementById("screen-generator"),
      settings: document.getElementById("screen-settings")
    };

    // Initialize individual screen controllers
    this.lockCtrl = initLockScreen({
      onUnlocked: () => this.handleUnlock()
    });

    this.dashCtrl = initDashboardScreen({
      onNavigateCategory: (catKey) => {
        this.catCtrl.loadCategory(catKey);
        this.showScreen("category");
      },
      onNavigateDetail: (id) => {
        this.detailCtrl.loadEntry(id);
        this.showScreen("detail");
      },
      onNavigateNew: (catKey) => {
        this.formCtrl.setupNew(catKey);
        this.showScreen("form");
      },
      onNavigateGenerator: () => {
        this.genCtrl.open();
        this.showScreen("generator");
      },
      onNavigateSettings: () => {
        this.settingsCtrl.loadSettings();
        this.showScreen("settings");
      },
      onLockVault: () => this.lockVault()
    });

    this.catCtrl = initCategoryScreen({
      onBack: () => this.showScreen("dashboard"),
      onNavigateDetail: (id) => {
        this.detailCtrl.loadEntry(id);
        this.showScreen("detail");
      },
      onNavigateNew: (catKey) => {
        this.formCtrl.setupNew(catKey);
        this.showScreen("form");
      }
    });

    this.detailCtrl = initEntryDetailScreen({
      onBack: () => this.showScreen("dashboard"),
      onNavigateEdit: (entry) => {
        this.formCtrl.setupEdit(entry);
        this.showScreen("form");
      },
      onDeleted: () => {
        this.dashCtrl.loadData();
        this.showScreen("dashboard");
      }
    });

    this.formCtrl = initEntryFormScreen({
      onBack: () => this.showScreen("dashboard"),
      onSaved: (entryId) => {
        this.dashCtrl.loadData();
        if (entryId) {
          this.detailCtrl.loadEntry(entryId);
          this.showScreen("detail");
        } else {
          this.showScreen("dashboard");
        }
      },
      onOpenGenerator: (cb) => {
        this.genCtrl.open(cb);
        this.showScreen("generator");
      }
    });

    this.genCtrl = initGeneratorScreen({
      onBack: () => this.showScreen(this.previousScreen || "dashboard")
    });

    this.settingsCtrl = initSettingsScreen({
      onBack: () => this.showScreen("dashboard"),
      onVaultWiped: () => {
        this.showScreen("lock");
        this.lockCtrl.reset();
      },
      onLockVault: () => this.lockVault(),
      onSettingsUpdated: (newSettings) => {
        if (newSettings && newSettings.auto_lock_minutes !== undefined) {
          this.autoLockMinutes = newSettings.auto_lock_minutes;
        }
      }
    });

    // Start on lock screen
    this.showScreen("lock");
    this.lockCtrl.checkStatus();

    // Setup activity tracking for auto-lock
    this.setupActivityListeners();
  }

  showScreen(name) {
    if (this.currentScreen && this.currentScreen !== name) {
      this.previousScreen = this.currentScreen;
    }
    for (const [key, el] of Object.entries(this.screens)) {
      if (el) {
        if (key === name) {
          el.classList.add("active");
        } else {
          el.classList.remove("active");
        }
      }
    }
    this.currentScreen = name;
  }

  async handleUnlock() {
    try {
      const settings = await invokeCommand("get_auth_settings");
      this.autoLockMinutes = settings.auto_lock_minutes ?? 5;
    } catch (_) {}
    this.resetAutoLockTimer();
    this.dashCtrl.loadData();
    this.showScreen("dashboard");
  }

  async lockVault() {
    try {
      await invokeCommand("lock_vault");
    } catch (_) {}
    if (this.autoLockTimer) clearInterval(this.autoLockTimer);
    this.showScreen("lock");
    this.lockCtrl.reset();
  }

  setupActivityListeners() {
    const recordActivity = () => {
      this.lastActivity = Date.now();
    };

    window.addEventListener("mousemove", recordActivity, { passive: true });
    window.addEventListener("mousedown", recordActivity, { passive: true });
    window.addEventListener("keydown", recordActivity, { passive: true });
    window.addEventListener("touchstart", recordActivity, { passive: true });

    // Periodic check every 10 seconds
    setInterval(() => {
      if (this.currentScreen === "lock") return;
      if (!this.autoLockMinutes || this.autoLockMinutes <= 0) return;

      const elapsedMs = Date.now() - this.lastActivity;
      if (elapsedMs >= this.autoLockMinutes * 60 * 1000) {
        console.log("[Auto-Lock] Inactivity detected, locking vault...");
        this.lockVault();
      }
    }, 10000);
  }

  resetAutoLockTimer() {
    this.lastActivity = Date.now();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const app = new VultApp();
  app.init();
});
