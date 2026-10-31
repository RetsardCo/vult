// Helper utilities for Vult
export const CATEGORIES = {
  login: { id: "login", label: "Logins", icon: "🔑", color: "#0A84FF" },
  api_key: { id: "api_key", label: "API Keys", icon: "🔌", color: "#FF9F0A" },
  seed_phrase: { id: "seed_phrase", label: "Seed Phrases", icon: "🌱", color: "#30D158" },
  recovery_code: { id: "recovery_code", label: "Recovery Codes", icon: "🛟", color: "#BF5AF2" },
  product_key: { id: "product_key", label: "Product Keys", icon: "🏷️", color: "#64D2FF" },
  secure_note: { id: "secure_note", label: "Secure Notes", icon: "📝", color: "#FFD60A" },
  ssh_key: { id: "ssh_key", label: "SSH & PGP", icon: "🗝️", color: "#FF375F" },
  wifi_password: { id: "wifi_password", label: "Wi-Fi", icon: "📶", color: "#5E5CE6" },
  payment_card: { id: "payment_card", label: "Cards", icon: "💳", color: "#32D74B" },
  custom: { id: "custom", label: "Custom", icon: "⚙️", color: "#98989F" }
};

export function getCategoryMeta(catId) {
  const norm = (catId || "").toLowerCase().replace(/[\s-]/g, "_");
  return CATEGORIES[norm] || { id: norm, label: catId || "Secret", icon: "🔒", color: "#98989F" };
}

export function formatRelativeTime(dateStr) {
  if (!dateStr) return "";
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  const now = new Date();
  const diffSec = Math.floor((now - d) / 1000);
  if (diffSec < 60) return "Just now";
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;
  if (diffDay < 30) return `${Math.floor(diffDay / 7)}w ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function maskSecret(secret, visibleCount = 0) {
  if (!secret) return "••••••••";
  if (visibleCount <= 0) return "••••••••••••";
  if (secret.length <= visibleCount) return secret;
  const prefix = secret.slice(0, visibleCount);
  return `${prefix}••••••••`;
}

export function calculatePasswordStrength(pwd) {
  if (!pwd) return { score: 0, label: "Empty", percent: 0, class: "weak" };
  let poolSize = 0;
  if (/[a-z]/.test(pwd)) poolSize += 26;
  if (/[A-Z]/.test(pwd)) poolSize += 26;
  if (/[0-9]/.test(pwd)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) poolSize += 33;
  if (poolSize === 0) poolSize = 10;

  const entropy = Math.log2(poolSize) * pwd.length;

  if (entropy < 35 || pwd.length < 8) {
    return { score: 1, label: "Weak", percent: 25, class: "weak" };
  } else if (entropy < 60 || pwd.length < 12) {
    return { score: 2, label: "Fair", percent: 50, class: "fair" };
  } else if (entropy < 85 || pwd.length < 16) {
    return { score: 3, label: "Good", percent: 75, class: "good" };
  } else {
    return { score: 4, label: "Strong", percent: 100, class: "strong" };
  }
}

export function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
