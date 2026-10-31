/**
 * Universal Recovery Code Format Identification & Extraction Engine
 * Automatically classifies backup/recovery codes from various services (Google, Discord, GitHub, Steam, Apple, Microsoft, etc.)
 */

export const CODE_FORMAT_PRESETS = [
  { id: "google", label: "Google 2FA Backup Codes (8 digits)", service: "Google" },
  { id: "discord", label: "Discord Backup Codes (xxxx-xxxx)", service: "Discord" },
  { id: "github", label: "GitHub Recovery Codes (xxxxx-xxxxx)", service: "GitHub" },
  { id: "github_legacy", label: "GitHub Legacy Recovery (10 chars)", service: "GitHub" },
  { id: "unity", label: "Unity Recovery Codes (8 digits)", service: "Unity" },
  { id: "steam", label: "Steam Guard Recovery Code (R#####)", service: "Steam" },
  { id: "twitter", label: "Twitter / X Backup Code (12 chars)", service: "Twitter / X" },
  { id: "apple", label: "Apple Recovery Key (28 chars)", service: "Apple" },
  { id: "microsoft", label: "Microsoft Recovery Key (25 chars)", service: "Microsoft" },
  { id: "totp", label: "TOTP Secret / Setup Key (Base32)", service: "Authenticator" },
  { id: "bip39", label: "BIP-39 Seed Phrase (12/24 words)", service: "Crypto Wallet" },
  { id: "uuid", label: "API Token / License UUID", service: "API / Service" },
  { id: "generic", label: "2FA Backup Codes (Generic)", service: "2FA Service" },
  { id: "other", label: "Other / Custom Format", service: "" }
];

/**
 * Clean a single line of pasted code, stripping prefixes like:
 * - "1. ", "2) ", "[1] ", "(1) "
 * - bullets "* ", "- ", "• ", "> "
 * - markdown checkboxes "[ ] ", "[x] "
 */
export function cleanCodeLine(raw) {
  if (!raw || typeof raw !== "string") return "";
  let line = raw.trim();
  // Strip list prefixes, numbering, bullet points, markdown checkboxes
  line = line.replace(/^(?:(?:\d+[\.\)\:\-]|\[[\s\dxX]*\]|\(\d+\)|[\*\-\•\–\—\>])\s*)+/, "").trim();
  return line;
}

/**
 * Extract clean individual codes from pasted multi-line, multi-column, or numbered text.
 */
export function extractCodes(rawText) {
  if (!rawText || typeof rawText !== "string") return [];
  const lines = rawText.split(/\r?\n/);
  const results = [];

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;

    // Check if line contains multiple column items e.g. "1. 1481 9401    6. 8301 9284"
    // Split by tabs or multiple spaces (>= 2 spaces) when followed by numbering or code pattern
    const parts = trimmed.split(/\t+|\s{2,}(?=(?:\d+[\.\)\:\-]|\[\d+\]|[a-zA-Z0-9]{4,}))/);

    for (const part of parts) {
      const cleaned = cleanCodeLine(part);
      if (cleaned) {
        // Skip obvious header/instruction lines
        if (/^(?:save|keep|these|your|backup|recovery|codes|security|download|print|remaining)\b/i.test(cleaned) && cleaned.split(/\s+/).length > 3) {
          continue;
        }
        results.push(cleaned);
      }
    }
  }

  return results;
}

/**
 * Analyze extracted codes and automatically identify their format/service.
 * Returns classification details, suggested service, badge text, and cleaned codes.
 */
export function detectCodeType(rawText) {
  const codes = extractCodes(rawText);

  if (codes.length === 0) {
    return {
      typeId: "generic",
      label: "2FA Backup Codes",
      suggestedService: "",
      hasCodes: false,
      count: 0,
      badgeText: "",
      cleanedCodes: []
    };
  }

  // 1. Check BIP-39 Seed Phrase (12, 15, 18, 21, or 24 space-separated words)
  const fullText = codes.join(" ").trim();
  const words = fullText.split(/\s+/).filter(Boolean);
  if ([12, 15, 18, 21, 24].includes(words.length) && words.every(w => /^[a-z]+$/i.test(w))) {
    return {
      typeId: "bip39",
      label: "BIP-39 Crypto Seed Phrase",
      suggestedService: "Crypto Wallet",
      hasCodes: true,
      count: words.length,
      badgeText: `✨ Detected: BIP-39 Seed Phrase (${words.length} words)`,
      cleanedCodes: [words.join(" ")]
    };
  }

  // Single code special signatures
  if (codes.length === 1) {
    const single = codes[0];
    const noSpaces = single.replace(/\s+/g, "");

    // Steam Guard: R##### or R-#####
    if (/^R-?[a-zA-Z0-9]{5}$/i.test(single)) {
      return {
        typeId: "steam",
        label: "Steam Guard Recovery Code",
        suggestedService: "Steam",
        hasCodes: true,
        count: 1,
        badgeText: "✨ Detected: Steam Guard Recovery Code (1 code)",
        cleanedCodes: [single.toUpperCase()]
      };
    }

    // Apple Recovery Key: 28 characters (7 groups of 4 separated by hyphens)
    if (/^[a-zA-Z0-9]{4}(?:-[a-zA-Z0-9]{4}){6}$/i.test(single)) {
      return {
        typeId: "apple",
        label: "Apple Recovery Key",
        suggestedService: "Apple",
        hasCodes: true,
        count: 1,
        badgeText: "✨ Detected: Apple Recovery Key (28 chars)",
        cleanedCodes: [single.toUpperCase()]
      };
    }

    // Microsoft Recovery / Product Key: 25 characters (5 groups of 5 separated by hyphens)
    if (/^[a-zA-Z0-9]{5}(?:-[a-zA-Z0-9]{5}){4}$/i.test(single)) {
      return {
        typeId: "microsoft",
        label: "Microsoft Recovery Key",
        suggestedService: "Microsoft",
        hasCodes: true,
        count: 1,
        badgeText: "✨ Detected: Microsoft Recovery Key (25 chars)",
        cleanedCodes: [single.toUpperCase()]
      };
    }

    // Standard UUID: 8-4-4-4-12 hex characters
    if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/i.test(single)) {
      return {
        typeId: "uuid",
        label: "API Token / License UUID",
        suggestedService: "API / License",
        hasCodes: true,
        count: 1,
        badgeText: "✨ Detected: API Token / License UUID",
        cleanedCodes: [single]
      };
    }

    // Twitter / X Backup Code: 12 continuous alphanumeric characters
    if (/^[a-zA-Z0-9]{12}$/i.test(single)) {
      return {
        typeId: "twitter",
        label: "Twitter / X Backup Code",
        suggestedService: "Twitter / X",
        hasCodes: true,
        count: 1,
        badgeText: "✨ Detected: Twitter / X Backup Code (12 chars)",
        cleanedCodes: [single]
      };
    }

    // TOTP Secret / Setup Key: 16, 24, 26, or 32 Base32 characters (A-Z, 2-7)
    if (/^(?:[A-Z2-7]{16}|[A-Z2-7]{24}|[A-Z2-7]{26}|[A-Z2-7]{32})$/i.test(noSpaces)) {
      return {
        typeId: "totp",
        label: "TOTP Secret / Setup Key",
        suggestedService: "Authenticator",
        hasCodes: true,
        count: 1,
        badgeText: `✨ Detected: TOTP Secret Key (${noSpaces.length}-char Base32)`,
        cleanedCodes: [noSpaces.toUpperCase()]
      };
    }
  }

  // Multi-code signatures: test each code format across sample
  const sample = codes.slice(0, 10);

  // Helper: check if all sample codes match a regex
  const allMatch = (regex) => sample.every(c => regex.test(c));

  // 2. Discord Backup Codes: xxxx-xxxx (4 alphanumeric - 4 alphanumeric)
  // e.g. 2dj4-xbtz, bbv0-2h6e
  if (allMatch(/^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$/i)) {
    return {
      typeId: "discord",
      label: "Discord Backup Codes",
      suggestedService: "Discord",
      hasCodes: true,
      count: codes.length,
      badgeText: `✨ Detected: Discord Backup Codes (${codes.length} code${codes.length === 1 ? "" : "s"})`,
      cleanedCodes: codes.map(c => c.toLowerCase())
    };
  }

  // 3. GitHub Recovery Codes: xxxxx-xxxxx (5 alphanumeric - 5 alphanumeric)
  // e.g. a1b2c-d3e4f
  if (allMatch(/^[a-zA-Z0-9]{5}-[a-zA-Z0-9]{5}$/i)) {
    return {
      typeId: "github",
      label: "GitHub Recovery Codes",
      suggestedService: "GitHub",
      hasCodes: true,
      count: codes.length,
      badgeText: `✨ Detected: GitHub Recovery Codes (${codes.length} code${codes.length === 1 ? "" : "s"})`,
      cleanedCodes: codes.map(c => c.toLowerCase())
    };
  }

  // 4. GitHub Legacy Recovery Codes: 10 continuous alphanumeric characters
  // e.g. a1b2c3d4e5
  if (allMatch(/^[a-zA-Z0-9]{10}$/i)) {
    return {
      typeId: "github_legacy",
      label: "GitHub Legacy Recovery",
      suggestedService: "GitHub",
      hasCodes: true,
      count: codes.length,
      badgeText: `✨ Detected: GitHub Legacy Recovery (${codes.length} code${codes.length === 1 ? "" : "s"})`,
      cleanedCodes: codes.map(c => c.toLowerCase())
    };
  }

  // 5. 8-digit formats: Google vs Unity
  // Google: "1481 9401" (paired 4-4 digits) or continuous 8 digits "14819401"
  // Unity: continuous 8 digits "99605153", exactly 5 codes
  const isGooglePaired = allMatch(/^\d{4}\s\d{4}$/);
  const isContinuous8Digits = allMatch(/^\d{8}$/);

  if (isGooglePaired || isContinuous8Digits) {
    // If formatted with space between 4-4 digits, it is Google
    // If continuous 8 digits and count is 5, it is Unity Recovery Codes
    if (isContinuous8Digits && codes.length === 5) {
      return {
        typeId: "unity",
        label: "Unity Recovery Codes",
        suggestedService: "Unity",
        hasCodes: true,
        count: codes.length,
        badgeText: `✨ Detected: Unity Recovery Codes (5 codes)`,
        cleanedCodes: codes
      };
    }

    // Otherwise, it is Google 2FA Backup Codes (or generic 8-digit)
    // Normalize to readable "#### ####" format if space was present, or preserve clean digits
    const cleaned = codes.map(c => {
      const digits = c.replace(/\s+/g, "");
      return digits.length === 8 ? `${digits.slice(0, 4)} ${digits.slice(4)}` : c;
    });

    return {
      typeId: "google",
      label: "Google 2FA Backup Codes",
      suggestedService: "Google",
      hasCodes: true,
      count: codes.length,
      badgeText: `✨ Detected: Google 2FA Backup Codes (${codes.length} code${codes.length === 1 ? "" : "s"})`,
      cleanedCodes: cleaned
    };
  }

  // 6. Twitter / X backup codes (12 continuous alphanumeric, typically 1 or 2 codes)
  if (allMatch(/^[a-zA-Z0-9]{12}$/i)) {
    return {
      typeId: "twitter",
      label: "Twitter / X Backup Code",
      suggestedService: "Twitter / X",
      hasCodes: true,
      count: codes.length,
      badgeText: `✨ Detected: Twitter / X Backup Codes (${codes.length} code${codes.length === 1 ? "" : "s"})`,
      cleanedCodes: codes
    };
  }

  // 7. Generic 2FA Backup codes (e.g. 6-16 characters without spaces)
  if (allMatch(/^[a-zA-Z0-9\-_]{6,20}$/)) {
    return {
      typeId: "generic",
      label: "2FA Backup Codes",
      suggestedService: "",
      hasCodes: true,
      count: codes.length,
      badgeText: `✨ Detected: 2FA Backup Codes (${codes.length} code${codes.length === 1 ? "" : "s"})`,
      cleanedCodes: codes
    };
  }

  // 8. Fallback to "Other / Custom"
  return {
    typeId: "other",
    label: "Other (Custom Code)",
    suggestedService: "",
    hasCodes: true,
    count: codes.length,
    badgeText: `✨ Custom Format (${codes.length} item${codes.length === 1 ? "" : "s"})`,
    cleanedCodes: codes
  };
}
