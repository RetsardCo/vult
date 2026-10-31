/**
 * Universal Recovery Code Format Identification & Extraction Engine
 * Automatically classifies backup/recovery codes from various services (Google, Discord, GitHub, Steam, Apple, Microsoft, etc.)
 */

export const CODE_FORMAT_PRESETS = [
  { id: "google", label: "Google 2FA Backup Codes", service: "Google" },
  { id: "unity", label: "Unity Recovery Codes", service: "Unity" },
  { id: "discord", label: "Discord Backup Codes", service: "Discord" },
  { id: "github", label: "GitHub Recovery Codes", service: "GitHub" },
  { id: "github_legacy", label: "GitHub Legacy Recovery", service: "GitHub" },
  { id: "steam", label: "Steam Guard Recovery Code", service: "Steam" },
  { id: "twitter", label: "Twitter / X Backup Code", service: "Twitter / X" },
  { id: "apple", label: "Apple Recovery Key", service: "Apple" },
  { id: "microsoft", label: "Microsoft Recovery Key", service: "Microsoft" },
  { id: "totp", label: "TOTP Secret / Setup Key", service: "Authenticator" },
  { id: "bip39", label: "BIP-39 Seed Phrase", service: "Crypto Wallet" },
  { id: "uuid", label: "API Token / License UUID", service: "API / License" },
  { id: "generic", label: "2FA Backup Codes", service: "2FA Service" },
  { id: "other", label: "Other / Custom", service: "" }
];

/**
 * Clean a single line of pasted code, stripping prefixes like:
 * - "1. ", "2) ", "[1] ", "(1) "
 * - bullets "* ", "- ", "• ", "> "
 * - markdown checkboxes "[ ] ", "[x] "
 * and normalizing internal whitespace/hyphenation for known segmented formats.
 */
export function cleanCodeLine(raw) {
  if (!raw || typeof raw !== "string") return "";
  let line = raw.trim();
  // Strip list prefixes, numbering, bullet points, markdown checkboxes
  line = line.replace(/^(?:(?:\d+[\.\)\:\-]|\[[\s\dxX]*\]|\(\d+\)|[\*\-\•\–\—\>])\s*)+/, "").trim();

  // Strip internal whitespace for segmented code signatures:
  // 1. Google 2FA: two 4-digit groups (e.g. "1481 9401" or "1481-9401" -> "14819401")
  if (/^\d{4}[\s\-]+\d{4}$/.test(line)) {
    return line.replace(/[\s\-]+/g, "");
  }

  // 2. Discord: two 4-char alphanumeric groups separated by space -> convert to "xxxx-xxxx"
  if (/^[a-zA-Z0-9]{4}\s+[a-zA-Z0-9]{4}$/.test(line)) {
    return line.replace(/\s+/, "-").toLowerCase();
  }

  // 3. GitHub: two 5-char alphanumeric groups separated by space -> convert to "xxxxx-xxxxx"
  if (/^[a-zA-Z0-9]{5}\s+[a-zA-Z0-9]{5}$/.test(line)) {
    return line.replace(/\s+/, "-").toLowerCase();
  }

  // 4. Apple: 7 groups of 4 separated by space or hyphen -> "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
  if (/^[a-zA-Z0-9]{4}(?:[\s\-][a-zA-Z0-9]{4}){6}$/.test(line)) {
    return line.replace(/[\s\-]+/g, "-").toUpperCase();
  }

  // 5. Microsoft: 5 groups of 5 separated by space or hyphen -> "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
  if (/^[a-zA-Z0-9]{5}(?:[\s\-][a-zA-Z0-9]{5}){4}$/.test(line)) {
    return line.replace(/[\s\-]+/g, "-").toUpperCase();
  }

  // 6. Steam Guard: R + 5 chars (e.g. "r 12345", "r-12345", "r12345")
  if (/^r[\s\-]?[a-zA-Z0-9]{5}$/i.test(line)) {
    return line.replace(/[\s\-]+/, "").toUpperCase();
  }

  // 7. TOTP: Base32 with spaces (16, 24, 26, 32 chars)
  const noSpace = line.replace(/\s+/g, "");
  if (/^(?:[A-Za-z2-7]{16}|[A-Za-z2-7]{24}|[A-Za-z2-7]{26}|[A-Za-z2-7]{32})$/.test(noSpace) && line.includes(" ")) {
    return noSpace.toUpperCase();
  }

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

    // Split on tabs, 2+ spaces before list numbering/bullets, or 3+ spaces before another code chunk
    const parts = trimmed.split(/\t+|\s{2,}(?=(?:\d+[\.\)\:\-]|\[\d+\]|\(\d+\)|[\*\-\•])\s*)|(?<=\S)\s{3,}(?=[a-zA-Z0-9])/);

    for (const part of parts) {
      const cleaned = cleanCodeLine(part);
      if (cleaned) {
        // Skip obvious header/instruction lines
        if (/^(?:save|keep|these|your|backup|recovery|codes|security|download|print|remaining|generated)\b/i.test(cleaned) && cleaned.split(/\s+/).length > 3) {
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
export function detectCodeType(rawText, serviceContext = "") {
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

  const sCtx = (serviceContext || "").trim().toLowerCase();
  const sample = codes.slice(0, 16);
  const allMatch = (regex) => sample.every(c => regex.test(c));

  // 1. Check BIP-39 Seed Phrase: 12, 15, 18, 21, or 24 space-separated words (3-8 letters each)
  const singlePhraseWords = rawText.trim().replace(/^(?:(?:\d+[\.\)\:\-]|\[\d+\])\s*)+/gm, "").split(/\s+/).filter(Boolean);
  if ([12, 15, 18, 21, 24].includes(singlePhraseWords.length) && 
      singlePhraseWords.every(w => /^[a-z]{3,8}$/i.test(w)) &&
      !allMatch(/^[a-zA-Z0-9]{10}$/)) {
    return {
      typeId: "bip39",
      label: "BIP-39 Seed Phrase",
      suggestedService: "Crypto Wallet",
      hasCodes: true,
      count: singlePhraseWords.length,
      badgeText: `✨ Detected: BIP-39 Seed Phrase (${singlePhraseWords.length} words)`,
      cleanedCodes: [singlePhraseWords.map(w => w.toLowerCase()).join(" ")]
    };
  }

  // Single code special signatures
  if (codes.length === 1) {
    const single = codes[0];
    const noSpaces = single.replace(/\s+/g, "");

    // Steam Guard: R##### or R-#####
    if (/^R-?[a-zA-Z0-9]{5}$/i.test(single)) {
      const steamCode = single.toUpperCase().replace(/\s+/, "");
      return {
        typeId: "steam",
        label: "Steam Guard Recovery Code",
        suggestedService: "Steam",
        hasCodes: true,
        count: 1,
        badgeText: "✨ Detected: Steam Guard Recovery Code (1 code)",
        cleanedCodes: [steamCode]
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
        cleanedCodes: [single.toLowerCase()]
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
        cleanedCodes: [single.toLowerCase()]
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
  // Google: 8 digits (often pasted as "1481 9401" with internal space, or 10 count)
  // Unity: continuous 8 digits "99605153", typical count 5
  const isAll8Digits = allMatch(/^\d{8}$/);
  if (isAll8Digits) {
    const hadPairedSpaces = /\b\d{4}\s+\d{4}\b/.test(rawText);
    const isGoogleService = sCtx.includes("google");
    const isUnityService = sCtx.includes("unity");

    if (!isGoogleService && (isUnityService || (!hadPairedSpaces && codes.length === 5))) {
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

    return {
      typeId: "google",
      label: "Google 2FA Backup Codes",
      suggestedService: "Google",
      hasCodes: true,
      count: codes.length,
      badgeText: `✨ Detected: Google 2FA Backup Codes (${codes.length} code${codes.length === 1 ? "" : "s"})`,
      cleanedCodes: codes
    };
  }

  // 6. Twitter / X backup codes (12 continuous alphanumeric)
  if (allMatch(/^[a-zA-Z0-9]{12}$/i)) {
    return {
      typeId: "twitter",
      label: "Twitter / X Backup Code",
      suggestedService: "Twitter / X",
      hasCodes: true,
      count: codes.length,
      badgeText: `✨ Detected: Twitter / X Backup Codes (${codes.length} code${codes.length === 1 ? "" : "s"})`,
      cleanedCodes: codes.map(c => c.toLowerCase())
    };
  }

  // 7. Generic 2FA Backup codes (e.g. 6-20 characters without spaces)
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
