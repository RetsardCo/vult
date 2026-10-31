import assert from "node:assert/strict";
import { cleanCodeLine, extractCodes, detectCodeType } from "../src/js/utils/code-detector.js";

console.log("Running Code Detector Tests...");

// 1. cleanCodeLine tests
assert.equal(cleanCodeLine("1.  1481 9401"), "1481 9401");
assert.equal(cleanCodeLine("2) 3068 8178"), "3068 8178");
assert.equal(cleanCodeLine("* 1336 5337"), "1336 5337");
assert.equal(cleanCodeLine("- 1940 5972"), "1940 5972");
assert.equal(cleanCodeLine("• 6810 3956"), "6810 3956");
assert.equal(cleanCodeLine("[1] 2dj4-xbtz"), "2dj4-xbtz");
assert.equal(cleanCodeLine("[x] a1b2c-d3e4f"), "a1b2c-d3e4f");
assert.equal(cleanCodeLine("(3) R12345"), "R12345");
console.log("✓ cleanCodeLine passed");

// 2. extractCodes multi-column & numbered lists
const googlePaste = `
1.  1481 9401
2.  3068 8178
3.  1336 5337
4.  1940 5972
5.  6810 3956
`;
const extractedGoogle = extractCodes(googlePaste);
assert.equal(extractedGoogle.length, 5);
assert.equal(extractedGoogle[0], "1481 9401");
assert.equal(extractedGoogle[4], "6810 3956");
console.log("✓ extractCodes for Google list passed");

// 2b. Two-column Google paste
const twoColumnGoogle = `
1. 1481 9401\t6. 8301 9284
2. 3068 8178\t7. 9920 1823
3. 1336 5337\t8. 4829 1049
4. 1940 5972\t9. 5501 9284
5. 6810 3956\t10. 1290 4819
`;
const extractedTwoCol = extractCodes(twoColumnGoogle);
assert.equal(extractedTwoCol.length, 10);
assert.equal(extractedTwoCol[0], "1481 9401");
assert.equal(extractedTwoCol[1], "8301 9284");
assert.equal(extractedTwoCol[9], "1290 4819");
console.log("✓ extractCodes for two-column Google list passed");

// 3. detectCodeType - Google 2FA (with space)
const detGoogle = detectCodeType(googlePaste);
assert.equal(detGoogle.typeId, "google");
assert.equal(detGoogle.suggestedService, "Google");
assert.equal(detGoogle.count, 5);
assert.ok(detGoogle.badgeText.includes("Google 2FA Backup Codes"));
console.log("✓ detectCodeType: Google 2FA (5 codes) passed");

// 3b. detectCodeType - Google 2FA (10 codes continuous)
const googleContinuous10 = `
14829051
83019284
99201823
48291049
55019284
12904819
39201948
59201948
10294819
49102948
`;
const detGoogle10 = detectCodeType(googleContinuous10);
assert.equal(detGoogle10.typeId, "google");
assert.equal(detGoogle10.suggestedService, "Google");
assert.equal(detGoogle10.count, 10);
console.log("✓ detectCodeType: Google 2FA (10 codes) passed");

// 4. detectCodeType - Unity (8 continuous digits, 5 codes)
const unityCodes = `
99605153
31095372
82910492
10294819
59201948
`;
const detUnity = detectCodeType(unityCodes);
assert.equal(detUnity.typeId, "unity");
assert.equal(detUnity.suggestedService, "Unity");
assert.equal(detUnity.count, 5);
assert.ok(detUnity.badgeText.includes("Unity Recovery Codes"));
console.log("✓ detectCodeType: Unity Recovery Codes passed");

// 5. detectCodeType - Discord (4-4 hyphenated, 10 codes)
const discordCodes = `
2dj4-xbtz
bbv0-2h6e
39wa-j5w2
k92m-pp01
m29x-49wa
q19z-091a
z091-m29a
a910-k192
bb91-m192
991a-zz01
`;
const detDiscord = detectCodeType(discordCodes);
assert.equal(detDiscord.typeId, "discord");
assert.equal(detDiscord.suggestedService, "Discord");
assert.equal(detDiscord.count, 10);
assert.ok(detDiscord.badgeText.includes("Discord Backup Codes"));
console.log("✓ detectCodeType: Discord Backup Codes passed");

// 6. detectCodeType - GitHub (5-5 hyphenated, 16 codes)
const githubCodes = Array.from({ length: 16 }, (_, i) => `a${i}b2c-d3e4f`).join("\n");
const detGithub = detectCodeType(githubCodes);
assert.equal(detGithub.typeId, "github");
assert.equal(detGithub.suggestedService, "GitHub");
assert.equal(detGithub.count, 16);
assert.ok(detGithub.badgeText.includes("GitHub Recovery Codes"));
console.log("✓ detectCodeType: GitHub Recovery Codes passed");

// 7. detectCodeType - GitHub Legacy (10 chars, 16 codes)
const githubLegacy = Array.from({ length: 16 }, (_, i) => `a1b2c3d4e${i.toString(16)}`).join("\n");
const detGithubLegacy = detectCodeType(githubLegacy);
assert.equal(detGithubLegacy.typeId, "github_legacy");
assert.equal(detGithubLegacy.suggestedService, "GitHub");
assert.equal(detGithubLegacy.count, 16);
assert.ok(detGithubLegacy.badgeText.includes("GitHub Legacy Recovery"));
console.log("✓ detectCodeType: GitHub Legacy Recovery passed");

// 8. detectCodeType - Steam Guard
const detSteam = detectCodeType("R12345");
assert.equal(detSteam.typeId, "steam");
assert.equal(detSteam.suggestedService, "Steam");
assert.ok(detSteam.badgeText.includes("Steam Guard"));

const detSteamHyphen = detectCodeType("R-ABCDE");
assert.equal(detSteamHyphen.typeId, "steam");
console.log("✓ detectCodeType: Steam Guard passed");

// 9. detectCodeType - Twitter / X (12 chars)
const detTwitter = detectCodeType("a1b2c3d4e5f6");
assert.equal(detTwitter.typeId, "twitter");
assert.equal(detTwitter.suggestedService, "Twitter / X");
console.log("✓ detectCodeType: Twitter / X passed");

// 10. detectCodeType - Apple Recovery Key (28 chars, 7x4)
const detApple = detectCodeType("ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12");
assert.equal(detApple.typeId, "apple");
assert.equal(detApple.suggestedService, "Apple");
assert.ok(detApple.badgeText.includes("Apple Recovery Key"));
console.log("✓ detectCodeType: Apple Recovery Key passed");

// 11. detectCodeType - Microsoft Key (25 chars, 5x5)
const detMs = detectCodeType("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");
assert.equal(detMs.typeId, "microsoft");
assert.equal(detMs.suggestedService, "Microsoft");
assert.ok(detMs.badgeText.includes("Microsoft Recovery Key"));
console.log("✓ detectCodeType: Microsoft Recovery Key passed");

// 12. detectCodeType - TOTP Secret (Base32)
const detTotp = detectCodeType("JBSWY3DPEHPK3PXP");
assert.equal(detTotp.typeId, "totp");
assert.equal(detTotp.suggestedService, "Authenticator");
console.log("✓ detectCodeType: TOTP Secret passed");

// 13. detectCodeType - BIP-39 Seed Phrase (12 words)
const seedPhrase = "witch collapse practice feed shame open despair creek road again ice track";
const detSeed = detectCodeType(seedPhrase);
assert.equal(detSeed.typeId, "bip39");
assert.equal(detSeed.suggestedService, "Crypto Wallet");
assert.equal(detSeed.count, 12);
console.log("✓ detectCodeType: BIP-39 Seed Phrase passed");

// 14. detectCodeType - UUID
const detUuid = detectCodeType("123e4567-e89b-12d3-a456-426614174000");
assert.equal(detUuid.typeId, "uuid");
assert.ok(detUuid.badgeText.includes("UUID"));
console.log("✓ detectCodeType: UUID passed");

// 15. detectCodeType - Other / Custom
const detCustom = detectCodeType("MY-CUSTOM-COMPANY-VPN-PASSCODE");
assert.equal(detCustom.typeId, "other");
assert.ok(detCustom.badgeText.includes("Custom Format"));
console.log("✓ detectCodeType: Other / Custom passed");

// 16. Empty input
const detEmpty = detectCodeType("");
assert.equal(detEmpty.hasCodes, false);
assert.equal(detEmpty.count, 0);
console.log("✓ detectCodeType: Empty input passed");

console.log("\nALL CODE DETECTOR TESTS PASSED SUCCESSFULLY! 🎉");
