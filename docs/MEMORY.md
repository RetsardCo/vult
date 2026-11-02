# Project Memory, Architectural Decisions & Bug Log — Vult

**Product**: Vult  
**Maintainer**: Kurados  
**Last Updated**: 2026-11-03  

---

## 1. Project Context & Philosophy

Vult was conceived as a reaction against bloated, cloud-dependent password managers that charge recurring subscriptions and expose master credentials to remote server breaches. The core mandate of Vult is **local-first sovereignty, zero telemetry, military-grade cryptography, and high-performance desktop ergonomics** (consuming <35MB RAM in a fixed 400×620px window).

---

## 2. Key Architectural Decisions (ADR)

### ADR-01: Authenticated Encryption with AES-256-GCM & Argon2id
- **Decision**: Vault storage uses `AES-256-GCM` with a 96-bit unique nonce and Argon2id key derivation.
- **Rationale**: AES-GCM provides both confidentiality and authentication. Any disk tampering or bit-flipping causes decryption to fail outright before any bytes are parsed. Argon2id protects against specialized GPU/FPGA/ASIC password cracking attacks.
- **Parameters**: 64 MiB RAM cost, 3 iterations, 4 parallelism lanes.

### ADR-02: Length-Prefixed Composite Key Framing
- **Problem**: When using `PIN + Password` mode, naive string concatenation (`PIN + Password`) introduces ambiguity (e.g. PIN `12` + Password `34` yields `1234`, identical to PIN `1` + Password `234`).
- **Solution**: Inputs are unambiguously length-prefixed:
  $$\text{KeyMaterial} = \text{SHA-256}(\text{len}(\text{PIN}) \parallel \text{PIN} \parallel \text{len}(\text{Password}) \parallel \text{Password})$$

### ADR-03: Windows DPAPI for Biometric Credentials
- **Decision**: When Windows Hello is enabled, the biometric unlock token is protected via the Windows Data Protection API (`CryptProtectData`) with custom entropy.
- **Rationale**: Prevents storing secrets in plaintext configuration files while leveraging Windows hardware-backed TPM security.

### ADR-04: Elimination of Native Browser Prompts (`window.prompt`)
- **Problem**: Chromium/WebView2 `window.prompt()` renders an unstyled host dialog (`127.0.0.1:1430 says...`) that breaks immersion and prevents styled validation.
- **Solution**: Completely replaced with in-DOM macOS-inspired dark frosted glass modals (`src/js/components/modal.js`).

### ADR-05: Web-Safe Symbol Sanitization in Password Generator
- **Problem**: The password generator included characters like `|`, `[ ]`, `{ }`, `:`, `;`, `<`, `>`, `,`, which cause input validation errors on banking, government, and corporate websites.
- **Solution**: Constrained generated symbols to universal, high-compatibility web-safe characters:
  ```javascript
  let syms = "!@#$%^&*()-_=+";
  ```
  Accepted universally across 99.9% of web forms without triggering invalid character rejections.

---

## 3. Bug Fixes & Hardening History

| Date | Issue / Bug | Root Cause | Resolution |
|:---|:---|:---|:---|
| **2026-10-31** | Dynamic PIN length discrepancy on unlock | Frontend hardcoded 6 dots while user had a 4 or 8 digit PIN. | Implemented dynamic PIN length tracking persisted in `AuthSettings.pin_length`. |
| **2026-11-01** | "Saving..." button hanging indefinitely | Uncaught validation error in entry form caused promise rejection without resetting button state. | Added comprehensive try/catch/finally block resetting button text and re-enabling clicks. |
| **2026-11-01** | Logo integration & glow styling | Legacy padlock icon used instead of new custom branding. | Integrated `src/assets/logo.png` seated inside dark-blue glowing squircle container across lock screen, settings, and window title bar. |
| **2026-11-02** | Premature validation on Enter key in modals | Pressing Enter on first input submitted the form before the confirm field was typed. | Added smart Enter navigation: advances focus to confirm input if empty, submits only when both fields are filled. |
| **2026-11-02** | Export backup file path ambiguity | Browser blob download silently saved to `Downloads/`. | Integrated native Windows File Explorer Save As dialog via `rfd` crate in Rust backend. |
| **2026-11-03** | Missing developer attribution in Settings | About box contained only version and description. | Added **"Developed by Kurados"** credit and updated about card with the official glowing app logo. |

---

## 4. Git Release & Baseline Status

- **Tag**: `v1.0.0` (commit `c65c9b0`)
- **Stable Backup Branch**: `v1.0.0-stable` (pushed to `origin/v1.0.0-stable`)
- **Active Development Branch**: `main`
- **Test Status**:
  - Rust Backend: 39 tests passing, 0 failures (`cargo test`).
  - Frontend Code Detector: 21 tests passing, 0 failures (`node tests/test-code-detector.mjs`).
