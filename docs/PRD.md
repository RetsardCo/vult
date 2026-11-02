# Product Requirements Document (PRD) — Vult

**Product**: Vult (Version 1.0.0 Stable $\rightarrow$ 2.0.0 Roadmap)  
**Author**: Kurados  
**Platform Target**: Windows Desktop (Tauri v2 + Rust) & Android Mobile (Tauri v2 Mobile)  
**Status**: Living Architecture Specification & Implementation Blueprint  

---

## 1. Executive Summary & Product Vision

**Vult** is an offline-first, zero-cloud personal secret manager and digital fortress engineered for developers, sysadmins, security researchers, and privacy purists. Unlike commercial password managers (1Password, Bitwarden, LastPass) that force vault data into centralized cloud silos, Vult guarantees absolute data sovereignty: **zero analytics, zero external network requests, zero telemetry, and zero subscription models**.

Vult protects sensitive digital credentials—passwords, 2FA recovery code batches, API tokens, crypto seed phrases, SSH credentials, and server keys—using military-grade authenticated encryption (**AES-256-GCM**) and memory-hard key derivation (**Argon2id**), paired with hardware-bound OS protection (Windows DPAPI, Windows Hello biometric unlock, and Android Keystore / BiometricPrompt).

---

## 2. Problem Statement & Market Opportunity

| Competitor Weakness | Market Reality | The Vult Advantage |
|:---|:---|:---|
| **Cloud Vault Breaches** | LastPass, Okta, and cloud sync vaults are major attack targets. Cloud breaches expose master salts and metadata. | **100% Offline Vault**: Vult has no server. Ciphertext files (`.vult`) reside strictly on the user's local disk, inaccessible remotely. |
| **Neglected 2FA Recovery Codes** | Most password managers store 2FA backup codes as raw, unformatted notes. When users lose a device, finding and tracking used codes is error-prone and stressful. | **2FA Recovery Code Lifeboat**: Native strike-through consumption tracking, remaining count indicators, auto-format detection (Google, Discord, GitHub, Steam), and low-code exhaustion warnings. |
| **No Plausible Deniability** | If coerced by border authorities, attackers, or corporate audits to unlock a vault, cloud managers display all secrets. | **Duress Vault / Decoy Mode**: A secondary PIN unlocks an authentic decoy vault with harmless accounts, while leaving the genuine vault hidden and mathematically untraceable. |
| **Bloated Desktop Apps** | Electron-based managers consume 300MB–800MB RAM with sluggish cold starts. | **Native Lightweight Architecture**: Tauri v2 + Rust backend consumes <35MB RAM, launches in milliseconds, and fits in a compact 400×620px window. |
| **Clipboard Snooping Malware** | Infostealers on Windows monitor the OS clipboard indefinitely for copied passwords. | **Disposable Clipboard & Ghost Typing**: Auto-wipe after customizable intervals, paste-once zero-trace mode, and direct keystroke OS injection bypassing the clipboard entirely. |

---

## 3. User Personas

1. **The Software Engineer / DevOps Lead ("Alex")**
   - *Needs*: Fast access to GitHub/AWS recovery codes, Stripe/OpenAI API keys, and server passwords.
   - *Pain point*: Dislikes pasting plaintext secrets into `.env` files or relying on cloud password managers that can be locked out during SSO outages.
   - *Vult Usage*: Uses Vult's Developer Profiles to export `.env` snippets and uses the Recovery Code Lifeboat for CI/CD emergency tokens.

2. **The Privacy Advocate / Crypto Custodian ("Elena")**
   - *Needs*: High-security storage for BIP-39 seed phrases, hardware wallet pin codes, and email backup codes.
   - *Pain point*: Refuses to trust any service connected to the Internet with root keys.
   - *Vult Usage*: Relies on Vult's zero-telemetry guarantee, Argon2id encryption, local encrypted USB backup exports, and Duress Mode for travel.

3. **The Everyday Power User ("Marcus")**
   - *Needs*: A clean, beautiful, fast desktop password manager that doesn't nag for subscriptions or internet access.
   - *Pain point*: Annoyed by ugly web popups, complicated browser extensions, and heavy apps.
   - *Vult Usage*: Loves the compact 400×620 floating window, Windows Hello biometric unlock, and one-click password generation.

---

## 4. Current State: Version 1.0.0 Feature Baseline

The current baseline is permanently locked and tagged at `v1.0.0` (backed up to GitHub branch `v1.0.0-stable`):

- **Three Authentication Modes**:
  - `PIN + Password` (Composite key derivation: `Argon2id(Salt, SHA-256(PIN || Password))`)
  - `Password Only` (Standard high-entropy passphrase)
  - `PIN Only` (4–8 digit numeric PIN with dynamic length detection)
- **Biometric Integration**: Windows Hello / TPM hardware-backed token storage via Windows DPAPI (`CryptProtectData`).
- **Comprehensive Secret Taxonomy**: 10 distinct categories with custom metadata models:
  1. *Passwords & Logins*
  2. *2FA Recovery & Backup Codes*
  3. *Credit & Debit Cards*
  4. *Crypto Seed Phrases (BIP-39)*
  5. *Secure Notes*
  6. *Software License Keys*
  7. *API & Secret Tokens*
  8. *SSH Passphrases & Keys*
  9. *Bank & Financial Accounts*
  10. *Identity & Documents*
- **Smart Code Auto-Detection Engine**: Automatically identifies 12+ recovery code formats upon pasting (Discord, Google, GitHub, Steam, Apple, Microsoft, BIP-39, UUID, etc.) and falls back to "Other/Custom".
- **Cryptographic Password Generator**: Cryptographically secure random generation (`window.crypto.getRandomValues`) with universal web-safe symbol sanitization (`!@#$%^&*()-_=+`).
- **Native Windows Save As Dialog**: Encrypted `.vult` exports prompt native Windows File Explorer (`rfd`) with automatic extension verification.
- **macOS Frosted Glass Dark UI**: Compact 400×620 non-resizable window, glassmorphism, zero browser `window.prompt` popups, and smooth transitions.

---

## 5. Version 2.0.0: Unique Selling Propositions (USP) & New Features

### Feature 1: The Definitive 2FA Recovery Code Lifeboat
- **One-Click Strike-Through**: Clicking a recovery code marks it as used, strikethrough styling (`~~code~~`), updating the remaining count indicator (e.g. `2 of 10 remaining`).
- **Depletion Alerts**: When remaining codes fall $\le 2$, a high-visibility amber warning alerts the user to generate a fresh batch.
- **Regeneration Batching**: Ability to replace an exhausted code set with a fresh batch while preserving historical consumption audit timestamps.

### Feature 2: Duress Vault / Decoy Mode (Plausible Deniability)
- **Dual Secret Provisioning**: When enabled in Settings, the user defines a secondary "Duress PIN" (e.g., Primary PIN `8492`, Duress PIN `1234`).
- **Isolated Storage**: Unlocking with the Duress PIN decrypts a completely separate `decoy_vault.vult` populated with harmless dummy accounts.
- **Zero Leakage**: The genuine vault file remains inert, untouched, and unindexed in memory. No UI elements indicate that Decoy Mode is active.

### Feature 3: Disposable Clipboard & Ghost Typing
- **Paste-Once Mode**: Clears the OS clipboard 3 seconds after a secret is copied or immediately when the Vult window loses focus.
- **Ghost Typing Simulation**: Optional direct keyboard emulation via OS input APIs (`enigo` in Rust). Types the secret character-by-character into the active target input field without ever placing plaintext into the Windows clipboard.

### Feature 4: Developer & Power-User Secret Profiles
- **Environment Exporter**: One-click copy or export of API keys and server tokens formatted as `.env`, shell exports (`export STRIPE_KEY="..."`), or JSON secrets.
- **Credential Rotation Timers**: Optional rotation intervals (e.g. 30, 90, 180 days) with visual indicators for expired credentials.

### Feature 5: Zero-Cloud P2P LAN / QR Delta Sync
- **Air-Gapped QR Transfer**: Display an animated QR code (UR / Uniform Resources format) representing an encrypted delta backup for instant scanning by the Vult mobile app.
- **Local LAN P2P Sync**: Ephemeral, mutual-TLS local network pairing over mDNS. Desktop and Android devices sync encrypted blobs without touching any third-party relay or cloud server.

### Feature 6: Android Mobile Version (Tauri v2 Mobile)
- **Shared Codebase**: 100% shared HTML/CSS/JS frontend; 100% shared Rust core cryptographic engine (`vult-core`).
- **Hardware Security**: Android Keystore integration for hardware-backed master key wrapping; Android BiometricPrompt (Fingerprint / Face Unlock).
- **Responsive Adaptive Layout**: Fluid scaling within Android viewport bounds with safe-area insets.

---

## 6. Non-Functional Requirements & Security Guarantees

1. **Security & Cryptography**:
   - AES-256-GCM authenticated encryption with 96-bit unique nonces.
   - Argon2id with production memory bounds (64 MiB RAM, 3 iterations, 4 parallelism threads).
   - Zeroize memory scrubbing for all intermediate master keys and decrypted plaintext structures.
2. **Performance**:
   - Vault unlock latency < 1.2s on mid-range hardware (dictated by Argon2id parameters).
   - Instant search filtering (< 10ms for 1,000 entries).
   - Cold startup time < 350ms.
   - Memory footprint < 45MB RAM.
3. **Reliability & Data Safety**:
   - Atomic file writes using temporary staging files (`.vult.tmp` $\rightarrow$ atomic rename) to eliminate corruption during power loss.
   - Automatic rolling snapshots (`vault.vult.bak`) before every write.
4. **Zero Telemetry**:
   - 0 HTTP/WebSocket connections.
   - Strict Content Security Policy (`default-src 'self'`).
   - No crash reporters transmitting payloads externally.

---

## 7. Acceptance Criteria & Milestone Gates

- **Gate 1**: Windows installer (`.msi` / `.exe`) compiles and installs cleanly with desktop shortcut and icon.
- **Gate 2**: Recovery Code Lifeboat tracks usage state, strikethrough, and remaining counts with 100% automated test coverage.
- **Gate 3**: Duress PIN reliably unlocks the decoy database and leaves zero forensic traces of the primary database in memory.
- **Gate 4**: Android compilation targets build successfully under Tauri v2 mobile CLI.
- **Gate 5**: 100% of Rust backend and JavaScript frontend tests pass with zero regressions.
