# Implementation Roadmap & Task Breakdown — Vult

**Product**: Vult Roadmap (Version 1.0.0 Stable $\rightarrow$ 2.0.0 Features)  
**Author**: Kurados  

---

## 1. Milestone 0: Version 1.0.0 Lockdown & Release Baseline (COMPLETED)

- [x] **Git Tagging**: Tagged commit `c65c9b0` with release tag `v1.0.0`.
- [x] **Backup Branch**: Created and pushed `v1.0.0-stable` branch to `origin/v1.0.0-stable` on GitHub.
- [x] **Windows Installer Build**: Compiling release production installer via Tauri v2 bundler (`npm run build`).
- [x] **Documentation Freeze**: Created `docs/` repository standard (`PRD.md`, `ARCHITECTURE.md`, `RULES.md`, `DESIGN.md`, `TASKS.md`, `MEMORY.md`).

---

## 2. Milestone 1: The 2FA Recovery Code Lifeboat

*Goal: Make Vult the world's best manager for two-factor authentication backup codes.*

- [ ] **Task 1.1: Backend Data Model Enhancement**
  - Update `SecretEntry` model in `src-tauri/src/models.rs` to support structured `recovery_codes: Vec<RecoveryCodeItem>`.
  - `RecoveryCodeItem`: `{ id: String, code: String, is_used: bool, used_at: Option<String> }`.
  - Maintain backward compatibility with legacy plaintext `code_list` string format during vault deserialization.
- [ ] **Task 1.2: Recovery Code Interactive Chip UI**
  - In `src/js/screens/entry-detail.js`, render recovery codes as interactive clickable chips rather than a static text box.
  - Display consumption state: active codes in high-contrast monospace; used codes styled with strikethrough (`text-decoration: line-through; opacity: 0.45;`).
- [ ] **Task 1.3: One-Click Consumption & Copy Action**
  - Add "Copy & Mark Used" button: copies the code to the OS clipboard and toggles `is_used = true` with a single tap.
  - Automatically persist the updated vault state via `update_entry`.
- [ ] **Task 1.4: Exhaustion Warning Header & Batch Replenishment**
  - Add visual progress bar: "Remaining: X of Y codes".
  - Trigger amber depletion warning when remaining codes drop to $\le 2$.
  - Add "Replenish Batch" modal button allowing users to paste a new code batch when old codes are exhausted.
- [ ] **Task 1.5: Automated Verification**
  - Write Rust tests verifying recovery code serialization, state toggling, and backward compatibility.
  - Run frontend test suite.

---

## 3. Milestone 2: Plausible Deniability (Duress Vault / Decoy Mode)

*Goal: Provide safety and plausible deniability under coercion or border inspection.*

- [ ] **Task 2.1: Secondary Decoy Master Key Infrastructure**
  - Extend `AuthSettings` in `models.rs` with `duress_enabled: bool` and `duress_pin_hash: Option<String>`.
  - Maintain an entirely separate encrypted storage file on disk: `decoy_vault.vult`.
- [ ] **Task 2.2: Dual-Unlock Routing in `auth.rs`**
  - In `unlock_vault`, compare input against both Primary credentials and Duress PIN.
  - If Primary credentials match $\rightarrow$ decrypt `vault.vult`.
  - If Duress PIN matches $\rightarrow$ decrypt `decoy_vault.vult` (or initialize a fresh decoy vault populated with believable starter entries if first time).
- [ ] **Task 2.3: Zero Leakage Memory Isolation**
  - Ensure the genuine vault remains completely untouched on disk and unallocated in RAM while in Decoy Mode.
  - Ensure the UI looks 100% normal with zero warnings or hints that Decoy Mode is active.
- [ ] **Task 2.4: Settings Provisioning UI**
  - In `src/js/screens/settings.js`, add "Duress PIN / Decoy Vault" configuration section protected behind Master Password authentication.
  - Provide a button to "Manage Decoy Entries".

---

## 4. Milestone 3: Disposable Clipboard & Ghost Typing

*Goal: Eliminate clipboard snooping malware risks on Windows.*

- [ ] **Task 3.1: Zero-Trace Auto-Wipe & Focus Clear**
  - In `src/js/utils/tauri-bridge.js`, support an immediate wipe mode: clears clipboard after 3 seconds or immediately when window focus is lost (`window.onblur`).
- [ ] **Task 3.2: Ghost Typing Subsystem (Direct OS Keystroke Injection)**
  - Add Rust crate `enigo` to `src-tauri/Cargo.toml`.
  - Implement Tauri command `ghost_type_secret(text: String)`:
    - Minimizes or shifts focus to the previous active window.
    - Emulates native keyboard scancodes character-by-character with micro-jitter (20–40ms delays).
    - Secret text completely bypasses the OS clipboard.
- [ ] **Task 3.3: UI Controls**
  - In `entry-detail.js`, add a discrete "Ghost Type" button next to "Copy".

---

## 5. Milestone 4: Developer & Power-User Secret Profiles

*Goal: Empower developers and sysadmins to manage tokens and `.env` configs safely.*

- [ ] **Task 4.1: Structured Token & Key Attributes**
  - Support environment variable naming (e.g. `STRIPE_SECRET_KEY`) on API Token entries.
  - Support credential rotation intervals (30, 90, 180 days) with visual badges on stale secrets.
- [ ] **Task 4.2: One-Click Syntax Exporters**
  - Add syntax generation dropdown in Secret Detail:
    - Shell Export: `export KEY="secret"`
    - `.env` line: `KEY=secret`
    - cURL header: `-H "Authorization: Bearer secret"`
- [ ] **Task 4.3: Bulk Category Export to `.env`**
  - In the "API & Secret Tokens" category view, add "Export Active Category to .env".

---

## 6. Milestone 5: Android Mobile Version (Tauri v2 Mobile)

*Goal: Bring Vult's zero-cloud security to mobile devices.*

- [ ] **Task 5.1: Tauri Mobile Scaffolding**
  - Run `tauri android init` to generate Android native harness in `src-tauri/gen/android`.
  - Configure Android package identifier `com.vult.mobile` and target SDKs.
- [ ] **Task 5.2: Hardware Keystore & BiometricPrompt**
  - Bridge Android Keystore and BiometricPrompt (via Tauri mobile biometric plugin) to match Windows Hello functionality.
- [ ] **Task 5.3: Adaptive Responsive CSS**
  - Optimize viewport meta tag and CSS safe-area insets (`env(safe-area-inset-top)`) for Android notch/punch-hole displays.

---

## 7. Milestone 6: Zero-Cloud P2P LAN & Air-Gapped QR Delta Sync

*Goal: Seamless cross-device synchronization without cloud servers.*

- [ ] **Task 6.1: Air-Gapped Animated QR Code (UR / Uniform Resources)**
  - Implement animated multipart QR code renderer in frontend for exporting encrypted vault deltas directly to phone camera.
- [ ] **Task 6.2: Local LAN Discovery & TLS Pairing**
  - Implement local network peer discovery via mDNS (`_vult-sync._tcp.local`).
  - Mutual TLS socket pairing over Wi-Fi with one-time pairing PIN code.
