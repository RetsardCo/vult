<div align="center">
  <img src="src/assets/logo.png" width="96" height="96" alt="Vult Logo" />
  <h1>Vult Technical & Architectural Documentation</h1>
</div>

> **Vult** — A high-security, local-first personal secret manager desktop application engineered with a compact 400 × 620 px footprint, macOS-inspired ergonomics, and military-grade authenticated encryption.

---

## 📑 Table of Contents

1. [Executive Overview & Vision](#1-executive-overview--vision)
2. [Threat Model & Security Principles](#2-threat-model--security-principles)
3. [System Architecture](#3-system-architecture)
4. [Cryptographic Engine Specification](#4-cryptographic-engine-specification)
5. [Windows Hello & DPAPI Token Protection](#5-windows-hello--dpapi-token-protection)
6. [Supported Secret Categories & Schema Reference](#6-supported-secret-categories--schema-reference)
7. [UI/UX Architecture & Design System](#7-uiux-architecture--design-system)
8. [Tauri IPC API Reference](#8-tauri-ipc-api-reference)
9. [Binary Storage & File Format Specification](#9-binary-storage--file-format-specification)
10. [Disaster Recovery, Export & Import](#10-disaster-recovery-export--import)
11. [Developer Guide & Verification Testing](#11-developer-guide--verification-testing)
12. [Release & Production Build Guide](#12-release--production-build-guide)

---

## 1. Executive Overview & Vision

**Vult** addresses a critical dilemma in modern credential and secret management: **cloud-based password managers** expose users to centralized breach risks, vendor lock-in, and remote cyberattacks, while **unencrypted local files** (e.g., text files, spreadsheets) leave credentials vulnerable to malware, infostealers, and accidental loss.

### Core Tenets

- 📴 **100% Offline & Local-First**: No external telemetry, no cloud servers, no account registration. Your encrypted vault exists exclusively on your physical storage device.
- 📐 **Compact Utility Footprint (400 × 620 px)**: Sized similarly to the native Windows 11 Clock utility, Vult stays unobtrusive beside active work windows rather than consuming an entire display.
- 🗃️ **Universal Secret Storage**: Beyond simple username/password pairs, Vult natively supports single-use 2FA recovery codes (e.g., Discord, Unity, Google, GitHub), BIP-39 cryptocurrency seed phrases, API keys, software license keys, SSH keys, Wi-Fi passwords, and custom data.
- 🛡️ **Defense-in-Depth Cryptography**: Implements authenticated symmetric encryption (**AES-256-GCM**) paired with memory-hard key derivation (**Argon2id**), hardware-backed Windows Hello access, and active in-RAM memory zeroization (**`zeroize`**).

---

## 2. Threat Model & Security Principles

Vult is engineered against the following real-world threat vectors:

| Threat Vector | Mitigation Strategy |
|---|---|
| **Stolen Vault File** (Drive theft or raw file exfiltration) | Protected by **AES-256-GCM** with **Argon2id** key stretching ($64\text{ MiB}$ RAM, $3$ iterations). Brute-force attacks are computationally prohibitive even on high-end GPU clusters. |
| **Ciphertext Tampering / Bit-Flipping** | AES-256-GCM's 16-byte authentication tag provides Authenticated Encryption with Associated Data (**AEAD**). Any single-bit alteration causes immediate decryption rejection. |
| **RAM Scraping & Infostealer Malware** | Plaintext credentials and derived keys implement the Rust `Zeroize` and `ZeroizeOnDrop` traits, clearing memory buffers upon lock, timeout, or application exit. |
| **Brute-Force Guessing on UI** | Exponential penalty backoff ($2\text{s} \to 5\text{s} \to 15\text{s} \to 30\text{s}$) prevents automated scripted keypad attacks. |
| **Clipboard Snooping** | Secrets copied to the clipboard are automatically overwritten and purged after a user-configurable duration (default $30$ seconds). |
| **Sudden Power Failure / Crash Corruption** | Writes use a two-phase commit: writes are flushed to a temporary file (`.tmp`), synced to disk via `sync_all()`, and atomically renamed over the target file. |

---

## 3. System Architecture

Vult utilizes a modular split-process architecture powered by **Tauri v2**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Frontend (WebView2)                  │
│                                                             │
│   ┌───────────────┐ ┌────────────────┐ ┌────────────────┐   │
│   │  Lock Screen  │ │   Dashboard    │ │  Category View │   │
│   └───────────────┘ └────────────────┘ └────────────────┘   │
│   ┌───────────────┐ ┌────────────────┐ ┌────────────────┐   │
│   │ Entry Detail  │ │   Entry Form   │ │ Pass Generator │   │
│   └───────────────┘ └────────────────┘ └────────────────┘   │
│   ┌───────────────┐ ┌────────────────┐ ┌────────────────┐   │
│   │ Settings View │ │ Tooltip Engine │ │ Modal & Toast  │   │
│   └───────────────┘ └────────────────┘ └────────────────┘   │
└──────────────────────────────┬──────────────────────────────┘
                               │ Tauri IPC (JSON Commands)
┌──────────────────────────────▼──────────────────────────────┐
│                    Rust Backend Core                        │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                   IPC Commands                      │   │
│   │  (unlock, lock, CRUD, export, clipboard, etc.)      │   │
│   └───────────────┬─────────────────────┬───────────────┘   │
│                   │                     │                   │
│   ┌───────────────▼──────────┐ ┌────────▼───────────────┐   │
│   │   Auth & Session Mgr     │ │    Clipboard Manager   │   │
│   │   - Mode resolution      │ │    - Auto-clear timer  │   │
│   │   - Brute-force delay    │ │    - Main thread sync  │   │
│   │   - RAM zeroization      │ └────────────────────────┘   │
│   └───────────────┬──────────┘                              │
│                   │                                         │
│   ┌───────────────▼──────────┐ ┌────────────────────────┐   │
│   │    Crypto Engine         │ │    Windows DPAPI       │   │
│   │    - Argon2id KDF        │ │    - CryptProtectData  │   │
│   │    - AES-256-GCM AEAD    │ │    - CryptUnprotectData│   │
│   └───────────────┬──────────┘ └────────────────────────┘   │
│                   │                                         │
│   ┌───────────────▼─────────────────────────────────────┐   │
│   │                   Atomic Storage                    │   │
│   │          - Crash-safe temp write + sync             │   │
│   └─────────────────────────┬───────────────────────────┘   │
└─────────────────────────────┼───────────────────────────────┘
                              │
               ┌──────────────▼──────────────┐
               │    Local Encrypted Vault    │
               │         `vault.vult`        │
               └─────────────────────────────┘
```

---

## 4. Cryptographic Engine Specification

### 4.1 Key Derivation Function (Argon2id)

The encryption key is derived using **Argon2id**, the hybrid version of Argon2 combining Argon2d's data-dependent memory access (resisting GPU attacks) with Argon2i's data-independent memory access (resisting side-channel timing attacks).

- **Algorithm**: Argon2id (Version `0x13`)
- **Memory Cost ($m$)**: $65,536\text{ KiB}$ ($64\text{ MiB}$)
- **Time Cost ($t$)**: $3\text{ iterations}$
- **Parallelism ($p$)**: $1\text{ lane}$
- **Salt Length**: $16\text{ bytes}$ (cryptographically secure random bytes generated via OS CSPRNG)
- **Derived Key Length**: $256\text{ bits}$ ($32\text{ bytes}$)

### 4.2 Composite Key Derivation (`PIN + Password` Mode)

When the user selects **PIN + Password** authentication, both secrets must be provided to unlock the vault. The effective key material is derived cryptographically:

$$\text{Secret} = \text{Password} \parallel \text{“::”} \parallel \text{PIN}$$

$$\text{AES-Key} = \text{Argon2id}(\text{Secret}, \text{Salt}, m=65536, t=3, p=1)$$

This guarantees that an attacker who compromises the PIN cannot decrypt the vault without the password, and an attacker who discovers the password cannot decrypt the vault without the PIN. Neither the PIN nor the master password is ever stored on disk in plaintext or as an unbonded hash.

### 4.3 Symmetric Encryption (AES-256-GCM)

- **Cipher**: AES-256 in Galois/Counter Mode (**GCM**)
- **Key Size**: $256\text{ bits}$ ($32\text{ bytes}$)
- **Nonce / IV**: $96\text{ bits}$ ($12\text{ bytes}$) unique CSPRNG nonce per write
- **Authentication Tag**: $128\text{ bits}$ ($16\text{ bytes}$)
- **Associated Data (AAD)**: Encodes file version and header parameters to prevent ciphertext-swapping attacks.

---

## 5. Windows Hello & DPAPI Token Protection

Vult supports native Windows Hello biometric (fingerprint and facial recognition) and OS PIN verification via the Windows Runtime API (`Windows.Security.Credentials.UI.UserConsentVerifier`).

### Windows DPAPI Integration Architecture

To allow seamless unlock without compromising the zero-knowledge security boundary:
1. When Windows Hello is enabled, the derived unlock secret is encrypted using **Windows Data Protection API (DPAPI)**:
   ```rust
   use windows::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};
   ```
2. DPAPI encrypts the token using a key derived from the active Windows user logon credentials and hardware TPM 2.0.
3. The resulting ciphertext is stored in `%APPDATA%/com.vult.Vult/vault.hello`.
4. When the user clicks **Unlock with Windows Hello**:
   - The OS displays the native Windows Hello dialog.
   - Upon successful verification (`UserConsentVerificationResult::Verified`), Vult invokes `CryptUnprotectData` to decrypt the token directly into memory, derives the AES key, and unlocks the vault.
   - The plaintext token is immediately wiped from memory using `Zeroize`.

---

## 6. Supported Secret Categories & Schema Reference

Every vault entry is represented by a strongly typed `VaultEntry` structure containing category-specific fields:

```typescript
interface VaultEntry {
  id: string;               // UUID v4
  category: Category;       // One of 10 category identifiers
  title: string;            // Primary display name
  fields: Record<string, any>; // Category-specific data payload
  notes?: string;           // Optional encrypted notes
  tags: string[];           // Search & categorization tags
  favorite: boolean;        // Quick access flag
  created_at: string;       // ISO 8601 timestamp
  modified_at: string;      // ISO 8601 timestamp
  accessed_at: string;      // ISO 8601 timestamp
}
```

### 6.1 Category Field Definitions

#### 1. Login Credentials (`login`)
```json
{
  "url": "https://discord.com/login",
  "username": "coder_pro",
  "email": "user@example.com",
  "password": "CorrectHorseBatteryStaple#42",
  "totp_secret": "JBSWY3DPEHPK3PXP"
}
```

#### 2. API Keys & Tokens (`api_key`)
```json
{
  "service": "OpenAI Platform",
  "key_name": "Production API Key",
  "key_value": "sk-proj-abc123xyz...",
  "secret": "optional-client-secret",
  "endpoint": "https://api.openai.com/v1",
  "expiry": "2027-12-31"
}
```

#### 3. Cryptocurrency Seed Phrases (`seed_phrase`)
```json
{
  "wallet_name": "MetaMask Main Vault",
  "words": [
    "witch", "collapse", "practice", "feed",
    "shame", "open", "despair", "creek",
    "road", "again", "ice", "least"
  ],
  "passphrase": "optional-bip39-passphrase",
  "derivation_path": "m/44'/60'/0'/0/0"
}
```

#### 4. Recovery & Backup Codes (`recovery_code`)
Features single-use strike-through tracking and remaining counts:
```json
{
  "service": "Discord",
  "code_type": "backup_codes",
  "codes": [
    { "code": "2dj4-xbtz", "used": false },
    { "code": "39wa-j5w2", "used": true },
    { "code": "5xgp-srpn", "used": false },
    { "code": "bbv0-2h6e", "used": false }
  ]
}
```

#### 5. Product & License Keys (`product_key`)
```json
{
  "software": "JetBrains All Products Pack",
  "key_format": "license_key",
  "key_value": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
  "activation_url": "https://account.jetbrains.com",
  "purchase_date": "2026-01-15",
  "expiry": "2027-01-15"
}
```

#### 6. Secure Notes (`secure_note`)
```json
{
  "content": "Confidential project checklist and hardware safe combination: 42-18-99."
}
```

#### 7. SSH & PGP Keys (`ssh_key`)
```json
{
  "key_name": "id_ed25519_production",
  "key_type": "Ed25519",
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@machine",
  "passphrase": "optional-key-passphrase",
  "fingerprint": "SHA256:d8b7a6c5..."
}
```

#### 8. Wi-Fi Passwords (`wifi_password`)
```json
{
  "ssid": "Studio_5GHz_Guest",
  "security_type": "WPA3-Personal",
  "password": "UltraSecretWirelessKey2026"
}
```

#### 9. Payment Cards (`payment_card`)
```json
{
  "cardholder": "Jane Doe",
  "card_number": "4111 2222 3333 4444",
  "expiry": "09/29",
  "cvv": "892",
  "billing_address": "123 Cryptography Way, Suite 400"
}
```

#### 10. Custom Secrets (`custom`)
Supports dynamic arbitrary key-value pairs:
```json
{
  "custom_fields": [
    { "label": "Server ID", "value": "srv-prod-east-01", "is_secret": false },
    { "label": "Root Password", "value": "SuperAdmin!2026", "is_secret": true },
    { "label": "Security Question Answer", "value": "Blueberry", "is_secret": true }
  ]
}
```

---

## 7. UI/UX Architecture & Design System

### 7.1 macOS Dark Theme Design Tokens

```css
:root {
  /* Surface Layers */
  --bg-app: #1C1C1E;         /* Deep canvas */
  --bg-card: #2C2C2E;        /* Layer 1 frosted card */
  --bg-card-hover: #3A3A3C;  /* Interactive hover */
  --bg-card-active: #48484A; /* Mouse active */
  --bg-input: #1C1C1E;       /* Inset input field */

  /* Text & Labels */
  --text-primary: #FFFFFF;
  --text-secondary: #8E8E93;
  --text-tertiary: #636366;

  /* Accent Colors */
  --accent: #0A84FF;         /* macOS San Francisco Blue */
  --accent-hover: #409CFF;
  --destructive: #FF453A;    /* Warning / Delete */
  --success: #30D158;        /* Affirmation / Copied */
  --warning: #FFD60A;        /* Caution */

  /* Borders & Dividers */
  --border-subtle: #2C2C2E;
  --border: #38383A;
  --border-focus: #0A84FF;

  /* Corner Radii */
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
  --radius-xl: 18px;
}
```

### 7.2 Header Anchoring & Layout Stability

To prevent the visual bouncing common in dynamic applications:
- The root layout container `.auth-container` is anchored to `justify-content: flex-start` with a consistent `28px` top padding.
- The `.auth-header` block containing the lock icon, **Vult** title, and subtitle uses `position: sticky; top: 0; flex-shrink: 0;`.
- When switching between authentication modes (PIN + Password, Password Only, PIN Only), the header remains fixed at the top of the window while input fields transition smoothly below it.

### 7.3 macOS-Grade Long-Hover Tooltip System

Tooltips are managed by `src/js/components/tooltip.js`:
- **450ms Hover Delay**: Prevents annoying visual flicker during rapid cursor sweeps.
- **Adaptive Screen Clamping**: Calculates bounding rects and clamps positions to ensure text never overflows outside the 400px window boundary.
- **Multi-line Support**: Wraps long descriptions cleanly into formatted bubbles with dark blur backdrops.

### 7.4 Dynamic PIN Keypad & Dots

- Rather than hardcoding a 6-digit indicator, Vult dynamically queries the vault configuration and renders the exact number of indicator dots corresponding to the user's PIN length ($4$ to $8$ dots).
- Keypad includes clear (✕), backspace (⌫), and supports direct keyboard entry while automatically bypassing keystrokes from `<input>` and `<textarea>` elements.

---

## 8. Tauri IPC API Reference

All communication between WebView2 and the Rust core occurs over strongly typed IPC commands:

| Command | Arguments | Returns | Description |
|---|---|---|---|
| `check_vault_exists` | None | `bool` | Checks if `vault.vult` is initialized. |
| `get_auth_settings` | None | `AuthSettings` | Returns public auth parameters (mode, PIN length, lockout). |
| `setup_vault` | `{ pin: Option<String>, password: Option<String>, mode: String }` | `Result<(), String>` | Initializes a new encrypted vault. |
| `unlock_vault` | `{ pin: Option<String>, password: Option<String> }` | `Result<bool, String>` | Unlocks vault and decrypts secrets into memory. |
| `unlock_windows_hello` | None | `Result<bool, String>` | Prompts OS Windows Hello and decrypts vault. |
| `lock_vault` | None | `Result<(), String>` | Clears decrypted secrets and wipes RAM. |
| `get_vault_stats` | None | `Result<VaultStats, String>` | Returns total entries and category breakdown. |
| `get_entries` | `{ category: Option<String> }` | `Result<Vec<VaultEntry>, String>` | Lists vault entries filtered by category. |
| `get_entry` | `{ id: String }` | `Result<VaultEntry, String>` | Fetches single entry by UUID. |
| `search_entries` | `{ query: String }` | `Result<Vec<VaultEntry>, String>` | Performs multi-field search across titles, URLs, tags. |
| `add_entry` | `{ entry: VaultEntry }` | `Result<String, String>` | Persists new secret entry. |
| `update_entry` | `{ entry: VaultEntry }` | `Result<(), String>` | Updates existing secret entry. |
| `delete_entry` | `{ id: String }` | `Result<(), String>` | Deletes an entry. |
| `toggle_code_used` | `{ entry_id: String, code_index: usize }` | `Result<bool, String>` | Toggles used status on a 2FA backup code. |
| `copy_to_clipboard` | `{ text: String, auto_clear_seconds: Option<u64> }` | `Result<(), String>` | Copies secret and schedules automatic wipe. |
| `export_vault_encrypted` | None | `Result<String, String>` | Exports encrypted Base64 `.vult` backup container. |
| `import_vault_data` | `{ payload: String, password: Option<String> }` | `Result<usize, String>` | Restores entries from an encrypted or JSON backup. |
| `update_auth_settings` | `{ settings: AuthSettings, current_password: Option<String>, current_pin: Option<String>, new_password: Option<String>, new_pin: Option<String> }` | `Result<(), String>` | Updates auth mode, PIN, or password and re-encrypts vault. |
| `wipe_all_data` | None | `Result<(), String>` | Zeroes and deletes vault file and local configurations. |

---

## 9. Binary Storage & File Format Specification

The vault file (`vault.vult`) is written as a structured binary container:

```
+---------------+---------------+-----------------------+
|  Magic Bytes  |    Version    | Argon2 Memory (KiB)   |
|   "VULT1"     |     0x01      |  u32 Big-Endian (4B)  |
|   (5 Bytes)   |    (1 Byte)   |                       |
+---------------+---------------+-----------------------+
|  Argon2 Time  |  Argon2 Lanes |      Salt (CSPRNG)    |
|   u32 (4B)    |    u32 (4B)   |        (16 Bytes)     |
+---------------+---------------+-----------------------+
|  Nonce (IV)   |   Auth Tag    |   Ciphertext Payload  |
|  (12 Bytes)   |  (16 Bytes)   |    (Variable Length)  |
+---------------+---------------+-----------------------+
```

### Parsing Pipeline
1. **Magic Verification**: Inspect initial 5 bytes for ASCII `VULT1`.
2. **Parameter Unpacking**: Read version byte and Argon2 parameters ($m, t, p$).
3. **Key Derivation**: Extract the 16-byte salt and derive the 256-bit key from the user's password/PIN via Argon2id.
4. **AEAD Verification**: Pass the 12-byte Nonce, 16-byte Tag, and Ciphertext to AES-256-GCM.
5. **Deserialization**: Parse the verified plaintext bytes into the strongly typed `VaultData` struct.

---

## 10. Disaster Recovery, Export & Import

### Encrypted Backups (`.vult`)
- Backups exported through **Settings → Export Encrypted Backup** contain the raw AES-256-GCM encrypted container encoded in standard Base64.
- An exported `.vult` backup cannot be read without the master password in effect when the export was created.
- Backups can be safely stored on USB drives, local backup partitions, or external storage without exposing plaintext credentials.

### Restoring a Backup
1. Navigate to **Settings → Import Vault**.
2. Select your `.vult` or `.json` file.
3. If importing an encrypted container, Vult prompts for the backup's master password, decrypts the payload, and merges entries without overwriting your current auth mode or active credentials.

---

## 11. Developer Guide & Verification Testing

### 11.1 Prerequisites
- **Node.js** v18+ and `npm`
- **Rust Toolchain** 1.78+ (`rustc` and `cargo`)
- Visual Studio C++ Build Tools with Windows 10/11 SDK

### 11.2 Running in Development
```powershell
# Navigate to workspace
cd "C:\Users\Kurados\.gemini\antigravity\scratch\vult"

# Install frontend dependencies
npm install

# Launch Tauri development environment
npm run dev
```

### 11.3 Executing Backend Cryptographic Tests
Vult features an automated test suite verifying roundtrip encryption, tamper rejection, DPAPI integration, brute-force delays, and memory zeroization:

```powershell
cd "C:\Users\Kurados\.gemini\antigravity\scratch\vult\src-tauri"
cargo test
```

Expected output:
```text
running 24 tests
test auth::tests::test_dpapi_protect_unprotect ... ok
test auth::tests::test_dynamic_pin_length_persisted_in_config ... ok
test auth::tests::test_corrupted_backup_rejected ... ok
test crypto::tests::test_derive_key_determinism ... ok
test auth::tests::test_mode_switch_reencrypts_correctly ... ok
test crypto::tests::test_empty_plaintext_roundtrip ... ok
test crypto::tests::test_encrypt_decrypt_roundtrip ... ok
test auth::tests::test_pin_change_reencrypts_correctly ... ok
test auth::tests::test_unlock_self_heals_missing_pin_length ... ok
test models::tests::test_zeroize_vault_data ... ok
test models::tests::test_vault_data_serialization ... ok
test crypto::tests::test_invalid_header_fails ... ok
test auth::tests::test_auth_manager_crud_operations ... ok
test auth::tests::test_brute_force_lockout_delays ... ok
test auth::tests::test_auth_manager_setup_and_unlock ... ok
test auth::tests::test_import_vault_preserves_active_auth_settings ... ok
test auth::tests::test_export_and_import_encrypted_vault ... ok
test crypto::tests::test_tamper_detection_ciphertext ... ok
test crypto::tests::test_tamper_detection_salt ... ok
test storage::tests::test_storage_save_load_roundtrip ... ok
test auth::tests::test_change_password_and_reencrypt ... ok
test crypto::tests::test_wrong_password_fails ... ok
test auth::tests::test_various_pin_lengths_setup_and_persist ... ok
test auth::tests::test_all_10_categories_storage ... ok

test result: ok. 24 passed; 0 failed; 0 ignored; finished in 1.20s
```

---

## 12. Release & Production Build Guide

To build a standalone production release `.exe` and MSI installer:

```powershell
cd "C:\Users\Kurados\.gemini\antigravity\scratch\vult"
npm run build
```

The output artifacts will be placed in:
- `src-tauri/target/release/vult.exe` (Standalone portable executable)
- `src-tauri/target/release/bundle/msi/Vult_1.0.0_x64_en-US.msi` (Windows Installer)

---

## 📄 License & Attribution

Vult is open-source software licensed under the **[MIT License](LICENSE)**.
Created by the **RetsardCo** team. Repository: [https://github.com/RetsardCo/vult](https://github.com/RetsardCo/vult).
