# 🔐 Vult — Compact Personal Secret Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/Tauri-v2-24C8D8.svg?logo=tauri&logoColor=white)](https://tauri.app/)
[![Backend](https://img.shields.io/badge/Rust-1.99+-DEA584.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-green.svg)](#security-architecture)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-blueviolet.svg)](#security-architecture)
[![Docs](https://img.shields.io/badge/Documentation-Full%20Guide-orange.svg)](DOCUMENTATION.md)

> **Vult** is a high-security, local-first personal secret manager desktop application engineered with a compact footprint (400 × 620 px), macOS-inspired dark ergonomics, and military-grade encryption.
>
> 📖 **Read the [Complete Technical & Architectural Documentation](DOCUMENTATION.md)** for exhaustive details on the crypto engine, DPAPI token protection, schemas, and IPC command APIs.

---

## ✨ Highlights

- 📐 **Compact 400 × 620 Desktop Size**: Optimized for instant access alongside active windows (inspired by the Windows 11 Clock utility).
- 🛡️ **Zero-Cloud & Local-First**: Your data lives exclusively on your machine in an authenticated, encrypted binary format. Zero telemetry, zero external network requests.
- 🔑 **10 Dedicated Secret Categories**: From standard logins to BIP-39 seed phrases, developer SSH keys, and single-use 2FA recovery codes.
- ⚡ **Lightning Fast & Lightweight**: Powered by Tauri v2 with a native Rust security core and sleek, vanilla web UI.
- 🔒 **Defense-in-Depth Authentication**: Multi-mode unlock (PIN only, Master Password only, or PIN + Master Password) with optional Windows Hello biometric integration.
- 📋 **Clipboard Protection**: Automatic clipboard wiping after 30 seconds to prevent accidental leaks.
- 🎲 **Built-in Password Generator**: Cryptographically secure customizable password generator with visual entropy indicators.
- 💥 **Crash-Safe Atomic Storage**: All writes execute atomically via temp files and OS-level sync, ensuring vault files cannot be corrupted even during sudden power failure.

---

## 🗂️ 10 Supported Secret Categories

| Category | Icon | Specialized Capabilities | Fields |
|---|:---:|---|---|
| **Login Credentials** | 🔑 | Password reveal/copy, quick generation | URL, Username, Email, Password, TOTP Secret, Notes |
| **API Keys & Tokens** | 🔌 | Masked keys & endpoints | Service, Key Name, Key Value, Secret, Endpoint, Expiry |
| **Seed Phrases** | 🌱 | Interactive 12 or 24-word numbered grid | Wallet Name, Mnemonic Words[], Passphrase, Derivation Path |
| **Recovery Codes** | 🛟 | Single-use strike-through tracking & "Copy Remaining" | Service, Code Format (Discord `xxxx-xxxx`, Google, Unity, etc.), Codes[] |
| **Product & License Keys** | 🏷️ | Formatted license keys & activation links | Software Name, Serial Key, Activation URL, Purchase Date, Expiry |
| **Secure Notes** | 📝 | Multi-line confidential scratchpad | Title, Content, Tags, Notes |
| **SSH & PGP Keys** | 🗝️ | Formatted key blocks & fingerprints | Key Name, Type (Ed25519/RSA), Private Key, Public Key, Passphrase |
| **Wi-Fi Passwords** | 📶 | Quick SSID & protocol lookup | Network SSID, Security Protocol (WPA3, WPA2, etc.), Password |
| **Payment Cards** | 💳 | Card formatting & CVV reveal protection | Cardholder, Card Number, Expiry (MM/YY), CVV, Billing Address |
| **Custom Secrets** | ⚙️ | Dynamic arbitrary key-value pairs | Title, Dynamic Custom Fields (with individual secret masking) |

---

## 🔒 Security Architecture

```
User Master Password + Salt (16B CSPRNG)
                │
                ▼
      [ Argon2id KDF ]
      Memory: 64 MiB (65,536 KiB)
      Iterations: 3
      Parallelism: 1 lane
                │
                ▼
       256-bit Derived Key
                │
                ▼
      [ AES-256-GCM AEAD ]  ◄── Nonce (12B CSPRNG)
                │
                ▼
┌────────────────────────────────────────────────────────┐
│ Magic ("VULT1") | Version | Argon2 Params | Salt | Nonce│
│ 16-Byte Auth Tag | Encrypted Ciphertext Payload        │
└────────────────────────────────────────────────────────┘
```

1. **Authenticated Encryption (AES-256-GCM)**: Every decryption operation cryptographically verifies the 16-byte authentication tag. Any alteration to the ciphertext, salt, or file header is immediately caught and rejected.
2. **GPU/ASIC-Resistant KDF (Argon2id)**: Configured according to current OWASP standards (64 MiB memory cost, 3 iterations) to resist offline dictionary and brute-force attacks.
3. **Memory Safety & Zeroization**: Decrypted secrets and master keys in memory implement `Zeroize` and `ZeroizeOnDrop`, wiping buffers from RAM upon lock or process termination.
4. **Brute-Force Lockout**: Failed attempts trigger exponential backoff delays (2s → 5s → 15s → 30s) to frustrate automated guessing.
5. **Configurable Inactivity Auto-Lock**: Automatically clears RAM and locks the application after 1, 5, 15, or 30 minutes of user inactivity.
6. **Windows Hello**: Supports native biometric (fingerprint/facial recognition) or Windows PIN unlock through `Windows.Security.Credentials.UI.UserConsentVerifier`.

---

## 🛠️ Development & Building

### Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Rust toolchain](https://www.rust-lang.org/) (1.78+)
- Visual Studio C++ Build Tools (on Windows)

### Installation

```bash
# Clone the repository
git clone https://github.com/RetsardCo/vult.git
cd vult

# Install dependencies
npm install
```

### Running in Development

```bash
npm run tauri dev
```

### Running Automated Security Tests

```bash
cd src-tauri
cargo test
```

### Building for Production

```bash
npm run tauri build
```

The compiled installer and standalone executable will be located in `src-tauri/target/release/`.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
