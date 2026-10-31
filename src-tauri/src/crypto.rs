use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAGIC_BYTES: &[u8; 5] = b"VULT1";
pub const FORMAT_VERSION: u8 = 1;

pub const DEFAULT_M_COST: u32 = 65536; // 64 MiB
pub const DEFAULT_T_COST: u32 = 3;     // 3 iterations
pub const DEFAULT_P_COST: u32 = 1;     // 1 lane

pub const FAST_TEST_M_COST: u32 = 4096; // 4 MiB for tests
pub const FAST_TEST_T_COST: u32 = 1;
pub const FAST_TEST_P_COST: u32 = 1;

// Bounds for KDF parameters to prevent memory exhaustion / DoS attacks
#[cfg(test)]
pub const MIN_M_COST: u32 = FAST_TEST_M_COST; // 4 MiB in test mode
#[cfg(not(test))]
pub const MIN_M_COST: u32 = 16384;            // 16 MiB (16384 KiB)
pub const MAX_M_COST: u32 = 262144;           // 256 MiB (262144 KiB)

pub const MIN_T_COST: u32 = 1;
pub const MAX_T_COST: u32 = 10;
pub const MIN_P_COST: u32 = 1;
pub const MAX_P_COST: u32 = 4;

// Bound decrypted plaintext size (16 MiB) to prevent decompression bomb / memory explosion
pub const MAX_PLAINTEXT_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
pub const MAX_CIPHERTEXT_SIZE: usize = MAX_PLAINTEXT_SIZE + 16; // 16 MiB + 16-byte GCM tag

pub const HEADER_SIZE: usize = 5 + 1 + 4 + 4 + 4 + 16 + 12; // 46 bytes
pub const MIN_TOTAL_SIZE: usize = HEADER_SIZE + 16;          // 62 bytes (header + tag)

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    KeyDerivationFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    TamperedOrInvalidKey,
    InvalidHeader,
    UnsupportedVersion(u8),
    DataTooShort,
    InvalidKdfParameters,
    PayloadTooLarge,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyDerivationFailed(e) => write!(f, "Key derivation failed: {}", e),
            CryptoError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            CryptoError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            CryptoError::TamperedOrInvalidKey => write!(f, "Vault decryption failed (invalid password or corrupted data)"),
            CryptoError::InvalidHeader => write!(f, "Invalid vault file header"),
            CryptoError::UnsupportedVersion(v) => write!(f, "Unsupported vault format version: {}", v),
            CryptoError::DataTooShort => write!(f, "Encrypted payload is corrupted or truncated"),
            CryptoError::InvalidKdfParameters => write!(f, "Invalid KDF parameters in vault header"),
            CryptoError::PayloadTooLarge => write!(f, "Vault payload exceeds maximum allowed size"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn validate_kdf_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), CryptoError> {
    validate_kdf_params_strict(m_cost, t_cost, p_cost, MIN_M_COST)
}

pub fn validate_kdf_params_strict(
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    min_m_cost: u32,
) -> Result<(), CryptoError> {
    if m_cost < min_m_cost || m_cost > MAX_M_COST {
        return Err(CryptoError::InvalidKdfParameters);
    }
    if t_cost < MIN_T_COST || t_cost > MAX_T_COST {
        return Err(CryptoError::InvalidKdfParameters);
    }
    if p_cost < MIN_P_COST || p_cost > MAX_P_COST {
        return Err(CryptoError::InvalidKdfParameters);
    }
    Ok(())
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; 32]);

pub struct CryptoEngine {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

impl CryptoEngine {
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self { m_cost, t_cost, p_cost }
    }

    pub fn fast_for_testing() -> Self {
        Self {
            m_cost: FAST_TEST_M_COST,
            t_cost: FAST_TEST_T_COST,
            p_cost: FAST_TEST_P_COST,
        }
    }

    /// Derive 256-bit encryption key from password and salt using Argon2id
    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<DerivedKey, CryptoError> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output_key = [0u8; 32];
        let res = argon2.hash_password_into(password, salt, &mut output_key);
        if let Err(e) = res {
            output_key.zeroize();
            return Err(CryptoError::KeyDerivationFailed(e.to_string()));
        }

        Ok(DerivedKey(output_key))
    }

    /// Encrypt plaintext using AES-256-GCM and serialize with header and salt
    pub fn encrypt_vault(&self, password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        validate_kdf_params(self.m_cost, self.t_cost, self.p_cost)?;
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(CryptoError::PayloadTooLarge);
        }

        // Generate 16 bytes random salt using OS CSPRNG
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Derive key
        let key = self.derive_key(password, &salt)?;

        // Generate 12 bytes random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AES-256-GCM authenticated encryption
        let cipher = Aes256Gcm::new_from_slice(&key.0)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Construct header:
        // [MAGIC 5B] [VERSION 1B] [M_COST 4B] [T_COST 4B] [P_COST 4B] [SALT 16B] [NONCE 12B]
        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.extend_from_slice(MAGIC_BYTES);
        header.push(FORMAT_VERSION);
        header.extend_from_slice(&self.m_cost.to_le_bytes());
        header.extend_from_slice(&self.t_cost.to_le_bytes());
        header.extend_from_slice(&self.p_cost.to_le_bytes());
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce_bytes);

        // Bind header as AEAD Associated Data (AAD)
        let payload = Payload {
            msg: plaintext,
            aad: &header,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut output = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        output.extend_from_slice(&header);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Decrypt vault binary blob using AES-256-GCM with AAD verification and legacy fallback
    pub fn decrypt_vault(&self, password: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < MIN_TOTAL_SIZE {
            return Err(CryptoError::DataTooShort);
        }
        if data.len() > HEADER_SIZE + MAX_CIPHERTEXT_SIZE {
            return Err(CryptoError::PayloadTooLarge);
        }

        // Check magic bytes
        if &data[0..5] != MAGIC_BYTES {
            return Err(CryptoError::InvalidHeader);
        }

        // Check version
        let version = data[5];
        if version != FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        // Read Argon2 parameters from file header
        let m_cost = u32::from_le_bytes(data[6..10].try_into().unwrap());
        let t_cost = u32::from_le_bytes(data[10..14].try_into().unwrap());
        let p_cost = u32::from_le_bytes(data[14..18].try_into().unwrap());

        // Strictly validate KDF parameters before calling Argon2id
        validate_kdf_params(m_cost, t_cost, p_cost)?;

        let salt = &data[18..34];
        let nonce_bytes = &data[34..46];
        let ciphertext = &data[HEADER_SIZE..];

        // Validate ciphertext size bound before decrypting
        if ciphertext.len() > MAX_CIPHERTEXT_SIZE {
            return Err(CryptoError::PayloadTooLarge);
        }

        // Derive key using the parameters stored in the file
        let engine = CryptoEngine::new(m_cost, t_cost, p_cost);
        let key = engine.derive_key(password, salt)?;

        let cipher = Aes256Gcm::new_from_slice(&key.0)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce_bytes);
        let header_bytes = &data[..HEADER_SIZE];

        // 1. Primary path: verify integrity with header as AEAD Associated Data (AAD)
        let payload_with_aad = Payload {
            msg: ciphertext,
            aad: header_bytes,
        };

        let mut plaintext = match cipher.decrypt(nonce, payload_with_aad) {
            Ok(pt) => pt,
            Err(_) => {
                // 2. Fallback path: legacy decryption without AAD for backwards compatibility
                let legacy_payload = Payload {
                    msg: ciphertext,
                    aad: b"",
                };
                cipher
                    .decrypt(nonce, legacy_payload)
                    .map_err(|_| CryptoError::TamperedOrInvalidKey)?
            }
        };

        // Final payload size check
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            plaintext.zeroize();
            return Err(CryptoError::PayloadTooLarge);
        }

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_determinism() {
        let engine = CryptoEngine::fast_for_testing();
        let pass = b"SuperSecretPassword123!";
        let salt = [42u8; 16];

        let key1 = engine.derive_key(pass, &salt).unwrap();
        let key2 = engine.derive_key(pass, &salt).unwrap();

        assert_eq!(key1.0, key2.0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let engine = CryptoEngine::fast_for_testing();
        let pass = b"MyStrongVaultPassphrase!";
        let secret_data = b"Hello, this is top-secret information stored in Vult!";

        let encrypted = engine.encrypt_vault(pass, secret_data).unwrap();
        assert_ne!(encrypted, secret_data);

        let decrypted = engine.decrypt_vault(pass, &encrypted).unwrap();
        assert_eq!(decrypted, secret_data);
    }

    #[test]
    fn test_wrong_password_fails() {
        let engine = CryptoEngine::fast_for_testing();
        let secret_data = b"Top secret classified";

        let encrypted = engine.encrypt_vault(b"RightPassword", secret_data).unwrap();
        let res = engine.decrypt_vault(b"WrongPassword", &encrypted);

        assert!(matches!(res, Err(CryptoError::TamperedOrInvalidKey)));
    }

    #[test]
    fn test_tamper_detection_ciphertext() {
        let engine = CryptoEngine::fast_for_testing();
        let secret_data = b"Important cryptographic secret";

        let mut encrypted = engine.encrypt_vault(b"Password", secret_data).unwrap();
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0x01; // flip 1 bit

        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert!(matches!(res, Err(CryptoError::TamperedOrInvalidKey)));
    }

    #[test]
    fn test_tamper_detection_salt() {
        let engine = CryptoEngine::fast_for_testing();
        let secret_data = b"Data to encrypt";

        let mut encrypted = engine.encrypt_vault(b"Password", secret_data).unwrap();
        // Modify salt byte (offset 18)
        encrypted[18] ^= 0xFF;

        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert!(matches!(res, Err(CryptoError::TamperedOrInvalidKey)));
    }

    #[test]
    fn test_invalid_header_fails() {
        let engine = CryptoEngine::fast_for_testing();
        let mut encrypted = engine.encrypt_vault(b"Password", b"Data").unwrap();
        encrypted[0] = b'X'; // Corrupt magic

        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert!(matches!(res, Err(CryptoError::InvalidHeader)));
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let engine = CryptoEngine::fast_for_testing();
        let empty_data = b"";

        let encrypted = engine.encrypt_vault(b"Password", empty_data).unwrap();
        let decrypted = engine.decrypt_vault(b"Password", &encrypted).unwrap();
        assert_eq!(decrypted, empty_data);
    }

    #[test]
    fn test_kdf_params_bounds_rejection() {
        let engine = CryptoEngine::fast_for_testing();
        let mut encrypted = engine.encrypt_vault(b"Password", b"Secret data").unwrap();

        // 1. m_cost too small (< 4096 in test mode)
        let too_small_m = 2048u32.to_le_bytes();
        encrypted[6..10].copy_from_slice(&too_small_m);
        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);

        // 2. m_cost too large (> 256 MiB = 262144 KiB)
        let too_large_m = 524288u32.to_le_bytes();
        encrypted[6..10].copy_from_slice(&too_large_m);
        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);

        // Restore valid m_cost
        encrypted[6..10].copy_from_slice(&FAST_TEST_M_COST.to_le_bytes());

        // 3. t_cost = 0 (too small)
        encrypted[10..14].copy_from_slice(&0u32.to_le_bytes());
        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);

        // 4. t_cost = 11 (too large)
        encrypted[10..14].copy_from_slice(&11u32.to_le_bytes());
        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);

        // Restore valid t_cost
        encrypted[10..14].copy_from_slice(&FAST_TEST_T_COST.to_le_bytes());

        // 5. p_cost = 0 (too small)
        encrypted[14..18].copy_from_slice(&0u32.to_le_bytes());
        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);

        // 6. p_cost = 5 (too large)
        encrypted[14..18].copy_from_slice(&5u32.to_le_bytes());
        let res = engine.decrypt_vault(b"Password", &encrypted);
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);
    }

    #[test]
    fn test_aad_header_tampering_rejected() {
        let engine = CryptoEngine::fast_for_testing();
        let encrypted = engine.encrypt_vault(b"Password", b"Secret sensitive payload").unwrap();

        // Tamper with nonce byte (offset 35) in the header
        let mut tampered_nonce = encrypted.clone();
        tampered_nonce[35] ^= 0x42;
        let res = engine.decrypt_vault(b"Password", &tampered_nonce);
        assert_eq!(res.unwrap_err(), CryptoError::TamperedOrInvalidKey);

        // Tamper with t_cost from 1 to 2 (both valid bounds, but AAD is bound to original 1)
        let mut tampered_t_cost = encrypted.clone();
        tampered_t_cost[10..14].copy_from_slice(&2u32.to_le_bytes());
        let res = engine.decrypt_vault(b"Password", &tampered_t_cost);
        assert_eq!(res.unwrap_err(), CryptoError::TamperedOrInvalidKey);
    }

    #[test]
    fn test_legacy_vault_without_aad_fallback_decryption() {
        let engine = CryptoEngine::fast_for_testing();
        let pass = b"LegacyVaultPassword";
        let secret = b"Data encrypted by previous Vult version without AAD";

        // Manually construct legacy vault without AAD
        let salt = [77u8; 16];
        let key = engine.derive_key(pass, &salt).unwrap();
        let nonce_bytes = [88u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&key.0).unwrap();

        // Legacy: encrypt without AAD
        let ciphertext = cipher.encrypt(nonce, secret.as_ref()).unwrap();

        let mut legacy_data = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
        legacy_data.extend_from_slice(MAGIC_BYTES);
        legacy_data.push(FORMAT_VERSION);
        legacy_data.extend_from_slice(&engine.m_cost.to_le_bytes());
        legacy_data.extend_from_slice(&engine.t_cost.to_le_bytes());
        legacy_data.extend_from_slice(&engine.p_cost.to_le_bytes());
        legacy_data.extend_from_slice(&salt);
        legacy_data.extend_from_slice(&nonce_bytes);
        legacy_data.extend_from_slice(&ciphertext);

        // Decrypt must succeed through legacy fallback path
        let decrypted = engine.decrypt_vault(pass, &legacy_data).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_max_payload_size_enforcement() {
        let engine = CryptoEngine::fast_for_testing();
        // Exceeding MAX_PLAINTEXT_SIZE should be rejected
        let huge_dummy = vec![0u8; MAX_PLAINTEXT_SIZE + 1];
        let res = engine.encrypt_vault(b"Password", &huge_dummy);
        assert_eq!(res.unwrap_err(), CryptoError::PayloadTooLarge);
    }

    #[test]
    fn test_encrypt_vault_rejects_invalid_kdf_params() {
        // m_cost = 0 (too small)
        let engine_bad_m = CryptoEngine::new(0, 1, 1);
        let res = engine_bad_m.encrypt_vault(b"Password", b"Secret");
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);

        // t_cost = 0 (too small)
        let engine_bad_t = CryptoEngine::new(FAST_TEST_M_COST, 0, 1);
        let res = engine_bad_t.encrypt_vault(b"Password", b"Secret");
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);

        // p_cost = 0 (too small)
        let engine_bad_p = CryptoEngine::new(FAST_TEST_M_COST, 1, 0);
        let res = engine_bad_p.encrypt_vault(b"Password", b"Secret");
        assert_eq!(res.unwrap_err(), CryptoError::InvalidKdfParameters);
    }

    #[test]
    fn test_decrypt_vault_rejects_oversized_payload() {
        let engine = CryptoEngine::fast_for_testing();
        let mut huge_data = vec![0u8; HEADER_SIZE + MAX_CIPHERTEXT_SIZE + 1];
        huge_data[..5].copy_from_slice(MAGIC_BYTES);
        huge_data[5] = FORMAT_VERSION;
        let res = engine.decrypt_vault(b"Password", &huge_data);
        assert_eq!(res.unwrap_err(), CryptoError::PayloadTooLarge);
    }

    #[test]
    fn test_production_kdf_bounds_strict_validation() {
        // Production lower bound is 16 MiB = 16384 KiB
        const PROD_MIN_M: u32 = 16384;
        assert_eq!(
            validate_kdf_params_strict(16383, 3, 1, PROD_MIN_M).unwrap_err(),
            CryptoError::InvalidKdfParameters
        );
        assert_eq!(
            validate_kdf_params_strict(4096, 3, 1, PROD_MIN_M).unwrap_err(),
            CryptoError::InvalidKdfParameters
        );
        assert!(validate_kdf_params_strict(16384, 3, 1, PROD_MIN_M).is_ok());
        assert!(validate_kdf_params_strict(65536, 3, 1, PROD_MIN_M).is_ok());
        assert!(validate_kdf_params_strict(262144, 3, 1, PROD_MIN_M).is_ok());
        assert_eq!(
            validate_kdf_params_strict(262145, 3, 1, PROD_MIN_M).unwrap_err(),
            CryptoError::InvalidKdfParameters
        );
    }
}
