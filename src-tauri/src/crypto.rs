use aes_gcm::aead::{Aead, KeyInit};
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

#[derive(Debug)]
pub enum CryptoError {
    KeyDerivationFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    TamperedOrInvalidKey,
    InvalidHeader,
    UnsupportedVersion(u8),
    DataTooShort,
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
        }
    }
}

impl std::error::Error for CryptoError {}

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
        argon2
            .hash_password_into(password, salt, &mut output_key)
            .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

        Ok(DerivedKey(output_key))
    }

    /// Encrypt plaintext using AES-256-GCM and serialize with header and salt
    pub fn encrypt_vault(&self, password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
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

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Pack binary format:
        // [MAGIC 5B] [VERSION 1B] [M_COST 4B] [T_COST 4B] [P_COST 4B] [SALT 16B] [NONCE 12B] [CIPHERTEXT...]
        let mut output = Vec::with_capacity(5 + 1 + 4 + 4 + 4 + 16 + 12 + ciphertext.len());
        output.extend_from_slice(MAGIC_BYTES);
        output.push(FORMAT_VERSION);
        output.extend_from_slice(&self.m_cost.to_le_bytes());
        output.extend_from_slice(&self.t_cost.to_le_bytes());
        output.extend_from_slice(&self.p_cost.to_le_bytes());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Decrypt vault binary blob using AES-256-GCM
    pub fn decrypt_vault(&self, password: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Minimum length: 5 + 1 + 4 + 4 + 4 + 16 + 12 + 16 (GCM tag) = 62 bytes
        const MIN_HEADER_SIZE: usize = 5 + 1 + 4 + 4 + 4 + 16 + 12;
        const MIN_TOTAL_SIZE: usize = MIN_HEADER_SIZE + 16;

        if data.len() < MIN_TOTAL_SIZE {
            return Err(CryptoError::DataTooShort);
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

        let salt = &data[18..34];
        let nonce_bytes = &data[34..46];
        let ciphertext = &data[46..];

        // Derive key using the parameters stored in the file
        let engine = CryptoEngine::new(m_cost, t_cost, p_cost);
        let key = engine.derive_key(password, salt)?;

        let cipher = Aes256Gcm::new_from_slice(&key.0)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(nonce_bytes);

        // Authenticated decryption verifies the integrity tag automatically
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::TamperedOrInvalidKey)?;

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
}
