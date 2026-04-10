//! envcrypt-lib: Library for loading encrypted .env files
//!
//! # Usage
//! ```rust,ignore
//! use envcrypt_lib::EnvcryptLoader;
//!
//! // From config file (~/.envcrypt.yaml)
//! let loader = EnvcryptLoader::from_config(None).unwrap();
//!
//! // Or hardcoded key (hex string, 32 bytes = 64 hex chars)
//! let loader = EnvcryptLoader::from_key("your-64-char-hex-key").unwrap();
//!
//! // Load .env and set environment variables
//! loader.load(".env").unwrap();
//!
//! // Now accessible via std::env
//! let value = std::env::var("MY_VAR").unwrap();
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const ENCRYPTED_PREFIX: &str = "encrypted:";
const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

#[derive(Error, Debug)]
pub enum EnvcryptError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    #[error("Parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
}

pub type Result<T> = std::result::Result<T, EnvcryptError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub key: String,
}

impl Config {
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".envcrypt.yaml")
    }

    pub fn load(path: Option<&Path>) -> Result<Self> {
        let config_path = path
            .map(PathBuf::from)
            .unwrap_or_else(Self::default_path);

        let content = fs::read_to_string(&config_path).map_err(|e| {
            EnvcryptError::Config(format!(
                "Failed to read config at {}: {}",
                config_path.display(),
                e
            ))
        })?;

        serde_yaml::from_str(&content).map_err(|e| {
            EnvcryptError::Config(format!("Failed to parse config: {}", e))
        })
    }

    pub fn save(&self, path: Option<&Path>) -> Result<()> {
        let config_path = path
            .map(PathBuf::from)
            .unwrap_or_else(Self::default_path);

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_yaml::to_string(self)
            .map_err(|e| EnvcryptError::Config(format!("Failed to serialize config: {}", e)))?;

        fs::write(&config_path, content)?;
        Ok(())
    }
}

/// Main struct for loading encrypted .env files
#[derive(Clone, Debug)]
pub struct EnvcryptLoader {
    key: [u8; KEY_SIZE],
}

impl EnvcryptLoader {
    /// Create loader from config file (default: ~/.envcrypt.yaml)
    pub fn from_config(path: Option<&Path>) -> Result<Self> {
        let config = Config::load(path)?;
        Self::from_key(&config.key)
    }

    /// Create loader from hex-encoded key string
    pub fn from_key(hex_key: &str) -> Result<Self> {
        let key_bytes = hex::decode(hex_key.trim()).map_err(|e| {
            EnvcryptError::InvalidKey(format!("Invalid hex: {}", e))
        })?;

        if key_bytes.len() != KEY_SIZE {
            return Err(EnvcryptError::InvalidKey(format!(
                "Key must be {} bytes ({} hex chars), got {} bytes",
                KEY_SIZE,
                KEY_SIZE * 2,
                key_bytes.len()
            )));
        }

        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&key_bytes);
        Ok(Self { key })
    }

    /// Create loader from raw key bytes
    pub fn from_key_bytes(key: [u8; KEY_SIZE]) -> Self {
        Self { key }
    }

    /// Generate a new random key (hex encoded)
    pub fn generate_key() -> String {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        hex::encode(key)
    }

    /// Encrypt a plaintext value
    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| EnvcryptError::Encryption(format!("Cipher init failed: {}", e)))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| EnvcryptError::Encryption(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(format!("{}{}", ENCRYPTED_PREFIX, BASE64.encode(&combined)))
    }

    /// Decrypt an encrypted value (with or without prefix)
    pub fn decrypt(&self, encrypted: &str) -> Result<String> {
        let data = encrypted.strip_prefix(ENCRYPTED_PREFIX).unwrap_or(encrypted);

        let combined = BASE64.decode(data).map_err(|e| {
            EnvcryptError::Decryption(format!("Invalid base64: {}", e))
        })?;

        if combined.len() < NONCE_SIZE {
            return Err(EnvcryptError::Decryption("Data too short".to_string()));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| EnvcryptError::Decryption(format!("Cipher init failed: {}", e)))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| EnvcryptError::Decryption("Decryption failed (wrong key?)".to_string()))?;

        String::from_utf8(plaintext)
            .map_err(|e| EnvcryptError::Decryption(format!("Invalid UTF-8: {}", e)))
    }

    /// Load .env file and set environment variables (auto-decrypt encrypted values)
    pub fn load<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = fs::read_to_string(path.as_ref())?;
        self.load_from_str(&content)
    }

    /// Load from string content and set environment variables
    pub fn load_from_str(&self, content: &str) -> Result<()> {
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse KEY=VALUE
            let (key, value) = parse_env_line(line).ok_or_else(|| EnvcryptError::Parse {
                line: line_num + 1,
                message: "Invalid format, expected KEY=VALUE".to_string(),
            })?;

            // Decrypt if needed
            let final_value = if value.starts_with(ENCRYPTED_PREFIX) {
                self.decrypt(value)?
            } else {
                value.to_string()
            };

            // Set actual environment variable
            std::env::set_var(key, &final_value);
        }

        Ok(())
    }

    /// Encrypt all values in .env content
    pub fn encrypt_content(&self, content: &str) -> Result<String> {
        let mut output = String::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Preserve empty lines
            if trimmed.is_empty() {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Handle commented-out KEY=VALUE lines
            if trimmed.starts_with('#') {
                let after_hash = trimmed[1..].trim_start();
                if let Some((key, value)) = parse_env_line(after_hash) {
                    if !value.starts_with(ENCRYPTED_PREFIX) && !value.is_empty() {
                        let encrypted = self.encrypt(value)?;
                        output.push_str(&format!("# {}={}", key, encrypted));
                        output.push('\n');
                        continue;
                    }
                }
                output.push_str(line);
                output.push('\n');
                continue;
            }

            if let Some((key, value)) = parse_env_line(trimmed) {
                // Skip already encrypted values
                if value.starts_with(ENCRYPTED_PREFIX) || value.is_empty() {
                    output.push_str(line);
                } else {
                    let encrypted = self.encrypt(value)?;
                    output.push_str(&format!("{}={}", key, encrypted));
                }
            } else {
                // Preserve malformed lines as-is
                output.push_str(line);
            }
            output.push('\n');
        }

        Ok(output)
    }

    /// Decrypt all encrypted values in .env content
    pub fn decrypt_content(&self, content: &str) -> Result<String> {
        let mut output = String::new();

        for line in content.lines() {
            let trimmed = line.trim();

            // Preserve empty lines
            if trimmed.is_empty() {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Handle commented-out KEY=VALUE lines
            if trimmed.starts_with('#') {
                let after_hash = trimmed[1..].trim_start();
                if let Some((key, value)) = parse_env_line(after_hash) {
                    if value.starts_with(ENCRYPTED_PREFIX) {
                        let decrypted = self.decrypt(value)?;
                        output.push_str(&format!("# {}={}", key, decrypted));
                        output.push('\n');
                        continue;
                    }
                }
                output.push_str(line);
                output.push('\n');
                continue;
            }

            if let Some((key, value)) = parse_env_line(trimmed) {
                if value.starts_with(ENCRYPTED_PREFIX) {
                    let decrypted = self.decrypt(value)?;
                    output.push_str(&format!("{}={}", key, decrypted));
                } else {
                    output.push_str(line);
                }
            } else {
                output.push_str(line);
            }
            output.push('\n');
        }

        Ok(output)
    }
}

/// Parse a single env line: KEY=VALUE
fn parse_env_line(line: &str) -> Option<(&str, &str)> {
    let eq_pos = line.find('=')?;
    let key = line[..eq_pos].trim();
    let value = line[eq_pos + 1..].trim();

    // Strip optional quotes
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);

    if key.is_empty() {
        return None;
    }

    Some((key, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_loader() -> EnvcryptLoader {
        let key = EnvcryptLoader::generate_key();
        EnvcryptLoader::from_key(&key).unwrap()
    }

    // === Key Generation & Validation ===

    #[test]
    fn test_generate_key_length() {
        let key = EnvcryptLoader::generate_key();
        assert_eq!(key.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_generate_key_uniqueness() {
        let key1 = EnvcryptLoader::generate_key();
        let key2 = EnvcryptLoader::generate_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_invalid_key_too_short() {
        let result = EnvcryptLoader::from_key("abcd1234");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EnvcryptError::InvalidKey(_)));
    }

    #[test]
    fn test_invalid_key_not_hex() {
        let result = EnvcryptLoader::from_key("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_key_with_whitespace() {
        let key = EnvcryptLoader::generate_key();
        let key_with_space = format!("  {}  ", key);
        let result = EnvcryptLoader::from_key(&key_with_space);
        assert!(result.is_ok());
    }

    // === Encryption & Decryption ===

    #[test]
    fn test_encrypt_decrypt_basic() {
        let loader = create_loader();
        let plaintext = "my-secret-value-123";
        let encrypted = loader.encrypt(plaintext).unwrap();

        assert!(encrypted.starts_with(ENCRYPTED_PREFIX));
        
        let decrypted = loader.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let loader = create_loader();
        let encrypted = loader.encrypt("").unwrap();
        let decrypted = loader.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let loader = create_loader();
        let plaintext = "こんにちは世界 🔐 مرحبا";
        let encrypted = loader.encrypt(plaintext).unwrap();
        let decrypted = loader.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_special_chars() {
        let loader = create_loader();
        let plaintext = "password=abc&key=xyz\n\t\"quotes\"";
        let encrypted = loader.encrypt(plaintext).unwrap();
        let decrypted = loader.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_long_value() {
        let loader = create_loader();
        let plaintext = "x".repeat(10000);
        let encrypted = loader.encrypt(&plaintext).unwrap();
        let decrypted = loader.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_without_prefix() {
        let loader = create_loader();
        let encrypted = loader.encrypt("test").unwrap();
        let without_prefix = encrypted.strip_prefix(ENCRYPTED_PREFIX).unwrap();
        let decrypted = loader.decrypt(without_prefix).unwrap();
        assert_eq!(decrypted, "test");
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let loader1 = create_loader();
        let loader2 = create_loader();
        
        let encrypted = loader1.encrypt("secret").unwrap();
        let result = loader2.decrypt(&encrypted);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EnvcryptError::Decryption(_)));
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let loader = create_loader();
        let result = loader.decrypt("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated_data() {
        let loader = create_loader();
        let result = loader.decrypt("YWJj"); // "abc" in base64, too short
        assert!(result.is_err());
    }

    #[test]
    fn test_same_plaintext_different_ciphertext() {
        let loader = create_loader();
        let encrypted1 = loader.encrypt("same").unwrap();
        let encrypted2 = loader.encrypt("same").unwrap();
        // Due to random nonce, ciphertexts should differ
        assert_ne!(encrypted1, encrypted2);
        // But both decrypt to same value
        assert_eq!(loader.decrypt(&encrypted1).unwrap(), "same");
        assert_eq!(loader.decrypt(&encrypted2).unwrap(), "same");
    }

    // === Environment Variable Loading ===

    #[test]
    fn test_load_and_set_env() {
        let loader = create_loader();
        let encrypted_val = loader.encrypt("secret123").unwrap();
        let content = format!(
            "# Comment\nTEST_PLAIN_VAR=hello\nTEST_ENCRYPTED_VAR={}\n",
            encrypted_val
        );

        loader.load_from_str(&content).unwrap();

        assert_eq!(std::env::var("TEST_PLAIN_VAR").unwrap(), "hello");
        assert_eq!(std::env::var("TEST_ENCRYPTED_VAR").unwrap(), "secret123");
    }

    #[test]
    fn test_load_with_quotes() {
        let loader = create_loader();
        let content = r#"
            DOUBLE_QUOTED="hello world"
            SINGLE_QUOTED='foo bar'
            NO_QUOTES=plain
        "#;
        
        loader.load_from_str(content).unwrap();
        
        assert_eq!(std::env::var("DOUBLE_QUOTED").unwrap(), "hello world");
        assert_eq!(std::env::var("SINGLE_QUOTED").unwrap(), "foo bar");
        assert_eq!(std::env::var("NO_QUOTES").unwrap(), "plain");
    }

    #[test]
    fn test_load_skips_comments_and_empty() {
        let loader = create_loader();
        let content = r#"
            # This is a comment
            
            VALID_KEY=value
            
            # Another comment
        "#;
        
        loader.load_from_str(content).unwrap();
        assert_eq!(std::env::var("VALID_KEY").unwrap(), "value");
    }

    #[test]
    fn test_load_mixed_encrypted_plain() {
        let loader = create_loader();
        let encrypted = loader.encrypt("encrypted_value").unwrap();
        let content = format!(
            "MIX_PLAIN=plain_value\nMIX_ENCRYPTED={}\n",
            encrypted
        );

        loader.load_from_str(&content).unwrap();

        assert_eq!(std::env::var("MIX_PLAIN").unwrap(), "plain_value");
        assert_eq!(std::env::var("MIX_ENCRYPTED").unwrap(), "encrypted_value");
    }

    // === Content Encryption/Decryption ===

    #[test]
    fn test_encrypt_content() {
        let loader = create_loader();
        let content = "DB_URL=postgres://localhost\nAPI_KEY=secret123\n";
        let encrypted = loader.encrypt_content(content).unwrap();

        assert!(encrypted.contains("DB_URL=encrypted:"));
        assert!(encrypted.contains("API_KEY=encrypted:"));

        let decrypted = loader.decrypt_content(&encrypted).unwrap();
        assert!(decrypted.contains("DB_URL=postgres://localhost"));
        assert!(decrypted.contains("API_KEY=secret123"));
    }

    #[test]
    fn test_encrypt_content_preserves_comments() {
        let loader = create_loader();
        let content = "# Database settings\nDB_URL=localhost\n\n# API\nAPI_KEY=secret\n";
        let encrypted = loader.encrypt_content(content).unwrap();

        assert!(encrypted.contains("# Database settings"));
        assert!(encrypted.contains("# API"));
    }

    #[test]
    fn test_encrypt_content_skips_already_encrypted() {
        let loader = create_loader();
        let encrypted_val = loader.encrypt("already").unwrap();
        let content = format!("ALREADY={}\nPLAIN=value\n", encrypted_val);
        
        let result = loader.encrypt_content(&content).unwrap();
        
        // Count occurrences of encrypted: - should still be 2 (one original, one new)
        let count = result.matches("encrypted:").count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_encrypt_content_commented_key_value() {
        let loader = create_loader();
        let content = "# DB_URL=postgres://localhost\nAPI_KEY=secret\n";
        let encrypted = loader.encrypt_content(content).unwrap();

        assert!(encrypted.contains("# DB_URL=encrypted:"));
        assert!(encrypted.contains("API_KEY=encrypted:"));

        let decrypted = loader.decrypt_content(&encrypted).unwrap();
        assert!(decrypted.contains("# DB_URL=postgres://localhost"));
        assert!(decrypted.contains("API_KEY=secret"));
    }

    #[test]
    fn test_encrypt_content_preserves_pure_comments() {
        let loader = create_loader();
        let content = "# This is a note\n# Another comment\nKEY=value\n";
        let encrypted = loader.encrypt_content(content).unwrap();

        assert!(encrypted.contains("# This is a note"));
        assert!(encrypted.contains("# Another comment"));
    }

    #[test]
    fn test_encrypt_content_commented_already_encrypted() {
        let loader = create_loader();
        let encrypted_val = loader.encrypt("secret").unwrap();
        let content = format!("# ALREADY={}\n", encrypted_val);

        let result = loader.encrypt_content(&content).unwrap();
        // Should not double-encrypt
        assert_eq!(result.matches("encrypted:").count(), 1);
    }

    #[test]
    fn test_decrypt_content_skips_plain() {
        let loader = create_loader();
        let content = "PLAIN_VAR=plain_value\n";
        let decrypted = loader.decrypt_content(content).unwrap();
        assert!(decrypted.contains("PLAIN_VAR=plain_value"));
    }

    #[test]
    fn test_encrypt_content_skips_empty_values() {
        let loader = create_loader();
        let content = "EMPTY=\nQUOTED_EMPTY=\"\"\nSINGLE_EMPTY=''\nHAS_VALUE=secret\n";
        let encrypted = loader.encrypt_content(content).unwrap();

        assert!(encrypted.contains("EMPTY=\n"));
        assert!(encrypted.contains("QUOTED_EMPTY=\"\"\n"));
        assert!(encrypted.contains("SINGLE_EMPTY=''\n"));
        assert!(encrypted.contains("HAS_VALUE=encrypted:"));
    }

    #[test]
    fn test_encrypt_content_skips_commented_empty_values() {
        let loader = create_loader();
        let content = "# EMPTY=\n# QUOTED=\"\"\nAPI_KEY=secret\n";
        let encrypted = loader.encrypt_content(content).unwrap();

        assert!(encrypted.contains("# EMPTY=\n"));
        assert!(encrypted.contains("# QUOTED=\"\"\n"));
        assert!(encrypted.contains("API_KEY=encrypted:"));
    }

    // === Parse Line ===

    #[test]
    fn test_parse_env_line_basic() {
        assert_eq!(parse_env_line("KEY=value"), Some(("KEY", "value")));
    }

    #[test]
    fn test_parse_env_line_with_equals_in_value() {
        assert_eq!(parse_env_line("KEY=a=b=c"), Some(("KEY", "a=b=c")));
    }

    #[test]
    fn test_parse_env_line_empty_value() {
        assert_eq!(parse_env_line("KEY="), Some(("KEY", "")));
    }

    #[test]
    fn test_parse_env_line_no_equals() {
        assert_eq!(parse_env_line("INVALID"), None);
    }

    #[test]
    fn test_parse_env_line_empty_key() {
        assert_eq!(parse_env_line("=value"), None);
    }

    #[test]
    fn test_parse_env_line_with_spaces() {
        assert_eq!(parse_env_line("  KEY  =  value  "), Some(("KEY", "value")));
    }

    // === Config ===

    #[test]
    fn test_config_default_path() {
        let path = Config::default_path();
        assert!(path.ends_with(".envcrypt.yaml"));
    }

    // === from_key_bytes ===

    #[test]
    fn test_from_key_bytes() {
        let key_bytes = [0u8; 32];
        let loader = EnvcryptLoader::from_key_bytes(key_bytes);
        
        let encrypted = loader.encrypt("test").unwrap();
        let decrypted = loader.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, "test");
    }
}
