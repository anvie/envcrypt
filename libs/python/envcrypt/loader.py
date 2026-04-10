"""
EnvcryptLoader - Load and decrypt .env files
"""

import os
import base64
import secrets
from pathlib import Path
from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENCRYPTED_PREFIX = "encrypted:"
NONCE_SIZE = 12
KEY_SIZE = 32


class EnvcryptError(Exception):
    """Base exception for envcrypt errors"""
    pass


class EnvcryptLoader:
    """
    Loader for encrypted .env files.
    
    Usage:
        # From config file (~/.envcrypt.yaml)
        loader = EnvcryptLoader.from_config()
        loader.load(".env")
        
        # From hex key
        loader = EnvcryptLoader.from_key("your-64-char-hex-key")
        loader.load(".env")
        
        # Now access via os.environ
        db_url = os.environ["DATABASE_URL"]
    """
    
    def __init__(self, key: bytes):
        """Initialize with raw key bytes (32 bytes)"""
        if len(key) != KEY_SIZE:
            raise EnvcryptError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
        self._key = key
        self._cipher = AESGCM(key)
    
    @classmethod
    def from_key(cls, hex_key: str) -> "EnvcryptLoader":
        """Create loader from hex-encoded key string (64 chars)"""
        hex_key = hex_key.strip()
        try:
            key_bytes = bytes.fromhex(hex_key)
        except ValueError as e:
            raise EnvcryptError(f"Invalid hex key: {e}")
        
        if len(key_bytes) != KEY_SIZE:
            raise EnvcryptError(
                f"Key must be {KEY_SIZE} bytes ({KEY_SIZE * 2} hex chars), "
                f"got {len(key_bytes)} bytes"
            )
        return cls(key_bytes)
    
    @classmethod
    def from_config(cls, path: Optional[Path] = None) -> "EnvcryptLoader":
        """Load key from config file (default: ~/.envcrypt.yaml)"""
        if path is None:
            path = Path.home() / ".envcrypt.yaml"
        
        if not path.exists():
            raise EnvcryptError(f"Config not found: {path}")
        
        # Simple YAML parsing (avoid extra dependency)
        content = path.read_text()
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("key:"):
                key_value = line[4:].strip().strip('"').strip("'")
                return cls.from_key(key_value)
        
        raise EnvcryptError(f"No 'key' found in config: {path}")
    
    @staticmethod
    def generate_key() -> str:
        """Generate a new random key (hex encoded)"""
        return secrets.token_hex(KEY_SIZE)
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt a plaintext value, returns prefixed encrypted string"""
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = self._cipher.encrypt(nonce, plaintext.encode("utf-8"), None)
        combined = nonce + ciphertext
        encoded = base64.b64encode(combined).decode("ascii")
        return f"{ENCRYPTED_PREFIX}{encoded}"
    
    def decrypt(self, encrypted: str) -> str:
        """Decrypt an encrypted value (with or without prefix)"""
        if encrypted.startswith(ENCRYPTED_PREFIX):
            encrypted = encrypted[len(ENCRYPTED_PREFIX):]
        
        try:
            combined = base64.b64decode(encrypted)
        except Exception as e:
            raise EnvcryptError(f"Invalid base64: {e}")
        
        if len(combined) < NONCE_SIZE:
            raise EnvcryptError("Encrypted data too short")
        
        nonce = combined[:NONCE_SIZE]
        ciphertext = combined[NONCE_SIZE:]
        
        try:
            plaintext = self._cipher.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except Exception:
            raise EnvcryptError("Decryption failed (wrong key?)")
    
    def load(self, path: str, override: bool = True) -> Dict[str, str]:
        """
        Load .env file, decrypt encrypted values, and set environment variables.
        
        Args:
            path: Path to .env file
            override: If True, override existing env vars (default: True)
        
        Returns:
            Dict of all loaded key-value pairs
        """
        env_path = Path(path)
        if not env_path.exists():
            raise EnvcryptError(f"File not found: {path}")
        
        content = env_path.read_text()
        return self.load_from_string(content, override=override)
    
    def load_from_string(self, content: str, override: bool = True) -> Dict[str, str]:
        """
        Load from string content, decrypt, and set environment variables.
        
        Args:
            content: .env file content
            override: If True, override existing env vars
        
        Returns:
            Dict of all loaded key-value pairs
        """
        result = {}
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            
            # Parse KEY=VALUE
            if "=" not in line:
                continue  # Skip malformed lines
            
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            
            if not key:
                continue
            
            # Strip quotes
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            
            # Decrypt if needed
            if value.startswith(ENCRYPTED_PREFIX):
                try:
                    value = self.decrypt(value)
                except EnvcryptError as e:
                    raise EnvcryptError(f"Line {line_num}: {e}")
            
            result[key] = value
            
            # Set environment variable
            if override or key not in os.environ:
                os.environ[key] = value
        
        return result
    
    def encrypt_content(self, content: str) -> str:
        """Encrypt all values in .env content"""
        lines = []
        
        for line in content.splitlines():
            stripped = line.strip()
            
            # Preserve empty lines and comments
            if not stripped or stripped.startswith("#"):
                lines.append(line)
                continue
            
            if "=" not in stripped:
                lines.append(line)
                continue
            
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()
            
            # Strip quotes for encryption
            quoted = False
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
                quoted = True
            
            # Skip already encrypted or empty values
            if value.startswith(ENCRYPTED_PREFIX) or value == "":
                lines.append(line)
            else:
                encrypted = self.encrypt(value)
                lines.append(f"{key}={encrypted}")
        
        return "\n".join(lines) + "\n"
    
    def decrypt_content(self, content: str) -> str:
        """Decrypt all encrypted values in .env content"""
        lines = []
        
        for line in content.splitlines():
            stripped = line.strip()
            
            # Preserve empty lines and comments
            if not stripped or stripped.startswith("#"):
                lines.append(line)
                continue
            
            if "=" not in stripped:
                lines.append(line)
                continue
            
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()
            
            if value.startswith(ENCRYPTED_PREFIX):
                decrypted = self.decrypt(value)
                lines.append(f"{key}={decrypted}")
            else:
                lines.append(line)
        
        return "\n".join(lines) + "\n"


# Convenience functions

def load(path: str, key: Optional[str] = None, config: Optional[Path] = None) -> Dict[str, str]:
    """
    Load encrypted .env file and set environment variables.
    
    Args:
        path: Path to .env file
        key: Hex-encoded key (optional, uses config if not provided)
        config: Path to config file (optional, defaults to ~/.envcrypt.yaml)
    
    Returns:
        Dict of loaded key-value pairs
    """
    if key:
        loader = EnvcryptLoader.from_key(key)
    else:
        loader = EnvcryptLoader.from_config(config)
    
    return loader.load(path)


def load_from_config(path: str, config: Optional[Path] = None) -> Dict[str, str]:
    """
    Load encrypted .env using key from config file.
    
    Args:
        path: Path to .env file
        config: Path to config file (optional, defaults to ~/.envcrypt.yaml)
    
    Returns:
        Dict of loaded key-value pairs
    """
    loader = EnvcryptLoader.from_config(config)
    return loader.load(path)
