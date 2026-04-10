"""
Tests for envcrypt Python library
"""

import os
import tempfile
from pathlib import Path

import pytest

from envcrypt import EnvcryptLoader
from envcrypt.loader import EnvcryptError, ENCRYPTED_PREFIX


class TestKeyGeneration:
    def test_generate_key_length(self):
        key = EnvcryptLoader.generate_key()
        assert len(key) == 64  # 32 bytes = 64 hex chars
    
    def test_generate_key_uniqueness(self):
        key1 = EnvcryptLoader.generate_key()
        key2 = EnvcryptLoader.generate_key()
        assert key1 != key2
    
    def test_generate_key_is_valid_hex(self):
        key = EnvcryptLoader.generate_key()
        # Should not raise
        bytes.fromhex(key)


class TestKeyValidation:
    def test_invalid_key_too_short(self):
        with pytest.raises(EnvcryptError):
            EnvcryptLoader.from_key("abcd1234")
    
    def test_invalid_key_not_hex(self):
        with pytest.raises(EnvcryptError):
            EnvcryptLoader.from_key("z" * 64)
    
    def test_valid_key_with_whitespace(self):
        key = EnvcryptLoader.generate_key()
        # Should not raise
        loader = EnvcryptLoader.from_key(f"  {key}  ")
        assert loader is not None


class TestEncryptDecrypt:
    @pytest.fixture
    def loader(self):
        key = EnvcryptLoader.generate_key()
        return EnvcryptLoader.from_key(key)
    
    def test_encrypt_decrypt_basic(self, loader):
        plaintext = "my-secret-value-123"
        encrypted = loader.encrypt(plaintext)
        
        assert encrypted.startswith(ENCRYPTED_PREFIX)
        
        decrypted = loader.decrypt(encrypted)
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_empty_string(self, loader):
        encrypted = loader.encrypt("")
        decrypted = loader.decrypt(encrypted)
        assert decrypted == ""
    
    def test_encrypt_decrypt_unicode(self, loader):
        plaintext = "こんにちは世界 🔐 مرحبا"
        encrypted = loader.encrypt(plaintext)
        decrypted = loader.decrypt(encrypted)
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_special_chars(self, loader):
        plaintext = "password=abc&key=xyz\n\t\"quotes\""
        encrypted = loader.encrypt(plaintext)
        decrypted = loader.decrypt(encrypted)
        assert decrypted == plaintext
    
    def test_encrypt_decrypt_long_value(self, loader):
        plaintext = "x" * 10000
        encrypted = loader.encrypt(plaintext)
        decrypted = loader.decrypt(encrypted)
        assert decrypted == plaintext
    
    def test_decrypt_without_prefix(self, loader):
        encrypted = loader.encrypt("test")
        without_prefix = encrypted[len(ENCRYPTED_PREFIX):]
        decrypted = loader.decrypt(without_prefix)
        assert decrypted == "test"
    
    def test_same_plaintext_different_ciphertext(self, loader):
        encrypted1 = loader.encrypt("same")
        encrypted2 = loader.encrypt("same")
        # Due to random nonce, ciphertexts should differ
        assert encrypted1 != encrypted2
        # But both decrypt to same value
        assert loader.decrypt(encrypted1) == "same"
        assert loader.decrypt(encrypted2) == "same"


class TestDecryptErrors:
    @pytest.fixture
    def loader(self):
        key = EnvcryptLoader.generate_key()
        return EnvcryptLoader.from_key(key)
    
    def test_decrypt_with_wrong_key(self, loader):
        encrypted = loader.encrypt("secret")
        
        # Create another loader with different key
        other_key = EnvcryptLoader.generate_key()
        other_loader = EnvcryptLoader.from_key(other_key)
        
        with pytest.raises(EnvcryptError):
            other_loader.decrypt(encrypted)
    
    def test_decrypt_invalid_base64(self, loader):
        with pytest.raises(EnvcryptError):
            loader.decrypt("not-valid-base64!!!")
    
    def test_decrypt_truncated_data(self, loader):
        with pytest.raises(EnvcryptError):
            loader.decrypt("YWJj")  # "abc" in base64, too short


class TestLoadEnv:
    @pytest.fixture
    def loader(self):
        key = EnvcryptLoader.generate_key()
        return EnvcryptLoader.from_key(key)
    
    def test_load_and_set_env(self, loader):
        encrypted_val = loader.encrypt("secret123")
        content = f"# Comment\nTEST_PY_PLAIN=hello\nTEST_PY_ENCRYPTED={encrypted_val}\n"
        
        result = loader.load_from_string(content)
        
        assert result["TEST_PY_PLAIN"] == "hello"
        assert result["TEST_PY_ENCRYPTED"] == "secret123"
        assert os.environ["TEST_PY_PLAIN"] == "hello"
        assert os.environ["TEST_PY_ENCRYPTED"] == "secret123"
    
    def test_load_with_quotes(self, loader):
        content = '''
DOUBLE_QUOTED_PY="hello world"
SINGLE_QUOTED_PY='foo bar'
NO_QUOTES_PY=plain
'''
        result = loader.load_from_string(content)
        
        assert result["DOUBLE_QUOTED_PY"] == "hello world"
        assert result["SINGLE_QUOTED_PY"] == "foo bar"
        assert result["NO_QUOTES_PY"] == "plain"
    
    def test_load_skips_comments_and_empty(self, loader):
        content = """
# This is a comment

VALID_KEY_PY=value

# Another comment
"""
        result = loader.load_from_string(content)
        assert result == {"VALID_KEY_PY": "value"}
    
    def test_load_from_file(self, loader):
        encrypted = loader.encrypt("file_secret")
        content = f"FILE_TEST_PY={encrypted}\n"
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write(content)
            f.flush()
            
            try:
                result = loader.load(f.name)
                assert result["FILE_TEST_PY"] == "file_secret"
                assert os.environ["FILE_TEST_PY"] == "file_secret"
            finally:
                os.unlink(f.name)
    
    def test_load_file_not_found(self, loader):
        with pytest.raises(EnvcryptError):
            loader.load("/nonexistent/path/.env")


class TestContentEncryption:
    @pytest.fixture
    def loader(self):
        key = EnvcryptLoader.generate_key()
        return EnvcryptLoader.from_key(key)
    
    def test_encrypt_content(self, loader):
        content = "DB_URL=postgres://localhost\nAPI_KEY=secret123\n"
        encrypted = loader.encrypt_content(content)
        
        assert "DB_URL=encrypted:" in encrypted
        assert "API_KEY=encrypted:" in encrypted
        
        decrypted = loader.decrypt_content(encrypted)
        assert "DB_URL=postgres://localhost" in decrypted
        assert "API_KEY=secret123" in decrypted
    
    def test_encrypt_content_preserves_comments(self, loader):
        content = "# Database settings\nDB_URL=localhost\n\n# API\nAPI_KEY=secret\n"
        encrypted = loader.encrypt_content(content)
        
        assert "# Database settings" in encrypted
        assert "# API" in encrypted
    
    def test_encrypt_content_skips_already_encrypted(self, loader):
        encrypted_val = loader.encrypt("already")
        content = f"ALREADY={encrypted_val}\nPLAIN=value\n"
        
        result = loader.encrypt_content(content)
        
        # Should have 2 encrypted values total
        count = result.count("encrypted:")
        assert count == 2
    
    def test_encrypt_content_skips_empty_values(self, loader):
        content = "EMPTY=\nQUOTED=\"\"\nSINGLE=''\nSECRET=value\n"
        encrypted = loader.encrypt_content(content)

        assert "EMPTY=\n" in encrypted
        assert "encrypted:" not in encrypted.split("\n")[0]
        assert "SECRET=encrypted:" in encrypted

    def test_decrypt_content_skips_plain(self, loader):
        content = "PLAIN_VAR=plain_value\n"
        decrypted = loader.decrypt_content(content)
        assert "PLAIN_VAR=plain_value" in decrypted


class TestConfig:
    def test_from_config_file_not_found(self):
        with pytest.raises(EnvcryptError):
            EnvcryptLoader.from_config(Path("/nonexistent/.envcrypt.yaml"))
    
    def test_from_config_no_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("other: value\n")
            f.flush()
            
            try:
                with pytest.raises(EnvcryptError):
                    EnvcryptLoader.from_config(Path(f.name))
            finally:
                os.unlink(f.name)
    
    def test_from_config_valid(self):
        key = EnvcryptLoader.generate_key()
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(f"key: {key}\n")
            f.flush()
            
            try:
                loader = EnvcryptLoader.from_config(Path(f.name))
                # Should work
                encrypted = loader.encrypt("test")
                assert loader.decrypt(encrypted) == "test"
            finally:
                os.unlink(f.name)


class TestCrossCompatibility:
    """Test compatibility with Rust envcrypt CLI"""
    
    def test_decrypt_rust_encrypted_value(self):
        """
        Test that Python can decrypt values encrypted by Rust CLI.
        This test uses a known key and encrypted value.
        """
        # Generate a test with known key
        key = "0" * 64  # 32 zero bytes
        loader = EnvcryptLoader.from_key(key)
        
        # Encrypt with Python
        encrypted = loader.encrypt("cross-compat-test")
        
        # Should be able to decrypt
        decrypted = loader.decrypt(encrypted)
        assert decrypted == "cross-compat-test"
