import { describe, it, expect, beforeEach } from "vitest";
import { writeFileSync, unlinkSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  EnvcryptLoader,
  EnvcryptError,
  ENCRYPTED_PREFIX,
} from "../src/index";
import { parseEnvLine } from "../src/parser";

function createLoader(): EnvcryptLoader {
  const key = EnvcryptLoader.generateKey();
  return EnvcryptLoader.fromKey(key);
}

// === Key Generation & Validation ===

describe("Key Generation", () => {
  it("generates 64 hex char key", () => {
    const key = EnvcryptLoader.generateKey();
    expect(key).toHaveLength(64);
    expect(/^[0-9a-f]+$/.test(key)).toBe(true);
  });

  it("generates unique keys", () => {
    const key1 = EnvcryptLoader.generateKey();
    const key2 = EnvcryptLoader.generateKey();
    expect(key1).not.toBe(key2);
  });
});

describe("Key Validation", () => {
  it("rejects too-short key", () => {
    expect(() => EnvcryptLoader.fromKey("abcd1234")).toThrow(EnvcryptError);
  });

  it("rejects non-hex key", () => {
    expect(() => EnvcryptLoader.fromKey("z".repeat(64))).toThrow(EnvcryptError);
  });

  it("accepts key with whitespace", () => {
    const key = EnvcryptLoader.generateKey();
    const loader = EnvcryptLoader.fromKey(`  ${key}  `);
    expect(loader).toBeInstanceOf(EnvcryptLoader);
  });
});

// === Encryption & Decryption ===

describe("Encrypt/Decrypt", () => {
  let loader: EnvcryptLoader;
  beforeEach(() => {
    loader = createLoader();
  });

  it("basic round-trip", () => {
    const plaintext = "my-secret-value-123";
    const encrypted = loader.encrypt(plaintext);
    expect(encrypted.startsWith(ENCRYPTED_PREFIX)).toBe(true);
    expect(loader.decrypt(encrypted)).toBe(plaintext);
  });

  it("empty string", () => {
    const encrypted = loader.encrypt("");
    expect(loader.decrypt(encrypted)).toBe("");
  });

  it("unicode", () => {
    const plaintext = "こんにちは世界 🔐 مرحبا";
    const encrypted = loader.encrypt(plaintext);
    expect(loader.decrypt(encrypted)).toBe(plaintext);
  });

  it("special characters", () => {
    const plaintext = 'password=abc&key=xyz\n\t"quotes"';
    const encrypted = loader.encrypt(plaintext);
    expect(loader.decrypt(encrypted)).toBe(plaintext);
  });

  it("long value", () => {
    const plaintext = "x".repeat(10000);
    const encrypted = loader.encrypt(plaintext);
    expect(loader.decrypt(encrypted)).toBe(plaintext);
  });

  it("decrypt without prefix", () => {
    const encrypted = loader.encrypt("test");
    const withoutPrefix = encrypted.slice(ENCRYPTED_PREFIX.length);
    expect(loader.decrypt(withoutPrefix)).toBe("test");
  });

  it("same plaintext produces different ciphertext", () => {
    const encrypted1 = loader.encrypt("same");
    const encrypted2 = loader.encrypt("same");
    expect(encrypted1).not.toBe(encrypted2);
    expect(loader.decrypt(encrypted1)).toBe("same");
    expect(loader.decrypt(encrypted2)).toBe("same");
  });
});

describe("Decrypt Errors", () => {
  let loader: EnvcryptLoader;
  beforeEach(() => {
    loader = createLoader();
  });

  it("wrong key fails", () => {
    const encrypted = loader.encrypt("secret");
    const otherLoader = createLoader();
    expect(() => otherLoader.decrypt(encrypted)).toThrow(EnvcryptError);
  });

  it("invalid base64 fails", () => {
    expect(() => loader.decrypt("not-valid-base64!!!")).toThrow(EnvcryptError);
  });

  it("truncated data fails", () => {
    expect(() => loader.decrypt("YWJj")).toThrow(EnvcryptError);
  });
});

// === Environment Variable Loading ===

describe("Load Env", () => {
  let loader: EnvcryptLoader;
  beforeEach(() => {
    loader = createLoader();
  });

  it("loads and sets env vars", () => {
    const encrypted = loader.encrypt("secret123");
    const content = `# Comment\nTEST_TS_PLAIN=hello\nTEST_TS_ENCRYPTED=${encrypted}\n`;

    const result = loader.loadFromString(content);

    expect(result["TEST_TS_PLAIN"]).toBe("hello");
    expect(result["TEST_TS_ENCRYPTED"]).toBe("secret123");
    expect(process.env["TEST_TS_PLAIN"]).toBe("hello");
    expect(process.env["TEST_TS_ENCRYPTED"]).toBe("secret123");
  });

  it("handles quotes", () => {
    const content = `DOUBLE_QUOTED_TS="hello world"\nSINGLE_QUOTED_TS='foo bar'\nNO_QUOTES_TS=plain\n`;
    const result = loader.loadFromString(content);

    expect(result["DOUBLE_QUOTED_TS"]).toBe("hello world");
    expect(result["SINGLE_QUOTED_TS"]).toBe("foo bar");
    expect(result["NO_QUOTES_TS"]).toBe("plain");
  });

  it("skips comments and empty lines", () => {
    const content = `\n# This is a comment\n\nVALID_KEY_TS=value\n\n# Another comment\n`;
    const result = loader.loadFromString(content);
    expect(result).toEqual({ VALID_KEY_TS: "value" });
  });

  it("loads from file", () => {
    const dir = mkdtempSync(join(tmpdir(), "envcrypt-test-"));
    const filePath = join(dir, ".env");
    const encrypted = loader.encrypt("file_secret");
    writeFileSync(filePath, `FILE_TEST_TS=${encrypted}\n`);

    try {
      const result = loader.load(filePath);
      expect(result["FILE_TEST_TS"]).toBe("file_secret");
      expect(process.env["FILE_TEST_TS"]).toBe("file_secret");
    } finally {
      unlinkSync(filePath);
    }
  });

  it("throws on file not found", () => {
    expect(() => loader.load("/nonexistent/path/.env")).toThrow(EnvcryptError);
  });

  it("loads mixed encrypted and plain", () => {
    const encrypted = loader.encrypt("encrypted_value");
    const content = `MIX_PLAIN_TS=plain_value\nMIX_ENCRYPTED_TS=${encrypted}\n`;

    const result = loader.loadFromString(content);

    expect(result["MIX_PLAIN_TS"]).toBe("plain_value");
    expect(result["MIX_ENCRYPTED_TS"]).toBe("encrypted_value");
  });
});

// === Content Encryption/Decryption ===

describe("Content Encryption", () => {
  let loader: EnvcryptLoader;
  beforeEach(() => {
    loader = createLoader();
  });

  it("encrypts content", () => {
    const content = "DB_URL=postgres://localhost\nAPI_KEY=secret123\n";
    const encrypted = loader.encryptContent(content);

    expect(encrypted).toContain("DB_URL=encrypted:");
    expect(encrypted).toContain("API_KEY=encrypted:");

    const decrypted = loader.decryptContent(encrypted);
    expect(decrypted).toContain("DB_URL=postgres://localhost");
    expect(decrypted).toContain("API_KEY=secret123");
  });

  it("preserves comments", () => {
    const content =
      "# Database settings\nDB_URL=localhost\n\n# API\nAPI_KEY=secret\n";
    const encrypted = loader.encryptContent(content);

    expect(encrypted).toContain("# Database settings");
    expect(encrypted).toContain("# API");
  });

  it("skips already encrypted", () => {
    const encryptedVal = loader.encrypt("already");
    const content = `ALREADY=${encryptedVal}\nPLAIN=value\n`;

    const result = loader.encryptContent(content);
    const count = (result.match(/encrypted:/g) || []).length;
    expect(count).toBe(2);
  });

  it("encrypts commented-out KEY=VALUE lines", () => {
    const content = "# DB_URL=postgres://localhost\nAPI_KEY=secret\n";
    const encrypted = loader.encryptContent(content);

    expect(encrypted).toContain("# DB_URL=encrypted:");
    expect(encrypted).toContain("API_KEY=encrypted:");

    const decrypted = loader.decryptContent(encrypted);
    expect(decrypted).toContain("# DB_URL=postgres://localhost");
    expect(decrypted).toContain("API_KEY=secret");
  });

  it("preserves pure comments", () => {
    const content = "# This is a note\n# Another comment\nKEY=value\n";
    const encrypted = loader.encryptContent(content);

    expect(encrypted).toContain("# This is a note");
    expect(encrypted).toContain("# Another comment");
  });

  it("does not double-encrypt commented values", () => {
    const encryptedVal = loader.encrypt("secret");
    const content = `# ALREADY=${encryptedVal}\n`;

    const result = loader.encryptContent(content);
    const count = (result.match(/encrypted:/g) || []).length;
    expect(count).toBe(1);
  });

  it("skips encryption of empty values", () => {
    const content = 'EMPTY=\nQUOTED=""\nSINGLE=\'\'\nSECRET=value\n';
    const encrypted = loader.encryptContent(content);

    expect(encrypted).toContain("EMPTY=\n");
    expect(encrypted).not.toContain("EMPTY=encrypted:");
    expect(encrypted).toContain("SECRET=encrypted:");
  });

  it("skips encryption of commented empty values", () => {
    const content = '# EMPTY=\n# QUOTED=""\nSECRET=value\n';
    const encrypted = loader.encryptContent(content);

    expect(encrypted).toContain("# EMPTY=\n");
    expect(encrypted).not.toContain("# EMPTY=encrypted:");
  });

  it("decrypt content skips plain values", () => {
    const content = "PLAIN_VAR=plain_value\n";
    const decrypted = loader.decryptContent(content);
    expect(decrypted).toContain("PLAIN_VAR=plain_value");
  });
});

// === Config ===

describe("Config", () => {
  it("throws on missing config", () => {
    expect(() =>
      EnvcryptLoader.fromConfig("/nonexistent/.envcrypt.yaml")
    ).toThrow(EnvcryptError);
  });

  it("throws on config without key", () => {
    const dir = mkdtempSync(join(tmpdir(), "envcrypt-test-"));
    const filePath = join(dir, ".envcrypt.yaml");
    writeFileSync(filePath, "other: value\n");

    try {
      expect(() => EnvcryptLoader.fromConfig(filePath)).toThrow(EnvcryptError);
    } finally {
      unlinkSync(filePath);
    }
  });

  it("loads valid config", () => {
    const key = EnvcryptLoader.generateKey();
    const dir = mkdtempSync(join(tmpdir(), "envcrypt-test-"));
    const filePath = join(dir, ".envcrypt.yaml");
    writeFileSync(filePath, `key: ${key}\n`);

    try {
      const loader = EnvcryptLoader.fromConfig(filePath);
      const encrypted = loader.encrypt("test");
      expect(loader.decrypt(encrypted)).toBe("test");
    } finally {
      unlinkSync(filePath);
    }
  });
});

// === Cross Compatibility ===

describe("Cross Compatibility", () => {
  it("encrypt/decrypt with known key", () => {
    const key = "0".repeat(64);
    const loader = EnvcryptLoader.fromKey(key);

    const encrypted = loader.encrypt("cross-compat-test");
    const decrypted = loader.decrypt(encrypted);
    expect(decrypted).toBe("cross-compat-test");
  });
});

// === Parse Env Line ===

describe("parseEnvLine", () => {

  it("basic KEY=value", () => {
    expect(parseEnvLine("KEY=value")).toEqual(["KEY", "value"]);
  });

  it("equals in value", () => {
    expect(parseEnvLine("KEY=a=b=c")).toEqual(["KEY", "a=b=c"]);
  });

  it("empty value", () => {
    expect(parseEnvLine("KEY=")).toEqual(["KEY", ""]);
  });

  it("no equals returns null", () => {
    expect(parseEnvLine("INVALID")).toBeNull();
  });

  it("empty key returns null", () => {
    expect(parseEnvLine("=value")).toBeNull();
  });

  it("with spaces", () => {
    expect(parseEnvLine("  KEY  =  value  ")).toEqual(["KEY", "value"]);
  });
});
