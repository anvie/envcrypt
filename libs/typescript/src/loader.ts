import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { ENCRYPTED_PREFIX, NONCE_SIZE, KEY_SIZE, TAG_SIZE } from "./constants";
import { EnvcryptError } from "./errors";
import { parseEnvLine } from "./parser";

export class EnvcryptLoader {
  private readonly key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== KEY_SIZE) {
      throw new EnvcryptError(
        `Key must be ${KEY_SIZE} bytes, got ${key.length}`
      );
    }
    this.key = key;
  }

  static fromKey(hexKey: string): EnvcryptLoader {
    hexKey = hexKey.trim();
    if (!/^[0-9a-fA-F]+$/.test(hexKey)) {
      throw new EnvcryptError(`Invalid hex key`);
    }
    const keyBytes = Buffer.from(hexKey, "hex");
    if (keyBytes.length !== KEY_SIZE) {
      throw new EnvcryptError(
        `Key must be ${KEY_SIZE} bytes (${KEY_SIZE * 2} hex chars), got ${keyBytes.length} bytes`
      );
    }
    return new EnvcryptLoader(keyBytes);
  }

  static fromConfig(path?: string): EnvcryptLoader {
    const configPath = path ?? join(homedir(), ".envcrypt.yaml");

    if (!existsSync(configPath)) {
      throw new EnvcryptError(`Config not found: ${configPath}`);
    }

    const content = readFileSync(configPath, "utf-8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.startsWith("key:")) {
        const keyValue = trimmed
          .slice(4)
          .trim()
          .replace(/^["']|["']$/g, "");
        return EnvcryptLoader.fromKey(keyValue);
      }
    }

    throw new EnvcryptError(`No 'key' found in config: ${configPath}`);
  }

  static generateKey(): string {
    return randomBytes(KEY_SIZE).toString("hex");
  }

  encrypt(plaintext: string): string {
    const nonce = randomBytes(NONCE_SIZE);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);

    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf-8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    // Wire format: nonce(12) + ciphertext(N) + tag(16)
    const combined = Buffer.concat([nonce, ciphertext, tag]);
    return `${ENCRYPTED_PREFIX}${combined.toString("base64")}`;
  }

  decrypt(encrypted: string): string {
    if (encrypted.startsWith(ENCRYPTED_PREFIX)) {
      encrypted = encrypted.slice(ENCRYPTED_PREFIX.length);
    }

    let combined: Buffer;
    try {
      combined = Buffer.from(encrypted, "base64");
    } catch {
      throw new EnvcryptError("Invalid base64");
    }

    if (combined.length < NONCE_SIZE + TAG_SIZE) {
      throw new EnvcryptError("Encrypted data too short");
    }

    const nonce = combined.subarray(0, NONCE_SIZE);
    const ciphertext = combined.subarray(NONCE_SIZE, combined.length - TAG_SIZE);
    const tag = combined.subarray(combined.length - TAG_SIZE);

    try {
      const decipher = createDecipheriv("aes-256-gcm", this.key, nonce);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);
      return plaintext.toString("utf-8");
    } catch {
      throw new EnvcryptError("Decryption failed (wrong key?)");
    }
  }

  load(path: string, override = true): Record<string, string> {
    if (!existsSync(path)) {
      throw new EnvcryptError(`File not found: ${path}`);
    }
    const content = readFileSync(path, "utf-8");
    return this.loadFromString(content, override);
  }

  loadFromString(content: string, override = true): Record<string, string> {
    const result: Record<string, string> = {};

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      if (!line || line.startsWith("#")) continue;

      const parsed = parseEnvLine(line);
      if (!parsed) continue;

      let [key, value] = parsed;

      if (value.startsWith(ENCRYPTED_PREFIX)) {
        try {
          value = this.decrypt(value);
        } catch (e) {
          throw new EnvcryptError(
            `Line ${i + 1}: ${e instanceof Error ? e.message : e}`
          );
        }
      }

      result[key] = value;

      if (override || !(key in process.env)) {
        process.env[key] = value;
      }
    }

    return result;
  }

  encryptContent(content: string): string {
    const lines = content.split("\n");
    const output: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed === "") {
        output.push(line);
        continue;
      }

      // Handle commented-out KEY=VALUE lines
      if (trimmed.startsWith("#")) {
        const afterHash = trimmed.slice(1).trimStart();
        const parsed = parseEnvLine(afterHash);
        if (parsed) {
          const [key, value] = parsed;
          if (!value.startsWith(ENCRYPTED_PREFIX) && value !== "") {
            const encrypted = this.encrypt(value);
            output.push(`# ${key}=${encrypted}`);
            continue;
          }
        }
        output.push(line);
        continue;
      }

      const parsed = parseEnvLine(trimmed);
      if (parsed) {
        const [key, value] = parsed;
        if (value.startsWith(ENCRYPTED_PREFIX) || value === "") {
          output.push(line);
        } else {
          const encrypted = this.encrypt(value);
          output.push(`${key}=${encrypted}`);
        }
      } else {
        output.push(line);
      }
    }

    return output.join("\n");
  }

  decryptContent(content: string): string {
    const lines = content.split("\n");
    const output: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed === "") {
        output.push(line);
        continue;
      }

      // Handle commented-out KEY=VALUE lines
      if (trimmed.startsWith("#")) {
        const afterHash = trimmed.slice(1).trimStart();
        const parsed = parseEnvLine(afterHash);
        if (parsed) {
          const [key, value] = parsed;
          if (value.startsWith(ENCRYPTED_PREFIX)) {
            const decrypted = this.decrypt(value);
            output.push(`# ${key}=${decrypted}`);
            continue;
          }
        }
        output.push(line);
        continue;
      }

      const parsed = parseEnvLine(trimmed);
      if (parsed) {
        const [key, value] = parsed;
        if (value.startsWith(ENCRYPTED_PREFIX)) {
          const decrypted = this.decrypt(value);
          output.push(`${key}=${decrypted}`);
        } else {
          output.push(line);
        }
      } else {
        output.push(line);
      }
    }

    return output.join("\n");
  }
}

export function load(
  path: string,
  options?: { key?: string; config?: string }
): Record<string, string> {
  const loader = options?.key
    ? EnvcryptLoader.fromKey(options.key)
    : EnvcryptLoader.fromConfig(options?.config);
  return loader.load(path);
}

export function loadFromConfig(
  path: string,
  config?: string
): Record<string, string> {
  const loader = EnvcryptLoader.fromConfig(config);
  return loader.load(path);
}
