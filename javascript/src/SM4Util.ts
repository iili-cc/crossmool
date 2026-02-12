import { sm4 } from 'sm-crypto-v2';
import {
  bytesToBase64,
  bytesToHex,
  decodeHexOrBase64ToBytes,
  hexToBytes,
  utf8ToBytes,
  bytesToUtf8
} from './utils/encoding';

const KEY_SIZE_BYTES = 16;

function normalizeKeyBytes(key: Uint8Array | string): Uint8Array {
  const keyBytes = typeof key === 'string' ? decodeHexOrBase64ToBytes(key) : key;
  if (keyBytes.length !== KEY_SIZE_BYTES) throw new Error('SM4 key must be 16 bytes (128 bits)');
  return keyBytes;
}

export class SM4Util {
  static generateKeyBytes(): Uint8Array {
    const key = new Uint8Array(KEY_SIZE_BYTES);
    if (globalThis.crypto?.getRandomValues) {
      globalThis.crypto.getRandomValues(key);
      return key;
    }
    throw new Error('No secure RNG available: globalThis.crypto.getRandomValues is missing');
  }

  static generateKeyHex(): string {
    return bytesToHex(this.generateKeyBytes());
  }

  static generateKeyBase64(): string {
    return bytesToBase64(this.generateKeyBytes());
  }

  static encryptEcbToBytes(input: Uint8Array, key: Uint8Array | string): Uint8Array {
    const k = normalizeKeyBytes(key);
    return sm4.encrypt(input, k, { mode: 'ecb', padding: 'pkcs#7', output: 'array' });
  }

  static decryptEcbToBytes(cipher: Uint8Array, key: Uint8Array | string): Uint8Array {
    const k = normalizeKeyBytes(key);
    return sm4.decrypt(cipher, k, { mode: 'ecb', padding: 'pkcs#7', output: 'array' });
  }

  static encryptEcbToHex(plainText: string, key: Uint8Array | string): string {
    const ct = this.encryptEcbToBytes(utf8ToBytes(plainText), key);
    return bytesToHex(ct);
  }

  static encryptEcbToBase64(plainText: string, key: Uint8Array | string): string {
    const ct = this.encryptEcbToBytes(utf8ToBytes(plainText), key);
    return bytesToBase64(ct);
  }

  static decryptEcbToUtf8(cipherHexOrBase64: string, key: Uint8Array | string): string {
    const cipherBytes = decodeHexOrBase64ToBytes(cipherHexOrBase64);
    const pt = this.decryptEcbToBytes(cipherBytes, key);
    return bytesToUtf8(pt);
  }

  static decryptEcbHexToUtf8(cipherHex: string, key: Uint8Array | string): string {
    const pt = this.decryptEcbToBytes(hexToBytes(cipherHex), key);
    return bytesToUtf8(pt);
  }
}
