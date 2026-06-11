import { sm4 } from 'sm-crypto-v2';
import {
  bytesToBase64,
  bytesToHex,
  decodeHexOrBase64ToBytes,
  hexToBytes,
  utf8ToBytes,
  bytesToUtf8,
  base64ToBytes
} from './utils/encoding';

const KEY_SIZE_BYTES = 16;
const GCM_IV_SIZE = 12;   // 96 bits
const GCM_TAG_SIZE = 16;  // 128 bits
const BLOCK_SIZE = 16;

function normalizeKeyBytes(key: Uint8Array | string): Uint8Array {
  const keyBytes = typeof key === 'string' ? decodeHexOrBase64ToBytes(key) : key;
  if (keyBytes.length !== KEY_SIZE_BYTES) throw new Error('SM4 key must be 16 bytes (128 bits)');
  return keyBytes;
}

// ========================
// GCM primitives
// ========================

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

function inc32(counter: Uint8Array): Uint8Array {
  const c = new Uint8Array(counter);
  // Increment the rightmost 32 bits (bytes 12-15)
  for (let i = 15; i >= 12; i--) {
    c[i] = (c[i]! + 1) & 0xff;
    if (c[i] !== 0) break;
  }
  return c;
}

// GF(2^128) multiplication with reduction polynomial x^128+x^7+x^2+x+1
function gf128Mul(x: bigint, y: bigint): bigint {
  const R = 0xE1000000000000000000000000000000n;
  const MASK = (1n << 128n) - 1n;
  let z = 0n;
  let v = y;
  for (let i = 0; i < 128; i++) {
    if (x & (1n << BigInt(127 - i))) {
      z ^= v;
    }
    if (v & 1n) {
      v = (v >> 1n) ^ R;
    } else {
      v >>= 1n;
    }
  }
  return z & MASK;
}

function bytesToBigint(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = 0; i < b.length; i++) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

function bigintToBytes(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function ghash(h: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const hInt = bytesToBigint(h);

  // Pad AAD to 16-byte boundary
  const aadPadLen = (16 - (aad.length % 16)) % 16;
  const aadPadded = new Uint8Array(aad.length + aadPadLen);
  aadPadded.set(aad);

  // Pad ciphertext to 16-byte boundary
  const ctPadLen = (16 - (ciphertext.length % 16)) % 16;
  const ctPadded = new Uint8Array(ciphertext.length + ctPadLen);
  ctPadded.set(ciphertext);

  // Length block: len(AAD)*8 || len(CT)*8 (each 64 bits big-endian)
  const lenBlock = new Uint8Array(16);
  const aadBitLen = BigInt(aad.length * 8);
  const ctBitLen = BigInt(ciphertext.length * 8);
  for (let i = 7; i >= 0; i--) {
    lenBlock[i] = Number(aadBitLen >> BigInt(7 - i) * 8n & 0xffn);
    lenBlock[8 + i] = Number(ctBitLen >> BigInt(7 - i) * 8n & 0xffn);
  }

  let y = 0n;
  for (let i = 0; i < aadPadded.length; i += 16) {
    y ^= bytesToBigint(aadPadded.subarray(i, i + 16));
    y = gf128Mul(y, hInt);
  }
  for (let i = 0; i < ctPadded.length; i += 16) {
    y ^= bytesToBigint(ctPadded.subarray(i, i + 16));
    y = gf128Mul(y, hInt);
  }
  y ^= bytesToBigint(lenBlock);
  y = gf128Mul(y, hInt);

  return bigintToBytes(y, 16);
}

// Encrypt a single 16-byte block using SM4 ECB (no padding)
// Internal helper for GCM - NOT a user-facing ECB mode
function sm4EcbEncryptBlock(key: Uint8Array, block: Uint8Array): Uint8Array {
  // sm-crypto-v2's sm4.encrypt with ECB mode adds PKCS7 padding,
  // so for a 16-byte input it produces 32 bytes. We only need the first 16.
  const encrypted = sm4.encrypt(block, key, { mode: 'ecb', padding: 'pkcs#7', output: 'array' });
  return new Uint8Array(encrypted.buffer, 0, 16);
}

function sm4CtrEncrypt(key: Uint8Array, counter: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const result = new Uint8Array(plaintext.length);
  let ctr = counter;
  for (let i = 0; i < plaintext.length; i += BLOCK_SIZE) {
    const keystream = sm4EcbEncryptBlock(key, ctr);
    const block = plaintext.subarray(i, Math.min(i + BLOCK_SIZE, plaintext.length));
    for (let j = 0; j < block.length; j++) {
      result[i + j] = block[j]! ^ keystream[j]!;
    }
    ctr = inc32(ctr);
  }
  return result;
}

function gcmEncryptCore(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array): { combined: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array } {
  // j0 = IV || 0x00000001
  const j0 = new Uint8Array(16);
  j0.set(iv, 0);
  j0[15] = 1;

  // H = SM4_ECB(key, 0^128)
  const h = sm4EcbEncryptBlock(key, new Uint8Array(16));

  // Ciphertext = SM4_CTR(key, inc32(j0), plaintext)
  const ciphertext = sm4CtrEncrypt(key, inc32(j0), plaintext);

  // Tag = GHASH(H, AAD, ciphertext) XOR SM4_ECB(key, j0)
  const ghashResult = ghash(h, new Uint8Array(0), ciphertext);
  const j0Encrypted = sm4EcbEncryptBlock(key, j0);
  const tag = xorBytes(ghashResult, j0Encrypted);

  // Combine: IV + ciphertext + Tag
  const combined = new Uint8Array(iv.length + ciphertext.length + tag.length);
  combined.set(iv, 0);
  combined.set(ciphertext, iv.length);
  combined.set(tag, iv.length + ciphertext.length);

  return { combined, ciphertext, tag };
}

function gcmDecryptCore(data: Uint8Array, key: Uint8Array): Uint8Array {
  if (data.length < GCM_IV_SIZE + GCM_TAG_SIZE) {
    throw new Error('Invalid GCM ciphertext: too short');
  }

  const iv = data.subarray(0, GCM_IV_SIZE);
  const tag = data.subarray(data.length - GCM_TAG_SIZE);
  const ciphertext = data.subarray(GCM_IV_SIZE, data.length - GCM_TAG_SIZE);

  // j0 = IV || 0x00000001
  const j0 = new Uint8Array(16);
  j0.set(iv, 0);
  j0[15] = 1;

  // H = SM4_ECB(key, 0^128)
  const h = sm4EcbEncryptBlock(key, new Uint8Array(16));

  // Verify tag: GHASH(H, AAD, ciphertext) XOR SM4_ECB(key, j0)
  const ghashResult = ghash(h, new Uint8Array(0), ciphertext);
  const j0Encrypted = sm4EcbEncryptBlock(key, j0);
  const computedTag = xorBytes(ghashResult, j0Encrypted);

  if (!tagEquals(computedTag, tag)) {
    throw new Error('SM4 GCM decryption failed (authentication failed)');
  }

  // Decrypt: SM4_CTR(key, inc32(j0), ciphertext)
  return sm4CtrEncrypt(key, inc32(j0), ciphertext);
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

  static parseHexKey(hexKey: string): Uint8Array {
    return hexToBytes(hexKey);
  }

  static generateGcmIV(): Uint8Array {
    const iv = new Uint8Array(GCM_IV_SIZE);
    if (globalThis.crypto?.getRandomValues) {
      globalThis.crypto.getRandomValues(iv);
      return iv;
    }
    throw new Error('No secure RNG available');
  }

  /**
   * SM4 GCM encryption.
   * Returns Hex(IV[12] + ciphertext + Tag[16]) by default, or Base64 if toBase64=true
   */
  static encryptGcm(plaintext: Uint8Array, key: Uint8Array | string, iv?: Uint8Array, toBase64 = false): string {
    const k = normalizeKeyBytes(key);
    const actualIv = iv ?? SM4Util.generateGcmIV();
    if (actualIv.length !== GCM_IV_SIZE) {
      throw new Error(`GCM IV must be ${GCM_IV_SIZE} bytes`);
    }
    const { combined } = gcmEncryptCore(plaintext, k, actualIv);
    return toBase64 ? bytesToBase64(combined) : bytesToHex(combined);
  }

  /**
   * SM4 GCM encryption, always returns Hex.
   */
  static encryptGcmHex(plaintext: Uint8Array, key: Uint8Array | string, iv?: Uint8Array): string {
    return this.encryptGcm(plaintext, key, iv, false);
  }

  /**
   * SM4 GCM encryption, always returns Base64.
   */
  static encryptGcmBase64(plaintext: Uint8Array, key: Uint8Array | string, iv?: Uint8Array): string {
    return this.encryptGcm(plaintext, key, iv, true);
  }

  /**
   * SM4 GCM decryption.
   * Input: Hex or Base64 encoded (IV[12] + ciphertext + Tag[16]), auto-detected
   * Returns plaintext bytes.
   */
  static decryptGcm(ciphertextHexOrBase64: string, key: Uint8Array | string): Uint8Array {
    const k = normalizeKeyBytes(key);
    const data = decodeHexOrBase64ToBytes(ciphertextHexOrBase64);
    return gcmDecryptCore(data, k);
  }

  /**
   * SM4 GCM decryption from Hex input only.
   */
  static decryptGcmFromHex(ciphertextHex: string, key: Uint8Array | string): Uint8Array {
    const k = normalizeKeyBytes(key);
    const data = hexToBytes(ciphertextHex);
    return gcmDecryptCore(data, k);
  }

  /**
   * SM4 GCM decrypt a UTF-8 string, returns Hex by default or Base64 if toBase64=true
   */
  static encryptGcmString(plainText: string, key: Uint8Array | string, iv?: Uint8Array, toBase64 = false): string {
    return SM4Util.encryptGcm(utf8ToBytes(plainText), key, iv, toBase64);
  }

  /**
   * SM4 GCM decrypt to UTF-8 string
   * Input: Hex or Base64 encoded, auto-detected
   */
  static decryptGcmToString(ciphertextHexOrBase64: string, key: Uint8Array | string): string {
    return bytesToUtf8(SM4Util.decryptGcm(ciphertextHexOrBase64, key));
  }
}

// Constant-time tag comparison to prevent timing attacks
function tagEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
