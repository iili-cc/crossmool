import { sm3 } from 'sm-crypto-v2';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  decodeHexOrBase64ToBytes,
  detectStringEncoding,
  hexToBytes,
  utf8ToBytes
} from './utils/encoding';

const HMAC_KEY_MIN_LENGTH = 32;

export class SM3Util {
  static digestToBytes(input: Uint8Array): Uint8Array {
    const hex = sm3(input);
    return hexToBytes(hex);
  }

  static digestToHex(input: Uint8Array | string): string {
    const bytes = typeof input === 'string' ? utf8ToBytes(input) : input;
    return sm3(bytes);
  }

  static digestToBase64(input: Uint8Array | string): string {
    const hex = this.digestToHex(input);
    return bytesToBase64(hexToBytes(hex));
  }

  static digestFromBase64ToHex(base64: string): string {
    return bytesToHex(this.digestToBytes(base64ToBytes(base64)));
  }

  static digest(input: Uint8Array | string, toBase64 = false): string {
    return toBase64 ? this.digestToBase64(input) : this.digestToHex(input);
  }

  static hmacBytes(data: Uint8Array, key: Uint8Array): Uint8Array {
    const blockSize = 64;
    let k = key;
    if (k.length > blockSize) {
      k = this.digestToBytes(k);
    }
    if (k.length < blockSize) {
      const padded = new Uint8Array(blockSize);
      padded.set(k);
      k = padded;
    }
    const ipad = new Uint8Array(blockSize);
    const opad = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      ipad[i] = k[i]! ^ 0x36;
      opad[i] = k[i]! ^ 0x5c;
    }
    const innerData = new Uint8Array(blockSize + data.length);
    innerData.set(ipad);
    innerData.set(data, blockSize);
    const innerHash = this.digestToBytes(innerData);
    const outerData = new Uint8Array(blockSize + innerHash.length);
    outerData.set(opad);
    outerData.set(innerHash, blockSize);
    return this.digestToBytes(outerData);
  }

  static hmacToHex(data: Uint8Array | string, key: Uint8Array | string): string {
    const keyBytes = typeof key === 'string' ? decodeHexOrBase64ToBytes(key) : key;
    const dataBytes = typeof data === 'string' ? utf8ToBytes(data) : data;
    return bytesToHex(this.hmacBytes(dataBytes, keyBytes));
  }

  static hmacToBase64(data: Uint8Array | string, key: Uint8Array | string): string {
    const keyBytes = typeof key === 'string' ? decodeHexOrBase64ToBytes(key) : key;
    const dataBytes = typeof data === 'string' ? utf8ToBytes(data) : data;
    return bytesToBase64(this.hmacBytes(dataBytes, keyBytes));
  }

  static hmac(data: Uint8Array | string, key: Uint8Array | string, toBase64 = false): string {
    return toBase64 ? this.hmacToBase64(data, key) : this.hmacToHex(data, key);
  }

  static generateHmacKeyBytes(keyLength = HMAC_KEY_MIN_LENGTH): Uint8Array {
    if (keyLength < HMAC_KEY_MIN_LENGTH) {
      throw new Error(`HMAC key length must be at least ${HMAC_KEY_MIN_LENGTH} bytes`);
    }
    const key = new Uint8Array(keyLength);
    if (globalThis.crypto?.getRandomValues) {
      globalThis.crypto.getRandomValues(key);
      return key;
    }
    throw new Error('No secure RNG available: globalThis.crypto.getRandomValues is missing');
  }

  static generateHmacKeyHex(keyLength = HMAC_KEY_MIN_LENGTH): string {
    return bytesToHex(this.generateHmacKeyBytes(keyLength));
  }

  static generateHmacKeyBase64(keyLength = HMAC_KEY_MIN_LENGTH): string {
    return bytesToBase64(this.generateHmacKeyBytes(keyLength));
  }

  static generateHmacKeyToStr(keyLength: number | boolean = HMAC_KEY_MIN_LENGTH, toBase64 = false): string {
    if (typeof keyLength === 'boolean') {
      return this.generateHmacKeyToStr(HMAC_KEY_MIN_LENGTH, keyLength);
    }
    const keyBytes = this.generateHmacKeyBytes(keyLength);
    return toBase64 ? bytesToBase64(keyBytes) : bytesToHex(keyBytes);
  }

  static hmacVerify(data: Uint8Array | string, key: Uint8Array | string, receivedHmac: string): boolean {
    const computed = this.hmacBytes(
      typeof data === 'string' ? utf8ToBytes(data) : data,
      typeof key === 'string' ? decodeHexOrBase64ToBytes(key) : key
    );
    const enc = detectStringEncoding(receivedHmac);
    let receivedBytes: Uint8Array;
    if (enc === 'hex') {
      receivedBytes = hexToBytes(receivedHmac);
    } else if (enc === 'base64') {
      receivedBytes = base64ToBytes(receivedHmac);
    } else {
      throw new Error('receivedHmac must be hex or base64 string');
    }
    if (computed.length !== receivedBytes.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i++) diff |= computed[i]! ^ receivedBytes[i]!;
    return diff === 0;
  }
}