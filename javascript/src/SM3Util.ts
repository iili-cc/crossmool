import { sm3 } from 'sm-crypto-v2';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes, utf8ToBytes } from './utils/encoding';

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
}
