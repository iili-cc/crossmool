import { sm2 } from 'sm-crypto-v2';
import {
  bytesToBase64,
  bytesToHex,
  decodeHexOrBase64ToBytes,
  detectStringEncoding,
  hexToBytes,
  utf8ToBytes,
  bytesToUtf8
} from './utils/encoding';
import { sm2PrivateKeyToRawHex, sm2PublicKeyToRawHex, type KeyInput } from './utils/sm2KeyFormats';

export interface CiphertextSignaturePair {
  ciphertext: string;
  signature: string;
}

const USER_ID = '1234567812345678';
const CIPHER_MODE_C1C3C2 = 1;

function normalizeCiphertextToHex(ciphertext: string): string {
  const enc = detectStringEncoding(ciphertext);
  if (enc === 'hex') return ciphertext.trim().toLowerCase();
  if (enc === 'base64') return bytesToHex(decodeHexOrBase64ToBytes(ciphertext));
  throw new Error('Ciphertext must be hex or base64');
}

function normalizeSignatureToHex(signature: string): string {
  const enc = detectStringEncoding(signature);
  if (enc === 'hex') return signature.trim().toLowerCase();
  if (enc === 'base64') return bytesToHex(decodeHexOrBase64ToBytes(signature));
  throw new Error('Signature must be hex or base64');
}

export class SM2Util {
  static encryptToBytes(content: Uint8Array, publicKey: KeyInput): Uint8Array {
    const pubHex = sm2PublicKeyToRawHex(publicKey);
    const cipherHex = sm2.doEncrypt(content, pubHex, CIPHER_MODE_C1C3C2);
    return hexToBytes(cipherHex);
  }

  static encryptToHex(content: string | Uint8Array, publicKey: KeyInput): string {
    const pubHex = sm2PublicKeyToRawHex(publicKey);
    return sm2.doEncrypt(typeof content === 'string' ? utf8ToBytes(content) : content, pubHex, CIPHER_MODE_C1C3C2);
  }

  static encryptToBase64(content: string | Uint8Array, publicKey: KeyInput): string {
    const hex = this.encryptToHex(content, publicKey);
    return bytesToBase64(hexToBytes(hex));
  }

  static encrypt(content: string, publicKey: KeyInput, toBase64 = false): string {
    return toBase64 ? this.encryptToBase64(content, publicKey) : this.encryptToHex(content, publicKey);
  }

  static decryptToBytes(cipherBytes: Uint8Array, privateKey: KeyInput): Uint8Array {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const cipherHex = bytesToHex(cipherBytes);
    return sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: 'array' });
  }

  static decryptToUtf8(cipherHexOrBase64: string, privateKey: KeyInput): string {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const cipherHex = normalizeCiphertextToHex(cipherHexOrBase64);
    return sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: 'string' });
  }

  static decryptToBytesFromString(cipherHexOrBase64: string, privateKey: KeyInput): Uint8Array {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const cipherHex = normalizeCiphertextToHex(cipherHexOrBase64);
    return sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: 'array' });
  }

  static decrypt(cipherHexOrBase64: string, privateKey: KeyInput): string {
    return this.decryptToUtf8(cipherHexOrBase64, privateKey);
  }

  static signToBytes(content: Uint8Array, privateKey: KeyInput): Uint8Array {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const sigHex = sm2.doSignature(content, privHex, { der: true, hash: true, userId: USER_ID });
    return hexToBytes(sigHex);
  }

  static signToHex(content: string | Uint8Array, privateKey: KeyInput): string {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    return sm2.doSignature(typeof content === 'string' ? utf8ToBytes(content) : content, privHex, {
      der: true,
      hash: true,
      userId: USER_ID
    });
  }

  static signToBase64(content: string | Uint8Array, privateKey: KeyInput): string {
    const sigHex = this.signToHex(content, privateKey);
    return bytesToBase64(hexToBytes(sigHex));
  }

  static sign(content: string, privateKey: KeyInput, toBase64 = false): string {
    return toBase64 ? this.signToBase64(content, privateKey) : this.signToHex(content, privateKey);
  }

  static verify(content: string | Uint8Array, publicKey: KeyInput, signatureHexOrBase64: string): boolean {
    const pubHex = sm2PublicKeyToRawHex(publicKey);
    const sigHex = normalizeSignatureToHex(signatureHexOrBase64);
    return sm2.doVerifySignature(typeof content === 'string' ? utf8ToBytes(content) : content, sigHex, pubHex, {
      der: true,
      hash: true,
      userId: USER_ID
    });
  }

  static encryptSign(content: string, encPublicKey: KeyInput, signPrivateKey: KeyInput, toBase64 = false): CiphertextSignaturePair {
    const ciphertext = this.encrypt(content, encPublicKey, toBase64);
    // Java signs the ciphertext string bytes in UTF-8
    const signature = this.sign(ciphertext, signPrivateKey, toBase64);
    return { ciphertext, signature };
  }

  static encryptSignWithSameFormatKeys(content: string, encPublicKey: string, signPrivateKey: string): CiphertextSignaturePair {
    const enc = detectStringEncoding(encPublicKey);
    const sigEnc = detectStringEncoding(signPrivateKey);
    if (enc === 'hex' && sigEnc === 'hex') return this.encryptSign(content, encPublicKey, signPrivateKey, false);
    if (enc === 'base64' && sigEnc === 'base64') return this.encryptSign(content, encPublicKey, signPrivateKey, true);
    throw new Error('encPublicKey and signPrivateKey must be both hex or both base64');
  }

  static verifyDecrypt(ciphertext: string, signature: string, signPublicKey: KeyInput, decPrivateKey: KeyInput): string {
    const ok = this.verify(ciphertext, signPublicKey, signature);
    if (!ok) throw new Error(`SM2 verify failed: ${ciphertext}`);
    return this.decrypt(ciphertext, decPrivateKey);
  }

  static verifyDecryptPair(pair: CiphertextSignaturePair, signPublicKey: KeyInput, decPrivateKey: KeyInput): string {
    return this.verifyDecrypt(pair.ciphertext, pair.signature, signPublicKey, decPrivateKey);
  }
}
