import { describe, expect, test } from 'vitest';
import { SM2Util } from '../src/SM2Util';
import { SM3Util } from '../src/SM3Util';
import { SM4Util } from '../src/SM4Util';
import { bytesToHex, hexToBytes, utf8ToBytes, bytesToUtf8, bytesToBase64 } from '../src/utils/encoding';
import { sm2PrivateKeyToRawHex, sm2PublicKeyToRawHex } from '../src/utils/sm2KeyFormats';
import { sm2 } from 'sm-crypto-v2';

// Copied from java/crossmool/src/main/java/cc/iili/tools/crossmool/constant/SM2Constant.java
const CIPHER_PUBLIC_KEY_BASE64 =
  'MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEO4gVFPrTdWaMRocy/GuyjUZYdbdsqzfcvrtjkCoTVfBSXVWElN6uj91ZxsiszlzQ3JxTYxLKd3sy6EWNuS22+g==';
const CIPHER_PRIVATE_KEY_BASE64 =
  'MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgLtLT8TS7TpI1t6JhId5PiZ7yI+DwNDWwXY54yyb89SmgCgYIKoEcz1UBgi2hRANCAAQ7iBUU+tN1ZoxGhzL8a7KNRlh1t2yrN9y+u2OQKhNV8FJdVYSU3q6P3VnGyKzOXNDcnFNjEsp3ezLoRY25Lbb6';
const SIGN_PRIVATE_KEY_BASE64 =
  'MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQghdEmDD4sgxQXfrDeGoHITWChGHSld/gV/ctXpxxNBTmgCgYIKoEcz1UBgi2hRANCAARmzTOQXN3qPrgm4pIy80fyorg5IK4FRAfabNl1X9/kFnTbwEcbFn+5kz1KGqb6sSCQnS8NuyveW5aFIASRhsuE';
const SIGN_PUBLIC_KEY_BASE64 =
  'MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEZs0zkFzd6j64JuKSMvNH8qK4OSCuBUQH2mzZdV/f5BZ028BHGxZ/uZM9Shqm+rEgkJ0vDbsr3luWhSAEkYbLhA==';

describe('SM3', () => {
  test('known vector: SM3("abc")', () => {
    const got = SM3Util.digestToHex('abc');
    expect(got.toUpperCase()).toBe('66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0');
  });
});

describe('SM4', () => {
  test('ECB pkcs#7 roundtrip', () => {
    const keyHex = '0123456789abcdeffedcba9876543210';
    const plain = 'Hello, 這是国密SM4測試數據';
    const cipherHex = SM4Util.encryptEcbToHex(plain, keyHex);
    const out = SM4Util.decryptEcbHexToUtf8(cipherHex, keyHex);
    expect(out).toBe(plain);
  });
});

describe('SM2 (Java key format interoperability)', () => {
  test('parse X509/PKCS8 to raw keys', () => {
    const pubRaw = sm2PublicKeyToRawHex(SIGN_PUBLIC_KEY_BASE64);
    const privRaw = sm2PrivateKeyToRawHex(SIGN_PRIVATE_KEY_BASE64);
    expect(sm2.verifyPublicKey(pubRaw)).toBe(true);
    expect(sm2.getPublicKeyFromPrivateKey(privRaw)).toBe(pubRaw);
  });

  test('encrypt/decrypt with Java DER keys (C1C3C2)', () => {
    const plain = '您好，我是SM2算法測試數據';
    const cipherHex = SM2Util.encryptToHex(plain, CIPHER_PUBLIC_KEY_BASE64);
    const out = SM2Util.decrypt(cipherHex, CIPHER_PRIVATE_KEY_BASE64);
    expect(out).toBe(plain);

    const cipherB64 = SM2Util.encryptToBase64(plain, CIPHER_PUBLIC_KEY_BASE64);
    const out2 = SM2Util.decrypt(cipherB64, CIPHER_PRIVATE_KEY_BASE64);
    expect(out2).toBe(plain);
  });

  test('sign/verify with Java DER keys (DER signature, SM3-with-ID)', () => {
    const msg = 'test message';
    const sigHex = SM2Util.signToHex(msg, SIGN_PRIVATE_KEY_BASE64);
    expect(SM2Util.verify(msg, SIGN_PUBLIC_KEY_BASE64, sigHex)).toBe(true);

    const sigB64 = SM2Util.signToBase64(msg, SIGN_PRIVATE_KEY_BASE64);
    expect(SM2Util.verify(msg, SIGN_PUBLIC_KEY_BASE64, sigB64)).toBe(true);
  });

  test('encryptSign/verifyDecrypt matches Java behavior (sign ciphertext utf8)', () => {
    const plain = 'hello';
    const pair = SM2Util.encryptSign(plain, CIPHER_PUBLIC_KEY_BASE64, SIGN_PRIVATE_KEY_BASE64, false);
    const out = SM2Util.verifyDecrypt(pair.ciphertext, pair.signature, SIGN_PUBLIC_KEY_BASE64, CIPHER_PRIVATE_KEY_BASE64);
    expect(out).toBe(plain);
  });

  test('byte[] APIs', () => {
    const plainBytes = utf8ToBytes('binary-OK');
    const cipherBytes = SM2Util.encryptToBytes(plainBytes, CIPHER_PUBLIC_KEY_BASE64);
    const outBytes = SM2Util.decryptToBytes(cipherBytes, CIPHER_PRIVATE_KEY_BASE64);
    expect(bytesToUtf8(outBytes)).toBe('binary-OK');

    const cipherB64 = bytesToBase64(cipherBytes);
    const outBytes2 = SM2Util.decryptToBytesFromString(cipherB64, CIPHER_PRIVATE_KEY_BASE64);
    expect(bytesToUtf8(outBytes2)).toBe('binary-OK');

    const sigBytes = SM2Util.signToBytes(plainBytes, SIGN_PRIVATE_KEY_BASE64);
    expect(SM2Util.verify(plainBytes, SIGN_PUBLIC_KEY_BASE64, bytesToHex(sigBytes))).toBe(true);
  });
});
