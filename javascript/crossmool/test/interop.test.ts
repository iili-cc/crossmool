import { describe, expect, test } from 'vitest';
import { SM2Util } from '../src/SM2Util';
import { SM3Util } from '../src/SM3Util';
import { SM4Util } from '../src/SM4Util';
import {
  bytesToHex, hexToBytes, utf8ToBytes, bytesToUtf8,
  bytesToBase64, base64ToBytes, isHexString, isBase64String,
  decodeHexOrBase64ToBytes
} from '../src/utils/encoding';
import { sm2PrivateKeyToRawHex, sm2PublicKeyToRawHex } from '../src/utils/sm2KeyFormats';
import { sm2 } from 'sm-crypto-v2';

// ========== Utils ==========
describe('Utils', () => {
  test('hex roundtrip', () => {
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(bytesToHex(data)).toBe('deadbeef');
    expect(hexToBytes('deadbeef')).toEqual(data);
  });

  test('base64 roundtrip', () => {
    const data = utf8ToBytes('Hello');
    expect(bytesToBase64(data)).toBe('SGVsbG8=');
    expect(base64ToBytes('SGVsbG8=')).toEqual(data);
  });

  test('decodeHexOrBase64ToBytes - hex', () => {
    const b = decodeHexOrBase64ToBytes('dead');
    expect(b).toEqual(new Uint8Array([0xde, 0xad]));
  });

  test('decodeHexOrBase64ToBytes - base64', () => {
    const b = decodeHexOrBase64ToBytes('SGVsbG8=');
    expect(bytesToUtf8(b)).toBe('Hello');
  });

  test('isHexString', () => {
    expect(isHexString('abcd1234')).toBe(true);
    expect(isHexString('xyz')).toBe(false);
  });

  test('isBase64String', () => {
    expect(isBase64String('SGVsbG8=')).toBe(true);
    expect(isBase64String('!@#')).toBe(false);
  });

  test('utf8 roundtrip', () => {
    const b = utf8ToBytes('测试');
    expect(bytesToUtf8(b)).toBe('测试');
  });
});

// ========== SM3 Digest ==========
describe('SM3 Digest', () => {
  test('known vector: abc', () => {
    const h = SM3Util.digestToHex('abc').toUpperCase();
    expect(h).toBe('66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0');
  });

  test('digestToHex length 64', () => {
    expect(SM3Util.digestToHex('hello').length).toBe(64);
  });

  test('digestToBase64', () => {
    const b64 = SM3Util.digestToBase64('hello');
    expect(b64.length).toBeGreaterThan(0);
  });

  test('digest deterministic', () => {
    const a = SM3Util.digestToHex('same');
    const b = SM3Util.digestToHex('same');
    expect(a).toBe(b);
  });

  test('digestToBytes length 32', () => {
    const d = SM3Util.digestToBytes(utf8ToBytes('test'));
    expect(d.length).toBe(32);
  });
});

// ========== SM3 HMAC ==========
describe('SM3 HMAC', () => {
  test('hmacToHex length 64', () => {
    const key = SM3Util.generateHmacKeyHex();
    expect(SM3Util.hmacToHex(key, 'data').length).toBe(64);
  });

  test('hmacToBase64', () => {
    const key = SM3Util.generateHmacKeyHex();
    const b64 = SM3Util.hmacToBase64(key, 'data');
    expect(b64.length).toBeGreaterThan(0);
  });

  test('generateHmacKeyBytes', () => {
    const k = SM3Util.generateHmacKeyBytes(32);
    expect(k.length).toBe(32);
  });

  test('generateHmacKeyHex length 64', () => {
    expect(SM3Util.generateHmacKeyHex().length).toBe(64);
  });

  test('generateHmacKeyBase64', () => {
    expect(SM3Util.generateHmacKeyBase64().length).toBeGreaterThan(0);
  });

  test('hmacVerify', () => {
    const key = SM3Util.generateHmacKeyHex();
    const data = 'test-data';
    const mac = SM3Util.hmacToHex(key, data);
    expect(SM3Util.hmacVerify(key, data, mac)).toBe(true);
    expect(SM3Util.hmacVerify(key, 'wrong', mac)).toBe(false);
  });

  test('hmacBytes', () => {
    const key = SM3Util.generateHmacKeyBytes();
    const data = utf8ToBytes('data');
    const mac = SM3Util.hmacToHex(key, data);
    expect(mac.length).toBe(64);
  });
});

// ========== SM4 GCM ==========
describe('SM4 GCM', () => {
  test('generateKeyBytes length 16', () => {
    expect(SM4Util.generateKeyBytes().length).toBe(16);
  });

  test('generateKeyHex length 32', () => {
    expect(SM4Util.generateKeyHex().length).toBe(32);
  });

  test('generateKeyBase64', () => {
    expect(SM4Util.generateKeyBase64().length).toBeGreaterThan(0);
  });

  test('encryptGcm / decryptGcm hex roundtrip', () => {
    const key = SM4Util.generateKeyBytes();
    const plain = utf8ToBytes('Hello SM4 GCM');
    const ct = SM4Util.encryptGcm(plain, key);
    const pt = SM4Util.decryptGcm(ct, key);
    expect(bytesToUtf8(pt)).toBe('Hello SM4 GCM');
  });

  test('encryptGcm / decryptGcm base64 roundtrip', () => {
    const key = SM4Util.generateKeyBytes();
    const plain = utf8ToBytes('Hello Base64');
    const ct = SM4Util.encryptGcm(plain, key, undefined, true);
    const pt = SM4Util.decryptGcm(ct, key);
    expect(bytesToUtf8(pt)).toBe('Hello Base64');
  });

  test('encryptGcmString / decryptGcmToString', () => {
    const key = SM4Util.generateKeyBytes();
    const ct = SM4Util.encryptGcmString('String test', key);
    expect(SM4Util.decryptGcmToString(ct, key)).toBe('String test');
  });

  test('encryptGcmHex / decryptGcm', () => {
    const key = SM4Util.generateKeyBytes();
    const ct = SM4Util.encryptGcmHex(utf8ToBytes('Hex API'), key);
    expect(bytesToUtf8(SM4Util.decryptGcm(ct, key))).toBe('Hex API');
  });

  test('encryptGcmBase64 / decryptGcm', () => {
    const key = SM4Util.generateKeyBytes();
    const ct = SM4Util.encryptGcmBase64(utf8ToBytes('B64 API'), key);
    expect(bytesToUtf8(SM4Util.decryptGcm(ct, key))).toBe('B64 API');
  });

  test('random IV produces different ciphertexts', () => {
    const key = SM4Util.generateKeyBytes();
    const plain = utf8ToBytes('test');
    expect(SM4Util.encryptGcm(plain, key)).not.toBe(SM4Util.encryptGcm(plain, key));
  });

  test('deterministic with same IV', () => {
    const key = hexToBytes('0123456789abcdeffedcba9876543210');
    const iv = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11]);
    const plain = utf8ToBytes('test');
    expect(SM4Util.encryptGcm(plain, key, iv)).toBe(SM4Util.encryptGcm(plain, key, iv));
  });

  test('tamper detection', () => {
    const key = hexToBytes('0123456789abcdeffedcba9876543210');
    const ct = SM4Util.encryptGcm(utf8ToBytes('msg'), key);
    const tampered = ct.slice(0, -2) + 'XX';
    expect(() => SM4Util.decryptGcm(tampered, key)).toThrow();
  });

  test('hex key string works', () => {
    const keyHex = '0123456789abcdeffedcba9876543210';
    const ct = SM4Util.encryptGcmString('Hello', keyHex);
    expect(SM4Util.decryptGcmToString(ct, keyHex)).toBe('Hello');
  });

  test('parseHexKey', () => {
    const k = SM4Util.parseHexKey('0123456789abcdeffedcba9876543210');
    expect(k.length).toBe(16);
    expect(k[0]).toBe(0x01);
  });

  test('generateGcmIV length 12', () => {
    expect(SM4Util.generateGcmIV().length).toBe(12);
  });
});

// ========== SM2 ==========
describe('SM2', () => {
  const cipherPubKeyB64 = 'MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEO4gVFPrTdWaMRocy/GuyjUZYdbdsqzfcvrtjkCoTVfBSXVWElN6uj91ZxsiszlzQ3JxTYxLKd3sy6EWNuS22+g==';
  const cipherPrivKeyB64 = 'MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgLtLT8TS7TpI1t6JhId5PiZ7yI+DwNDWwXY54yyb89SmgCgYIKoEcz1UBgi2hRANCAAQ7iBUU+tN1ZoxGhzL8a7KNRlh1t2yrN9y+u2OQKhNV8FJdVYSU3q6P3VnGyKzOXNDcnFNjEsp3ezLoRY25Lbb6';
  const signPubKeyB64 = 'MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEZs0zkFzd6j64JuKSMvNH8qK4OSCuBUQH2mzZdV/f5BZ028BHGxZ/uZM9Shqm+rEgkJ0vDbsr3luWhSAEkYbLhA==';
  const signPrivKeyB64 = 'MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQghdEmDD4sgxQXfrDeGoHITWChGHSld/gV/ctXpxxNBTmgCgYIKoEcz1UBgi2hRANCAARmzTOQXN3qPrgm4pIy80fyorg5IK4FRAfabNl1X9/kFnTbwEcbFn+5kz1KGqb6sSCQnS8NuyveW5aFIASRhsuE';

  test('parse X509/PKCS8 keys', () => {
    const pubRaw = sm2PublicKeyToRawHex(signPubKeyB64);
    const privRaw = sm2PrivateKeyToRawHex(signPrivKeyB64);
    expect(sm2.verifyPublicKey(pubRaw)).toBe(true);
    expect(sm2.getPublicKeyFromPrivateKey(privRaw)).toBe(pubRaw);
  });

  test('encryptToHex / decrypt', () => {
    const ct = SM2Util.encryptToHex('Hello SM2', cipherPubKeyB64);
    expect(SM2Util.decrypt(ct, cipherPrivKeyB64)).toBe('Hello SM2');
  });

  test('encryptToBase64 / decrypt', () => {
    const ct = SM2Util.encryptToBase64('Hello B64', cipherPubKeyB64);
    expect(SM2Util.decrypt(ct, cipherPrivKeyB64)).toBe('Hello B64');
  });

  test('encrypt / decrypt with flags', () => {
    const ctHex = SM2Util.encrypt('Hello', cipherPubKeyB64, false);
    expect(SM2Util.decrypt(ctHex, cipherPrivKeyB64)).toBe('Hello');
    const ctB64 = SM2Util.encrypt('Hello', cipherPubKeyB64, true);
    expect(SM2Util.decrypt(ctB64, cipherPrivKeyB64)).toBe('Hello');
  });

  test('signToHex / verify', () => {
    const sig = SM2Util.signToHex('test msg', signPrivKeyB64);
    expect(SM2Util.verify('test msg', signPubKeyB64, sig)).toBe(true);
    expect(SM2Util.verify('wrong msg', signPubKeyB64, sig)).toBe(false);
  });

  test('signToBase64 / verify', () => {
    const sig = SM2Util.signToBase64('test msg', signPrivKeyB64);
    expect(SM2Util.verify('test msg', signPubKeyB64, sig)).toBe(true);
  });

  test('sign / verify with flags', () => {
    const sigHex = SM2Util.sign('msg', signPrivKeyB64, false);
    expect(SM2Util.verify('msg', signPubKeyB64, sigHex)).toBe(true);
    const sigB64 = SM2Util.sign('msg', signPrivKeyB64, true);
    expect(SM2Util.verify('msg', signPubKeyB64, sigB64)).toBe(true);
  });

  test('encryptSign / verifyDecrypt', () => {
    const { ciphertext, signature } = SM2Util.encryptSign('combo', cipherPubKeyB64, signPrivKeyB64, false);
    expect(SM2Util.verifyDecrypt(ciphertext, signature, signPubKeyB64, cipherPrivKeyB64)).toBe('combo');
  });

  test('byte APIs', () => {
    const plainBytes = utf8ToBytes('binary');
    const ct = SM2Util.encryptToBytes(plainBytes, cipherPubKeyB64);
    const pt = SM2Util.decryptToBytes(ct, cipherPrivKeyB64);
    expect(bytesToUtf8(pt)).toBe('binary');

    const ctB64 = bytesToBase64(ct);
    const pt2 = SM2Util.decryptToBytesFromString(ctB64, cipherPrivKeyB64);
    expect(bytesToUtf8(pt2)).toBe('binary');

    const sig = SM2Util.signToBytes(plainBytes, signPrivKeyB64);
    expect(SM2Util.verify(plainBytes, signPubKeyB64, bytesToHex(sig))).toBe(true);
  });
});
