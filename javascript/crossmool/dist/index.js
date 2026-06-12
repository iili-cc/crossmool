"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  SM2Util: () => SM2Util,
  SM3Util: () => SM3Util,
  SM4Util: () => SM4Util,
  base64ToBytes: () => base64ToBytes,
  bytesToBase64: () => bytesToBase64,
  bytesToHex: () => bytesToHex,
  bytesToUtf8: () => bytesToUtf8,
  decodeHexOrBase64ToBytes: () => decodeHexOrBase64ToBytes,
  hexToBytes: () => hexToBytes,
  isBase64String: () => isBase64String,
  isHexString: () => isHexString,
  sm2PrivateKeyToRawHex: () => sm2PrivateKeyToRawHex,
  sm2PublicKeyToRawHex: () => sm2PublicKeyToRawHex,
  utf8ToBytes: () => utf8ToBytes
});
module.exports = __toCommonJS(index_exports);

// src/SM2Util.ts
var import_sm_crypto_v2 = require("sm-crypto-v2");

// src/utils/encoding.ts
var HEX_RE = /^[0-9a-fA-F]+$/;
function isHexString(input) {
  const s = input.trim();
  return s.length > 0 && s.length % 2 === 0 && HEX_RE.test(s);
}
function isBase64String(input) {
  const s = input.trim();
  if (s.length === 0 || s.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return false;
  try {
    base64ToBytes(s);
    return true;
  } catch {
    return false;
  }
}
function hexToBytes(hex) {
  const s = hex.trim();
  if (!isHexString(s)) throw new Error("Invalid hex string");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}
function hasBuffer() {
  return typeof globalThis.Buffer !== "undefined";
}
function base64ToBytes(base64) {
  const s = base64.trim();
  if (hasBuffer()) {
    const B = globalThis.Buffer;
    return new Uint8Array(B.from(s, "base64"));
  }
  if (typeof globalThis.atob !== "function") {
    throw new Error("No base64 decoder available (Buffer/atob missing)");
  }
  const bin = globalThis.atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToBase64(bytes) {
  if (hasBuffer()) {
    const B = globalThis.Buffer;
    return B.from(bytes).toString("base64");
  }
  if (typeof globalThis.btoa !== "function") {
    throw new Error("No base64 encoder available (Buffer/btoa missing)");
  }
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return globalThis.btoa(bin);
}
function utf8ToBytes(text) {
  if (typeof globalThis.TextEncoder !== "undefined") return new TextEncoder().encode(text);
  if (hasBuffer()) {
    const B = globalThis.Buffer;
    return new Uint8Array(B.from(text, "utf8"));
  }
  throw new Error("No UTF-8 encoder available");
}
function bytesToUtf8(bytes) {
  if (typeof globalThis.TextDecoder !== "undefined") return new TextDecoder().decode(bytes);
  if (hasBuffer()) {
    const B = globalThis.Buffer;
    return B.from(bytes).toString("utf8");
  }
  throw new Error("No UTF-8 decoder available");
}
function detectStringEncoding(input) {
  if (isHexString(input)) return "hex";
  if (isBase64String(input)) return "base64";
  return "unknown";
}
function decodeHexOrBase64ToBytes(input) {
  const enc = detectStringEncoding(input);
  if (enc === "hex") return hexToBytes(input);
  if (enc === "base64") return base64ToBytes(input);
  throw new Error("Input must be hex or base64 string");
}

// src/utils/der.ts
var DerReader = class _DerReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }
  eof() {
    return this.offset >= this.bytes.length;
  }
  readByte() {
    if (this.offset >= this.bytes.length) throw new Error("DER: out of range");
    return this.bytes[this.offset++];
  }
  readLength() {
    const first = this.readByte();
    if ((first & 128) === 0) return first;
    const numBytes = first & 127;
    if (numBytes === 0) throw new Error("DER: indefinite length not supported");
    let len = 0;
    for (let i = 0; i < numBytes; i++) len = len << 8 | this.readByte();
    return len;
  }
  readValue(tag) {
    const actual = this.readByte();
    if (actual !== tag) throw new Error(`DER: expected tag 0x${tag.toString(16)}, got 0x${actual.toString(16)}`);
    const len = this.readLength();
    const start = this.offset;
    const end = start + len;
    if (end > this.bytes.length) throw new Error("DER: length out of range");
    this.offset = end;
    return this.bytes.slice(start, end);
  }
  readSequence() {
    const content = this.readValue(48);
    return new _DerReader(content);
  }
  readIntegerBytes() {
    return this.readValue(2);
  }
  readOctetString() {
    return this.readValue(4);
  }
  readBitString() {
    const content = this.readValue(3);
    if (content.length === 0) throw new Error("DER: invalid BIT STRING");
    const unusedBits = content[0];
    return { unusedBits, data: content.slice(1) };
  }
  readOID() {
    const content = this.readValue(6);
    if (content.length === 0) throw new Error("DER: empty OID");
    const first = content[0];
    const parts = [Math.floor(first / 40), first % 40];
    let value = 0;
    for (let i = 1; i < content.length; i++) {
      const b = content[i];
      value = value << 7 | b & 127;
      if ((b & 128) === 0) {
        parts.push(value);
        value = 0;
      }
    }
    return parts.join(".");
  }
  readContextSpecific(tagNumber) {
    const tag = 160 + tagNumber;
    const content = this.readValue(tag);
    return new _DerReader(content);
  }
  peekTag() {
    if (this.offset >= this.bytes.length) throw new Error("DER: out of range");
    return this.bytes[this.offset];
  }
  skipAny() {
    this.readByte();
    const len = this.readLength();
    this.offset += len;
    if (this.offset > this.bytes.length) throw new Error("DER: length out of range");
  }
};

// src/utils/sm2KeyFormats.ts
var OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
var OID_SM2_CURVE = "1.2.156.10197.1.301";
function toBytes(input) {
  if (typeof input !== "string") return input;
  return decodeHexOrBase64ToBytes(input);
}
function looksLikeDer(bytes) {
  return bytes.length > 2 && bytes[0] === 48;
}
function ensureUncompressedPublicKeyHex(pubHex) {
  const s = pubHex.trim().toLowerCase();
  if (!isHexString(s)) throw new Error("Public key must be hex");
  if (s.length === 128) return `04${s}`;
  if (s.length === 130 && s.startsWith("04")) return s;
  throw new Error("Unsupported SM2 public key hex length");
}
function leftPadHexToBytes(hex, lengthBytes) {
  const s = hex.trim().toLowerCase();
  if (!isHexString(s)) throw new Error("Invalid hex");
  const bytes = hexToBytes(s);
  if (bytes.length > lengthBytes) {
    const start = bytes.length - lengthBytes;
    return bytes.slice(start);
  }
  if (bytes.length === lengthBytes) return bytes;
  const out = new Uint8Array(lengthBytes);
  out.set(bytes, lengthBytes - bytes.length);
  return out;
}
function sm2PublicKeyToRawHex(publicKey) {
  const bytes = toBytes(publicKey);
  if (!looksLikeDer(bytes)) {
    return ensureUncompressedPublicKeyHex(typeof publicKey === "string" ? publicKey : bytesToHex(bytes));
  }
  const spki = new DerReader(bytes).readSequence();
  const alg = spki.readSequence();
  const algOid = alg.readOID();
  if (algOid !== OID_EC_PUBLIC_KEY) throw new Error(`Unsupported public key algorithm OID: ${algOid}`);
  const curveOid = alg.readOID();
  if (curveOid !== OID_SM2_CURVE) {
  }
  const { unusedBits, data } = spki.readBitString();
  if (unusedBits !== 0) throw new Error("Unsupported BIT STRING with unused bits");
  const raw = bytesToHex(data);
  return ensureUncompressedPublicKeyHex(raw);
}
function sm2PrivateKeyToRawHex(privateKey) {
  const bytes = toBytes(privateKey);
  if (!looksLikeDer(bytes)) {
    const hex = typeof privateKey === "string" ? privateKey.trim().toLowerCase() : bytesToHex(bytes);
    if (isHexString(hex)) {
      if (hex.length === 64) return hex;
      if (hex.length < 64) return bytesToHex(leftPadHexToBytes(hex, 32));
      if (hex.startsWith("30")) return sm2PrivateKeyToRawHex(hexToBytes(hex));
    }
    throw new Error("Unsupported SM2 private key format");
  }
  const pki = new DerReader(bytes).readSequence();
  pki.readIntegerBytes();
  const alg = pki.readSequence();
  const algOid = alg.readOID();
  if (algOid !== OID_EC_PUBLIC_KEY) {
  }
  if (!alg.eof()) {
    const curveOid = alg.readOID();
    if (curveOid !== OID_SM2_CURVE) {
    }
  }
  const privateKeyOctets = pki.readOctetString();
  const ec = new DerReader(privateKeyOctets).readSequence();
  ec.readIntegerBytes();
  const dOctets = ec.readOctetString();
  const dHex = bytesToHex(dOctets);
  return bytesToHex(leftPadHexToBytes(dHex, 32));
}

// src/SM2Util.ts
var USER_ID = "1234567812345678";
var CIPHER_MODE_C1C3C2 = 1;
function normalizeCiphertextToHex(ciphertext) {
  const enc = detectStringEncoding(ciphertext);
  let hex;
  if (enc === "hex") {
    hex = ciphertext.trim().toLowerCase();
  } else if (enc === "base64") {
    hex = bytesToHex(decodeHexOrBase64ToBytes(ciphertext));
  } else {
    throw new Error("Ciphertext must be hex or base64");
  }
  if (hex.startsWith("04") && hex.length > 130) {
    hex = hex.substring(2);
  }
  return hex;
}
function normalizeSignatureToHex(signature) {
  const enc = detectStringEncoding(signature);
  if (enc === "hex") return signature.trim().toLowerCase();
  if (enc === "base64") return bytesToHex(decodeHexOrBase64ToBytes(signature));
  throw new Error("Signature must be hex or base64");
}
var SM2Util = class {
  static encryptToBytes(content, publicKey) {
    const pubHex = sm2PublicKeyToRawHex(publicKey);
    const cipherHex = import_sm_crypto_v2.sm2.doEncrypt(content, pubHex, CIPHER_MODE_C1C3C2);
    return hexToBytes(cipherHex);
  }
  static encryptToHex(content, publicKey) {
    const pubHex = sm2PublicKeyToRawHex(publicKey);
    const cipherHex = import_sm_crypto_v2.sm2.doEncrypt(typeof content === "string" ? utf8ToBytes(content) : content, pubHex, CIPHER_MODE_C1C3C2);
    return "04" + cipherHex;
  }
  static encryptToBase64(content, publicKey) {
    const hex = this.encryptToHex(content, publicKey);
    return bytesToBase64(hexToBytes(hex));
  }
  static encrypt(content, publicKey, toBase64 = false) {
    return toBase64 ? this.encryptToBase64(content, publicKey) : this.encryptToHex(content, publicKey);
  }
  static decryptToBytes(cipherBytes, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const cipherHex = bytesToHex(cipherBytes);
    return import_sm_crypto_v2.sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: "array", asn1: false });
  }
  static decryptToUtf8(cipherHexOrBase64, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const cipherHex = normalizeCiphertextToHex(cipherHexOrBase64);
    return import_sm_crypto_v2.sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: "string", asn1: false });
  }
  static decryptToBytesFromString(cipherHexOrBase64, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const cipherHex = normalizeCiphertextToHex(cipherHexOrBase64);
    return import_sm_crypto_v2.sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: "array", asn1: false });
  }
  static decrypt(cipherHexOrBase64, privateKey) {
    return this.decryptToUtf8(cipherHexOrBase64, privateKey);
  }
  static signToBytes(content, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const sigHex = import_sm_crypto_v2.sm2.doSignature(content, privHex, { der: true, hash: true, userId: USER_ID });
    return hexToBytes(sigHex);
  }
  static signToHex(content, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    return import_sm_crypto_v2.sm2.doSignature(typeof content === "string" ? utf8ToBytes(content) : content, privHex, {
      der: true,
      hash: true,
      userId: USER_ID
    });
  }
  static signToBase64(content, privateKey) {
    const sigHex = this.signToHex(content, privateKey);
    return bytesToBase64(hexToBytes(sigHex));
  }
  static sign(content, privateKey, toBase64 = false) {
    return toBase64 ? this.signToBase64(content, privateKey) : this.signToHex(content, privateKey);
  }
  static verify(content, publicKey, signatureHexOrBase64) {
    const pubHex = sm2PublicKeyToRawHex(publicKey);
    const sigHex = normalizeSignatureToHex(signatureHexOrBase64);
    return import_sm_crypto_v2.sm2.doVerifySignature(typeof content === "string" ? utf8ToBytes(content) : content, sigHex, pubHex, {
      der: true,
      hash: true,
      userId: USER_ID
    });
  }
  static encryptSign(content, encPublicKey, signPrivateKey, toBase64 = false) {
    const ciphertext = this.encrypt(content, encPublicKey, toBase64);
    const signature = this.sign(ciphertext, signPrivateKey, toBase64);
    return { ciphertext, signature };
  }
  static encryptSignWithSameFormatKeys(content, encPublicKey, signPrivateKey) {
    const enc = detectStringEncoding(encPublicKey);
    const sigEnc = detectStringEncoding(signPrivateKey);
    if (enc === "hex" && sigEnc === "hex") return this.encryptSign(content, encPublicKey, signPrivateKey, false);
    if (enc === "base64" && sigEnc === "base64") return this.encryptSign(content, encPublicKey, signPrivateKey, true);
    throw new Error("encPublicKey and signPrivateKey must be both hex or both base64");
  }
  static verifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey) {
    const ok = this.verify(ciphertext, signPublicKey, signature);
    if (!ok) throw new Error(`SM2 verify failed: ${ciphertext}`);
    return this.decrypt(ciphertext, decPrivateKey);
  }
  static verifyDecryptPair(pair, signPublicKey, decPrivateKey) {
    return this.verifyDecrypt(pair.ciphertext, pair.signature, signPublicKey, decPrivateKey);
  }
};

// src/SM3Util.ts
var import_sm_crypto_v22 = require("sm-crypto-v2");
var HMAC_KEY_MIN_LENGTH = 32;
var SM3Util = class {
  static digestToBytes(input) {
    const hex = (0, import_sm_crypto_v22.sm3)(input);
    return hexToBytes(hex);
  }
  static digestToHex(input) {
    const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
    return (0, import_sm_crypto_v22.sm3)(bytes);
  }
  static digestToBase64(input) {
    const hex = this.digestToHex(input);
    return bytesToBase64(hexToBytes(hex));
  }
  static digestFromBase64ToHex(base64) {
    return bytesToHex(this.digestToBytes(base64ToBytes(base64)));
  }
  static digest(input, toBase64 = false) {
    return toBase64 ? this.digestToBase64(input) : this.digestToHex(input);
  }
  static hmacBytes(key, data) {
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
      ipad[i] = k[i] ^ 54;
      opad[i] = k[i] ^ 92;
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
  static hmacToHex(key, data) {
    const keyBytes = typeof key === "string" ? decodeHexOrBase64ToBytes(key) : key;
    const dataBytes = typeof data === "string" ? utf8ToBytes(data) : data;
    return bytesToHex(this.hmacBytes(keyBytes, dataBytes));
  }
  static hmacToBase64(key, data) {
    const keyBytes = typeof key === "string" ? decodeHexOrBase64ToBytes(key) : key;
    const dataBytes = typeof data === "string" ? utf8ToBytes(data) : data;
    return bytesToBase64(this.hmacBytes(keyBytes, dataBytes));
  }
  static hmac(key, data, toBase64 = false) {
    return toBase64 ? this.hmacToBase64(key, data) : this.hmacToHex(key, data);
  }
  static generateHmacKeyBytes(keyLength = HMAC_KEY_MIN_LENGTH) {
    var _a;
    if (keyLength < HMAC_KEY_MIN_LENGTH) {
      throw new Error(`HMAC key length must be at least ${HMAC_KEY_MIN_LENGTH} bytes`);
    }
    const key = new Uint8Array(keyLength);
    if ((_a = globalThis.crypto) == null ? void 0 : _a.getRandomValues) {
      globalThis.crypto.getRandomValues(key);
      return key;
    }
    throw new Error("No secure RNG available: globalThis.crypto.getRandomValues is missing");
  }
  static generateHmacKeyHex(keyLength = HMAC_KEY_MIN_LENGTH) {
    return bytesToHex(this.generateHmacKeyBytes(keyLength));
  }
  static generateHmacKeyBase64(keyLength = HMAC_KEY_MIN_LENGTH) {
    return bytesToBase64(this.generateHmacKeyBytes(keyLength));
  }
  static generateHmacKeyToStr(keyLength = HMAC_KEY_MIN_LENGTH, toBase64 = false) {
    if (typeof keyLength === "boolean") {
      return this.generateHmacKeyToStr(HMAC_KEY_MIN_LENGTH, keyLength);
    }
    const keyBytes = this.generateHmacKeyBytes(keyLength);
    return toBase64 ? bytesToBase64(keyBytes) : bytesToHex(keyBytes);
  }
  static hmacVerify(key, data, receivedHmac) {
    const computed = this.hmacBytes(
      typeof key === "string" ? decodeHexOrBase64ToBytes(key) : key,
      typeof data === "string" ? utf8ToBytes(data) : data
    );
    const enc = detectStringEncoding(receivedHmac);
    let receivedBytes;
    if (enc === "hex") {
      receivedBytes = hexToBytes(receivedHmac);
    } else if (enc === "base64") {
      receivedBytes = base64ToBytes(receivedHmac);
    } else {
      throw new Error("receivedHmac must be hex or base64 string");
    }
    if (computed.length !== receivedBytes.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i++) diff |= computed[i] ^ receivedBytes[i];
    return diff === 0;
  }
};

// src/SM4Util.ts
var import_sm_crypto_v23 = require("sm-crypto-v2");
var KEY_SIZE_BYTES = 16;
var GCM_IV_SIZE = 12;
var GCM_TAG_SIZE = 16;
var BLOCK_SIZE = 16;
function normalizeKeyBytes(key) {
  const keyBytes = typeof key === "string" ? decodeHexOrBase64ToBytes(key) : key;
  if (keyBytes.length !== KEY_SIZE_BYTES) throw new Error("SM4 key must be 16 bytes (128 bits)");
  return keyBytes;
}
function xorBytes(a, b) {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}
function inc32(counter) {
  const c = new Uint8Array(counter);
  for (let i = 15; i >= 12; i--) {
    c[i] = c[i] + 1 & 255;
    if (c[i] !== 0) break;
  }
  return c;
}
function gf128Mul(x, y) {
  const R = /* @__PURE__ */ BigInt("0xE1000000000000000000000000000000");
  const MASK = (/* @__PURE__ */ BigInt("1") << /* @__PURE__ */ BigInt("128")) - /* @__PURE__ */ BigInt("1");
  let z = /* @__PURE__ */ BigInt("0");
  let v = y;
  for (let i = 0; i < 128; i++) {
    if (x & /* @__PURE__ */ BigInt("1") << BigInt(127 - i)) {
      z ^= v;
    }
    if (v & /* @__PURE__ */ BigInt("1")) {
      v = v >> /* @__PURE__ */ BigInt("1") ^ R;
    } else {
      v >>= /* @__PURE__ */ BigInt("1");
    }
  }
  return z & MASK;
}
function bytesToBigint(b) {
  let n = /* @__PURE__ */ BigInt("0");
  for (let i = 0; i < b.length; i++) n = n << /* @__PURE__ */ BigInt("8") | BigInt(b[i]);
  return n;
}
function bigintToBytes(n, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & /* @__PURE__ */ BigInt("0xff"));
    n >>= /* @__PURE__ */ BigInt("8");
  }
  return out;
}
function ghash(h, aad, ciphertext) {
  const hInt = bytesToBigint(h);
  const aadPadLen = (16 - aad.length % 16) % 16;
  const aadPadded = new Uint8Array(aad.length + aadPadLen);
  aadPadded.set(aad);
  const ctPadLen = (16 - ciphertext.length % 16) % 16;
  const ctPadded = new Uint8Array(ciphertext.length + ctPadLen);
  ctPadded.set(ciphertext);
  const lenBlock = new Uint8Array(16);
  const aadBitLen = BigInt(aad.length * 8);
  const ctBitLen = BigInt(ciphertext.length * 8);
  for (let i = 7; i >= 0; i--) {
    lenBlock[i] = Number(aadBitLen >> BigInt(7 - i) * /* @__PURE__ */ BigInt("8") & /* @__PURE__ */ BigInt("0xff"));
    lenBlock[8 + i] = Number(ctBitLen >> BigInt(7 - i) * /* @__PURE__ */ BigInt("8") & /* @__PURE__ */ BigInt("0xff"));
  }
  let y = /* @__PURE__ */ BigInt("0");
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
function sm4EcbEncryptBlock(key, block) {
  const encrypted = import_sm_crypto_v23.sm4.encrypt(block, key, { mode: "ecb", padding: "pkcs#7", output: "array" });
  return new Uint8Array(encrypted.buffer, 0, 16);
}
function sm4CtrEncrypt(key, counter, plaintext) {
  const result = new Uint8Array(plaintext.length);
  let ctr = counter;
  for (let i = 0; i < plaintext.length; i += BLOCK_SIZE) {
    const keystream = sm4EcbEncryptBlock(key, ctr);
    const block = plaintext.subarray(i, Math.min(i + BLOCK_SIZE, plaintext.length));
    for (let j = 0; j < block.length; j++) {
      result[i + j] = block[j] ^ keystream[j];
    }
    ctr = inc32(ctr);
  }
  return result;
}
function gcmEncryptCore(plaintext, key, iv) {
  const j0 = new Uint8Array(16);
  j0.set(iv, 0);
  j0[15] = 1;
  const h = sm4EcbEncryptBlock(key, new Uint8Array(16));
  const ciphertext = sm4CtrEncrypt(key, inc32(j0), plaintext);
  const ghashResult = ghash(h, new Uint8Array(0), ciphertext);
  const j0Encrypted = sm4EcbEncryptBlock(key, j0);
  const tag = xorBytes(ghashResult, j0Encrypted);
  const combined = new Uint8Array(iv.length + ciphertext.length + tag.length);
  combined.set(iv, 0);
  combined.set(ciphertext, iv.length);
  combined.set(tag, iv.length + ciphertext.length);
  return { combined, ciphertext, tag };
}
function gcmDecryptCore(data, key) {
  if (data.length < GCM_IV_SIZE + GCM_TAG_SIZE) {
    throw new Error("Invalid GCM ciphertext: too short");
  }
  const iv = data.subarray(0, GCM_IV_SIZE);
  const tag = data.subarray(data.length - GCM_TAG_SIZE);
  const ciphertext = data.subarray(GCM_IV_SIZE, data.length - GCM_TAG_SIZE);
  const j0 = new Uint8Array(16);
  j0.set(iv, 0);
  j0[15] = 1;
  const h = sm4EcbEncryptBlock(key, new Uint8Array(16));
  const ghashResult = ghash(h, new Uint8Array(0), ciphertext);
  const j0Encrypted = sm4EcbEncryptBlock(key, j0);
  const computedTag = xorBytes(ghashResult, j0Encrypted);
  if (!tagEquals(computedTag, tag)) {
    throw new Error("SM4 GCM decryption failed (authentication failed)");
  }
  return sm4CtrEncrypt(key, inc32(j0), ciphertext);
}
var SM4Util = class _SM4Util {
  static generateKeyBytes() {
    var _a;
    const key = new Uint8Array(KEY_SIZE_BYTES);
    if ((_a = globalThis.crypto) == null ? void 0 : _a.getRandomValues) {
      globalThis.crypto.getRandomValues(key);
      return key;
    }
    throw new Error("No secure RNG available: globalThis.crypto.getRandomValues is missing");
  }
  static generateKeyHex() {
    return bytesToHex(this.generateKeyBytes());
  }
  static generateKeyBase64() {
    return bytesToBase64(this.generateKeyBytes());
  }
  static parseHexKey(hexKey) {
    return hexToBytes(hexKey);
  }
  static generateGcmIV() {
    var _a;
    const iv = new Uint8Array(GCM_IV_SIZE);
    if ((_a = globalThis.crypto) == null ? void 0 : _a.getRandomValues) {
      globalThis.crypto.getRandomValues(iv);
      return iv;
    }
    throw new Error("No secure RNG available");
  }
  /**
   * SM4 GCM encryption.
   * Returns Hex(IV[12] + ciphertext + Tag[16]) by default, or Base64 if toBase64=true
   */
  static encryptGcm(plaintext, key, iv, toBase64 = false) {
    const k = normalizeKeyBytes(key);
    const actualIv = iv != null ? iv : _SM4Util.generateGcmIV();
    if (actualIv.length !== GCM_IV_SIZE) {
      throw new Error(`GCM IV must be ${GCM_IV_SIZE} bytes`);
    }
    const { combined } = gcmEncryptCore(plaintext, k, actualIv);
    return toBase64 ? bytesToBase64(combined) : bytesToHex(combined);
  }
  /**
   * SM4 GCM encryption, always returns Hex.
   */
  static encryptGcmHex(plaintext, key, iv) {
    return this.encryptGcm(plaintext, key, iv, false);
  }
  /**
   * SM4 GCM encryption, always returns Base64.
   */
  static encryptGcmBase64(plaintext, key, iv) {
    return this.encryptGcm(plaintext, key, iv, true);
  }
  /**
   * SM4 GCM decryption.
   * Input: Hex or Base64 encoded (IV[12] + ciphertext + Tag[16]), auto-detected
   * Returns plaintext bytes.
   */
  static decryptGcm(ciphertextHexOrBase64, key) {
    const k = normalizeKeyBytes(key);
    const data = decodeHexOrBase64ToBytes(ciphertextHexOrBase64);
    return gcmDecryptCore(data, k);
  }
  /**
   * SM4 GCM decryption from Hex input only.
   */
  static decryptGcmFromHex(ciphertextHex, key) {
    const k = normalizeKeyBytes(key);
    const data = hexToBytes(ciphertextHex);
    return gcmDecryptCore(data, k);
  }
  /**
   * SM4 GCM decrypt a UTF-8 string, returns Hex by default or Base64 if toBase64=true
   */
  static encryptGcmString(plainText, key, iv, toBase64 = false) {
    return _SM4Util.encryptGcm(utf8ToBytes(plainText), key, iv, toBase64);
  }
  /**
   * SM4 GCM decrypt to UTF-8 string
   * Input: Hex or Base64 encoded, auto-detected
   */
  static decryptGcmToString(ciphertextHexOrBase64, key) {
    return bytesToUtf8(_SM4Util.decryptGcm(ciphertextHexOrBase64, key));
  }
};
function tagEquals(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
//# sourceMappingURL=index.js.map