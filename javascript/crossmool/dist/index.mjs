// src/SM2Util.ts
import { sm2 } from "sm-crypto-v2";

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
  if (enc === "hex") return ciphertext.trim().toLowerCase();
  if (enc === "base64") return bytesToHex(decodeHexOrBase64ToBytes(ciphertext));
  throw new Error("Ciphertext must be hex or base64");
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
    const cipherHex = sm2.doEncrypt(content, pubHex, CIPHER_MODE_C1C3C2);
    return hexToBytes(cipherHex);
  }
  static encryptToHex(content, publicKey) {
    const pubHex = sm2PublicKeyToRawHex(publicKey);
    return sm2.doEncrypt(typeof content === "string" ? utf8ToBytes(content) : content, pubHex, CIPHER_MODE_C1C3C2);
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
    return sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: "array" });
  }
  static decryptToUtf8(cipherHexOrBase64, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const cipherHex = normalizeCiphertextToHex(cipherHexOrBase64);
    return sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: "string" });
  }
  static decryptToBytesFromString(cipherHexOrBase64, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const cipherHex = normalizeCiphertextToHex(cipherHexOrBase64);
    return sm2.doDecrypt(cipherHex, privHex, CIPHER_MODE_C1C3C2, { output: "array" });
  }
  static decrypt(cipherHexOrBase64, privateKey) {
    return this.decryptToUtf8(cipherHexOrBase64, privateKey);
  }
  static signToBytes(content, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    const sigHex = sm2.doSignature(content, privHex, { der: true, hash: true, userId: USER_ID });
    return hexToBytes(sigHex);
  }
  static signToHex(content, privateKey) {
    const privHex = sm2PrivateKeyToRawHex(privateKey);
    return sm2.doSignature(typeof content === "string" ? utf8ToBytes(content) : content, privHex, {
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
    return sm2.doVerifySignature(typeof content === "string" ? utf8ToBytes(content) : content, sigHex, pubHex, {
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
import { sm3 } from "sm-crypto-v2";
var SM3Util = class {
  static digestToBytes(input) {
    const hex = sm3(input);
    return hexToBytes(hex);
  }
  static digestToHex(input) {
    const bytes = typeof input === "string" ? utf8ToBytes(input) : input;
    return sm3(bytes);
  }
  static digestToBase64(input) {
    const hex = this.digestToHex(input);
    return bytesToBase64(hexToBytes(hex));
  }
  static digestFromBase64ToHex(base64) {
    return bytesToHex(this.digestToBytes(base64ToBytes(base64)));
  }
};

// src/SM4Util.ts
import { sm4 } from "sm-crypto-v2";
var KEY_SIZE_BYTES = 16;
function normalizeKeyBytes(key) {
  const keyBytes = typeof key === "string" ? decodeHexOrBase64ToBytes(key) : key;
  if (keyBytes.length !== KEY_SIZE_BYTES) throw new Error("SM4 key must be 16 bytes (128 bits)");
  return keyBytes;
}
var SM4Util = class {
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
  static encryptEcbToBytes(input, key) {
    const k = normalizeKeyBytes(key);
    return sm4.encrypt(input, k, { mode: "ecb", padding: "pkcs#7", output: "array" });
  }
  static decryptEcbToBytes(cipher, key) {
    const k = normalizeKeyBytes(key);
    return sm4.decrypt(cipher, k, { mode: "ecb", padding: "pkcs#7", output: "array" });
  }
  static encryptEcbToHex(plainText, key) {
    const ct = this.encryptEcbToBytes(utf8ToBytes(plainText), key);
    return bytesToHex(ct);
  }
  static encryptEcbToBase64(plainText, key) {
    const ct = this.encryptEcbToBytes(utf8ToBytes(plainText), key);
    return bytesToBase64(ct);
  }
  static decryptEcbToUtf8(cipherHexOrBase64, key) {
    const cipherBytes = decodeHexOrBase64ToBytes(cipherHexOrBase64);
    const pt = this.decryptEcbToBytes(cipherBytes, key);
    return bytesToUtf8(pt);
  }
  static decryptEcbHexToUtf8(cipherHex, key) {
    const pt = this.decryptEcbToBytes(hexToBytes(cipherHex), key);
    return bytesToUtf8(pt);
  }
};
export {
  SM2Util,
  SM3Util,
  SM4Util,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToUtf8,
  decodeHexOrBase64ToBytes,
  hexToBytes,
  isBase64String,
  isHexString,
  sm2PrivateKeyToRawHex,
  sm2PublicKeyToRawHex,
  utf8ToBytes
};
//# sourceMappingURL=index.mjs.map