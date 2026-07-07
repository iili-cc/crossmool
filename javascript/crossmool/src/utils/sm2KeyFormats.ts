import { bytesToBase64, bytesToHex, decodeHexOrBase64ToBytes, hexToBytes, isHexString } from './encoding';
import { DerReader } from './der';

const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_SM2_CURVE = '1.2.156.10197.1.301';

// ────────────────── DER encoding helpers ──────────────────

function concatArrays(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

function encodeLength(len: number): Uint8Array {
  if (len < 128) return new Uint8Array([len]);
  const parts: number[] = [];
  let v = len;
  while (v > 0) {
    parts.unshift(v & 0xff);
    v >>>= 8;
  }
  return new Uint8Array([0x80 | parts.length, ...parts]);
}

function encodeTaggedValue(tag: number, content: Uint8Array): Uint8Array {
  return concatArrays(new Uint8Array([tag]), encodeLength(content.length), content);
}

function encodeInteger(value: Uint8Array): Uint8Array {
  // strip leading zeros, ensure positive (add 0x00 if MSB >= 0x80)
  let start = 0;
  while (start < value.length && value[start] === 0) start++;
  if (start === value.length) return encodeTaggedValue(0x02, new Uint8Array([0]));
  const trimmed = value.slice(start);
  if (trimmed[0]! >= 0x80) {
    return encodeTaggedValue(0x02, concatArrays(new Uint8Array([0]), trimmed));
  }
  return encodeTaggedValue(0x02, trimmed);
}

function encodeOID(oid: string): Uint8Array {
  const parts = oid.split('.').map(Number);
  const result: number[] = [parts[0]! * 40 + parts[1]!];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i]!;
    const stack: number[] = [v & 0x7f];
    v >>>= 7;
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    result.push(...stack);
  }
  return encodeTaggedValue(0x06, new Uint8Array(result));
}

function encodeOctetString(data: Uint8Array): Uint8Array {
  return encodeTaggedValue(0x04, data);
}

function encodeBitString(data: Uint8Array, unusedBits = 0): Uint8Array {
  return encodeTaggedValue(0x03, concatArrays(new Uint8Array([unusedBits]), data));
}

function encodeSequence(content: Uint8Array): Uint8Array {
  return encodeTaggedValue(0x30, content);
}

function encodeContextSpecific(tagNumber: number, content: Uint8Array): Uint8Array {
  return encodeTaggedValue(0xa0 | tagNumber, content);
}

// ────────────────── Key encoding to DER ──────────────────

/**
 * Encode a raw-hex SM2 public key (130 chars, 04+X+Y) to X.509 SubjectPublicKeyInfo DER (hex).
 */
function encodePublicKeyToDer(pubHex: string): string {
  const raw = ensureUncompressedPublicKeyHex(pubHex);
  const pubPoint = hexToBytes(raw); // 65 bytes: 04||X||Y

  const algSeq = encodeSequence(concatArrays(
    encodeOID(OID_EC_PUBLIC_KEY),
    encodeOID(OID_SM2_CURVE)
  ));

  const spki = encodeSequence(concatArrays(
    algSeq,
    encodeBitString(pubPoint, 0)
  ));

  return bytesToHex(spki);
}

/**
 * Encode raw-hex SM2 keys to PKCS#8 PrivateKeyInfo DER (hex).
 * @param privHex  private key hex (64 chars)
 * @param pubHex   public key hex (130 chars, 04+X+Y) — optional, included in ECPrivateKey
 */
function encodePrivateKeyToDer(privHex: string, pubHex: string): string {
  const d = hexToBytes(ensureRawPrivateKeyHex(privHex)); // 32 bytes
  const pubPoint = hexToBytes(ensureUncompressedPublicKeyHex(pubHex)); // 65 bytes

  // ECPrivateKey SEQUENCE (SEC 1, RFC 5915)
  const ecPrivKey = encodeSequence(concatArrays(
    encodeInteger(new Uint8Array([1])),                        // version = 1
    encodeOctetString(d),                                      // private key
    encodeContextSpecific(1, encodeBitString(pubPoint, 0))    // [1] public key
  ));

  // AlgorithmIdentifier
  const algSeq = encodeSequence(concatArrays(
    encodeOID(OID_EC_PUBLIC_KEY),
    encodeOID(OID_SM2_CURVE)
  ));

  // PrivateKeyInfo SEQUENCE
  const pki = encodeSequence(concatArrays(
    encodeInteger(new Uint8Array([0])),  // version
    algSeq,
    encodeOctetString(ecPrivKey)
  ));

  return bytesToHex(pki);
}

function ensureRawPrivateKeyHex(privHex: string): string {
  const s = privHex.trim().toLowerCase();
  if (!isHexString(s)) throw new Error('Private key must be hex');
  if (s.length === 64) return s;
  throw new Error('Unsupported SM2 private key hex length');
}

// Re-export for external use
export { encodePublicKeyToDer, encodePrivateKeyToDer };

export type KeyInput = string | Uint8Array;

function toBytes(input: KeyInput): Uint8Array {
  if (typeof input !== 'string') return input;
  return decodeHexOrBase64ToBytes(input);
}

function looksLikeDer(bytes: Uint8Array): boolean {
  return bytes.length > 2 && bytes[0] === 0x30;
}

function ensureUncompressedPublicKeyHex(pubHex: string): string {
  const s = pubHex.trim().toLowerCase();
  if (!isHexString(s)) throw new Error('Public key must be hex');
  if (s.length === 128) return `04${s}`; // X||Y
  if (s.length === 130 && s.startsWith('04')) return s;
  throw new Error('Unsupported SM2 public key hex length');
}

function leftPadHexToBytes(hex: string, lengthBytes: number): Uint8Array {
  const s = hex.trim().toLowerCase();
  if (!isHexString(s)) throw new Error('Invalid hex');
  const bytes = hexToBytes(s);
  if (bytes.length > lengthBytes) {
    // tolerate leading 0x00 for INTEGER
    const start = bytes.length - lengthBytes;
    return bytes.slice(start);
  }
  if (bytes.length === lengthBytes) return bytes;
  const out = new Uint8Array(lengthBytes);
  out.set(bytes, lengthBytes - bytes.length);
  return out;
}

export function sm2PublicKeyToRawHex(publicKey: KeyInput): string {
  const bytes = toBytes(publicKey);
  if (!looksLikeDer(bytes)) {
    return ensureUncompressedPublicKeyHex(typeof publicKey === 'string' ? publicKey : bytesToHex(bytes));
  }

  // SubjectPublicKeyInfo
  const spki = new DerReader(bytes).readSequence();
  const alg = spki.readSequence();
  const algOid = alg.readOID();
  if (algOid !== OID_EC_PUBLIC_KEY) throw new Error(`Unsupported public key algorithm OID: ${algOid}`);
  const curveOid = alg.readOID();
  if (curveOid !== OID_SM2_CURVE) {
    // Some encoders omit/alter parameters; still attempt to parse.
  }
  const { unusedBits, data } = spki.readBitString();
  if (unusedBits !== 0) throw new Error('Unsupported BIT STRING with unused bits');
  const raw = bytesToHex(data);
  return ensureUncompressedPublicKeyHex(raw);
}

export function sm2PrivateKeyToRawHex(privateKey: KeyInput): string {
  const bytes = toBytes(privateKey);
  if (!looksLikeDer(bytes)) {
    const hex = typeof privateKey === 'string' ? privateKey.trim().toLowerCase() : bytesToHex(bytes);
    // raw private key: 32-byte hex
    if (isHexString(hex)) {
      if (hex.length === 64) return hex;
      if (hex.length < 64) return bytesToHex(leftPadHexToBytes(hex, 32));
      // If someone passed ECPrivateKey DER hex as string, it starts with 30
      if (hex.startsWith('30')) return sm2PrivateKeyToRawHex(hexToBytes(hex));
    }
    throw new Error('Unsupported SM2 private key format');
  }

  // PrivateKeyInfo (PKCS8)
  const pki = new DerReader(bytes).readSequence();
  pki.readIntegerBytes(); // version
  const alg = pki.readSequence();
  const algOid = alg.readOID();
  if (algOid !== OID_EC_PUBLIC_KEY) {
    // some PKCS8 may use id-ecPublicKey; expect that
  }
  if (!alg.eof()) {
    const curveOid = alg.readOID();
    if (curveOid !== OID_SM2_CURVE) {
      // tolerate
    }
  }

  const privateKeyOctets = pki.readOctetString();

  // ECPrivateKey (SEC1)
  const ec = new DerReader(privateKeyOctets).readSequence();
  ec.readIntegerBytes(); // version
  const dOctets = ec.readOctetString();
  const dHex = bytesToHex(dOctets);
  return bytesToHex(leftPadHexToBytes(dHex, 32));
}
