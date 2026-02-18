import { bytesToHex, decodeHexOrBase64ToBytes, hexToBytes, isHexString } from './encoding';
import { DerReader } from './der';

const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_SM2_CURVE = '1.2.156.10197.1.301';

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
