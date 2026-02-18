export type Bytes = Uint8Array;

const HEX_RE = /^[0-9a-fA-F]+$/;

export function isHexString(input: string): boolean {
  const s = input.trim();
  return s.length > 0 && s.length % 2 === 0 && HEX_RE.test(s);
}

export function isBase64String(input: string): boolean {
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

export function hexToBytes(hex: string): Bytes {
  const s = hex.trim();
  if (!isHexString(s)) throw new Error('Invalid hex string');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Bytes): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, '0');
  return out;
}

function hasBuffer(): boolean {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return typeof (globalThis as any).Buffer !== 'undefined';
}

export function base64ToBytes(base64: string): Bytes {
  const s = base64.trim();
  if (hasBuffer()) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const B = (globalThis as any).Buffer as typeof Buffer;
    return new Uint8Array(B.from(s, 'base64'));
  }
  if (typeof globalThis.atob !== 'function') {
    throw new Error('No base64 decoder available (Buffer/atob missing)');
  }
  const bin = globalThis.atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Bytes): string {
  if (hasBuffer()) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const B = (globalThis as any).Buffer as typeof Buffer;
    return B.from(bytes).toString('base64');
  }
  if (typeof globalThis.btoa !== 'function') {
    throw new Error('No base64 encoder available (Buffer/btoa missing)');
  }
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return globalThis.btoa(bin);
}

export function utf8ToBytes(text: string): Bytes {
  if (typeof globalThis.TextEncoder !== 'undefined') return new TextEncoder().encode(text);
  if (hasBuffer()) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const B = (globalThis as any).Buffer as typeof Buffer;
    return new Uint8Array(B.from(text, 'utf8'));
  }
  throw new Error('No UTF-8 encoder available');
}

export function bytesToUtf8(bytes: Bytes): string {
  if (typeof globalThis.TextDecoder !== 'undefined') return new TextDecoder().decode(bytes);
  if (hasBuffer()) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const B = (globalThis as any).Buffer as typeof Buffer;
    return B.from(bytes).toString('utf8');
  }
  throw new Error('No UTF-8 decoder available');
}

export function detectStringEncoding(input: string): 'hex' | 'base64' | 'unknown' {
  if (isHexString(input)) return 'hex';
  if (isBase64String(input)) return 'base64';
  return 'unknown';
}

export function decodeHexOrBase64ToBytes(input: string): Bytes {
  const enc = detectStringEncoding(input);
  if (enc === 'hex') return hexToBytes(input);
  if (enc === 'base64') return base64ToBytes(input);
  throw new Error('Input must be hex or base64 string');
}
