# crossmool

A cross-language toolkit for the Chinese national cryptographic standards **SM2** / **SM3** / **SM4**.
This is the JavaScript/TypeScript implementation, built on top of [sm-crypto-v2](https://www.npmjs.com/package/sm-crypto-v2).

The name comes from **cross [S]M [T]ool**: it lets you encrypt in one language and decrypt in
another, with a single unified data format across all supported languages (Java, Python,
JavaScript, Go, Rust, C, C++, C#).

## Features

- **SM2** — asymmetric encryption / decryption, signing / verification, combined encrypt-then-sign
- **SM3** — 256-bit hash and HMAC-SM3 message authentication
- **SM4** — symmetric encryption in GCM mode (authenticated, tamper-evident)
- **Cross-language interop** — C1C3C2 ciphertext layout, X.509 public key / PKCS#8 private key (DER),
  PEM import/export, HEX (default) and Base64 encodings
- **TypeScript-first** — full type declarations, ESM + CommonJS + IIFE (browser) builds

## Installation

```bash
npm install crossmool
```

## Quick start

```ts
import { SM2Util, SM3Util, SM4Util } from 'crossmool';

// --- SM2: encrypt / decrypt ---
const { publicKey, privateKey } = SM2Util.generateKeyPairHex();
const ciphertext = SM2Util.encryptToHex('hello 简体中文 繁體中文', publicKey);
const plaintext = SM2Util.decrypt(ciphertext, privateKey);

// --- SM2: sign / verify ---
const signature = SM2Util.signToHex(plaintext, privateKey);
const ok = SM2Util.verify(plaintext, publicKey, signature);

// --- SM3: digest + HMAC ---
const hash = SM3Util.digest(plaintext);            // 64-char HEX
const key = SM3Util.generateHmacKeyToStr();
const mac = SM3Util.hmac(plaintext, key);
const valid = SM3Util.hmacVerify(plaintext, key, mac);

// --- SM4: GCM encrypt / decrypt ---
const sm4Key = SM4Util.generateKeyHex();
const sm4Cipher = SM4Util.encryptGcmString(plaintext, sm4Key);
const sm4Plain = SM4Util.decryptGcmToString(sm4Cipher, sm4Key);
```

## API overview

| Utility | Method | Description |
|---------|--------|-------------|
| `SM2Util` | `generateKeyPairHex()` / `generateKeyPairRaw()` | Generate key pair (HEX / raw DER) |
| | `encryptToHex` / `encryptToBase64` | Encrypt with public key |
| | `decrypt` | Decrypt with private key |
| | `signToHex` / `signToBase64` | Sign with private key |
| | `verify` | Verify with public key |
| | `encryptSign` / `verifyDecrypt` | Combined encrypt-then-sign |
| | `exportPublicKeyPEM` / `exportPrivateKeyPEM` / `importPublicKeyPEM` | PEM import/export |
| `SM3Util` | `digest` / `digestToHex` | SM3 hash |
| | `generateHmacKeyToStr` / `hmac` / `hmacVerify` | HMAC-SM3 |
| `SM4Util` | `generateKeyHex` / `generateKeyBase64` | Generate 128-bit key |
| | `encryptGcmString` / `decryptGcmToString` | SM4-GCM encrypt/decrypt |

## Cross-language interoperability

Data formats are unified across all 8 language implementations:

- SM2 public key: X.509 (DER), private key: PKCS#8 (DER)
- SM2 ciphertext: `C1C3C2` layout
- SM4: GCM mode only (IV 12 bytes, tag 128 bits)
- Output: HEX by default, Base64 optional

For the full function-by-function specification, see
[`userdoc/public_function_specification.md`](../../userdoc/public_function_specification.md).

## Requirements

- Node.js 22 or newer

## License

[LGPL-3.0](./LICENSE)
