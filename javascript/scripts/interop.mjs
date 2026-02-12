#!/usr/bin/env node

import { SM2Util, SM3Util, SM4Util, bytesToHex, bytesToBase64 } from '../dist/index.mjs';

const JAVA = {
  CIPHER_PUBLIC_KEY_BASE64:
    'MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEO4gVFPrTdWaMRocy/GuyjUZYdbdsqzfcvrtjkCoTVfBSXVWElN6uj91ZxsiszlzQ3JxTYxLKd3sy6EWNuS22+g==',
  CIPHER_PRIVATE_KEY_BASE64:
    'MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgLtLT8TS7TpI1t6JhId5PiZ7yI+DwNDWwXY54yyb89SmgCgYIKoEcz1UBgi2hRANCAAQ7iBUU+tN1ZoxGhzL8a7KNRlh1t2yrN9y+u2OQKhNV8FJdVYSU3q6P3VnGyKzOXNDcnFNjEsp3ezLoRY25Lbb6',
  SIGN_PRIVATE_KEY_BASE64:
    'MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQghdEmDD4sgxQXfrDeGoHITWChGHSld/gV/ctXpxxNBTmgCgYIKoEcz1UBgi2hRANCAARmzTOQXN3qPrgm4pIy80fyorg5IK4FRAfabNl1X9/kFnTbwEcbFn+5kz1KGqb6sSCQnS8NuyveW5aFIASRhsuE',
  SIGN_PUBLIC_KEY_BASE64:
    'MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEZs0zkFzd6j64JuKSMvNH8qK4OSCuBUQH2mzZdV/f5BZ028BHGxZ/uZM9Shqm+rEgkJ0vDbsr3luWhSAEkYbLhA=='
};

function usage(exitCode = 0) {
  const msg = `
Usage:
  node scripts/interop.mjs gen [--plain <text>] [--out <path>]
  node scripts/interop.mjs check --json <json>
  node scripts/interop.mjs check --file <path>
  node scripts/interop.mjs check   (read JSON from stdin)

JSON schema:
  {
    plain: string,
    sm2: {
      ciphertextHex: string,
      ciphertextBase64: string,
      signatureHex: string,
      signatureBase64: string
    }
  }
`;
  process.stdout.write(msg);
  process.exit(exitCode);
}

function arg(name) {
  const idx = process.argv.indexOf(name);
  if (idx === -1) return undefined;
  return process.argv[idx + 1];
}

async function readStdin() {
  return await new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function loadJsonPayload() {
  const jsonArg = arg('--json');
  if (jsonArg) return JSON.parse(jsonArg);

  const file = arg('--file');
  if (file) {
    const fs = await import('node:fs/promises');
    const text = await fs.readFile(file, { encoding: 'utf8' });
    return JSON.parse(text);
  }

  const stdin = (await readStdin()).trim();
  if (!stdin) throw new Error('No input JSON provided');
  return JSON.parse(stdin);
}

async function gen(plain) {
  // SM3 example
  const sm3Hex = SM3Util.digestToHex(plain);

  // SM4 example (deterministic demo key)
  const sm4KeyHex = '0123456789abcdeffedcba9876543210';
  const sm4CipherHex = SM4Util.encryptEcbToHex(plain, sm4KeyHex);

  // SM2 interop: encrypt + sign (Java signs ciphertext string bytes)
  const ciphertextHex = SM2Util.encryptToHex(plain, JAVA.CIPHER_PUBLIC_KEY_BASE64);
  const ciphertextBase64 = SM2Util.encryptToBase64(plain, JAVA.CIPHER_PUBLIC_KEY_BASE64);
  const signatureHex = SM2Util.signToHex(ciphertextHex, JAVA.SIGN_PRIVATE_KEY_BASE64);
  const signatureBase64 = SM2Util.signToBase64(ciphertextHex, JAVA.SIGN_PRIVATE_KEY_BASE64);

  const payload = {
    plain,
    sm3: { hex: sm3Hex },
    sm4: { keyHex: sm4KeyHex, cipherHex: sm4CipherHex },
    sm2: { ciphertextHex, ciphertextBase64, signatureHex, signatureBase64 },
    keys: {
      cipherPublicKeyBase64: JAVA.CIPHER_PUBLIC_KEY_BASE64,
      cipherPrivateKeyBase64: JAVA.CIPHER_PRIVATE_KEY_BASE64,
      signPublicKeyBase64: JAVA.SIGN_PUBLIC_KEY_BASE64,
      signPrivateKeyBase64: JAVA.SIGN_PRIVATE_KEY_BASE64
    }
  };

  const outPath = arg('--out');
  const jsonText = JSON.stringify(payload, null, 2);

  if (outPath) {
    const fs = await import('node:fs/promises');
    await fs.writeFile(outPath, jsonText, { encoding: 'utf8' });
    process.stdout.write(`Wrote ${outPath}\n`);
    return;
  }

  process.stdout.write(jsonText);
}

function check(payload) {
  const plain = payload.plain;
  if (typeof plain !== 'string') throw new Error('payload.plain must be string');
  if (!payload.sm2) throw new Error('payload.sm2 missing');

  const { ciphertextHex, ciphertextBase64, signatureHex, signatureBase64 } = payload.sm2;

  // decrypt (hex & base64)
  const p1 = SM2Util.decrypt(ciphertextHex, JAVA.CIPHER_PRIVATE_KEY_BASE64);
  const p2 = SM2Util.decrypt(ciphertextBase64, JAVA.CIPHER_PRIVATE_KEY_BASE64);

  // verify (hex & base64)
  const v1 = SM2Util.verify(ciphertextHex, JAVA.SIGN_PUBLIC_KEY_BASE64, signatureHex);
  const v2 = SM2Util.verify(ciphertextHex, JAVA.SIGN_PUBLIC_KEY_BASE64, signatureBase64);

  const ok = p1 === plain && p2 === plain && v1 === true && v2 === true;

  const report = {
    ok,
    decryptedFromHex: p1,
    decryptedFromBase64: p2,
    verifySigHex: v1,
    verifySigBase64: v2
  };

  process.stdout.write(JSON.stringify(report, null, 2));
  if (!ok) process.exitCode = 2;
}

async function main() {
  const cmd = process.argv[2];
  if (!cmd) usage(1);

  if (cmd === 'gen') {
    const plain = arg('--plain') ?? '您好，我是SM2算法測試數據，包括简体中文，繁體中文，English三种文字';
    return await gen(plain);
  }

  if (cmd === 'check') {
    const payload = await loadJsonPayload();
    return check(payload);
  }

  usage(1);
}

main().catch((e) => {
  console.error(e?.stack || String(e));
  process.exit(1);
});
