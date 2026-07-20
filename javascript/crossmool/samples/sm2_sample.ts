/**
 * SM2 国密非对称加密算法示例
 *
 * 快速上手：
 *   1. cd javascript/crossmool
 *   2. npm install && npm run build
 *   3. npx tsx samples/sm2_sample.ts
 *   或：node --import tsx samples/sm2_sample.ts
 *
 * 核心能力：
 *   - 生成 SM2 密钥对（Hex / Base64 / Raw DER）
 *   - 公钥加密 → 私钥解密
 *   - 私钥签名 → 公钥验签
 *   - 先加密再签名 → 先验签再解密（防篡改 + 防抵赖）
 *   - PEM 格式导入导出
 */

import { SM2Util } from '../src/index';

function main() {
  console.log('============================================================');
  console.log('  SM2 Sample — 国密非对称加密 (SM2P256V1)');
  console.log('============================================================');
  console.log();

  // ==================== 原始内容 ====================
  const originalContent =
    '今天天气真好，气温大约 28°C，我决定出門走走。' +
    '路过咖啡店时買了一杯美式，順便（顺便）看了下手机。' +
    "Don't forget to bring your umbrella!";

  console.log(`OriginalContent ::: ${originalContent}`);
  console.log();

  // ==================== 1. 生成两对密钥 ====================
  console.log('>>> 1. 生成两对 SM2 密钥（第1对加解密，第2对签名）');

  const { publicKey: pubKey1, privateKey: priKey1 } = SM2Util.generateKeyPairHex();
  const { publicKey: pubKey2, privateKey: priKey2 } = SM2Util.generateKeyPairHex();

  console.log(`  privateKeyHex-1 ::: ${priKey1}`);
  console.log(`  publicKeyHex-1  ::: ${pubKey1}`);
  console.log(`  privateKeyHex-2 ::: ${priKey2}`);
  console.log(`  publicKeyHex-2  ::: ${pubKey2}`);
  console.log();

  // ==================== 2. 加密并签名 → 验签并解密 ====================
  console.log('>>> 2. 加密并签名 → 验签并解密（先加密再签名，先验签再解密）');

  const pair = SM2Util.encryptSign(originalContent, pubKey1, priKey2);
  console.log(`  CipherText ::: ${pair.ciphertext.substring(0, 150)}...`);
  console.log(`  Signature  ::: ${pair.signature}`);
  console.log();

  const verifyDecrypt = SM2Util.verifyDecrypt(pair.ciphertext, pair.signature, pubKey2, priKey1);
  console.log(`  VerifyDecrypt ::: ${verifyDecrypt}`);
  console.log(`  WhetherVerifyDecryptEqualsOriginalContent ::: ${originalContent === verifyDecrypt}`);
  console.log();

  // ==================== 3. 仅加密/解密 ====================
  console.log('>>> 3. 公钥加密 → 私钥解密');

  const encryptedContent = SM2Util.encryptToHex(originalContent, pubKey1);
  console.log(`  EncryptedContent ::: ${encryptedContent.substring(0, 150)}...`);

  const decryptedContent = SM2Util.decrypt(encryptedContent, priKey1);
  console.log(`  DecryptedContent ::: ${decryptedContent}`);
  console.log(`  WhetherDecryptEqualsOriginalContent ::: ${originalContent === decryptedContent}`);
  console.log();

  // ==================== 4. 签名/验签 ====================
  console.log('>>> 4. 私钥签名 → 公钥验签');

  const contentSignature = SM2Util.signToHex(originalContent, priKey2);
  console.log(`  ContentSignature ::: ${contentSignature}`);

  const verify = SM2Util.verify(originalContent, pubKey2, contentSignature);
  console.log(`  WhetherVerifyEqualsOriginalContent ::: ${verify}`);
  console.log();

  // ==================== 5. Base64 格式示例 ====================
  console.log('>>> 5. Base64 格式输出（可选）');

  const encryptedB64 = SM2Util.encryptToBase64(originalContent, pubKey1);
  console.log(`  Encrypted (Base64) ::: ${encryptedB64.substring(0, 100)}...`);

  const signatureB64 = SM2Util.signToBase64(originalContent, priKey2);
  console.log(`  Signature  (Base64) ::: ${signatureB64}`);
  console.log();

  // ==================== 6. PEM 导出示例 ====================
  console.log('>>> 6. PEM 格式（跨语言密钥交换）');

  const rawKp = SM2Util.generateKeyPairRaw();
  const pubPEM = SM2Util.exportPublicKeyPEM(rawKp.publicKey);
  const priPEM = SM2Util.exportPrivateKeyPEM(rawKp.privateKey);
  console.log(`  Public Key PEM:\n${pubPEM}`);
  console.log(`  Private Key PEM:\n${priPEM}`);

  const importedPub = SM2Util.importPublicKeyPEM(pubPEM);
  console.log(`  PEM Roundtrip ::: ${importedPub === rawKp.publicKey}`);
  console.log();

  console.log('=== SM2 Sample 完成 ===');
}

main();
