/**
 * SM4 国密对称加密算法示例（GCM 模式）
 *
 * 快速上手：
 *   1. cd javascript/crossmool
 *   2. npm install && npm run build
 *   3. npx tsx samples/sm4_sample.ts
 *
 * 核心能力：
 *   - 生成 SM4 密钥（128-bit，Hex / Base64 格式）
 *   - SM4-GCM 加密（带认证标签，防篡改）
 *   - SM4-GCM 解密（自动检测 Hex / Base64 输入）
 *   - GCM 模式：任何篡改都会导致解密失败
 */

import { SM4Util } from '../src/index';

function main() {
  console.log('============================================================');
  console.log('  SM4 Sample — 国密对称加密 (GCM 模式)');
  console.log('============================================================');
  console.log();

  // ==================== 原始内容 ====================
  const originalContent =
    '今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。' +
    '路过咖啡店时買了一杯美式，順便（顺便）看了下手机，' +
    '今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。' +
    '朋友发来一条消息说："Don\'t forget to bring your umbrella, just in case!" ' +
    '我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。';

  console.log(`OriginalContent ::: ${originalContent}`);
  console.log();

  // ==================== 1. 生成 SM4 密钥 ====================
  console.log('>>> 1. 生成 SM4 密钥（128-bit）');

  const hexKey = SM4Util.generateKeyHex();
  console.log(`  SM4 Hex Key    ::: ${hexKey}`);

  const base64Key = SM4Util.generateKeyBase64();
  console.log(`  SM4 Base64 Key ::: ${base64Key}`);
  console.log();

  // ==================== 2. Hex 输出 GCM 加解密 ====================
  console.log('>>> 2. 使用 Hex 密钥进行 GCM 加解密');

  const encryptedHex = SM4Util.encryptGcmString(originalContent, hexKey);
  console.log(`  Encrypted (Hex) ::: ${encryptedHex.substring(0, 150)}...`);

  const decryptedHex = SM4Util.decryptGcmToString(encryptedHex, hexKey);
  console.log(`  Decrypted (Hex) ::: ${decryptedHex}`);
  console.log(`  WhetherDecryptEqualsOriginalContent (Hex) ::: ${originalContent === decryptedHex}`);
  console.log();

  // ==================== 3. Base64 输出 GCM 加解密 ====================
  console.log('>>> 3. 使用 Base64 输出进行 GCM 加解密');

  const encryptedB64 = SM4Util.encryptGcmString(originalContent, hexKey, undefined, true);
  console.log(`  Encrypted (Base64) ::: ${encryptedB64.substring(0, 100)}...`);

  const decryptedB64 = SM4Util.decryptGcmToString(encryptedB64, hexKey);
  console.log(`  Decrypted (Base64) ::: ${decryptedB64}`);
  console.log(`  WhetherDecryptEqualsOriginalContent (Base64) ::: ${originalContent === decryptedB64}`);
  console.log();

  // ==================== 4. 随机 IV 验证 ====================
  console.log('>>> 4. 随机 IV 验证（每次 GCM 加密密文不同）');

  const ct1 = SM4Util.encryptGcmString('Same plaintext', hexKey);
  const ct2 = SM4Util.encryptGcmString('Same plaintext', hexKey);
  console.log(`  Ciphertext 1 ::: ${ct1.substring(0, 50)}...`);
  console.log(`  Ciphertext 2 ::: ${ct2.substring(0, 50)}...`);
  console.log(`  IV differs (ciphertexts not equal) ::: ${ct1 !== ct2}`);
  console.log();

  // ==================== 5. GCM 防篡改验证 ====================
  console.log('>>> 5. GCM 防篡改验证');
  console.log('  （故意篡改密文末尾字符，GCM 应检测到并拒绝解密）');

  const tampered = encryptedHex.substring(0, encryptedHex.length - 2) + 'XX';
  try {
    const hacked = SM4Util.decryptGcmToString(tampered, hexKey);
    console.log(`  Tampered decrypted ::: ${hacked}`);
  } catch (ex: any) {
    console.log(`  GCM detected tampering, decryption failed ::: ${ex.message}`);
  }
  console.log();

  console.log('=== SM4 Sample 完成 ===');
}

main();
