/**
 * SM3 国密哈希算法示例
 *
 * 快速上手：
 *   1. cd javascript/crossmool
 *   2. npm install && npm run build
 *   3. npx tsx samples/sm3_sample.ts
 *
 * 核心能力：
 *   - SM3 消息摘要（256-bit，类似 SHA-256）
 *   - HMAC-SM3 消息认证码（防篡改 + 防伪造）
 *   - 支持 Hex / Base64 输出
 */

import { SM3Util } from '../src/index';

function main() {
  console.log('============================================================');
  console.log('  SM3 Sample — 国密哈希算法 (256-bit)');
  console.log('============================================================');
  console.log();

  // ==================== 1. SM3 消息摘要 ====================
  console.log('>>> 1. SM3 消息摘要 (Digest)');

  const input =
    '在这个全球化时代，無論身處何地，' +
    'learning and growth are always the keys to a fulfilling life.';

  console.log(`  Input        ::: ${input}`);

  const hash = SM3Util.digest(input);
  console.log(`  SM3 Hash     ::: ${hash}`);

  const hashHex = SM3Util.digest(input, false);
  console.log(`  SM3 Hash (Hex) ::: ${hashHex}`);

  const equals = hash === hashHex;
  console.log(`  Whether Hash Equals Hex ::: ${equals}`);
  console.log();

  // ==================== 2. HMAC-SM3 消息认证码 ====================
  console.log('>>> 2. HMAC-SM3 消息认证码');

  const hmacKey = SM3Util.generateHmacKeyToStr();
  console.log(`  HMAC Key      ::: ${hmacKey}`);

  const hmacValue = SM3Util.hmac(input, hmacKey);
  console.log(`  HMAC Value    ::: ${hmacValue}`);

  const hmacValue2 = SM3Util.hmac(input, hmacKey);
  console.log(`  HMAC Value 2  ::: ${hmacValue2}`);

  const hmacEquals = hmacValue === hmacValue2;
  console.log(`  Whether HMAC Values Equal ::: ${hmacEquals}`);
  console.log();

  // ==================== 3. HMAC 校验 ====================
  console.log('>>> 3. HMAC 校验（防篡改验证）');

  const hmacVerified = SM3Util.hmacVerify(input, hmacKey, hmacValue);
  console.log(`  HMAC Verify (correct)   ::: ${hmacVerified}`);

  const hmacTampered = SM3Util.hmacVerify(input + 'X', hmacKey, hmacValue);
  console.log(`  HMAC Verify (tampered)  ::: ${hmacTampered}`);
  console.log();

  // ==================== 4. 字节数组输入 ====================
  console.log('>>> 4. 字节数组摘要（非字符串场景）');

  const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
  const digestHex = SM3Util.digestToHex(data);

  const hexStr = Array.from(data).map(b => b.toString(16).padStart(2, '0')).join(' ');
  console.log(`  Input (5 bytes): ${hexStr}`);
  console.log(`  Digest (HEX)  : ${digestHex}`);
  console.log();

  // ==================== 5. Base64 输出示例 ====================
  console.log('>>> 5. Base64 格式输出（可选）');

  const hashB64 = SM3Util.digest(input, true);
  console.log(`  SM3 Hash (Base64) ::: ${hashB64}`);

  const hmacKeyB64 = SM3Util.generateHmacKeyToStr(32, true);
  console.log(`  HMAC Key (Base64) ::: ${hmacKeyB64}`);
  console.log();

  console.log('=== SM3 Sample 完成 ===');
}

main();
