const { SM2Util } = require('./javascript/crossmool/dist/index.js');
const fs = require('fs');

// 读取密钥
const keys = JSON.parse(fs.readFileSync('testcase/keys/javascript/keys.json', 'utf-8'));

const content = 'Hello, Crossmool!';

// JavaScript 加密
console.log('=== JavaScript 加密 ===');
const jsCipher = SM2Util.encrypt(content, keys.encryption_public_key.hex, false);
console.log('密文 (Hex):', jsCipher);

// JavaScript 解密
console.log('\n=== JavaScript 解密 ===');
try {
    const jsDecrypted = SM2Util.decrypt(jsCipher, keys.encryption_private_key.hex);
    console.log('解密结果:', jsDecrypted);
} catch (e) {
    console.error('解密错误:', e.message);
    console.error('堆栈:', e.stack);
}

// 模拟 Java 加密输出（使用 JavaScript 加密的结果）
console.log('\n=== 测试解密 Java 格式密文 ===');
try {
    const decrypted = SM2Util.decrypt(jsCipher, keys.encryption_private_key.hex);
    console.log('解密成功:', decrypted);
} catch (e) {
    console.error('解密失败:', e.message);
}

// 测试密钥解析
console.log('\n=== 测试密钥解析 ===');
try {
    const { sm2PublicKeyToRawHex, sm2PrivateKeyToRawHex } = require('./javascript/crossmool/dist/index.js');
    const pubRaw = sm2PublicKeyToRawHex(keys.encryption_public_key.hex);
    const privRaw = sm2PrivateKeyToRawHex(keys.encryption_private_key.hex);
    console.log('公钥原始 Hex:', pubRaw);
    console.log('私钥原始 Hex:', privRaw);
} catch (e) {
    console.error('密钥解析错误:', e.message);
}