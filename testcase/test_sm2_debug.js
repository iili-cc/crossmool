const { SM2Util } = require('./javascript/crossmool/dist/index.js');
const fs = require('fs');

// 读取密钥
const javaKeys = JSON.parse(fs.readFileSync('testcase/keys/java/keys.json', 'utf-8'));
const jsKeys = JSON.parse(fs.readFileSync('testcase/keys/javascript/keys.json', 'utf-8'));

console.log('=== 测试 Java 密钥格式 ===');
console.log('Java 公钥 Hex 长度:', javaKeys.encryption_public_key.hex.length);
console.log('Java 私钥 Hex 长度:', javaKeys.encryption_private_key.hex.length);
console.log('JS 公钥 Hex 长度:', jsKeys.encryption_public_key.hex.length);
console.log('JS 私钥 Hex 长度:', jsKeys.encryption_private_key.hex.length);

const content = 'Hello, Crossmool!';

// 使用 JavaScript 密钥加密
console.log('\n=== JavaScript 加密测试 ===');
const jsCipher = SM2Util.encrypt(content, jsKeys.encryption_public_key.hex, false);
console.log('JS 加密结果:', jsCipher);
const jsDecrypted = SM2Util.decrypt(jsCipher, jsKeys.encryption_private_key.hex);
console.log('JS 解密结果:', jsDecrypted);

// 尝试用 JavaScript 解密 Java 格式的密钥
console.log('\n=== 测试 Java 密钥 ===');
try {
    const testCipher = SM2Util.encrypt(content, javaKeys.encryption_public_key.hex, false);
    console.log('使用 Java 公钥加密:', testCipher);
    const testDecrypted = SM2Util.decrypt(testCipher, javaKeys.encryption_private_key.hex);
    console.log('使用 Java 私钥解密:', testDecrypted);
} catch (e) {
    console.error('错误:', e.message);
}