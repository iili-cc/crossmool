const { SM2Util } = require('./javascript/crossmool/dist/index.js');
const fs = require('fs');

const keys = JSON.parse(fs.readFileSync('testcase/keys/javascript/keys.json', 'utf-8'));
const content = 'Hello, Crossmool!';

// JavaScript 加密
const jsCipher = SM2Util.encrypt(content, keys.encryption_public_key.hex, false);
console.log('JS 加密结果:', jsCipher);
console.log('JS 密文长度:', jsCipher.length, '字符 =', jsCipher.length / 2, '字节');

// JavaScript 解密
const jsDecrypted = SM2Util.decrypt(jsCipher, keys.encryption_private_key.hex);
console.log('JS 解密结果:', jsDecrypted);

// 尝试手动解析密文结构
console.log('\n=== 密文结构分析 ===');
console.log('第 1 字节:', jsCipher.substring(0, 2), '(应该是 04 - 未压缩点)');
console.log('C1 (公钥点):', jsCipher.substring(0, 130), '(65 字节 = 130 字符)');
console.log('C3 (SM3 哈希):', jsCipher.substring(130, 194), '(32 字节 = 64 字符)');
console.log('C2 (密文):', jsCipher.substring(194));
console.log('C2 长度:', (jsCipher.length - 194) / 2, '字节');