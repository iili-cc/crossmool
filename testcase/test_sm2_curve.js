const { sm2 } = require('sm-crypto-v2');
const fs = require('fs');

// 读取密钥
const keys = JSON.parse(fs.readFileSync('testcase/keys/javascript/keys.json', 'utf-8'));

// 密钥解析（使用 sm2KeyFormats 的逻辑）
function sm2PublicKeyToRawHex(publicKey) {
    const bytes = Buffer.from(publicKey, 'hex');
    if (bytes[0] === 0x30) {
        // DER 格式，需要解析
        // 简化处理：直接跳过 DER 头
        const pubStart = publicKey.indexOf('04');
        const raw = publicKey.substring(pubStart);
        return raw.toLowerCase();
    }
    return publicKey.toLowerCase();
}

const pubRaw = sm2PublicKeyToRawHex(keys.encryption_public_key.hex);
console.log('公钥原始 Hex:', pubRaw);
console.log('公钥长度:', pubRaw.length, '字符');

// 测试加密
const content = 'Hello, Crossmool!';
const contentBytes = Buffer.from(content, 'utf-8');
const contentHex = contentBytes.toString('hex');

const cipherHex = sm2.doEncrypt(contentHex, pubRaw, 1);
console.log('\n加密结果:', cipherHex);
console.log('密文长度:', cipherHex.length, '字符 =', cipherHex.length / 2, '字节');

// 分析密文结构
console.log('\n=== 密文结构 ===');
console.log('C1 (公钥点):', cipherHex.substring(0, 130));
console.log('C3 (SM3 哈希):', cipherHex.substring(130, 194));
console.log('C2 (密文):', cipherHex.substring(194));

// 测试解密
const privKey = keys.encryption_private_key.hex;
// 解析私钥
function sm2PrivateKeyToRawHex(privateKey) {
    if (privateKey.startsWith('30')) {
        // PKCS#8 格式，需要解析
        // 简化：查找私钥部分（在 DER 结构中）
        const privStart = privateKey.indexOf('0420') + 4;
        const privKeyRaw = privateKey.substring(privStart, privStart + 64);
        return privKeyRaw.toLowerCase();
    }
    return privateKey.toLowerCase();
}

const privRaw = sm2PrivateKeyToRawHex(privKey);
console.log('\n私钥原始 Hex:', privRaw);

const decryptedHex = sm2.doDecrypt(cipherHex, privRaw, 1, { output: 'string' });
console.log('解密结果 (Hex):', decryptedHex);
const decrypted = Buffer.from(decryptedHex, 'hex').toString('utf-8');
console.log('解密结果 (文本):', decrypted);