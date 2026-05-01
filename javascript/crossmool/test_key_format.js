const { SM2Util } = require('./dist/index.js');
const { sm2PublicKeyToRawHex } = require('./dist/utils/sm2KeyFormats.js');

// 来自 testcase/keys/javascript/keys.json 的公钥
const encPublicKeyHex = "3059301306072a8648ce3d020106082a811ccf5501822d034200041d772f3edc37263e7c0196f67b791a2e6fa1b3fbeb35cb6c6ba3f165b5e511900712888b0bee602e987c2cd388100ee8e38a23f65e105ff524ea3431053d029a";
const encPublicKeyBase64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEGNrnFJnYs1gbyAyohPFJ7TBNDhvwfCEkyjQ+GazFPbDDYmMTwEsuKhBRk/d20rGOwWyM/HGuCt6cPzrJgmt3ig==";

console.log("=== 测试公钥格式解析 ===\n");

try {
    console.log("1. 测试 Hex 格式公钥 (来自 keys.json):");
    console.log(`   输入：${encPublicKeyHex.substring(0, 60)}...`);
    const rawHex = sm2PublicKeyToRawHex(encPublicKeyHex);
    console.log(`   输出：${rawHex}`);
    console.log(`   长度：${rawHex.length}`);
    console.log("   ✓ Hex 格式解析成功\n");
} catch (error) {
    console.log(`   ✗ Hex 格式解析失败：${error.message}\n`);
}

try {
    console.log("2. 测试 Base64 格式公钥:");
    console.log(`   输入：${encPublicKeyBase64.substring(0, 60)}...`);
    const rawHex2 = sm2PublicKeyToRawHex(encPublicKeyBase64);
    console.log(`   输出：${rawHex2}`);
    console.log(`   长度：${rawHex2.length}`);
    console.log("   ✓ Base64 格式解析成功\n");
} catch (error) {
    console.log(`   ✗ Base64 格式解析失败：${error.message}\n`);
}

try {
    console.log("3. 测试加密操作 (使用 Hex 公钥):");
    const plain = "测试消息";
    const cipherHex = SM2Util.encryptToHex(plain, encPublicKeyHex);
    console.log(`   明文：${plain}`);
    console.log(`   密文：${cipherHex.substring(0, 60)}...`);
    console.log("   ✓ 加密成功\n");
} catch (error) {
    console.log(`   ✗ 加密失败：${error.message}\n`);
}