const { SM3Util } = require('../javascript/crossmool/dist/index.js');

// 测试 HMAC-SM3
const hmacKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// 测试 "abc"
const content = "abc";
const hmacHex = SM3Util.hmacToHex(hmacKeyHex, content);
console.log("Content:", content);
console.log("HMAC-SM3 (Hex):", hmacHex);
console.log("HMAC length:", hmacHex.length);

// 测试 "Hello, Crossmool!"
const content2 = "Hello, Crossmool!";
const hmacHex2 = SM3Util.hmacToHex(hmacKeyHex, content2);
console.log("\nContent:", content2);
console.log("HMAC-SM3 (Hex):", hmacHex2);
console.log("HMAC length:", hmacHex2.length);