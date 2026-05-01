## Crossmool JavaScript Crypto

基于 `sm-crypto-v2` 的 SM2 / SM3 / SM4 实用工具库，目标是与 `crossmool/java` 下的实现互通。

### 与 Java 端对齐的关键点

- **SM2 密文格式**：`C1C3C2`（对应 `sm2.doEncrypt(..., cipherMode=1)`）
- **SM2 签名格式**：DER 编码（`der: true`）
- **SM2 杂凑/ID**：SM3-with-ID（`hash: true` 且固定 `userId = "1234567812345678"`）
- **SM2 Key 格式**：兼容 Java 的
	- 公钥：X.509 / SubjectPublicKeyInfo（Hex/Base64）
	- 私钥：PKCS8 / PrivateKeyInfo（Hex/Base64）

### API（bytes / Hex / Base64）

- `SM2Util`：`encryptToBytes/encryptToHex/encryptToBase64`、`decryptToBytes/decrypt/decryptToBytesFromString`、`signToBytes/signToHex/signToBase64`、`verify`、`encryptSign`、`verifyDecrypt`
- `SM3Util`：`digestToBytes/digestToHex/digestToBase64`
- `SM4Util`：`encryptEcbToBytes/encryptEcbToHex/encryptEcbToBase64`、`decryptEcbToBytes/decryptEcbToUtf8`

### 使用示例

```ts
import { SM2Util, SM3Util, SM4Util } from '@crossmool/crypto';

// SM3
const sm3Hex = SM3Util.digestToHex('abc');

// SM4 (ECB + PKCS#7)
const keyHex = '0123456789abcdeffedcba9876543210';
const sm4CipherHex = SM4Util.encryptEcbToHex('hello', keyHex);
const sm4Plain = SM4Util.decryptEcbHexToUtf8(sm4CipherHex, keyHex);

// SM2（直接用 Java 侧 X.509/PKCS8 的 Base64 或 Hex key）
const cipherHex = SM2Util.encryptToHex('hello', JAVA_X509_PUBLIC_KEY_BASE64);
const plain = SM2Util.decrypt(cipherHex, JAVA_PKCS8_PRIVATE_KEY_BASE64);
const sigHex = SM2Util.signToHex(cipherHex, JAVA_PKCS8_SIGN_PRIVATE_KEY_BASE64);
const ok = SM2Util.verify(cipherHex, JAVA_X509_SIGN_PUBLIC_KEY_BASE64, sigHex);
```

### 构建与测试

```powershell
cd d:\workspaces\git\corssmool\crossmool\javascript
npm install
npm test
npm run build
```

### 与 Java 端互相验签/互相解密（对照脚本）

1) **JS 生成互通数据**（给 Java 去解密/验签）：

```powershell
cd d:\workspaces\git\corssmool\crossmool\javascript
npm run interop:gen
```

`interop.json` 里包含：
- `sm2.ciphertextHex` / `sm2.ciphertextBase64`
- `sm2.signatureHex` / `sm2.signatureBase64`（签的是 `ciphertextHex` 的 UTF-8 字节，和 Java 的 `SM2Util.encryptSign` 一致）

2) **JS 校验 Java 生成的数据**：

把 Java 输出组织成同样 schema 的 JSON（至少包含 `plain` 和 `sm2.*` 字段），然后：

```powershell
cd d:\workspaces\git\corssmool\crossmool\javascript
npm run interop:check -- --file interop.json
```

也支持从 stdin 读：

```powershell
Get-Content interop.json | npm run interop:check
```

注意：如果你要从 stdin 喂 JSON（如上例），请直接执行 `node scripts/interop.mjs check`（不要带自动 build 的 npm script），避免构建日志污染 stdin。

构建产物位于 `javascript/dist/`，包含 ESM/CJS 与浏览器 IIFE（`dist/index.global.js`）。