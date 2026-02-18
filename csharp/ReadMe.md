This is a GM tool, and it includes SM2, SM3 and SM4.
It is not a full implementation, it is just a easy implementation for you to use GM algorithms directly.
Crossmool Crypto Utilities (SM2/SM3/SM4)

- Library: `crossmool/src/Crossmool.Crypto`
- Sample: `crossmool/samples/Crossmool.Crypto.Sample`

Supported:
- `SM2Util`: `encrypt(byte[] originalTextBytes, byte[] publicKeyBytes)`, `encrypt(string originalText, string publicKeyString)`, `decrypt(byte[] encryptedTextBytes, byte[] privateKeyBytes)`, `decrypt(string encryptedText, string privateKeyString)`, `generateKeyPair()`
- `SM3Util`: `digest(byte[] input)`, `digest(string input)`
- `SM4Util`: `encrypt(byte[] originalTextBytes, byte[] keyBytes)`, `encrypt(string originalText, string keyString)`, `decrypt(byte[] encryptedTextBytes, byte[] keyBytes)`, `decrypt(string encryptedText, string keyString)`

Notes:
- Charset: UTF-8 for string conversions.
- Encoding: Accepts Base64 or Hex for inputs (keys, ciphertext); string outputs default to Base64 for SM2/SM4 and Hex for SM3.
- SM2 uses `SM2Engine` in `C1C3C2` mode; public key must be uncompressed (starts with `04`).
- SM4 uses CBC with PKCS7 padding; a random 16-byte IV is prefixed to the ciphertext.

SM2 PEM helpers (PKCS#8 / SubjectPublicKeyInfo):

- `exportPrivateKeyPem(byte[] priv)`, `exportPublicKeyPem(byte[] pub)`
- `importPrivateKeyPem(string pem)`, `importPublicKeyPem(string pem)`
- PEM is standard PKCS#8 for private keys and SubjectPublicKeyInfo for public keys.

Quick start (PowerShell):

```
dotnet build
dotnet run --project crossmool\samples\Crossmool.Crypto.Sample\Crossmool.Crypto.Sample.csproj
```

Example (C#):

```
var json = SM2Util.generateKeyPair();
var privHex = Extract(json, "privateKeyHex");
var pubHex  = Extract(json, "publicKeyHex");

var cipherB64 = SM2Util.encrypt("hello", pubHex);
var plain     = SM2Util.decrypt(cipherB64, privHex);

var sm3Hex = SM3Util.digest("hello");

var sm4KeyHex = "00112233445566778899aabbccddeeff"; // 16 bytes
var sm4Cipher = SM4Util.encrypt("hello", sm4KeyHex);
var sm4Plain  = SM4Util.decrypt(sm4Cipher, sm4KeyHex);

// PEM helpers
var privPem = SM2Util.exportPrivateKeyPem(EncodingUtils.FromHex(privHex));
var pubPem  = SM2Util.exportPublicKeyPem(EncodingUtils.FromHex(pubHex));
var privBytes = SM2Util.importPrivateKeyPem(privPem);
var pubBytes  = SM2Util.importPublicKeyPem(pubPem);
var roundtrip = SM2Util.decrypt(SM2Util.encrypt("hi", pubBytes), privBytes);
```
```