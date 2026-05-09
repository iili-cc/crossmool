# Java SM2 Implementation Test Report

**Test Date:** 2026-05-09  
**Test Status:** ✅ PASSED (2/2 tests)

## Summary

Successfully tested Java SM2 implementation using BouncyCastle provider. Both encrypt/decrypt and sign/verify operations work correctly.

## Test Results

| Test Case | Result | Notes |
|-----------|--------|-------|
| SM2 Encrypt/Decrypt | ✅ PASS | C1C3C2 format with HEX encoding |
| SM2 Sign/Verify | ✅ PASS | DER-encoded signatures with HEX encoding |

## Key Findings

### 1. BouncyCastle Provider Registration

The BouncyCastle provider must be registered before using SM2KeyUtil. SM2Util has a static initializer block that registers BC:

```java
static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        Security.addProvider(new BouncyCastleProvider());
    }
}
```

**Important:** SM2Util must be loaded first to trigger the static initializer before SM2KeyUtil is used.

### 2. Parameter Order

SM2Util.decrypt() method signature:
```java
public static String decrypt(String content, String privateKey)
```

**Correct usage:** `SM2Util.decrypt(ciphertext, privateKey)`

### 3. Key Formats

- **Public Key:** X.509/SubjectPublicKeyInfo DER format, HEX encoded (182 characters)
- **Private Key:** PKCS#8 DER format, HEX encoded (300 characters)
- **Ciphertext:** RAW C1C3C2 format with 04 prefix, HEX encoded (244 characters)
- **Signature:** DER-encoded SEQUENCE {r, s}, HEX encoded (~142 characters)

### 4. HEX vs Base64

All test operations use HEX encoding (default). The library also supports Base64 encoding via overloaded methods.

## Test Program

**File:** `testcase/GenerateAndTest.java`

**Compile:**
```bash
cd g:/workspaces/git/corssmool/crossmool/testcase
javac -encoding UTF-8 -cp "../java/crossmool/target/classes;../java/crossmool/target/dependency/*" GenerateAndTest.java
```

**Run:**
```bash
java -cp ".;../java/crossmool/target/classes;../java/crossmool/target/dependency/*" GenerateAndTest
```

**Expected Output:**
```
Generate and Test SM2
=====================

Keys generated:
  Public key length: 182
  Private key length: 300

Encrypting...
  Ciphertext length: 244

Decrypting...
  Decrypted: Hello, Generate and Test!
  [PASS] Decrypt works!

Signing...
  Signature length: 142

Verifying...
  Verified: true
  [PASS] Verify works!

Test complete!
```

## Issues Fixed

1. **BC Provider Not Registered:** SM2KeyUtil failed because BC provider wasn't registered. Fixed by ensuring SM2Util is loaded first.

2. **Parameter Order:** Test code had incorrect parameter order for SM2Util.decrypt(). Fixed to use `decrypt(ciphertext, privateKey)`.

3. **Parameter Order in Verify:** Test code had incorrect parameter order for SM2Util.verify(). Fixed to use `verify(message, publicKey, signature)`.

## Next Steps

1. ✅ Java SM2 encrypt/decrypt - COMPLETE
2. ✅ Java SM2 sign/verify - COMPLETE  
3. ⏭️ Java-Python SM2 interop - See `JAVA_PYTHON_SM_INTEROP_REPORT.md`
4. ⏭️ Java-C SM2 interop - Pending

## Conclusion

Java SM2 implementation is working correctly. The library provides a clean API for encrypt/decrypt and sign/verify operations with proper format handling (HEX/Base64 encoding, DER signatures, C1C3C2 ciphertext format).