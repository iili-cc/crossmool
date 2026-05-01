#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试 Java 和 C 语言 SM2 验签差异
"""

import json
from binascii import unhexlify

# 读取测试数据
with open('testcase/results/java_encrypt/test_1_simple_text.json', 'r', encoding='utf-8') as f:
    test_data = json.load(f)

ciphertext_hex = test_data['ciphertext_hex']
signature_hex = test_data['signature_hex']
plaintext = test_data['plaintext']

# 读取密钥
with open('testcase/keys/java/keys.json', 'r', encoding='utf-8') as f:
    keys = json.load(f)

sign_public_key_hex = keys['signature_public_key']['hex']
print(f"验签公钥 (HEX): {sign_public_key_hex[:60]}...")
print(f"密文 (HEX): {ciphertext_hex[:60]}...")
print(f"签名 (HEX): {signature_hex[:60]}...")
print()

# Java encryptSign 流程：
# 1. 加密明文得到密文字符串 (HEX)
# 2. 对密文字符串 (HEX) 签名 → 将字符串按 UTF-8 编码为字节，然后签名

# 验证：Java 是对密文字符串 (HEX) 签名
print("=" * 60)
print("Java 签名流程分析:")
print("=" * 60)
print(f"1. 密文字符串 (HEX): {ciphertext_hex[:40]}...")
print(f"   长度：{len(ciphertext_hex)} 字符")

# Java sign 方法将字符串按 UTF-8 编码为字节
ciphertext_utf8_bytes = ciphertext_hex.encode('utf-8')
print(f"2. 密文字符串 UTF-8 编码字节：{ciphertext_utf8_bytes[:40]}...")
print(f"   长度：{len(ciphertext_utf8_bytes)} 字节")

# 将 HEX 密文解码为字节 (这是密文的实际字节)
ciphertext_actual_bytes = unhexlify(ciphertext_hex)
print(f"3. 密文实际字节 (HEX 解码): {ciphertext_actual_bytes[:20]}...")
print(f"   长度：{len(ciphertext_actual_bytes)} 字节")

print()
print("关键发现:")
print(f"  - Java 对密文字符串签名时，使用的是 UTF-8 编码的字节 ({len(ciphertext_utf8_bytes)} 字节)")
print(f"  - 而不是密文的实际字节 ({len(ciphertext_actual_bytes)} 字节)")
print(f"  - 对于 HEX 字符串，UTF-8 编码长度 = 字符串长度 = {len(ciphertext_hex)}")

print()
print("=" * 60)
print("签名格式分析:")
print("=" * 60)
signature_bytes = bytes.fromhex(signature_hex)
print(f"签名字节：{signature_bytes.hex()}")
print(f"签名长度：{len(signature_bytes)} 字节")
print(f"签名前缀：{signature_bytes[:10].hex()}")

# Java BouncyCastle 生成的签名是 DER ASN.1 格式
# 格式：30 <total_len> 02 <r_len> <r> 02 <s_len> <s>
if signature_bytes[0] == 0x30:
    print("签名格式：DER ASN.1 (BouncyCastle 默认格式)")
    total_len = signature_bytes[1]
    print(f"  总长度：{total_len} 字节")
    if signature_bytes[2] == 0x02:
        r_len = signature_bytes[3]
        r = signature_bytes[4:4+r_len]
        s_start = 4 + r_len + 2
        s_len = signature_bytes[4+r_len]
        s = signature_bytes[s_start:s_start+s_len]
        print(f"  R 值：{r.hex()} ({r_len} 字节)")
        print(f"  S 值：{s.hex()} ({s_len} 字节)")
        
        # 拼接 R||S 格式 (GmSSL 可能期望的格式)
        rs_concat = r + s
        print(f"  R||S 拼接：{rs_concat.hex()} ({len(rs_concat)} 字节)")

print()
print("=" * 60)
print("使用 Java 本地验签验证:")
print("=" * 60)

# 使用 Java 本地验签
import subprocess
import tempfile
import os

java_verify_code = f'''
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.params.ParametersWithID;
import java.security.Security;
import java.math.BigInteger;

public class VerifyTest {{
    public static void main(String[] args) {{
        Security.addProvider(new BouncyCastleProvider());
        
        String publicKeyHex = "{sign_public_key_hex}";
        String signatureHex = "{signature_hex}";
        String contentToVerify = "{ciphertext_hex}";
        
        try {{
            // 解析公钥
            byte[] publicKeyBytes = hexToBytes(publicKeyHex);
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyBytes);
            ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(
                subjectPublicKeyInfo.getPublicKey(),
                subjectPublicKeyInfo.getAlgorithm().getParameters()
            );
            
            // 初始化验签器
            SM2Signer signer = new SM2Signer();
            ParametersWithID params = new ParametersWithID(publicKeyParams, "1234567812345678".getBytes());
            signer.init(false, params);
            
            // 更新内容
            byte[] contentBytes = contentToVerify.getBytes("UTF-8");
            signer.update(contentBytes, 0, contentBytes.length);
            
            // 解析签名
            byte[] signatureBytes = hexToBytes(signatureHex);
            boolean verified = signer.verifySignature(signatureBytes);
            
            System.out.println("VERIFIED:" + verified);
        }} catch (Exception e) {{
            e.printStackTrace();
        }}
    }}
    
    private static byte[] hexToBytes(String hex) {{
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {{
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }}
        return data;
    }}
}}
'''

with tempfile.TemporaryDirectory() as tmpdir:
    java_file = os.path.join(tmpdir, "VerifyTest.java")
    class_file = os.path.join(tmpdir, "VerifyTest.class")
    
    with open(java_file, 'w', encoding='utf-8') as f:
        f.write(java_verify_code)
    
    # 编译
    compile_result = subprocess.run(
        ['javac', '-cp', 'java/crossmool/target/classes', java_file, '-d', tmpdir],
        capture_output=True, text=True
    )
    
    if compile_result.returncode != 0:
        print(f"Java 编译失败：{compile_result.stderr}")
    else:
        # 运行
        run_result = subprocess.run(
            ['java', '-cp', f'{tmpdir}:java/crossmool/target/classes', 'VerifyTest'],
        capture_output=True, text=True, cwd='java/crossmool'
        )
        print(f"Java 验签结果：{run_result.stdout.strip()}")
        if run_result.stderr:
            print(f"错误信息：{run_result.stderr}")
