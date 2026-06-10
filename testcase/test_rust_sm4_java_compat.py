#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单的 Rust SM4 Java 互操作性测试
测试 Rust 的 SM4 GCM 实现是否与 Java 兼容
"""

import subprocess
import sys
import tempfile
import os

def test_rust_sm4_gcm():
    """测试 Rust SM4 GCM 加密解密"""
    
    rust_code = '''
use crossmool::sm4;

fn main() {
    // 使用与 Java 测试向量相同的密钥和 IV
    let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let iv: Vec<u8> = (0u8..12).collect();
    let plain = "Hello, 这是国密 SM4 测试数据";
    
    println!("原文：{}", plain);
    println!("密钥 (Hex): 0123456789abcdeffedcba9876543210");
    println!("IV (Hex): 000102030405060708090a0b");
    
    // GCM 加密 (Hex 输出)
    match sm4::encrypt_gcm_hex_with_iv(&key, plain.as_bytes(), &iv) {
        Ok(ciphertext_hex) => {
            println!("\\nRust 加密结果 (Hex):");
            println!("{}", ciphertext_hex);
            
            // 解密
            match sm4::decrypt_gcm_from_hex(&key, &ciphertext_hex) {
                Ok(decrypted) => {
                    let decrypted_str = String::from_utf8(decrypted).unwrap();
                    println!("\\nRust 解密结果：{}", decrypted_str);
                    if decrypted_str == plain {
                        println!("[PASS] Hex 加解密测试通过");
                    } else {
                        println!("[FAIL] Hex 加解密测试失败：解密结果不匹配");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    println!("[FAIL] Hex 解密失败：{}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            println!("[FAIL] Hex 加密失败：{}", e);
            std::process::exit(1);
        }
    }
    
    // GCM 加密 (Base64 输出)
    match sm4::encrypt_gcm_base64_with_iv(&key, plain.as_bytes(), &iv) {
        Ok(ciphertext_base64) => {
            println!("\\nRust 加密结果 (Base64):");
            println!("{}", ciphertext_base64);
            
            // 解密
            match sm4::decrypt_gcm(&key, &ciphertext_base64) {
                Ok(decrypted) => {
                    let decrypted_str = String::from_utf8(decrypted).unwrap();
                    println!("\\nRust 解密结果：{}", decrypted_str);
                    if decrypted_str == plain {
                        println!("[PASS] Base64 加解密测试通过");
                    } else {
                        println!("[FAIL] Base64 加解密测试失败：解密结果不匹配");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    println!("[FAIL] Base64 解密失败：{}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            println!("[FAIL] Base64 加密失败：{}", e);
            std::process::exit(1);
        }
    }
    
    // 测试 Java 生成的 Base64 密文
    let java_cipher_base64 = "AAECAwQFBgcICQoLHUR0/d6difbkGWUzdLn96G1Wr/4NZVgH6lwAiXZ4q53any/1ebT8w7FURBOKOUB3W+c=";
    println!("\\n测试 Java 生成的 Base64 密文:");
    println!("{}", java_cipher_base64);
    
    match sm4::decrypt_gcm_base64_to_string(&key, java_cipher_base64) {
        Ok(decrypted) => {
            println!("Java 密文解密结果：{}", decrypted);
            if decrypted == plain {
                println!("[PASS] Java-Rust SM4 GCM 互操作性测试通过");
            } else {
                println!("[FAIL] Java-Rust SM4 GCM 互操作性测试失败：解密结果不匹配");
                println!("  期望：{}", plain);
                println!("  实际：{}", decrypted);
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!("[FAIL] Java 密文解密失败：{}", e);
            std::process::exit(1);
        }
    }
    
    println!("\\n[SUCCESS] 所有 SM4 GCM 测试通过!");
}
'''
    
    # 创建临时项目
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_project = os.path.join(temp_dir, "rust_sm4_test")
        os.makedirs(temp_project)
        
        # Cargo.toml
        cargo_toml = '''[package]
name = "rust_sm4_test"
version = "0.1.0"
edition = "2021"

[dependencies]
crossmool = { path = "../../rust/crossmool" }
hex = "0.4"
base64 = "0.21"
'''
        
        with open(os.path.join(temp_project, "Cargo.toml"), 'w') as f:
            f.write(cargo_toml)
        
        # main.rs
        os.makedirs(os.path.join(temp_project, "src"))
        with open(os.path.join(temp_project, "src", "main.rs"), 'w', encoding='utf-8') as f:
            f.write(rust_code)
        
        print("="*70)
        print("Rust SM4 GCM Java 互操作性测试")
        print("="*70)
        
        # 编译
        print("\n编译 Rust 程序...")
        build_result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=temp_project,
            capture_output=True,
            text=True, errors="replace",
            timeout=300
        )
        
        if build_result.returncode != 0:
            print("编译失败")
            return False
        
        print("编译成功")
        
        # 运行
        exe_name = "rust_sm4_test.exe" if sys.platform == "win32" else "rust_sm4_test"
        exe_path = os.path.join(temp_project, "target", "release", exe_name)
        
        print("运行测试...")
        run_result = subprocess.run(
            [exe_path],
            capture_output=True,
            text=True, errors="replace",
            timeout=60
        )
        
        print(run_result.stdout)
        
        if run_result.returncode != 0:
            print(f"测试失败：{run_result.stderr.encode("utf-8", errors="replace").decode("gbk", errors="replace")}")
            return False
        
        return True

def test_rust_sm3():
    """测试 Rust SM3 哈希"""
    
    rust_code = '''
use crossmool::sm3;

fn main() {
    let test_cases = vec![
        "Hello, Crossmool!",
        "跨语言互操作性测试",
        "Test 测试 123!@#",
    ];
    
    println!("SM3 哈希测试");
    println!("="*50);
    
    for (i, test) in test_cases.iter().enumerate() {
        println!("\\n测试 {}: {}", i+1, test);
        let hex = sm3::digest_hex(test.as_bytes());
        let base64 = sm3::digest_base64(test.as_bytes());
        println!("  Hex:   {}", hex);
        println!("  Base64: {}", base64);
    }
    
    // HMAC 测试
    println!("\\nHMAC-SM3 测试");
    println!("="*50);
    let key = b"test-key-1234567890123456789012";
    let data = "hello";
    let mac_hex = sm3::hmac_hex(key, data.as_bytes());
    let mac_base64 = sm3::hmac_base64(key, data.as_bytes());
    println!("密钥：test-key-1234567890123456789012");
    println!("数据：hello");
    println!("HMAC (Hex):   {}", mac_hex);
    println!("HMAC (Base64): {}", mac_base64);
    
    println!("\\n[SUCCESS] SM3 测试完成");
}
'''
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_project = os.path.join(temp_dir, "rust_sm3_test")
        os.makedirs(temp_project)
        
        cargo_toml = '''[package]
name = "rust_sm3_test"
version = "0.1.0"
edition = "2021"

[dependencies]
crossmool = { path = "../../rust/crossmool" }
hex = "0.4"
base64 = "0.21"
'''
        
        with open(os.path.join(temp_project, "Cargo.toml"), 'w', encoding='utf-8') as f:
            f.write(cargo_toml)
        
        os.makedirs(os.path.join(temp_project, "src"))
        with open(os.path.join(temp_project, "src", "main.rs"), 'w', encoding='utf-8') as f:
            f.write(rust_code)
        
        print("\n" + "="*70)
        print("Rust SM3 哈希测试")
        print("="*70)
        
        print("\n编译 Rust 程序...")
        build_result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=temp_project,
            capture_output=True,
            text=True, errors="replace",
            timeout=300
        )
        
        if build_result.returncode != 0:
            print("编译失败")
            return False
        
        print("编译成功")
        
        exe_name = "rust_sm3_test.exe" if sys.platform == "win32" else "rust_sm3_test"
        exe_path = os.path.join(temp_project, "target", "release", exe_name)
        
        print("运行测试...")
        run_result = subprocess.run(
            [exe_path],
            capture_output=True,
            text=True, errors="replace",
            timeout=60
        )
        
        print(run_result.stdout)
        
        if run_result.returncode != 0:
            print(f"测试失败：{run_result.stderr.encode("utf-8", errors="replace").decode("gbk", errors="replace")}")
            return False
        
        return True

def test_rust_sm2():
    """测试 Rust SM2 加密签名"""
    
    rust_code = '''
use crossmool::sm2;

fn main() {
    println!("SM2 加密签名测试");
    println!("="*50);
    
    // 生成密钥对
    let keys = sm2::generate_keypair().expect("密钥生成失败");
    println!("\\n生成密钥对成功");
    println!("公钥 PEM: {}... ( truncated)", &keys.public_key_pem[..50]);
    println!("私钥 PEM: {}... (truncated)", &keys.private_key_pem[..50]);
    
    let plaintext = b"Hello, SM2 test!";
    
    // 加密 (Hex)
    match sm2::encrypt_with_public_pem_hex(&keys.public_key_pem, plaintext) {
        Ok(ciphertext_hex) => {
            println!("\\n加密结果 (Hex): {}", &ciphertext_hex[..60]);
            
            // 解密
            match sm2::decrypt_with_private_pem_hex(&keys.private_key_pem, &ciphertext_hex) {
                Ok(decrypted) => {
                    let decrypted_str = String::from_utf8(decrypted).unwrap();
                    println!("解密结果：{}", decrypted_str);
                    if decrypted == plaintext {
                        println!("[PASS] SM2 加解密测试通过 (Hex)");
                    } else {
                        println!("[FAIL] SM2 加解密测试失败");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    println!("[FAIL] 解密失败：{}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            println!("[FAIL] 加密失败：{}", e);
            std::process::exit(1);
        }
    }
    
    // 加密 (Base64)
    match sm2::encrypt_with_public_pem_base64(&keys.public_key_pem, plaintext) {
        Ok(ciphertext_base64) => {
            println!("\\n加密结果 (Base64): {}", &ciphertext_base64[..60]);
            
            // 解密
            match sm2::decrypt_with_private_pem_base64(&keys.private_key_pem, &ciphertext_base64) {
                Ok(decrypted) => {
                    let decrypted_str = String::from_utf8(decrypted).unwrap();
                    println!("解密结果：{}", decrypted_str);
                    if decrypted == plaintext {
                        println!("[PASS] SM2 加解密测试通过 (Base64)");
                    } else {
                        println!("[FAIL] SM2 加解密测试失败");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    println!("[FAIL] 解密失败：{}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            println!("[FAIL] 加密失败：{}", e);
            std::process::exit(1);
        }
    }
    
    // 签名验签
    match sm2::sign_with_private_pem(plaintext, &keys.private_key_pem) {
        Ok(signature) => {
            let sig_hex = hex::encode(&signature);
            println!("\\n签名结果 (Hex): {}", &sig_hex[..60]);
            
            match sm2::verify_with_public_pem(plaintext, &signature, &keys.public_key_pem) {
                Ok(true) => {
                    println!("[PASS] SM2 签名验签测试通过");
                }
                Ok(false) => {
                    println!("[FAIL] SM2 验签失败");
                    std::process::exit(1);
                }
                Err(e) => {
                    println!("[FAIL] 验签错误：{}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            println!("[FAIL] 签名失败：{}", e);
            std::process::exit(1);
        }
    }
    
    println!("\\n[SUCCESS] 所有 SM2 测试通过!");
}
'''
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_project = os.path.join(temp_dir, "rust_sm2_test")
        os.makedirs(temp_project)
        
        cargo_toml = '''[package]
name = "rust_sm2_test"
version = "0.1.0"
edition = "2021"

[dependencies]
crossmool = { path = "../../rust/crossmool" }
hex = "0.4"
base64 = "0.21"
'''
        
        with open(os.path.join(temp_project, "Cargo.toml"), 'w', encoding='utf-8') as f:
            f.write(cargo_toml)
        
        os.makedirs(os.path.join(temp_project, "src"))
        with open(os.path.join(temp_project, "src", "main.rs"), 'w', encoding='utf-8') as f:
            f.write(rust_code)
        
        print("\n" + "="*70)
        print("Rust SM2 加密签名测试")
        print("="*70)
        
        print("\n编译 Rust 程序...")
        build_result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=temp_project,
            capture_output=True,
            text=True, errors="replace",
            timeout=300
        )
        
        if build_result.returncode != 0:
            print("编译失败")
            return False
        
        print("编译成功")
        
        exe_name = "rust_sm2_test.exe" if sys.platform == "win32" else "rust_sm2_test"
        exe_path = os.path.join(temp_project, "target", "release", exe_name)
        
        print("运行测试...")
        run_result = subprocess.run(
            [exe_path],
            capture_output=True,
            text=True, errors="replace",
            timeout=60
        )
        
        print(run_result.stdout)
        
        if run_result.returncode != 0:
            print(f"测试失败：{run_result.stderr.encode("utf-8", errors="replace").decode("gbk", errors="replace")}")
            return False
        
        return True

if __name__ == "__main__":
    print("="*70)
    print("Java-Rust SM 算法互操作性测试")
    print("="*70)
    
    # 测试 SM2
    sm2_ok = test_rust_sm2()
    
    # 测试 SM3
    sm3_ok = test_rust_sm3()
    
    # 测试 SM4
    sm4_ok = test_rust_sm4_gcm()
    
    print("\n" + "="*70)
    print("测试总结")
    print("="*70)
    print(f"SM2: {'[PASS]' if sm2_ok else '[FAIL]'}")
    print(f"SM3: {'[PASS]' if sm3_ok else '[FAIL]'}")
    print(f"SM4: {'[PASS]' if sm4_ok else '[FAIL]'}")
    print("="*70)
    
    if sm2_ok and sm3_ok and sm4_ok:
        print("\n[SUCCESS] 所有测试通过!")
        sys.exit(0)
    else:
        print("\n[FAILED] 部分测试失败")
        sys.exit(1)
