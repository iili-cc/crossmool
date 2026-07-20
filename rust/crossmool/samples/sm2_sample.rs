/// SM2 国密非对称加密算法示例
///
/// 快速上手：
///   1. cd rust/crossmool
///   2. cargo run --example sm2_sample
///
/// 核心能力：
///   - 生成 SM2 密钥对（PEM / Hex / Base64）
///   - 公钥加密 → 私钥解密
///   - 私钥签名 → 公钥验签
///   - 先加密再签名 → 先验签再解密（防篡改 + 防抵赖）

use crossmool::sm2;
use crossmool::encoding;

fn main() {
    println!("============================================================");
    println!("  SM2 Sample — 国密非对称加密 (SM2P256V1)");
    println!("============================================================");
    println!();

    let original = "今天天气真好，气温大约 28°C，我决定出門走走。\
                    路过咖啡店时買了一杯美式，順便（顺便）看了下手机。\
                    Don't forget to bring your umbrella!";

    println!("OriginalContent ::: {}", original);
    println!();

    // === 1. 生成两对密钥 ===
    println!(">>> 1. 生成两对 SM2 密钥（第1对加解密，第2对签名）");

    let kp1 = sm2::generate_keypair().unwrap();
    let kp2 = sm2::generate_keypair().unwrap();
    let (pub1, pri1) = (kp1.public_key_pem.clone(), kp1.private_key_pem.clone());
    let (pub2, pri2) = (kp2.public_key_pem.clone(), kp2.private_key_pem.clone());

    println!("  Public Key PEM-1  ::: {}...", &pub1[..50.min(pub1.len())]);
    println!("  Private Key PEM-1 ::: {}...", &pri1[..50.min(pri1.len())]);
    println!("  Public Key PEM-2  ::: {}...", &pub2[..50.min(pub2.len())]);
    println!("  Private Key PEM-2 ::: {}...", &pri2[..50.min(pri2.len())]);
    println!();

    // Hex 格式（跨语言交换用）
    let (pub1_hex, pri1_hex) = sm2::generate_keypair_hex().unwrap();
    println!("  publicKeyHex (raw)  ::: {}", pub1_hex);
    println!("  privateKeyHex (raw) ::: {}", pri1_hex);
    println!();

    // === 2. 加密并签名 → 验签并解密 ===
    println!(">>> 2. 加密并签名 → 验签并解密（先加密再签名，先验签再解密）");

    let enc_result = sm2::encrypt_with_public_pem_hex(&pub1, original.as_bytes()).unwrap();
    println!("  CipherText ::: {}...", &enc_result[..150.min(enc_result.len())]);

    let sig_result = sm2::sign_with_private_pem(enc_result.as_bytes(), &pri2).unwrap();
    let sig_hex = encoding::to_hex(&sig_result);
    println!("  Signature  ::: {}", sig_hex);
    println!();

    let dec_result = sm2::verify_decrypt(&enc_result, &sig_hex, &pub2, &pri1).unwrap();
    println!("  VerifyDecrypt ::: {}", dec_result);
    println!("  WhetherVerifyDecryptEqualsOriginalContent ::: {}", original == dec_result);
    println!();

    // === 3. 仅加密/解密 ===
    println!(">>> 3. 公钥加密 → 私钥解密");

    let encrypted = sm2::encrypt_with_public_pem_hex(&pub1, original.as_bytes()).unwrap();
    println!("  EncryptedContent ::: {}...", &encrypted[..150.min(encrypted.len())]);

    let decrypted = sm2::decrypt_with_private_pem_hex(&pri1, &encrypted).unwrap();
    let dec_str = String::from_utf8_lossy(&decrypted);
    println!("  DecryptedContent ::: {}", dec_str);
    println!("  WhetherDecryptEqualsOriginalContent ::: {}", original == dec_str);
    println!();

    // === 4. 签名/验签 ===
    println!(">>> 4. 私钥签名 → 公钥验签");

    let sig = sm2::sign_with_private_pem(original.as_bytes(), &pri2).unwrap();
    let sig_hex2 = encoding::to_hex(&sig);
    println!("  ContentSignature ::: {}", sig_hex2);

    let verify_ok = sm2::verify_with_public_pem(original.as_bytes(), &sig, &pub2).unwrap();
    println!("  WhetherVerifyEqualsOriginalContent ::: {}", verify_ok);
    println!();

    // === 5. Base64 格式 ===
    println!(">>> 5. Base64 格式输出（可选）");

    let enc_b64 = sm2::encrypt_with_public_pem_base64(&pub1, original.as_bytes()).unwrap();
    println!("  Encrypted (Base64) ::: {}...", &enc_b64[..100.min(enc_b64.len())]);

    let sig_b = sm2::sign_with_private_pem(original.as_bytes(), &pri2).unwrap();
    println!("  Signature  (Base64) ::: {}", encoding::to_base64(&sig_b));
    println!();

    println!("=== SM2 Sample 完成 ===");
}
