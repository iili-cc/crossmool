/// SM4 国密对称加密算法示例（GCM 模式）
///
/// 快速上手：
///   1. cd rust/crossmool
///   2. cargo run --example sm4_sample
///
/// 核心能力：
///   - 生成 SM4 密钥（128-bit）
///   - SM4-GCM 加密（带认证标签，防篡改）
///   - SM4-GCM 解密（自动检测 Hex/Base64）
///   - GCM 防篡改验证

use crossmool::sm4;
use crossmool::encoding;

fn main() {
    println!("============================================================");
    println!("  SM4 Sample — 国密对称加密 (GCM 模式)");
    println!("============================================================");
    println!();

    let original = "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。\
                    路过咖啡店时買了一杯美式，順便（顺便）看了下手机，\
                    今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。\
                    朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" \
                    我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。";

    println!("OriginalContent ::: {}", original);
    println!();

    // === 1. 生成 SM4 密钥 ===
    println!(">>> 1. 生成 SM4 密钥（128-bit）");

    let key = sm4::generate_key();
    let hex_key = encoding::to_hex(&key);
    println!("  SM4 Hex Key    ::: {}", hex_key);
    println!("  SM4 Base64 Key ::: {}", encoding::to_base64(&key));
    println!();

    // === 2. Hex 输出 GCM 加解密 ===
    println!(">>> 2. 使用 Hex 密钥进行 GCM 加解密");

    let enc_hex = sm4::encrypt_gcm_string(&key, original, false).unwrap();
    println!("  Encrypted (Hex) ::: {}...", &enc_hex[..150.min(enc_hex.len())]);

    let dec_hex = sm4::decrypt_gcm_to_string(&key, &enc_hex).unwrap();
    println!("  Decrypted (Hex) ::: {}", dec_hex);
    println!("  WhetherDecryptEqualsOriginalContent (Hex) ::: {}", original == dec_hex);
    println!();

    // === 3. Base64 输出 GCM 加解密 ===
    println!(">>> 3. 使用 Base64 输出进行 GCM 加解密");

    let enc_b64 = sm4::encrypt_gcm_string(&key, original, true).unwrap();
    println!("  Encrypted (Base64) ::: {}...", &enc_b64[..100.min(enc_b64.len())]);

    let dec_b64 = sm4::decrypt_gcm_to_string(&key, &enc_b64).unwrap();
    println!("  Decrypted (Base64) ::: {}", dec_b64);
    println!("  WhetherDecryptEqualsOriginalContent (Base64) ::: {}", original == dec_b64);
    println!();

    // === 4. 随机 IV ===
    println!(">>> 4. 随机 IV 验证（每次 GCM 加密密文不同）");

    let ct1 = sm4::encrypt_gcm_string(&key, "Same plaintext", false).unwrap();
    let ct2 = sm4::encrypt_gcm_string(&key, "Same plaintext", false).unwrap();
    println!("  Ciphertext 1 ::: {}...", &ct1[..50.min(ct1.len())]);
    println!("  Ciphertext 2 ::: {}...", &ct2[..50.min(ct2.len())]);
    println!("  IV differs (ciphertexts not equal) ::: {}", ct1 != ct2);
    println!();

    // === 5. GCM 防篡改 ===
    println!(">>> 5. GCM 防篡改验证");
    println!("  （故意篡改密文末尾字符，GCM 应检测到并拒绝解密）");

    let tampered = enc_hex[..enc_hex.len() - 2].to_owned() + "XX";
    match sm4::decrypt_gcm_to_string(&key, &tampered) {
        Ok(hacked) => println!("  Tampered decrypted ::: {}", hacked),
        Err(e) => println!("  GCM detected tampering, decryption failed ::: {}", e),
    }
    println!();

    println!("=== SM4 Sample 完成 ===");
}
