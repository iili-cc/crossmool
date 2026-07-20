/// SM3 国密哈希算法示例
///
/// 快速上手：
///   1. cd rust/crossmool
///   2. cargo run --example sm3_sample
///
/// 核心能力：
///   - SM3 消息摘要（256-bit）
///   - HMAC-SM3 消息认证码
///   - 支持 Hex / Base64 输出

use crossmool::sm3;

fn main() {
    println!("============================================================");
    println!("  SM3 Sample — 国密哈希算法 (256-bit)");
    println!("============================================================");
    println!();

    // === 1. SM3 消息摘要 ===
    println!(">>> 1. SM3 消息摘要 (Digest)");

    let input = "在这个全球化时代，無論身處何地，\
                 learning and growth are always the keys to a fulfilling life.";

    println!("  Input        ::: {}", input);

    let hash = sm3::digest_str(input, false);
    println!("  SM3 Hash     ::: {}", hash);
    println!("  SM3 Hash (Hex) ::: {}", sm3::digest_str(input, false));
    println!("  Whether Hash Equals Hex ::: {}", hash == sm3::digest_str(input, false));
    println!();

    // === 2. HMAC-SM3 ===
    println!(">>> 2. HMAC-SM3 消息认证码");

    let hmac_key = sm3::generate_hmac_key_str_default();
    println!("  HMAC Key      ::: {}", hmac_key);

    let hmac_val = sm3::hmac_str_default(&hmac_key, input).unwrap();
    println!("  HMAC Value    ::: {}", hmac_val);

    let hmac_val2 = sm3::hmac_str_default(&hmac_key, input).unwrap();
    println!("  HMAC Value 2  ::: {}", hmac_val2);
    println!("  Whether HMAC Values Equal ::: {}", hmac_val == hmac_val2);
    println!();

    // === 3. HMAC 校验 ===
    println!(">>> 3. HMAC 校验（防篡改验证）");

    let verified = sm3::hmac_verify(&hmac_key, input, &hmac_val).unwrap();
    println!("  HMAC Verify (correct)   ::: {}", verified);

    let tampered = sm3::hmac_verify(&hmac_key, &(input.to_owned() + "X"), &hmac_val).unwrap();
    println!("  HMAC Verify (tampered)  ::: {}", tampered);
    println!();

    // === 4. 字节数组输入 ===
    println!(">>> 4. 字节数组摘要（非字符串场景）");

    let data = vec![0x01u8, 0x02, 0x03, 0x04, 0x05];
    let digest_hex = sm3::digest_hex(&data);
    print!("  Input (5 bytes): ");
    for b in &data { print!("{:02x} ", b); }
    println!();
    println!("  Digest (HEX)  : {}", digest_hex);
    println!();

    // === 5. Base64 输出 ===
    println!(">>> 5. Base64 格式输出（可选）");
    println!("  SM3 Hash (Base64) ::: {}", sm3::digest_str(input, true));
    println!("  HMAC Key (Base64) ::: {}", sm3::generate_hmac_key_str(true));
    println!();

    println!("=== SM3 Sample 完成 ===");
}
