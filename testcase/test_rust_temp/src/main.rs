use crossmool::sm4;

fn main() {
    println!("Testing Rust SM4");
    let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
    let plain = b"Hello";
    match sm4::encrypt_ecb_hex(&key, plain) {
        Ok(ct) => println!("Encrypted: {}", ct),
        Err(e) => println!("Error: {}", e),
    }
}
