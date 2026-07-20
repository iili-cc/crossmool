use base64::{engine::general_purpose, Engine as _};
use hex;
use crossmool::sm2::{generate_keypair, sign_with_private_pem, verify_with_public_pem, encrypt_with_public_pem, decrypt_with_private_pem};

fn main() {
    println!("SM2 simple demo");

    let keys = generate_keypair().expect("keygen");
    let public_pem = keys.public_key_pem;
    let private_pem = keys.private_key_pem;

    println!("Public PEM:\n{}", public_pem);
    println!("Private PEM:\n{}", private_pem);

    let msg = b"hello crossmool example";
    let sig = sign_with_private_pem(msg, &private_pem).expect("sign");
    println!("Signature (hex): {}", hex::encode(&sig));
    println!("Signature (base64): {}", general_purpose::STANDARD.encode(&sig));

    let ok = verify_with_public_pem(msg, &sig, &public_pem).expect("verify");
    println!("Signature verify: {}", ok);

    let plain = b"example plaintext for sm2 pke";
    let ct = encrypt_with_public_pem(&public_pem, plain).expect("encrypt");
    println!("Ciphertext (hex): {}", hex::encode(&ct));
    println!("Ciphertext (base64): {}", general_purpose::STANDARD.encode(&ct));

    let pt = decrypt_with_private_pem(&private_pem, &ct).expect("decrypt");
    println!("Decrypted equals original: {}", pt == plain);
}
