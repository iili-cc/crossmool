use crossmool::sm2::{
    decrypt_with_private_pem, encrypt_with_public_pem, generate_keypair, sign_with_private_pem,
    verify_with_public_pem,
};

#[test]
fn sm2_roundtrip_sign_encrypt() {
    // generate keys
    let keys = generate_keypair().expect("keygen");
    let public_pem = keys.public_key_pem;
    let private_pem = keys.private_key_pem;

    // sign/verify
    let msg = b"hello crossmool";
    let sig = sign_with_private_pem(msg, &private_pem).expect("sign");
    let ok = verify_with_public_pem(msg, &sig, &public_pem).expect("verify");
    assert!(ok, "signature verification failed");

    // encrypt/decrypt
    let plain = b"crossmool plaintext data";
    let ct = encrypt_with_public_pem(&public_pem, plain).expect("encrypt");
    let pt = decrypt_with_private_pem(&private_pem, &ct).expect("decrypt");
    assert_eq!(pt, plain);
}

#[test]
fn sm2_roundtrip_hex_base64_wrappers() {
    let keys = generate_keypair().expect("keygen");
    let public_pem = keys.public_key_pem;
    let private_pem = keys.private_key_pem;

    let plain = b"wrapper test data";
    let ct_hex = crossmool::sm2::encrypt_with_public_pem_hex(&public_pem, plain).expect("encrypt hex");
    let pt = crossmool::sm2::decrypt_with_private_pem_hex(&private_pem, &ct_hex).expect("decrypt hex");
    assert_eq!(pt, plain);

    let ct_b64 = crossmool::sm2::encrypt_with_public_pem_base64(&public_pem, plain).expect("encrypt b64");
    let pt2 = crossmool::sm2::decrypt_with_private_pem_base64(&private_pem, &ct_b64).expect("decrypt b64");
    assert_eq!(pt2, plain);
}
