fn der_base64_to_pem(der_b64: &str, header: &str) -> String {
    // Wrap base64 into 64-character lines which many PEM parsers expect.
    let mut wrapped = String::new();
    for chunk in der_b64.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap());
        wrapped.push('\n');
    }
    format!("-----BEGIN {header}-----\n{}-----END {header}-----\n", wrapped)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Java test keys from `java/crossmool/src/main/java/cc/iili/tools/crossmool/constant/SM2Constant.java`
    // Cipher keys (X.509 / PKCS#8 in base64 form)
    let public_b64 = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEO4gVFPrTdWaMRocy/GuyjUZYdbdsqzfcvrtjkCoTVfBSXVWElN6uj91ZxsiszlzQ3JxTYxLKd3sy6EWNuS22+g==";
    let private_b64 = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgLtLT8TS7TpI1t6JhId5PiZ7yI+DwNDWwXY54yyb89SmgCgYIKoEcz1UBgi2hRANCAAQ7iBUU+tN1ZoxGhzL8a7KNRlh1t2yrN9y+u2OQKhNV8FJdVYSU3q6P3VnGyKzOXNDcnFNjEsp3ezLoRY25Lbb6";

    // Convert DER-base64 to PEM-wrapped strings
    let public_pem = der_base64_to_pem(public_b64, "PUBLIC KEY");
    let private_pem = der_base64_to_pem(private_b64, "PRIVATE KEY");

    let plaintext = "Hello, 张三丰!".as_bytes();

    // Use the library functions
    let ct_b64 = crossmool::sm2::encrypt_with_public_pem_base64(&public_pem, plaintext)?;
    println!("Rust ciphertext (Base64): {}", ct_b64);

    let decrypted = crossmool::sm2::decrypt_with_private_pem_base64(&private_pem, &ct_b64)?;
    let dec_str = String::from_utf8(decrypted)?;
    println!("Rust decrypted: {}", dec_str);

    // Now try decrypting the ciphertext produced by Java test run (from surefire output)
    let java_ct_b64 = "BIhDbFtiMubhGEXw2D7dbnnbfIwSfWcgO+Qs6HS7LcVVy7yfbVH9hH/yv9RA83r5eSfbhHUn/zxFYoz99X3Eltjej5cYxU9iNfwXoTyJ4Tihu48aTLHl/z3FNA+9SzoFbd3Ky5J1isO3aXoqEOpfbh4z";
    let java_dec = crossmool::sm2::decrypt_with_private_pem_base64(&private_pem, java_ct_b64)?;
    let java_dec_str = String::from_utf8(java_dec)?;
    println!("Decrypted Java ciphertext: {}", java_dec_str);

    Ok(())
}
