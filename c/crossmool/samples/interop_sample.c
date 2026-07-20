#include <stdio.h>
#include <string.h>
#include "crossmool.h"

/**
 * 跨语言互通性示例
 *
 * 演示 C 语言版 Crossmool 的输出如何与其他语言版本互通。
 * 所有密文、签名均使用 Hex 编码，密钥支持 Hex / Base64 双格式。
 *
 * 快速上手：
 * 1. 运行本程序，观察输出的密钥和密文
 * 2. 将 Hex 密钥复制到 Java/C#/Python 等版本的 sample 中
 * 3. 验证跨语言加解密、签名验签结果一致
 *
 * 数据格式约定：
 * - SM2 公钥：X.509 DER (Hex)
 * - SM2 私钥：PKCS#8 DER (Hex)
 * - SM2 密文：C1C3C2 (Hex)
 * - SM4 密文：GCM (IV[12] + Ciphertext + Tag[16])
 */
int main(void)
{
    printf("============================================================\n");
    printf("  Cross-Language Interop Sample\n");
    printf("============================================================\n\n");

    /* ==================== 1. SM2 密钥生成（Hex + Base64 双格式） ==================== */
    printf(">>> 1. SM2 密钥生成\n");

    crossmool_sm2_keypair_t *keypair = NULL;
    int ret = crossmool_sm2_generate_keypair(&keypair);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        return 1;
    }

    crossmool_sm2_keypair_to_hex(keypair);
    crossmool_sm2_keypair_to_base64(keypair);

    printf("  Private Key (HEX)    ::: %.80s...\n", keypair->private_key_hex);
    printf("  Public Key  (HEX)    ::: %.80s...\n", keypair->public_key_hex);
    printf("  Private Key (Base64) ::: %s\n", keypair->private_key_base64);
    printf("  Public Key  (Base64) ::: %s\n\n", keypair->public_key_base64);

    /* ==================== 2. SM2 加密 → 输出给其他语言解密 ==================== */
    printf(">>> 2. SM2 加密（C1C3C2，其他语言可解密）\n");

    const char *message = "Hello， crossmool！ 跨语言互通测试文本。";
    char *ciphertext_hex = NULL;
    ret = crossmool_sm2_encrypt(message, NULL, keypair->public_key_hex,
                                 &ciphertext_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        goto cleanup_keypair;
    }

    printf("  Message           ::: %s\n", message);
    printf("  Ciphertext (HEX)  ::: %.150s...\n", ciphertext_hex);
    printf("  → 将此 Hex 密文复制到 Java/C#/Python 的 SM2Util.decrypt() 即可解密\n\n");

    /* ==================== 3. SM2 解密 ==================== */
    printf(">>> 3. SM2 解密\n");

    char *decrypted = NULL;
    ret = crossmool_sm2_decrypt(ciphertext_hex, keypair->private_key_hex,
                                 NULL, &decrypted);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        goto cleanup_keypair;
    }

    printf("  Decrypted ::: %s\n", decrypted);
    printf("  Match    ::: %s\n\n",
           strcmp(message, decrypted) == 0 ? "true" : "false");
    free(decrypted);
    free(ciphertext_hex);

    /* ==================== 4. SM2 签名 → 其他语言可验签 ==================== */
    printf(">>> 4. SM2 签名（其他语言可验签）\n");

    const char *data = "Sign this across languages！";
    char *signature_hex = NULL;
    ret = crossmool_sm2_sign(data, NULL, keypair->private_key_hex,
                              &signature_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        goto cleanup_keypair;
    }

    printf("  Data              ::: %s\n", data);
    printf("  Signature (HEX)   ::: %s\n", signature_hex);
    printf("  → 将此签名和公钥复制到其他语言版本 verify() 即可验签\n\n");

    /* 自验证 */
    int verify_result = crossmool_sm2_verify(data, NULL, signature_hex,
                                              keypair->public_key_hex);
    printf("  Self-Verify       ::: %s\n\n",
           verify_result == 1 ? "PASS" : "FAIL");
    free(signature_hex);

    /* ==================== 5. SM3 摘要 ==================== */
    printf(">>> 5. SM3 摘要\n");

    const char *sm3_input =
        "在这个全球化时代，無論身處何地，"
        "learning and growth are always the keys to a fulfilling life.";
    char *sm3_digest = NULL;
    ret = crossmool_sm3_digest_str(sm3_input, NULL, &sm3_digest);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        goto cleanup_keypair;
    }

    printf("  Input       ::: %s\n", sm3_input);
    printf("  Digest (HEX) ::: %s\n", sm3_digest);
    printf("  → 在所有语言版本中，相同输入的 SM3 摘要必须完全一致\n\n");

    /* ==================== 6. HMAC-SM3 ==================== */
    printf(">>> 6. HMAC-SM3\n");

    const char *hmac_key_str = "crossmool_interop_key_2024!!";
    const char *hmac_data = "Hello, HMAC!";
    char *hmac_hex = NULL;
    ret = crossmool_sm3_hmac_str(hmac_key_str, NULL, hmac_data, NULL,
                                  &hmac_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(sm3_digest);
        goto cleanup_keypair;
    }

    printf("  Key         ::: %s\n", hmac_key_str);
    printf("  Data        ::: %s\n", hmac_data);
    printf("  HMAC (HEX)  ::: %s\n\n", hmac_hex);

    /* ==================== 7. SM4 GCM 加密（GCM 模式，其他语言可解密） ==================== */
    printf(">>> 7. SM4 GCM 加密\n");

    char *sm4_key_hex = NULL;
    ret = crossmool_sm4_generate_key_hex(&sm4_key_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(sm3_digest);
        free(hmac_hex);
        goto cleanup_keypair;
    }

    unsigned char sm4_key[16];
    crossmool_sm4_parse_hex_key(sm4_key_hex, sm4_key);

    const char *sm4_plaintext = "Hello, SM4 GCM! 跨语言加密测试。";
    char *sm4_ciphertext = NULL;
    ret = crossmool_sm4_encrypt_gcm_str_hex(sm4_key, sm4_plaintext,
                                             &sm4_ciphertext);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(sm3_digest);
        free(hmac_hex);
        free(sm4_key_hex);
        goto cleanup_keypair;
    }

    printf("  SM4 Key (HEX)     ::: %s\n", sm4_key_hex);
    printf("  Plaintext         ::: %s\n", sm4_plaintext);
    printf("  Ciphertext (HEX)  ::: %.150s...\n", sm4_ciphertext);
    printf("  → 将密钥和 Hex 密文复制到其他语言版本的 SM4 解密接口即可\n\n");

    /* 清理 */
    free(sm3_digest);
    free(hmac_hex);
    free(sm4_key_hex);
    free(sm4_ciphertext);

cleanup_keypair:
    crossmool_sm2_keypair_free(keypair);

    printf("=== Interop Sample 完成 ===\n\n");
    printf("提示：\n");
    printf("  跨语言互通验证步骤：\n");
    printf("  1. 将上方输出的 Hex 密钥复制到 Java/C#/Python/Go/Rust/JS 的 sample 程序\n");
    printf("  2. 分别运行各语言版本的 SM2/SM3/SM4 示例\n");
    printf("  3. 对比摘要/加解密/签名验签结果，应完全一致\n");
    return 0;
}
