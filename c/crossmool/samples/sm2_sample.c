#include <stdio.h>
#include <string.h>
#include "crossmool.h"

/**
 * SM2 国密非对称加密算法示例
 *
 * 快速上手：
 * 1. 确保已安装 CMake >= 3.20 和 C 编译器（MSVC / GCC / Clang）
 * 2. cd 到项目根目录，执行：
 *    mkdir build && cd build
 *    cmake .. -DBUILD_EXAMPLES=ON
 *    cmake --build .
 * 3. 运行：./bin/sm2_sample  (或 build\bin\Release\sm2_sample.exe)
 *
 * 核心能力：
 * - 生成 SM2 密钥对
 * - 公钥加密 → 私钥解密
 * - 私钥签名 → 公钥验签
 * - 先加密再签名 → 先验签再解密（防篡改 + 防抵赖）
 */
int main(void)
{
    printf("============================================================\n");
    printf("  SM2 Sample — 国密非对称加密 (SM2P256V1)\n");
    printf("============================================================\n\n");

    /* ==================== 原始内容 ==================== */
    const char *original_content =
        "今天天气真好，气温大约 28°C，我决定出門走走。"
        "路过咖啡店时買了一杯美式，順便（顺便）看了下手机。"
        "Don't forget to bring your umbrella!";

    printf("OriginalContent ::: %s\n\n", original_content);

    /* ==================== 1. 生成两对密钥 ==================== */
    printf(">>> 1. 生成两对 SM2 密钥（第1对加解密，第2对签名）\n");

    crossmool_sm2_keypair_t *keypair1 = NULL;
    crossmool_sm2_keypair_t *keypair2 = NULL;

    int ret = crossmool_sm2_generate_keypair(&keypair1);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        return 1;
    }
    ret = crossmool_sm2_generate_keypair(&keypair2);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        crossmool_sm2_keypair_free(keypair1);
        return 1;
    }

    ret = crossmool_sm2_keypair_to_hex(keypair1);
    crossmool_sm2_keypair_to_hex(keypair2);

    printf("  privateKeyHex-1 ::: %s\n", keypair1->private_key_hex);
    printf("  publicKeyHex-1  ::: %s\n", keypair1->public_key_hex);
    printf("  privateKeyHex-2 ::: %s\n", keypair2->private_key_hex);
    printf("  publicKeyHex-2  ::: %s\n\n", keypair2->public_key_hex);

    /* ==================== 2. 加密并签名 → 验签并解密 ==================== */
    printf(">>> 2. 加密并签名 → 验签并解密（先加密再签名，先验签再解密）\n");

    crossmool_sm2_cipher_sig_pair_t *pair = NULL;
    ret = crossmool_sm2_encrypt_sign(original_content, NULL,
                                      keypair1->public_key_hex,
                                      keypair2->private_key_hex, &pair);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        goto cleanup_pair;
    }

    printf("  CipherText ::: %.150s...\n", pair->ciphertext_hex);
    printf("  Signature  ::: %s\n\n", pair->signature_hex);

    char *verify_decrypt = NULL;
    ret = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex,
                                        keypair2->public_key_hex,
                                        keypair1->private_key_hex,
                                        NULL, &verify_decrypt);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        goto cleanup_pair;
    }

    printf("  VerifyDecrypt ::: %s\n", verify_decrypt);
    printf("  WhetherVerifyDecryptEqualsOriginalContent ::: %s\n\n",
           strcmp(original_content, verify_decrypt) == 0 ? "true" : "false");

    free(verify_decrypt);

    /* ==================== 3. 仅加密/解密 ==================== */
    printf(">>> 3. 公钥加密 → 私钥解密\n");

    char *ciphertext = NULL;
    ret = crossmool_sm2_encrypt(original_content, NULL,
                                 keypair1->public_key_hex, &ciphertext);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        goto cleanup_pair;
    }

    printf("  EncryptedContent ::: %.150s...\n", ciphertext);

    char *decrypted = NULL;
    ret = crossmool_sm2_decrypt(ciphertext, keypair1->private_key_hex,
                                 NULL, &decrypted);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext);
        goto cleanup_pair;
    }

    printf("  DecryptedContent ::: %s\n", decrypted);
    printf("  WhetherDecryptEqualsOriginalContent ::: %s\n\n",
           strcmp(original_content, decrypted) == 0 ? "true" : "false");

    free(ciphertext);
    free(decrypted);

    /* ==================== 4. 签名/验签 ==================== */
    printf(">>> 4. 私钥签名 → 公钥验签\n");

    char *signature_hex = NULL;
    ret = crossmool_sm2_sign(original_content, NULL,
                              keypair2->private_key_hex, &signature_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        goto cleanup_pair;
    }

    printf("  ContentSignature ::: %s\n", signature_hex);

    int verify_result = crossmool_sm2_verify(original_content, NULL,
                                              signature_hex,
                                              keypair2->public_key_hex);
    printf("  WhetherVerifyEqualsOriginalContent ::: %s\n\n",
           verify_result == 1 ? "true" : "false");

    free(signature_hex);

    printf("=== SM2 Sample 完成 ===\n");

    /* 清理 */
cleanup_pair:
    crossmool_sm2_cipher_sig_pair_free(pair);
    crossmool_sm2_keypair_free(keypair1);
    crossmool_sm2_keypair_free(keypair2);
    return (ret == CROSSMOOL_SUCCESS) ? 0 : 1;
}
