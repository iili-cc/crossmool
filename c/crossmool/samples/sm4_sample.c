#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

/**
 * SM4 国密对称加密算法示例（GCM 模式）
 *
 * 快速上手：
 * 1. cd 到项目 build 目录，执行 cmake --build .
 * 2. 运行：./bin/sm4_sample
 *
 * 核心能力：
 * - 生成 SM4 密钥（128-bit，Hex / Base64 格式）
 * - SM4-GCM 加密（带认证标签，防篡改）
 * - SM4-GCM 解密（自动检测 Hex / Base64 输入）
 * - GCM 模式：任何篡改都会导致解密失败
 */
int main(void)
{
    printf("============================================================\n");
    printf("  SM4 Sample — 国密对称加密 (GCM 模式)\n");
    printf("============================================================\n\n");

    /* ==================== 原始内容 ==================== */
    const char *original_content =
        "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。"
        "路过咖啡店时買了一杯美式，順便（顺便）看了下手机，"
        "今日步數（步数）已经 12，345 步了，距離目標還差 3，000 步左右。"
        "朋友发来一条消息说：\"Don't forget to bring your umbrella， just in case！\" "
        "我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。";

    printf("OriginalContent ::: %s\n\n", original_content);

    /* ==================== 1. 生成 SM4 密钥 ==================== */
    printf(">>> 1. 生成 SM4 密钥（128-bit）\n");

    char *hex_key = NULL;
    int ret = crossmool_sm4_generate_key_hex(&hex_key);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        return 1;
    }

    char *base64_key = NULL;
    ret = crossmool_sm4_generate_key_base64(&base64_key);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(hex_key);
        return 1;
    }

    printf("  SM4 Hex Key    ::: %s\n", hex_key);
    printf("  SM4 Base64 Key ::: %s\n\n", base64_key);

    /* 解析密钥为字节数组 */
    unsigned char key_bytes[16];
    crossmool_sm4_parse_hex_key(hex_key, key_bytes);

    /* ==================== 2. Hex 密钥 GCM 加解密 ==================== */
    printf(">>> 2. 使用 Hex 密钥进行 GCM 加解密\n");

    char *encrypted_hex = NULL;
    ret = crossmool_sm4_encrypt_gcm_str_hex(key_bytes, original_content,
                                             &encrypted_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(hex_key);
        free(base64_key);
        return 1;
    }

    printf("  Encrypted (Hex) ::: %.150s...\n", encrypted_hex);

    char *decrypted_hex = NULL;
    ret = crossmool_sm4_decrypt_gcm_hex_str(key_bytes, encrypted_hex,
                                             &decrypted_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(hex_key);
        free(base64_key);
        free(encrypted_hex);
        return 1;
    }

    printf("  Decrypted (Hex) ::: %s\n", decrypted_hex);
    printf("  WhetherDecryptEqualsOriginalContent (Hex) ::: %s\n\n",
           strcmp(original_content, decrypted_hex) == 0 ? "true" : "false");

    free(decrypted_hex);

    /* ==================== 3. Base64 密钥 GCM 加解密 ==================== */
    printf(">>> 3. 使用 Base64 密钥进行 GCM 加解密\n");

    unsigned char base64_key_bytes[16];
    crossmool_sm4_parse_hex_key(hex_key, base64_key_bytes);  /* 复用同一密钥 */

    char *encrypted_b64 = NULL;
    ret = crossmool_sm4_encrypt_gcm_str_base64(key_bytes, original_content,
                                                &encrypted_b64);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(hex_key);
        free(base64_key);
        free(encrypted_hex);
        return 1;
    }

    printf("  Encrypted (Base64) ::: %.100s...\n", encrypted_b64);

    char *decrypted_b64 = NULL;
    ret = crossmool_sm4_decrypt_gcm_base64_str(key_bytes, encrypted_b64,
                                                &decrypted_b64);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(hex_key);
        free(base64_key);
        free(encrypted_hex);
        free(encrypted_b64);
        return 1;
    }

    printf("  Decrypted (Base64) ::: %s\n", decrypted_b64);
    printf("  WhetherDecryptEqualsOriginalContent (Base64) ::: %s\n\n",
           strcmp(original_content, decrypted_b64) == 0 ? "true" : "false");

    free(decrypted_b64);
    free(encrypted_b64);

    /* ==================== 4. GCM 防篡改验证 ==================== */
    printf(">>> 4. GCM 防篡改验证\n");
    printf("  （故意篡改密文末尾字符，GCM 应检测到并拒绝解密）\n");

    /* 构造一个被篡改的密文（修改 HEX 尾部） */
    size_t hex_len = strlen(encrypted_hex);
    char *tampered = malloc(hex_len + 1);
    memcpy(tampered, encrypted_hex, hex_len - 2);
    tampered[hex_len - 2] = 'X';
    tampered[hex_len - 1] = 'X';
    tampered[hex_len] = '\0';

    char *hacked = NULL;
    ret = crossmool_sm4_decrypt_gcm_hex_str(key_bytes, tampered, &hacked);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("  GCM detected tampering， decryption failed ::: %s\n",
               crossmool_error_string(ret));
    } else {
        printf("  Tampered decrypted ::: %s\n", hacked);
        free(hacked);
    }
    printf("\n");

    /* 清理 */
    free(hex_key);
    free(base64_key);
    free(encrypted_hex);
    free(tampered);

    printf("=== SM4 Sample 完成 ===\n");
    return 0;
}
