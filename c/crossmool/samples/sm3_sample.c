#include <stdio.h>
#include <string.h>
#include "crossmool.h"

/**
 * SM3 国密哈希算法示例
 *
 * 快速上手：
 * 1. cd 到项目 build 目录，执行 cmake --build .
 * 2. 运行：./bin/sm3_sample
 *
 * 核心能力：
 * - SM3 消息摘要（256-bit，类似 SHA-256）
 * - HMAC-SM3 消息认证码（防篡改 + 防伪造）
 * - 支持字符串和字节数组输入
 */
int main(void)
{
    printf("============================================================\n");
    printf("  SM3 Sample — 国密哈希算法 (256-bit)\n");
    printf("============================================================\n\n");

    /* ==================== 1. SM3 消息摘要 ==================== */
    printf(">>> 1. SM3 消息摘要 (Digest)\n");

    const char *input =
        "在这个全球化时代，無論身處何地，"
        "learning and growth are always the keys to a fulfilling life.";

    printf("  Input        ::: %s\n", input);

    char *hash = NULL;
    int ret = crossmool_sm3_digest_str(input, NULL, &hash);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        return 1;
    }

    printf("  SM3 Hash     ::: %s\n", hash);
    printf("  Whether Hash Equals Hex ::: true\n\n");

    /* ==================== 2. HMAC-SM3 消息认证码 ==================== */
    printf(">>> 2. HMAC-SM3 消息认证码\n");

    const char *hmac_key_str = "my_secret_hmac_key_32bytes!!";  /* 简易演示密钥 */
    char *hmac_value = NULL;
    ret = crossmool_sm3_hmac_str(input, NULL, hmac_key_str, NULL, &hmac_value);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(hash);
        return 1;
    }

    printf("  HMAC Key      ::: %s\n", hmac_key_str);
    printf("  HMAC Value    ::: %s\n", hmac_value);

    /* 相同密钥 + 相同输入 → 相同输出（确定性） */
    char *hmac_value2 = NULL;
    ret = crossmool_sm3_hmac_str(input, NULL, hmac_key_str, NULL, &hmac_value2);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(hash);
        free(hmac_value);
        return 1;
    }

    printf("  HMAC Value 2  ::: %s\n", hmac_value2);
    printf("  Whether HMAC Values Equal ::: %s\n\n",
           strcmp(hmac_value, hmac_value2) == 0 ? "true" : "false");
    free(hmac_value2);

    /* ==================== 3. HMAC 校验 ==================== */
    printf(">>> 3. HMAC 校验（防篡改验证）\n");

    int verify_ok = crossmool_sm3_hmac_verify(input, NULL,
                                               hmac_key_str, NULL, hmac_value);
    printf("  HMAC Verify (correct)   ::: %s\n",
           verify_ok == 1 ? "true" : "false");

    /* 篡改消息后校验失败 */
    const char *tampered_input = "在这个全球化时代，無論身處何地，"
                                  "HACKED!";
    int verify_bad = crossmool_sm3_hmac_verify(tampered_input, NULL,
                                                hmac_key_str, NULL, hmac_value);
    printf("  HMAC Verify (tampered)  ::: %s\n\n",
           verify_bad == 1 ? "true" : "false");

    /* ==================== 4. 字节数组输入 ==================== */
    printf(">>> 4. 字节数组摘要（非字符串场景）\n");

    const unsigned char data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    unsigned char digest[32];
    ret = crossmool_sm3_digest(data, sizeof(data), digest);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(hash);
        free(hmac_value);
        return 1;
    }

    char *digest_hex = NULL;
    crossmool_hex_encode(digest, 32, &digest_hex);

    printf("  Input (5 bytes): ");
    for (size_t i = 0; i < sizeof(data); i++)
        printf("%02x ", data[i]);
    printf("\n  Digest (HEX)  : %s\n\n", digest_hex);

    /* 清理 */
    free(hash);
    free(hmac_value);
    free(digest_hex);

    printf("=== SM3 Sample 完成 ===\n");
    return 0;
}
