#include <stdio.h>
#include <stdlib.h>

/* 在 include GmSSL 之前禁用 DEBUG */
#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>

int main(void) {
    printf("Start\n"); fflush(stdout);
    
    SM2_KEY key;
    printf("Before generate\n"); fflush(stdout);
    int ret = sm2_key_generate(&key);
    printf("After generate: ret=%d\n", ret); fflush(stdout);
    
    if (ret < 0) {
        printf("Key generation failed\n");
        return 1;
    }
    
    /* 获取公钥（65 字节） */
    unsigned char pub[65];
    sm2_point_to_uncompressed_octets(&key.public_key, pub);
    printf("Public key prefix: %02x\n", pub[0]); fflush(stdout);
    
    /* 设置公钥 */
    SM2_KEY pub_key;
    SM2_POINT tmp_pub;
    memcpy(tmp_pub.x, pub + 1, 32);
    memcpy(tmp_pub.y, pub + 1 + 32, 32);
    
    printf("Before set_public_key\n"); fflush(stdout);
    ret = sm2_key_set_public_key(&pub_key, &tmp_pub);
    printf("After set_public_key: ret=%d\n", ret); fflush(stdout);
    
    /* 加密测试 */
    const char* msg = "Hello";
    unsigned char ciphertext[512];
    size_t ct_len = 0;
    printf("Before encrypt\n"); fflush(stdout);
    ret = sm2_encrypt(&pub_key, (const unsigned char*)msg, 5, ciphertext, &ct_len);
    printf("After encrypt: ret=%d, len=%zu\n", ret, ct_len); fflush(stdout);
    
    return 0;
}
