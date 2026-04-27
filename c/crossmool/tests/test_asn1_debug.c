#include <stdio.h>
#include <string.h>
#include <gmssl/sm2.h>

/* 手动 hex 解码 */
static size_t hex_decode(const char* hex, unsigned char* out) {
    size_t len = strlen(hex);
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int b;
        sscanf(hex + 2*i, "%02x", &b);
        out[i] = (unsigned char)b;
    }
    return len / 2;
}

int main() {
    /* Java CIPHER_PUBLIC_KEY_HEX - 从 SM2Constant.java 复制 */
    const char* pub_hex =
        "3059301306072a8648ce3d020106082a811ccf5501822d03420004"
        "3b881514fad375668c468732fc6bb28d465875b76cab37dcbebb63"
        "902a1355f0525d558494deae8fdd59c6c8acce5cd0dc9c536312ca"
        "777b32e8458db92db6fa";

    /* Java CIPHER_PRIVATE_KEY_HEX - 从 SM2Constant.java 复制 */
    const char* priv_hex =
        "308193020100301306072a8648ce3d020106082a811ccf5501822d"
        "0479307702010104202ed2d3f134bb4e9235b7a26121de4f899ef2"
        "23e0f03435b05d8e78cb26fcf529a00a06082a811ccf5501822da1"
        "44034200043b881514fad375668c468732fc6bb28d465875b76cab3"
        "7dcbebb63902a1355f0525d558494deae8fdd59c6c8acce5cd0dc9"
        "c536312ca777b32e8458db92db6fa";

    unsigned char pub_buf[256];
    size_t pub_len = hex_decode(pub_hex, pub_buf);
    printf("Public key DER: %zu bytes\n", pub_len);

    unsigned char priv_buf[256];
    size_t priv_len = hex_decode(priv_hex, priv_buf);
    printf("Private key DER: %zu bytes\n", priv_len);

    /* Test 1: sm2_public_key_info_from_der */
    {
        const unsigned char* p = pub_buf;
        size_t len = pub_len;
        SM2_KEY key;
        memset(&key, 0, sizeof(key));
        int ret = sm2_public_key_info_from_der(&key, &p, &len);
        printf("\nsm2_public_key_info_from_der returned %d\n", ret);
        if (ret == 1) {
            unsigned char pt[65];
            sm2_point_to_uncompressed_octets(&key.public_key, pt);
            printf("  Public key EC point:\n");
            printf("  04");
            for (int i = 1; i < 65; i++) printf("%02x", pt[i]);
            printf("\n");
        } else {
            printf("  FAILED! ret=%d\n", ret);
        }
    }

    /* Test 2: sm2_private_key_info_from_der */
    {
        const unsigned char* p = priv_buf;
        size_t len = priv_len;
        const unsigned char* attrs = NULL;
        size_t attrslen = 0;
        SM2_KEY key;
        memset(&key, 0, sizeof(key));
        int ret = sm2_private_key_info_from_der(&key, &attrs, &attrslen, &p, &len);
        printf("\nsm2_private_key_info_from_der returned %d\n", ret);
        if (ret == 1) {
            printf("  Private key: ");
            for (int i = 0; i < 32; i++) printf("%02x", key.private_key[i]);
            printf("\n");
            unsigned char pt[65];
            sm2_point_to_uncompressed_octets(&key.public_key, pt);
            printf("  Public key from priv: 04");
            for (int i = 1; i < 65; i++) printf("%02x", pt[i]);
            printf("\n");
        } else {
            printf("  FAILED! ret=%d\n", ret);
        }
    }

    /* Test 3: 用 DER 解析出的 key 做加密/解密 */
    {
        const unsigned char* p = pub_buf;
        size_t len = pub_len;
        SM2_KEY pub_key;
        memset(&pub_key, 0, sizeof(pub_key));
        int ret = sm2_public_key_info_from_der(&pub_key, &p, &len);
        if (ret == 1) {
            const char* msg = "Hello SM2!";
            unsigned char cipher[256];
            size_t cipher_len = sizeof(cipher);
            ret = sm2_encrypt(&pub_key, (const unsigned char*)msg, strlen(msg), cipher, &cipher_len);
            printf("\nsm2_encrypt returned %d, cipher_len=%zu\n", ret, cipher_len);

            if (ret == 1) {
                /* 用私钥解密 */
                const unsigned char* pp = priv_buf;
                size_t plen = priv_len;
                const unsigned char* attrs2 = NULL;
                size_t attrs2len = 0;
                SM2_KEY priv_key;
                memset(&priv_key, 0, sizeof(priv_key));
                ret = sm2_private_key_info_from_der(&priv_key, &attrs2, &attrs2len, &pp, &plen);
                if (ret == 1) {
                    unsigned char plaintext[256];
                    size_t pt_len = sizeof(plaintext);
                    ret = sm2_decrypt(&priv_key, cipher, cipher_len, plaintext, &pt_len);
                    printf("sm2_decrypt returned %d, pt_len=%zu\n", ret, pt_len);
                    if (ret == 1) {
                        plaintext[pt_len] = 0;
                        printf("Decrypted: %s\n", (char*)plaintext);
                    }
                } else {
                    printf("Private key DER parse failed, cannot decrypt\n");
                }
            }
        } else {
            printf("\nCannot test encrypt/decrypt - public key DER parse failed\n");
        }
    }

    /* Test 4: 用原始 EC point 字节直接设置 key（绕过 ASN.1） */
    printf("\n--- Test 4: Set public key from raw EC point bytes ---\n");
    {
        /* 从 DER 中手动提取的 EC point */
        const char* point_hex = "043b881514fad375668c468732fc6bb28d465875b76cab37dcbebb63902a1355f0525d558494deae8fdd59c6c8acce5cd0dc9c536312ca777b32e8458db92db6fa";
        unsigned char point_buf[65];
        hex_decode(point_hex, point_buf);

        SM2_KEY key;
        memset(&key, 0, sizeof(key));
        SM2_POINT point;
        int ret = sm2_point_from_octets(&point, point_buf, 65);
        printf("sm2_point_from_octets returned %d\n", ret);
        if (ret == 1) {
            ret = sm2_key_set_public_key(&key, &point);
            printf("sm2_key_set_public_key returned %d\n", ret);
            if (ret == 1) {
                const char* msg = "Hello SM2 via raw key!";
                unsigned char cipher[256];
                size_t cipher_len = sizeof(cipher);
                ret = sm2_encrypt(&key, (const unsigned char*)msg, strlen(msg), cipher, &cipher_len);
                printf("sm2_encrypt with raw key returned %d, cipher_len=%zu\n", ret, cipher_len);
            }
        }
    }

    /* Test 5: 用原始私钥字节直接设置 key */
    printf("\n--- Test 5: Set private key from raw 32-byte SK ---\n");
    {
        /* 从 DER 中手动提取的 private key */
        const char* sk_hex = "2ed2d3f134bb4e9235b7a26121de4f899ef223e0f03435b05d8e78cb26fcf529";
        unsigned char sk_buf[32];
        hex_decode(sk_hex, sk_buf);

        SM2_KEY key;
        memset(&key, 0, sizeof(key));
        int ret = sm2_key_set_private_key(&key, sk_buf);
        printf("sm2_key_set_private_key returned %d\n", ret);
        if (ret == 1) {
            unsigned char pt[65];
            sm2_point_to_uncompressed_octets(&key.public_key, pt);
            printf("  Derived public key: 04");
            for (int i = 1; i < 65; i++) printf("%02x", pt[i]);
            printf("\n");

            /* 比较与公钥DER中提取的EC point是否一致 */
            const char* expected_x = "3b881514fad375668c468732fc6bb28d465875b76cab37dcbebb63902a1355f0";
            const char* expected_y = "525d558494deae8fdd59c6c8acce5cd0dc9c536312ca777b32e8458db92db6fa";
            unsigned char exp_x[32], exp_y[32];
            hex_decode(expected_x, exp_x);
            hex_decode(expected_y, exp_y);

            int x_match = (memcmp(pt + 1, exp_x, 32) == 0);
            int y_match = (memcmp(pt + 33, exp_y, 32) == 0);
            printf("  X match: %s\n", x_match ? "YES" : "NO");
            printf("  Y match: %s\n", y_match ? "YES" : "NO");
        }
    }

    return 0;
}
