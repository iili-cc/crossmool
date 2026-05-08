#include <stdio.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/asn1.h>

int main() {
    // Java 生成的 X.509 公钥 (HEX)
    const char* java_pub_hex = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
    
    unsigned char pub_bytes[128];
    size_t pub_len = 0;
    
    // HEX 解码
    for (size_t i = 0; i < strlen(java_pub_hex); i += 2) {
        char hex_byte[3] = {java_pub_hex[i], java_pub_hex[i+1], 0};
        pub_bytes[pub_len++] = (unsigned char)strtoul(hex_byte, NULL, 16);
    }
    
    printf("公钥字节长度：%zu\n", pub_len);
    printf("公钥 HEX: ");
    for (size_t i = 0; i < pub_len; i++) {
        printf("%02x", pub_bytes[i]);
    }
    printf("\n\n");
    
    // 尝试用 GmSSL 解析 X.509 公钥
    const unsigned char* p = pub_bytes;
    size_t len = pub_len;
    SM2_KEY sm2_key;
    memset(&sm2_key, 0, sizeof(sm2_key));
    
    int ret = sm2_public_key_info_from_der(&sm2_key, &p, &len);
    printf("sm2_public_key_info_from_der 返回：%d\n", ret);
    
    if (ret == 1) {
        printf("公钥解析成功!\n");
        printf("公钥 X: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", sm2_key.public_key.x[i]);
        }
        printf("\n公钥 Y: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", sm2_key.public_key.y[i]);
        }
        printf("\n");
    } else {
        printf("公钥解析失败!\n");
    }
    
    return 0;
}