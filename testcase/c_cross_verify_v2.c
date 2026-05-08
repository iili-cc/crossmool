#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

/*
 * 交叉验证测试 v2
 * 使用 BouncyCastle 生成的签名数据进行 C 验签
 */

int main() {
    const char* public_key = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
    const char* private_key = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";

    int ret;
    int vret;
    char* sig_hex = NULL;

    /* ====== Test 1: C self-sign/verify ====== */
    printf("=== Test 1: C self-sign/verify ===\n");
    const char* msg1 = "Hello SM2 Test!";
    ret = crossmool_sm2_sign(msg1, NULL, private_key, &sig_hex);
    if (ret == 0 && sig_hex) {
        printf("  C sig (msg1): %s\n", sig_hex);
        vret = crossmool_sm2_verify(msg1, NULL, sig_hex, public_key);
        printf("  C self-verify: %s (ret=%d)\n\n", vret == 1 ? "PASS" : "FAIL", vret);
        free(sig_hex); sig_hex = NULL;
    } else {
        printf("  C sign failed! ret=%d\n\n", ret);
    }

    /* ====== Test 2: C verify BouncyCastle signature (msg1) ====== */
    printf("=== Test 2: C verify BC signature on 'Hello SM2 Test!' ===\n");
    const char* bc_sig1 = "3045022100fa0d4bf5e035a2833fb8264a0b20dea919bc1c2135118ef381cd3c2ba5ea247f02201d944d3d087a9ea4a0e3e17caef799f428408a0e473615af77144155dc3d32d2";
    vret = crossmool_sm2_verify(msg1, NULL, bc_sig1, public_key);
    printf("  C verify BC sig: %s (ret=%d)\n\n", vret == 1 ? "PASS" : "FAIL", vret);

    /* ====== Test 3: C verify BouncyCastle signature (ciphertext) ====== */
    printf("=== Test 3: C verify BC signature on ciphertext string ===\n");
    const char* ct = "046a2146cffa0e592b74f49304a75eb73449be5ae5f7cabac4a3938ae34539207472a2b912701a096ad7182772cede4439cc0642c3b56d123ca9c8b11b569ab94197d41b436a9240ef89ed76d01bee13129c5abc6aefa0d262424f147382f478fae20b93b2b671f0a33eec6a00830f44a191";
    const char* bc_sig_ct = "3045022073d62d7a36cc2e19373a9972cc91152393907ba6b988b9fdf416f9f27dd9d304022100aea4dd89e6a98ad6c1ffe52d3c2224d500f962ed103a6805b30a1173e620f38d";
    vret = crossmool_sm2_verify(ct, NULL, bc_sig_ct, public_key);
    printf("  C verify BC ct sig: %s (ret=%d)\n\n", vret == 1 ? "PASS" : "FAIL", vret);

    /* ====== Test 4: C sign, then Java-style verify ====== */
    printf("=== Test 4: C sign ciphertext, Python can verify? ===\n");
    ret = crossmool_sm2_sign(ct, NULL, private_key, &sig_hex);
    if (ret == 0 && sig_hex) {
        printf("  C sig (ct): %s\n", sig_hex);
        vret = crossmool_sm2_verify(ct, NULL, sig_hex, public_key);
        printf("  C self-verify ct: %s (ret=%d)\n", vret == 1 ? "PASS" : "FAIL", vret);
        /* 记录签名供 Python 验证 */
        printf("  [For Python] sig_hex = %s\n", sig_hex);
        free(sig_hex);
    }

    /* ====== Test 5: OLD Java signature (from test_1_simple_text.json) ====== */
    printf("\n=== Test 5: Old Java signature (from test_1) ===\n");
    const char* old_java_sig = "3045022100c75cb782f822a99281d280bce9af156265252b60f1e28b74f34d1e4361c298a80220148a04be093709891f64484eb657fd54b1eab5c20c933b8133bdebe7dea4880f";
    vret = crossmool_sm2_verify(ct, NULL, old_java_sig, public_key);
    printf("  C verify old Java sig: %s (ret=%d)\n", vret == 1 ? "PASS" : "FAIL", vret);

    printf("\n=== All tests done ===\n");
    return 0;
}
