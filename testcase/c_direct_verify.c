#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

int main() {
    const char* public_key = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
    const char* private_key = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";

    /* Test 1: C self-sign and self-verify */
    printf("=== Test 1: C self-sign and self-verify ===\n");
    const char* content = "Hello, Crossmool!";
    char* sig_hex = NULL;

    int ret = crossmool_sm2_sign(content, NULL, private_key, &sig_hex);
    printf("Sign returned: %d\n", ret);
    if (ret == 0 && sig_hex) {
        printf("Signature: %s\n", sig_hex);

        /* Self verify */
        int vret = crossmool_sm2_verify(content, NULL, sig_hex, public_key);
        printf("Self verify returned: %d\n", vret);
        printf("Self verify: %s\n", vret == 1 ? "SUCCESS" : "FAILED");

        free(sig_hex);
    } else {
        printf("Sign failed!\n");
    }

    /* Test 2: Verify Java's signature on ciphertext */
    printf("\n=== Test 2: Verify Java signature (ciphertext) ===\n");
    const char* ct_content = "046a2146cffa0e592b74f49304a75eb73449be5ae5f7cabac4a3938ae34539207472a2b912701a096ad7182772cede4439cc0642c3b56d123ca9c8b11b569ab94197d41b436a9240ef89ed76d01bee13129c5abc6aefa0d262424f147382f478fae20b93b2b671f0a33eec6a00830f44a191";
    const char* java_sig = "3045022100c75cb782f822a99281d280bce9af156265252b60f1e28b74f34d1e4361c298a80220148a04be093709891f64484eb657fd54b1eab5c20c933b8133bdebe7dea4880f";

    int vret2 = crossmool_sm2_verify(ct_content, NULL, java_sig, public_key);
    printf("Java sig verify (ct): %s (ret=%d)\n", vret2 == 1 ? "SUCCESS" : "FAILED", vret2);

    /* Test 3: Sign ciphertext with C and verify */
    printf("\n=== Test 3: C sign ciphertext and self-verify ===\n");
    char* ct_sig = NULL;
    ret = crossmool_sm2_sign(ct_content, NULL, private_key, &ct_sig);
    printf("Sign ct returned: %d\n", ret);
    if (ret == 0 && ct_sig) {
        printf("CT Signature: %s\n", ct_sig);
        int vret3 = crossmool_sm2_verify(ct_content, NULL, ct_sig, public_key);
        printf("CT self verify: %s (ret=%d)\n", vret3 == 1 ? "SUCCESS" : "FAILED", vret3);
        free(ct_sig);
    }

    /* Test 4: Use raw pubkey (04||x||y) instead of X.509 */
    printf("\n=== Test 4: Use raw pubkey (04||x||y) ===\n");
    const char* raw_pubkey = "048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
    const char* raw_privkey = "72e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057";

    char* raw_sig = NULL;
    ret = crossmool_sm2_sign(content, NULL, raw_privkey, &raw_sig);
    printf("Sign with raw key returned: %d\n", ret);
    if (ret == 0 && raw_sig) {
        printf("Raw key signature: %s\n", raw_sig);
        int vret4 = crossmool_sm2_verify(content, NULL, raw_sig, raw_pubkey);
        printf("Raw key verify: %s (ret=%d)\n", vret4 == 1 ? "SUCCESS" : "FAILED", vret4);

        /* Also verify with X.509 key */
        int vret5 = crossmool_sm2_verify(content, NULL, raw_sig, public_key);
        printf("X.509 key verify of raw-key sig: %s (ret=%d)\n", vret5 == 1 ? "SUCCESS" : "FAILED", vret5);
        free(raw_sig);
    }

    /* Test 5: C sign content, Java verify C sig */
    printf("\n=== Test 5: C sign, check if format is compatible ===\n");
    char* cross_sig = NULL;
    ret = crossmool_sm2_sign(content, NULL, raw_privkey, &cross_sig);
    if (ret == 0 && cross_sig) {
        printf("C signature (first 4 chars): %.4s\n", cross_sig);
        printf("C signature (first byte): %02x\n", (unsigned char)cross_sig[0]);
        printf("C signature length: %d hex chars = %d bytes\n", (int)strlen(cross_sig), (int)strlen(cross_sig)/2);
        free(cross_sig);
    }

    return 0;
}
