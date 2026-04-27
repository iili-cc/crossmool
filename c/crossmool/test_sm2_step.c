#include <stdio.h>
#include <string.h>
#include "crossmool.h"

int main(void) {
    printf("Step 1: Program started\n");
    fflush(stdout);

    crossmool_sm2_keypair_t* keypair = NULL;
    printf("Step 2: keypair pointer declared\n");
    fflush(stdout);

    int ret = crossmool_sm2_generate_keypair(&keypair);
    printf("Step 3: generate_keypair returned %d\n", ret);
    fflush(stdout);

    if (ret == 0 && keypair != NULL) {
        printf("Step 4: keypair generated OK\n");
        printf("  Private Key: %s\n", keypair->private_key_hex ? keypair->private_key_hex : "(null)");
        printf("  Public Key: %s\n", keypair->public_key_hex ? keypair->public_key_hex : "(null)");
        fflush(stdout);

        const char* plaintext = "Hello SM2";
        char* ciphertext = NULL;
        printf("Step 5: About to encrypt...\n");
        fflush(stdout);

        ret = crossmool_sm2_encrypt(plaintext, NULL, keypair->public_key_hex, &ciphertext);
        printf("Step 6: encrypt returned %d\n", ret);
        fflush(stdout);

        if (ret == 0 && ciphertext != NULL) {
            printf("  Ciphertext len: %zu\n", strlen(ciphertext));
            fflush(stdout);

            char* decrypted = NULL;
            printf("Step 7: About to decrypt...\n");
            fflush(stdout);

            ret = crossmool_sm2_decrypt(ciphertext, keypair->private_key_hex, NULL, &decrypted);
            printf("Step 8: decrypt returned %d\n", ret);
            fflush(stdout);

            if (ret == 0 && decrypted != NULL) {
                printf("  Decrypted: %s\n", decrypted);
                free(decrypted);
            }
            free(ciphertext);
        }

        char* sig = NULL;
        printf("Step 9: About to sign...\n");
        fflush(stdout);

        ret = crossmool_sm2_sign(plaintext, NULL, keypair->private_key_hex, &sig);
        printf("Step 10: sign returned %d\n", ret);
        fflush(stdout);

        if (ret == 0 && sig != NULL) {
            printf("  Signature len: %zu\n", strlen(sig));
            fflush(stdout);

            printf("Step 11: About to verify...\n");
            fflush(stdout);

            int vr = crossmool_sm2_verify(plaintext, NULL, sig, keypair->public_key_hex);
            printf("Step 12: verify returned %d\n", vr);
            fflush(stdout);

            free(sig);
        }

        crossmool_sm2_keypair_free(keypair);
    }

    printf("Step 13: All done!\n");
    return 0;
}
