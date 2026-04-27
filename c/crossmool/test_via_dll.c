#include <stdio.h>
#include "include/crossmool.h"

int main(void) {
    printf("Start via DLL\n"); fflush(stdout);
    
    crossmool_sm2_keypair_t* kp = NULL;
    printf("Before generate_keypair\n"); fflush(stdout);
    
    int ret = crossmool_sm2_generate_keypair(&kp);
    printf("After generate_keypair: ret=%d, kp=%p\n", ret, (void*)kp); fflush(stdout);
    
    if (ret == 0 && kp) {
        printf("Private: %s\n", kp->private_key);
        printf("Public:  %s\n", kp->public_key);
        crossmool_sm2_keypair_free(kp);
    }
    printf("Done\n");
    return 0;
}
