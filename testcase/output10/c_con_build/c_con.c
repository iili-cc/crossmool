#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"
#include "crossmool_sm2.h"
#include "crossmool_sm4.h"
int main(void) {
    char b[8192] = {0};
    int n = fread(b, 1, 8192, stdin);
    FILE* f = stdout;
    unsigned char sk[16];
    crossmool_sm4_parse_hex_key("0123456789abcdeffedcba9876543210", sk);
    /* Debug: print received data */
    fprintf(stderr, "READ %d bytes\n", n);
    fprintf(stderr, "First 100: %.100s\n", b);
    
    /* Search for keys */
    char* pe = strstr(b, "x_enc");
    char* ps = strstr(b, "x_sig");
    char* pm = strstr(b, "x_sm4");
    fprintf(stderr, "x_enc found at offset: %ld\n", pe ? (long)(pe-b) : -1L);
    fprintf(stderr, "x_sig found at offset: %ld\n", ps ? (long)(ps-b) : -1L);
    fprintf(stderr, "x_sm4 found at offset: %ld\n", pm ? (long)(pm-b) : -1L);
    
    fputs("{", f);
    int fl = 0;
    char *p, *q;
    
    /* Simple parser: find between quotes */
    if (pe) {
        pe = strstr(b, "\"x_enc\":\"");
        if (pe) {
            pe += 9;
            q = strchr(pe, '"');
            if (q) {
                *q = 0;
                unsigned char* d = NULL;
                size_t dl;
                const char* msg = "Hello, \xe8\xbf\x99\xe6\x98\xaf\xe8\xb7\xa8\xe8\xaf\xad\xe8\xa8\x80\xe5\x9b\xbd\xe5\xaf\x86\xe4\xba\x92\xe9\x80\x9a\xe6\x80\xa7\xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae";
                int r = crossmool_sm2_decrypt_bytes(pe, "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", &d, &dl);
                int ok = (r == 0 && dl == 49 && memcmp(d, msg, 49) == 0);
                fprintf(f, "\"enc\":\"%s\"", ok ? "PASS" : "FAIL");
                fl = 1;
                if (d) free(d);
            }
        }
    }
    
    if (ps) {
        ps = strstr(b, "\"x_sig\":\"");
        if (ps) {
            ps += 9;
            q = strchr(ps, '"');
            if (q) {
                *q = 0;
                const char* msg = "Hello, \xe8\xbf\x99\xe6\x98\xaf\xe8\xb7\xa8\xe8\xaf\xad\xe8\xa8\x80\xe5\x9b\xbd\xe5\xaf\x86\xe4\xba\x92\xe9\x80\x9a\xe6\x80\xa7\xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae";
                int v = crossmool_sm2_verify_bytes((unsigned char*)msg, 49, ps,
                    "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226");
                if (fl) fputc(',', f); fl = 1;
                fprintf(f, "\"sig\":\"%s\"", (v == 1) ? "PASS" : "FAIL");
            }
        }
    }
    
    if (pm) {
        pm = strstr(b, "\"x_sm4\":\"");
        if (pm) {
            pm += 9;
            q = strchr(pm, '"');
            if (q) {
                *q = 0;
                unsigned char* dd = NULL;
                size_t dl;
                int r = crossmool_sm4_decrypt_gcm_hex(sk, pm, &dd, &dl);
                const char* msg = "Hello, \xe8\xbf\x99\xe6\x98\xaf\xe8\xb7\xa8\xe8\xaf\xad\xe8\xa8\x80\xe5\x9b\xbd\xe5\xaf\x86\xe4\xba\x92\xe9\x80\x9a\xe6\x80\xa7\xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae";
                int ok = (r == 0 && dl == 49 && memcmp(dd, msg, 49) == 0);
                if (fl) fputc(',', f); fl = 1;
                fprintf(f, "\"sm4\":\"%s\"", ok ? "PASS" : "FAIL");
                if (dd) free(dd);
            }
        }
    }
    
    fputs("}\n", f);
    return 0;
}
