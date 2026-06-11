#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// SM3 implementation (compact, from GB/T 32905-2016)
// This provides SM3 and SM3-HMAC for cross-language validation

#define SM3_DIGEST_LENGTH 32
#define SM3_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[SM3_BLOCK_SIZE];
    uint32_t buffer_idx;
} sm3_ctx;

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL32((x), 9) ^ ROTL32((x), 17))
#define P1(x) ((x) ^ ROTL32((x), 15) ^ ROTL32((x), 23))

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

void sm3_init(sm3_ctx *ctx) {
    ctx->state[0] = 0x7380166f; ctx->state[1] = 0x4914b2b9;
    ctx->state[2] = 0x172442d7; ctx->state[3] = 0xda8a0600;
    ctx->state[4] = 0xa96f30bc; ctx->state[5] = 0x163138aa;
    ctx->state[6] = 0xe38dee4d; ctx->state[7] = 0xb0fb0e4e;
    ctx->count = 0; ctx->buffer_idx = 0;
}

void sm3_compress(sm3_ctx *ctx) {
    uint32_t W[68], W1[64], A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;
    int j;
    for (j = 0; j < 16; j++) {
        W[j] = ((uint32_t)ctx->buffer[j*4] << 24) | ((uint32_t)ctx->buffer[j*4+1] << 16) |
               ((uint32_t)ctx->buffer[j*4+2] << 8) | (uint32_t)ctx->buffer[j*4+3];
    }
    for (j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15)) ^ ROTL32(W[j-13], 7) ^ W[j-6];
    }
    for (j = 0; j < 64; j++) W1[j] = W[j] ^ W[j+4];
    A = ctx->state[0]; B = ctx->state[1]; C = ctx->state[2]; D = ctx->state[3];
    E = ctx->state[4]; F = ctx->state[5]; G = ctx->state[6]; H = ctx->state[7];
    for (j = 0; j < 64; j++) {
        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32((j < 16 ? 0x79cc4519 : 0x7a879d8a), j % 32), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = (j < 16 ? FF0(A, B, C) : FF1(A, B, C)) + D + SS2 + W1[j];
        TT2 = (j < 16 ? GG0(E, F, G) : GG1(E, F, G)) + H + SS1 + W[j];
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);
    }
    ctx->state[0] ^= A; ctx->state[1] ^= B; ctx->state[2] ^= C; ctx->state[3] ^= D;
    ctx->state[4] ^= E; ctx->state[5] ^= F; ctx->state[6] ^= G; ctx->state[7] ^= H;
}

void sm3_update(sm3_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->count += len;
    while (len > 0) {
        size_t n = SM3_BLOCK_SIZE - ctx->buffer_idx;
        if (n > len) n = len;
        memcpy(ctx->buffer + ctx->buffer_idx, data, n);
        ctx->buffer_idx += n;
        data += n; len -= n;
        if (ctx->buffer_idx == SM3_BLOCK_SIZE) {
            sm3_compress(ctx);
            ctx->buffer_idx = 0;
        }
    }
}

void sm3_final(sm3_ctx *ctx, uint8_t *digest) {
    uint64_t bits = ctx->count * 8;
    ctx->buffer[ctx->buffer_idx++] = 0x80;
    if (ctx->buffer_idx > 56) {
        memset(ctx->buffer + ctx->buffer_idx, 0, SM3_BLOCK_SIZE - ctx->buffer_idx);
        sm3_compress(ctx); ctx->buffer_idx = 0;
    }
    memset(ctx->buffer + ctx->buffer_idx, 0, 56 - ctx->buffer_idx);
    ctx->buffer[56] = (bits >> 56) & 0xff; ctx->buffer[57] = (bits >> 48) & 0xff;
    ctx->buffer[58] = (bits >> 40) & 0xff; ctx->buffer[59] = (bits >> 32) & 0xff;
    ctx->buffer[60] = (bits >> 24) & 0xff; ctx->buffer[61] = (bits >> 16) & 0xff;
    ctx->buffer[62] = (bits >> 8) & 0xff;  ctx->buffer[63] = bits & 0xff;
    sm3_compress(ctx);
    int i;
    for (i = 0; i < 8; i++) {
        digest[i*4]   = (ctx->state[i] >> 24) & 0xff;
        digest[i*4+1] = (ctx->state[i] >> 16) & 0xff;
        digest[i*4+2] = (ctx->state[i] >> 8) & 0xff;
        digest[i*4+3] = ctx->state[i] & 0xff;
    }
}

void sm3_hash(const uint8_t *data, size_t len, uint8_t *digest) {
    sm3_ctx ctx; sm3_init(&ctx); sm3_update(&ctx, data, len); sm3_final(&ctx, digest);
}

// HMAC-SM3
void hmac_sm3(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *mac) {
    uint8_t k[SM3_BLOCK_SIZE], o_key_pad[SM3_BLOCK_SIZE], i_key_pad[SM3_BLOCK_SIZE];
    uint8_t inner_hash[SM3_DIGEST_LENGTH];
    memset(k, 0, SM3_BLOCK_SIZE);
    if (key_len > SM3_BLOCK_SIZE) { sm3_hash(key, key_len, k); }
    else { memcpy(k, key, key_len); }
    int i;
    for (i = 0; i < SM3_BLOCK_SIZE; i++) { o_key_pad[i] = k[i] ^ 0x5C; i_key_pad[i] = k[i] ^ 0x36; }
    sm3_ctx ctx;
    sm3_init(&ctx); sm3_update(&ctx, i_key_pad, SM3_BLOCK_SIZE);
    sm3_update(&ctx, data, data_len); sm3_final(&ctx, inner_hash);
    sm3_init(&ctx); sm3_update(&ctx, o_key_pad, SM3_BLOCK_SIZE);
    sm3_update(&ctx, inner_hash, SM3_DIGEST_LENGTH); sm3_final(&ctx, mac);
}

// Hex output helper
void print_hex(const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) printf("%02x", data[i]);
}

// Hex decode
int hex_decode(const char *hex, uint8_t *out) {
    size_t len = strlen(hex);
    if (len % 2) return -1;
    size_t i;
    for (i = 0; i < len/2; i++) {
        int h;
        if (sscanf(hex + i*2, "%2x", &h) != 1) return -1;
        out[i] = (uint8_t)h;
    }
    return (int)(len/2);
}

int main(int argc, char **argv) {
    const char *MSG = "\x48\x65\x6c\x6c\x6f\x2c\x20\xe8\xbf\x99\xe6\x98\xaf\xe8\xb7\xa8\xe8\xaf\xad\xe8\xa8\x80\xe5\x9b\xbd\xe5\xaf\x86\xe4\xba\x92\xe9\x80\x9a\xe6\x80\xa7\xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae";
    size_t msg_len = 55;
    
    const char *HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    uint8_t hmac_key[32];
    hex_decode(HMAC_KEY_HEX, hmac_key);
    
    // SM3
    uint8_t sm3_dig[SM3_DIGEST_LENGTH];
    sm3_hash((const uint8_t*)MSG, msg_len, sm3_dig);
    printf("{\"sm3\":\""); print_hex(sm3_dig, SM3_DIGEST_LENGTH);
    printf("\",\"sm3_ok\":");
    // Check against expected
    const char *EXP_SM3 = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b";
    uint8_t exp_buf[32]; hex_decode(EXP_SM3, exp_buf);
    printf(memcmp(sm3_dig, exp_buf, 32) == 0 ? "true" : "false");
    
    // SM3-HMAC
    uint8_t hmac_dig[SM3_DIGEST_LENGTH];
    hmac_sm3(hmac_key, 32, (const uint8_t*)MSG, msg_len, hmac_dig);
    printf(",\"sm3_hmac\":\""); print_hex(hmac_dig, SM3_DIGEST_LENGTH);
    printf("\",\"sm3_hmac_ok\":");
    const char *EXP_HMAC = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";
    hex_decode(EXP_HMAC, exp_buf);
    printf(memcmp(hmac_dig, exp_buf, 32) == 0 ? "true" : "false");
    
    printf("}\n");
    return 0;
}
