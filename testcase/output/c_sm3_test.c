#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SM3_DIGEST_LENGTH 32
#define SM3_BLOCK_SIZE 64

typedef struct { uint32_t state[8]; uint64_t count; uint8_t buffer[64]; uint32_t buffer_idx; } sm3_ctx;
#define ROTL32(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define P0(x) ((x)^ROTL32((x),9)^ROTL32((x),17))
#define P1(x) ((x)^ROTL32((x),15)^ROTL32((x),23))
#define FF0(x,y,z) ((x)^(y)^(z))
#define FF1(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
#define GG0(x,y,z) ((x)^(y)^(z))
#define GG1(x,y,z) (((x)&(y))|((~(x))&(z)))

static void sm3_init(sm3_ctx *c) {
    c->state[0]=0x7380166f;c->state[1]=0x4914b2b9;c->state[2]=0x172442d7;c->state[3]=0xda8a0600;
    c->state[4]=0xa96f30bc;c->state[5]=0x163138aa;c->state[6]=0xe38dee4d;c->state[7]=0xb0fb0e4e;
    c->count=0;c->buffer_idx=0;
}
static void sm3_compress(sm3_ctx *c) {
    uint32_t W[68],W1[64],A,B,C,D,E,F,G,H,SS1,SS2,TT1,TT2;int j;
    for(j=0;j<16;j++) W[j]=((uint32_t)c->buffer[j*4]<<24)|((uint32_t)c->buffer[j*4+1]<<16)|((uint32_t)c->buffer[j*4+2]<<8)|(uint32_t)c->buffer[j*4+3];
    for(j=16;j<68;j++) W[j]=P1(W[j-16]^W[j-9]^ROTL32(W[j-3],15))^ROTL32(W[j-13],7)^W[j-6];
    for(j=0;j<64;j++) W1[j]=W[j]^W[j+4];
    A=c->state[0];B=c->state[1];C=c->state[2];D=c->state[3];E=c->state[4];F=c->state[5];G=c->state[6];H=c->state[7];
    for(j=0;j<64;j++){SS1=ROTL32(ROTL32(A,12)+E+ROTL32((j<16?0x79cc4519:0x7a879d8a),j%32),7);SS2=SS1^ROTL32(A,12);TT1=(j<16?FF0(A,B,C):FF1(A,B,C))+D+SS2+W1[j];TT2=(j<16?GG0(E,F,G):GG1(E,F,G))+H+SS1+W[j];D=C;C=ROTL32(B,9);B=A;A=TT1;H=G;G=ROTL32(F,19);F=E;E=P0(TT2);}
    c->state[0]^=A;c->state[1]^=B;c->state[2]^=C;c->state[3]^=D;c->state[4]^=E;c->state[5]^=F;c->state[6]^=G;c->state[7]^=H;
}
static void sm3_update(sm3_ctx *c, const uint8_t *d, size_t l) {
    c->count+=l;
    while(l>0){size_t n=SM3_BLOCK_SIZE-c->buffer_idx;if(n>l)n=l;memcpy(c->buffer+c->buffer_idx,d,n);c->buffer_idx+=n;d+=n;l-=n;if(c->buffer_idx==SM3_BLOCK_SIZE){sm3_compress(c);c->buffer_idx=0;}}
}
static void sm3_final(sm3_ctx *c, uint8_t *dig) {
    uint64_t bits=c->count*8;int i;
    c->buffer[c->buffer_idx++]=0x80;
    if(c->buffer_idx>56){memset(c->buffer+c->buffer_idx,0,SM3_BLOCK_SIZE-c->buffer_idx);sm3_compress(c);c->buffer_idx=0;}
    memset(c->buffer+c->buffer_idx,0,56-c->buffer_idx);
    c->buffer[56]=(bits>>56)&0xff;c->buffer[57]=(bits>>48)&0xff;c->buffer[58]=(bits>>40)&0xff;c->buffer[59]=(bits>>32)&0xff;
    c->buffer[60]=(bits>>24)&0xff;c->buffer[61]=(bits>>16)&0xff;c->buffer[62]=(bits>>8)&0xff;c->buffer[63]=bits&0xff;
    sm3_compress(c);
    for(i=0;i<8;i++){dig[i*4]=(c->state[i]>>24)&0xff;dig[i*4+1]=(c->state[i]>>16)&0xff;dig[i*4+2]=(c->state[i]>>8)&0xff;dig[i*4+3]=c->state[i]&0xff;}
}
static void sm3_hash(const uint8_t *d, size_t l, uint8_t *dig){sm3_ctx c;sm3_init(&c);sm3_update(&c,d,l);sm3_final(&c,dig);}
static void hmac_sm3(const uint8_t *k, size_t kl, const uint8_t *d, size_t dl, uint8_t *m){
    uint8_t kp[64],okp[64],ikp[64],ih[32];int i;memset(kp,0,64);
    if(kl>64)sm3_hash(k,kl,kp);else memcpy(kp,k,kl);
    for(i=0;i<64;i++){okp[i]=kp[i]^0x5C;ikp[i]=kp[i]^0x36;}
    sm3_ctx c;sm3_init(&c);sm3_update(&c,ikp,64);sm3_update(&c,d,dl);sm3_final(&c,ih);
    sm3_init(&c);sm3_update(&c,okp,64);sm3_update(&c,ih,32);sm3_final(&c,m);
}
int hex2bin(const char *h, uint8_t *b){size_t l=strlen(h);if(l%2)return-1;size_t i;for(i=0;i<l/2;i++){int v;if(sscanf(h+i*2,"%2x",&v)!=1)return-1;b[i]=(uint8_t)v;}return(int)(l/2);}

int main(){
    const char *MSG="Hello, \xe8\xbf\x99\xe6\x98\xaf\xe8\xb7\xa8\xe8\xaf\xad\xe8\xa8\x80\xe5\x9b\xbd\xe5\xaf\x86\xe4\xba\x92\xe9\x80\x9a\xe6\x80\xa7\xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae";
    size_t ml=strlen(MSG);
    const char *EXP_SM3="0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b";
    const char *EXP_HMAC="3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";
    const char *HK="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    
    uint8_t dg[32], eb[32], hk[32];
    hex2bin(EXP_SM3,eb);
    hex2bin(HK,hk);
    
    sm3_hash((const uint8_t*)MSG,ml,dg);
    int sm3ok=(memcmp(dg,eb,32)==0);
    
    uint8_t hm[32], eh[32];
    hex2bin(EXP_HMAC,eh);
    hmac_sm3(hk,32,(const uint8_t*)MSG,ml,hm);
    int hmok=(memcmp(hm,eh,32)==0);
    
    printf("{\"lang\":\"C\",\"sm3_ok\":%s,\"sm3_hmac_ok\":%s}",sm3ok?"true":"false",hmok?"true":"false");
    return 0;
}
