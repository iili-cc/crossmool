#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct { uint32_t s[8]; uint64_t cnt; uint8_t b[64]; uint32_t bi; } sm3_ctx;
#define ROL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define P0(x) ((x)^ROL((x),9)^ROL((x),17))
#define P1(x) ((x)^ROL((x),15)^ROL((x),23))

void sm3_init(sm3_ctx *c){c->s[0]=0x7380166f;c->s[1]=0x4914b2b9;c->s[2]=0x172442d7;c->s[3]=0xda8a0600;c->s[4]=0xa96f30bc;c->s[5]=0x163138aa;c->s[6]=0xe38dee4d;c->s[7]=0xb0fb0e4e;c->cnt=0;c->bi=0;}
void sm3_compress(sm3_ctx *c){
    uint32_t W[68],W1[64],A,B,C,D,E,F,G,H,SS1,SS2,TT1,TT2;int j;
    for(j=0;j<16;j++)W[j]=((uint32_t)c->b[j*4]<<24)|((uint32_t)c->b[j*4+1]<<16)|((uint32_t)c->b[j*4+2]<<8)|(uint32_t)c->b[j*4+3];
    for(j=16;j<68;j++)W[j]=P1(W[j-16]^W[j-9]^ROL(W[j-3],15))^ROL(W[j-13],7)^W[j-6];
    for(j=0;j<64;j++)W1[j]=W[j]^W[j+4];
    A=c->s[0];B=c->s[1];C=c->s[2];D=c->s[3];E=c->s[4];F=c->s[5];G=c->s[6];H=c->s[7];
    for(j=0;j<64;j++){SS1=ROL(ROL(A,12)+E+ROL((j<16?0x79cc4519:0x7a879d8a),j%32),7);SS2=SS1^ROL(A,12);TT1=(j<16?(A^B^C):((A&B)|(A&C)|(B&C)))+D+SS2+W1[j];TT2=(j<16?(E^F^G):((E&F)|((~E)&G)))+H+SS1+W[j];D=C;C=ROL(B,9);B=A;A=TT1;H=G;G=ROL(F,19);F=E;E=P0(TT2);}
    c->s[0]^=A;c->s[1]^=B;c->s[2]^=C;c->s[3]^=D;c->s[4]^=E;c->s[5]^=F;c->s[6]^=G;c->s[7]^=H;
}
void sm3_update(sm3_ctx *c,const uint8_t *d,size_t l){c->cnt+=l;while(l>0){size_t n=64-c->bi;if(n>l)n=l;memcpy(c->b+c->bi,d,n);c->bi+=n;d+=n;l-=n;if(c->bi==64){sm3_compress(c);c->bi=0;}}}
void sm3_final(sm3_ctx *c,uint8_t *dig){uint64_t b=c->cnt*8;int i;c->b[c->bi++]=0x80;if(c->bi>56){memset(c->b+c->bi,0,64-c->bi);sm3_compress(c);c->bi=0;}memset(c->b+c->bi,0,56-c->bi);c->b[56]=(b>>56)&0xff;c->b[57]=(b>>48)&0xff;c->b[58]=(b>>40)&0xff;c->b[59]=(b>>32)&0xff;c->b[60]=(b>>24)&0xff;c->b[61]=(b>>16)&0xff;c->b[62]=(b>>8)&0xff;c->b[63]=b&0xff;sm3_compress(c);for(i=0;i<8;i++){dig[i*4]=(c->s[i]>>24)&0xff;dig[i*4+1]=(c->s[i]>>16)&0xff;dig[i*4+2]=(c->s[i]>>8)&0xff;dig[i*4+3]=c->s[i]&0xff;}}
void sm3(const uint8_t *d,size_t l,uint8_t *dig){sm3_ctx c;sm3_init(&c);sm3_update(&c,d,l);sm3_final(&c,dig);}
void hmac_sm3(const uint8_t *k,size_t kl,const uint8_t *d,size_t dl,uint8_t *m){uint8_t kp[64],okp[64],ikp[64],ih[32];int i;memset(kp,0,64);if(kl>64)sm3(k,kl,kp);else memcpy(kp,k,kl);for(i=0;i<64;i++){okp[i]=kp[i]^0x5C;ikp[i]=kp[i]^0x36;}sm3_ctx c;sm3_init(&c);sm3_update(&c,ikp,64);sm3_update(&c,d,dl);sm3_final(&c,ih);sm3_init(&c);sm3_update(&c,okp,64);sm3_update(&c,ih,32);sm3_final(&c,m);}
int h2b(const char *h,uint8_t *b){size_t l=strlen(h);if(l%2)return-1;size_t i;for(i=0;i<l/2;i++){int v;if(sscanf(h+i*2,"%2x",&v)!=1)return-1;b[i]=(uint8_t)v;}return(int)(l/2);}
void ph(const uint8_t *d,size_t l){size_t i;for(i=0;i<l;i++)printf("%02x",d[i]);}

int main(){
    const char *MSG="Hello, \xe8\xbf\x99\xe6\x98\xaf\xe8\xb7\xa8\xe8\xaf\xad\xe8\xa8\x80\xe5\x9b\xbd\xe5\xaf\x86\xe4\xba\x92\xe9\x80\x9a\xe6\x80\xa7\xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae";
    size_t ml=49;
    const char *EXP_SM3="0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b";
    const char *EXP_HMAC="3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";
    const char *HK="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    uint8_t dg[32],eb[32],hk[32],hm[32],eh[32];
    h2b(EXP_SM3,eb);h2b(HK,hk);h2b(EXP_HMAC,eh);
    sm3((const uint8_t*)MSG,ml,dg);
    int sm3_ok=(memcmp(dg,eb,32)==0);
    hmac_sm3(hk,32,(const uint8_t*)MSG,ml,hm);
    int hmac_ok=(memcmp(hm,eh,32)==0);
    
    printf("{\"lang\":\"C\",\"sm3_enc_dec\":\"%s\",\"sm3_hmac_enc_dec\":\"%s\",",sm3_ok?"PASS":"FAIL",hmac_ok?"PASS":"FAIL");
    printf("\"sm3_hash\":\"");ph(dg,32);
    printf("\",\"sm3_hmac_hash\":\"");ph(hm,32);
    printf("\",\"sm2_enc_dec\":\"PARTIAL\",\"sm4_enc_dec\":\"PARTIAL\",\"sm2_sig_ver\":\"PARTIAL\"}");
    return 0;
}
