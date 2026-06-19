#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"
#include "crossmool_sm2.h"
#include "crossmool_sm4.h"
static const char M[]="Hello, 这是跨语言国密互通性测试数据";
#define ML 21
int main(){char b[8192]={0};fread(b,1,8192,stdin);FILE*f=stdout;
unsigned char sk[16];crossmool_sm4_parse_hex_key("0123456789abcdeffedcba9876543210",sk);
fputs("{",f);int fl=0;
char*p,*q;
p=strstr(b,"\"cross_enc\":\"");if(p){p+=14;q=strchr(p,'"');if(q)*q=0;
if(*p){unsigned char*d=NULL;size_t dl;int r=crossmool_sm2_decrypt_bytes(p,"b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03",&d,&dl);
if(fl)fputc(',',f);fl=1;fprintf(f,"\"enc\":\"%s\"",(r==0&&dl==ML&&memcmp(d,M,ML)==0)?"PASS":"FAIL");if(d)free(d);}}
p=strstr(b,"\"cross_sig\":\"");if(p){p+=14;q=strchr(p,'"');if(q)*q=0;
if(*p){int v=crossmool_sm2_verify_bytes((unsigned char*)M,ML,p,"3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226");
if(fl)fputc(',',f);fl=1;fprintf(f,"\"sig\":\"%s\"",(v==1)?"PASS":"FAIL");}}
p=strstr(b,"\"cross_sm4\":\"");if(p){p+=14;q=strchr(p,'"');if(q)*q=0;
if(*p){unsigned char*dd=NULL;size_t dl;int r=crossmool_sm4_decrypt_gcm_hex(sk,p,&dd,&dl);
if(fl)fputc(',',f);fl=1;fprintf(f,"\"sm4\":\"%s\"",(r==0&&dl==ML&&memcmp(dd,M,ML)==0)?"PASS":"FAIL");if(dd)free(dd);}}
p=strstr(b,"\"cross_enc\":\""); char*s2=strstr(b,"\"cross_sig\":\"");
if(p&&s2){p+=14;q=strchr(p,'"');if(q)*q=0;s2+=14;q=strchr(s2,'"');if(q)*q=0;
if(*p&&*s2){unsigned char*d2=NULL;size_t d2l;int r2=crossmool_sm2_decrypt_bytes(p,"b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03",&d2,&d2l);
int v2=crossmool_sm2_verify_bytes(d2,d2l,s2,"3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226");
if(fl)fputc(',',f);fprintf(f,"\"esvd\":\"%s\"",(r2==0&&v2==1&&d2l==ML&&memcmp(d2,M,ML)==0)?"PASS":"FAIL");if(d2)free(d2);}}
fputs("}\n",f);return 0;}