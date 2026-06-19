#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <sstream>
#include "SM2Util.h"
#include "SM4Util.h"
#include "HexUtil.h"
int main(){std::string j,l;while(std::getline(std::cin,l))j+=l;std::cout<<"{";int fl=0;
auto g=[&](const std::string&k)->std::string{auto p=j.find("\""+k+"\":\"");if(p==std::string::npos)return"";p+=k.length()+4;auto e=j.find("\"",p);if(e==std::string::npos)return"";return j.substr(p,e-p);};
std::string cs=g("cross_enc"),ss=g("cross_sig"),sc=g("cross_sm4");
if(!cs.empty()){try{auto d=SM2Util::decrypt(cs,"b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03");if(fl)std::cout<<",";fl=1;std::cout<<"\"enc\":\""<<(d=="Hello, 这是跨语言国密互通性测试数据"?"PASS":"FAIL")<<"\"";}catch(...){if(fl)std::cout<<",";fl=1;std::cout<<"\"enc\":\"FAIL\"";}}
if(!ss.empty()){try{bool ok=SM2Util::verify(std::string("Hello, 这是跨语言国密互通性测试数据"),"3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",ss);if(fl)std::cout<<",";fl=1;std::cout<<"\"sig\":\""<<(ok?"PASS":"FAIL")<<"\"";}catch(...){if(fl)std::cout<<",";fl=1;std::cout<<"\"sig\":\"FAIL\"";}}
if(!sc.empty()){try{auto sk=HexUtil::decodeHexStr("0123456789abcdeffedcba9876543210");auto d=SM4Util::decryptGcm(sk,sc);std::string ds(d.begin(),d.end());if(fl)std::cout<<",";fl=1;std::cout<<"\"sm4\":\""<<(ds=="Hello, 这是跨语言国密互通性测试数据"?"PASS":"FAIL")<<"\"";}catch(...){if(fl)std::cout<<",";fl=1;std::cout<<"\"sm4\":\"FAIL\"";}}
if(!cs.empty()&&!ss.empty()){try{auto d2=SM2Util::decrypt(cs,"b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03");bool ok2=SM2Util::verify(d2,"3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",ss);if(fl)std::cout<<",";std::cout<<"\"esvd\":\""<<(d2=="Hello, 这是跨语言国密互通性测试数据"&&ok2?"PASS":"FAIL")<<"\"";}catch(...){if(fl)std::cout<<",";std::cout<<"\"esvd\":\"FAIL\"";}}
std::cout<<"}"<<std::endl;return 0;}