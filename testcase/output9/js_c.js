
const{SM2Util,SM3Util,SM4Util,hexToBytes}=require("G:/workspaces/git/corssmool/crossmool/javascript/crossmool/dist/index.js");
const M="Hello, 这是跨语言国密互通性测试数据";const K={"eR": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sP": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"};
const ref={"cross_enc": "0438567bf30a7d4032a4a6ae923532bd6fe2498e1555efbdd8fea5ab2ac94c517bc2402484de05aa610e945d7ad4d1b240ba5e6e53bd5484212f9dbd737fd6748ea94a1e97df1712f03f81aaff676cd273d800938440b79ee989f7212efee15e51760e3ca31629bf9f8ee90fc7ab8956a4515ba4f565a1f71f5b1625da051ad44351b2d698b7ada02e3a63168ce8bc2328ff", "cross_sig": "3044022038778f329bd0b61747bdbedbe65f62c43503cae48aeb39f4c54716154165d3240220366c79abd3ca2c9faeac61b1ff48b338625bbb54091a80fcc4291c8021057594", "cross_sm4": "86887d44a685f354e7504178fd7aff22aa845d5a77bab2af4b1f8313b4503ece478a3c766925cc1919833a9c8d6b95abdf3d79b3a7834170ef6bb47daf6f7fab86b2a17279d35fdd975b30e8c9"};
const r={};
try{if(ref.cross_enc){r.enc=SM2Util.decrypt(ref.cross_enc,K.eR)===M?"PASS":"FAIL";}}catch(e){r.enc="FAIL:"+e.message;}
try{if(ref.cross_sig){r.sig=SM2Util.verify(M,K.sP,ref.cross_sig)?"PASS":"FAIL";}}catch(e){r.sig="FAIL:"+e.message;}
try{if(ref.cross_enc&&ref.cross_sig){const d=SM2Util.decrypt(ref.cross_enc,K.eR);r.esvd=(d===M&&SM2Util.verify(d,K.sP,ref.cross_sig))?"PASS":"FAIL";}}catch(e){r.esvd="FAIL:"+e.message;}
try{if(ref.cross_sm4){const sk=hexToBytes("0123456789abcdeffedcba9876543210");r.sm4=SM4Util.decryptGcmToString(ref.cross_sm4,sk)===M?"PASS":"FAIL";}}catch(e){r.sm4="FAIL:"+e.message;}
console.log(JSON.stringify(r));
