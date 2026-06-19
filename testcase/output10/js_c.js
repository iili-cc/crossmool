
const{SM2Util,SM3Util,SM4Util,hexToBytes}=require("G:/workspaces/git/corssmool/crossmool/javascript/crossmool/dist/index.js");
const M="Hello, 这是跨语言国密互通性测试数据";const K={"eR": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sP": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"};
const ref={"x_enc": "047d79b685bc8f421bed86075b6d476cec4c2eed2e20d89b55d581088834b997f3f213e7196cce61a1401054b478591537341f642df83ce0bca53aaf0a8b4a018c7eee7071c87cd6fa2177642cb78176129c655e942cdc6bc27bb6f1496d2c85b973d7b02316c4218e1d51b6c64b83f5033e915188c1538d2c00800b3eb76a01e4312dee34199b8f3ed9c11a1c625b67f608", "x_sig": "30440220048fdb4f5c97e47ea4ddb9f6bba28b7bcc08b9f87e09fb7b1a6f4f1ed6c88eca02202dc90f6cf7e451ac20b757d36283602b62e26bd4640bae0b8455cdc14343ba2b", "x_sm4": "c066ffaaae728693e5d7b2bcbdbc6855a1708efd5e843c6aaf9beac994441a8d77babd797081d5f7c15b6225325ecf0d1338bb774880a036eca9952f40d79896b7290d058b8b3fb75a631eaab8"};
const r={};
try{if(ref.x_enc){r.enc=SM2Util.decrypt(ref.x_enc,K.eR)===M?"PASS":"FAIL";}}catch(e){r.enc="FAIL:"+e.message;}
try{if(ref.x_sig){r.sig=SM2Util.verify(M,K.sP,ref.x_sig)?"PASS":"FAIL";}}catch(e){r.sig="FAIL:"+e.message;}
try{if(ref.x_enc&&ref.x_sig){const d=SM2Util.decrypt(ref.x_enc,K.eR);r.esvd=(d===M&&SM2Util.verify(d,K.sP,ref.x_sig))?"PASS":"FAIL";}}catch(e){r.esvd="FAIL:"+e.message;}
try{if(ref.x_sm4){const sk=hexToBytes("0123456789abcdeffedcba9876543210");r.sm4=SM4Util.decryptGcmToString(ref.x_sm4,sk)===M?"PASS":"FAIL";}}catch(e){r.sm4="FAIL:"+e.message;}
console.log(JSON.stringify(r));
