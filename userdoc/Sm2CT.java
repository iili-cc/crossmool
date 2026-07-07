
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

public class Sm2CT {
    public static void main(String[] a) throws Exception {
        String encPub=a[0], encPriv=a[1], sigPub=a[2], sigPriv=a[3], p1=a[4], p2=a[5];
        String ct1H=a[6], ct1B=a[7], ct2H=a[8], s2H=a[9], ct2B=a[10], s2B=a[11];
        int pass=0, fail=0;

        try { String c=SM2Util.encrypt(p1,encPub); check("enc_hex",!c.isEmpty()); pass++; } catch(Exception e) { System.out.println("  enc_hex FAIL: "+e.getMessage()); fail++; }
        try { String c=SM2Util.encrypt(p1,encPub); String d=SM2Util.decrypt(c,encPriv); check("dec_hex_self",d.equals(p1)); pass++; } catch(Exception e) { System.out.println("  dec_hex_self FAIL: "+e.getMessage()); fail++; }
        try { String d=SM2Util.decrypt(ct1H,encPriv); check("dec_hex_py",d.equals(p1)); pass++; } catch(Exception e) { System.out.println("  dec_hex_py FAIL: "+e.getMessage()); fail++; }
        try { String d2=SM2Util.decrypt(ct1B,encPriv); check("dec_b64_py",d2.equals(p1)); pass++; } catch(Exception e) { System.out.println("  dec_b64_py FAIL: "+e.getMessage()); fail++; }
        try { CiphertextSignaturePair e=SM2Util.encryptSign(p2,encPub,sigPriv); check("enc_sign_hex",e.getCiphertext()!=null); pass++; } catch(Exception e) { System.out.println("  enc_sign_hex FAIL: "+e.getMessage()); fail++; }
        try { CiphertextSignaturePair e=SM2Util.encryptSign(p2,encPub,sigPriv); String v=SM2Util.verifyDecrypt(e.getCiphertext(),e.getSignature(),sigPub,encPriv); check("vd_hex_self",v.equals(p2)); pass++; } catch(Exception e) { System.out.println("  vd_hex_self FAIL: "+e.getMessage()); fail++; }
        try { String v=SM2Util.verifyDecrypt(ct2H,s2H,sigPub,encPriv); check("vd_hex_py",v.equals(p2)); pass++; } catch(Exception e) { System.out.println("  vd_hex_py FAIL: "+e.getMessage()); fail++; }
        try { String v=SM2Util.verifyDecrypt(ct2B,s2B,sigPub,encPriv); check("vd_b64_py",v.equals(p2)); pass++; } catch(Exception e) { System.out.println("  vd_b64_py FAIL: "+e.getMessage()); fail++; }
        System.out.println("  " + pass + "/" + (pass+fail) + " passed");
        if(fail>0) System.exit(1);
    }
    static void check(String n, boolean o) { System.out.println("  "+n+" "+(o?"PASS":"FAIL")); }
}
