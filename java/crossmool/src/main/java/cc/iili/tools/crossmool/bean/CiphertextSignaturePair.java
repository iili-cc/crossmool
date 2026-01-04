package cc.iili.tools.crossmool.bean;


public class CiphertextSignaturePair implements java.io.Serializable {
    
    /**
     * 
     */
    private static final long serialVersionUID = -289847178151860549L;
    
    private String ciphertext;
    private String signature;
    
    public CiphertextSignaturePair(String ciphertext, String signature) {
        this.ciphertext = ciphertext;
        this.signature = signature;
    }
    
    public String getCiphertext() {
        return ciphertext;
    }
    public String getSignature() {
        return signature;
    }
    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }
    public void setSignature(String signature) {
        this.signature = signature;
    }
    
    @Override
    public String toString() {
        return "CiphertextSignaturePair [ciphertext=" + ciphertext + ", signature=" + signature + "]";
    }

}
