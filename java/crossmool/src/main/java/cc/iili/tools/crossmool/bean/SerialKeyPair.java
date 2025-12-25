package cc.iili.tools.crossmool.bean;

public class SerialKeyPair implements java.io.Serializable {
    
    /**
     * 
     */
    private static final long serialVersionUID = -7763027907746794578L;
    
    private String publicKey;
    private String privateKey;

    public SerialKeyPair(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
    
    @Override
    public String toString() {
        return "SerialKeyPair [publicKey=" + publicKey + ", privateKey=" + privateKey + "]";
    }
    
}
