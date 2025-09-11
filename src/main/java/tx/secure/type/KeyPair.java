package tx.secure.type;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Wrapper class for holding a key pair.
 */
public class KeyPair {
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * @return the original private key object
     */
    public PrivateKey getPrivate() {
        return privateKey;
    }

    /**
     * @return the original public key object
     */
    public PublicKey getPublic() {
        return publicKey;
    }

    public String getPrivateBase64() {
        return java.util.Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public String getPublicBase64() {
        return java.util.Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
