package tx.secure.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Wrapper class for holding a key pair.
 */
public class AsymmetricKeyPair {
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public AsymmetricKeyPair(PublicKey publicKey, PrivateKey privateKey) {
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
}
