package tx.secure.asymmetric;

import tx.secure.symmetric.SymmetricEncryptionResult;

/**
 * Holds encrypted data (Base64-encoded) along with the ephemeral public key (Base64-encoded)
 * generated during encryption.
 */
public class AsymmetricEncryptionResult {
    private final String encryptedSymmetricKey;
    private final SymmetricEncryptionResult symmetricResult;

    public AsymmetricEncryptionResult(String encryptedSymmetricKey, SymmetricEncryptionResult symmetricResult) {
        this.encryptedSymmetricKey = encryptedSymmetricKey;
        this.symmetricResult = symmetricResult;
    }

    /**
     * @return Base64-encoded encrypted data
     */
    public String getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }

    /**
     * @return Symmetric encryption result object
     */
    public SymmetricEncryptionResult getSymmetricResult() {
        return symmetricResult;
    }
}
