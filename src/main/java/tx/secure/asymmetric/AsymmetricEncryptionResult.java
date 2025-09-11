package tx.secure.asymmetric;

import org.json.JSONException;
import tx.secure.symmetric.SymmetricEncryptionResult;

/**
 * Holds encrypted data (Base64-encoded) along with the ephemeral public key (Base64-encoded)
 * generated during encryption.
 */
public record AsymmetricEncryptionResult(String encryptedSymmetricKey, SymmetricEncryptionResult symmetricResult) {

    /**
     * @return Base64-encoded encrypted data
     */
    @Override
    public String encryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }

    /**
     * @return Symmetric encryption result object
     */
    @Override
    public SymmetricEncryptionResult symmetricResult() {
        return symmetricResult;
    }

    public String getEncryptionJson() throws JSONException {
        System.out.println("symmetricResult.toJson().toString() = " + symmetricResult.toJson().toString());
        return symmetricResult.toJson().toString();
    }
}
