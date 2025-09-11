package tx.secure.symmetric;

public interface SymmetricEncryptionHelper {
    /**
     * Generate a random symmetric key and return it as Base64 encoded string
     */
    String generateKeyBase64() throws Exception;

    /**
     * Encrypt plaintext using the provided symmetric key
     */
    SymmetricEncryptionResult encrypt(String plaintext, String keyBase64) throws Exception;

    /**
     * Decrypt the encrypted result using the provided symmetric key
     */
    String decrypt(SymmetricEncryptionResult result, String keyBase64) throws Exception;
}
