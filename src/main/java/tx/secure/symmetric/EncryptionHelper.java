package tx.secure.symmetric;

import tx.secure.type.Result;

public interface EncryptionHelper {
    /**
     * Generate a random symmetric key and return it as Base64 encoded string
     */
    String generateKeyBase64() throws Exception;

    /**
     * Encrypt plaintext using the provided symmetric key
     */
    Result encrypt(String plaintext, String keyBase64) throws Exception;

    /**
     * Decrypt the encrypted result using the provided symmetric key
     */
    String decrypt(Result result, String keyBase64) throws Exception;
}
