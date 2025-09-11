package tx.secure.asymmetric;

import tx.secure.type.KeyPair;
import tx.secure.type.Result;

public interface EncryptionHelper {
    KeyPair generateKeyPair() throws Exception;

    Result encrypt(String plaintext, String base64RecipientPublicKey) throws Exception;

    String decrypt(String encryptedJson, String base64EphemeralPublicKey, String base64RecipientPrivateKey) throws Exception;
}
