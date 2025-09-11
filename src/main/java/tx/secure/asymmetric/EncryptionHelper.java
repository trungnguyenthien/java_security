package tx.secure.asymmetric;

import tx.secure.type.KeyPair;
import tx.secure.type.Result;

// Interface for asymmetric encryption and decryption
public interface EncryptionHelper {
    // Generate a new asymmetric key pair
    KeyPair generateKeyPair() throws Exception;
    // Encrypt plaintext using the recipient's public key
    Result encrypt(String plaintext, String base64RecipientPublicKey) throws Exception;
    // Decrypt the encrypted JSON using the recipient's private key and the ephemeral public key
    String decrypt(String encryptedJson, String base64EphemeralPublicKey, String base64RecipientPrivateKey) throws Exception;
}
