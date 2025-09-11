package tx.secure.asymmetric;

import tx.secure.symmetric.SymmetricEncryptionHelper;
import tx.secure.symmetric.SymmetricEncryptionResult;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class AsymmetricEncryptionHelper {
    private final SymmetricEncryptionHelper symmetricHelper;

    public AsymmetricEncryptionHelper(SymmetricEncryptionHelper symmetricHelper) {
        this.symmetricHelper = symmetricHelper;
    }

    /**
     * Generate a new RSA key pair
     */
    public AsymmetricKeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return new AsymmetricKeyPair(keyPair.getPublic(), keyPair.getPrivate());
    }

    /**
     * Encrypt plaintext using hybrid encryption:
     * 1. Generate a symmetric key
     * 2. Encrypt the plaintext with the symmetric key
     * 3. Encrypt the symmetric key with the RSA public key
     */
    public AsymmetricEncryptionResult encrypt(String plaintext, PublicKey publicKey) throws Exception {
        // Generate symmetric key and encrypt the plaintext
        String symmetricKey = symmetricHelper.generateKeyBase64();
        SymmetricEncryptionResult symmetricResult = symmetricHelper.encrypt(plaintext, symmetricKey);

        // Encrypt the symmetric key with RSA public key
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKeyBytes = cipher.doFinal(Base64.getDecoder().decode(symmetricKey));
        String encryptedSymmetricKey = Base64.getEncoder().encodeToString(encryptedKeyBytes);

        return new AsymmetricEncryptionResult(encryptedSymmetricKey, symmetricResult);
    }

    /**
     * Decrypt the encrypted result using hybrid decryption:
     * 1. Decrypt the symmetric key using the RSA private key
     * 2. Use the decrypted symmetric key to decrypt the actual data
     */
    public String decrypt(AsymmetricEncryptionResult result, PrivateKey privateKey) throws Exception {
        // Decrypt the symmetric key with RSA private key
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(Base64.getDecoder().decode(result.getEncryptedSymmetricKey()));
        String symmetricKey = Base64.getEncoder().encodeToString(decryptedKeyBytes);

        // Decrypt the actual data using the symmetric key
        return symmetricHelper.decrypt(result.getSymmetricResult(), symmetricKey);
    }
}
