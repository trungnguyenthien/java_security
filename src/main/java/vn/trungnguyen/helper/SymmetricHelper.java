package vn.trungnguyen.helper;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

/**
 * SymmetricHelper - A helper class for symmetric encryption/decryption using AES-GCM-256 with Bouncy Castle
 * Random 12-byte (96-bit) IV
 */
public class SymmetricHelper {
    private static final String PROVIDER = "BC"; // Bouncy Castle
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_LENGTH = 256; // AES-256
    private static final int IV_LENGTH = 12;   // 96-bit IV
    private static final int GCM_TAG_LENGTH = 16; // 128-bit authentication tag

    private final SecureRandom secureRandom;

    public SymmetricHelper() {
        this.secureRandom = new SecureRandom();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generate a random AES-256 key as Base64 string.
     */
    public String generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
        keyGenerator.init(KEY_LENGTH);
        byte[] keyBytes = keyGenerator.generateKey().getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    /**
     * Encrypt plaintext bytes using AES-GCM-256.
     *
     * @param plaintext data to encrypt
     * @param base64Key AES key as Base64 string
     * @return encrypted data (IV + ciphertext)
     */
    public byte[] encrypt(byte[] plaintext, String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        byte[] iv = generateIV();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, ALGORITHM), gcmParameterSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] encryptedData = new byte[IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, IV_LENGTH);
        System.arraycopy(ciphertext, 0, encryptedData, IV_LENGTH, ciphertext.length);
        return encryptedData;
    }

    /**
     * Encrypt plaintext string and return Base64 ciphertext.
     */
    public String encrypt(String plaintext, String base64Key) throws Exception {
        byte[] encrypted = encrypt(plaintext.getBytes("UTF-8"), base64Key);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypt ciphertext bytes (IV + ciphertext) using AES-GCM-256.
     */
    public byte[] decrypt(byte[] encryptedData, String base64Key) throws Exception {
        if (encryptedData.length < IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data format.");
        }

        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, IV_LENGTH, encryptedData.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, ALGORITHM), gcmParameterSpec);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Decrypt Base64 ciphertext and return plaintext string.
     */
    public String decrypt(String encryptedText, String base64Key) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedText);
        byte[] decrypted = decrypt(encryptedData, base64Key);
        return new String(decrypted, "UTF-8");
    }

    /**
     * Generate a random IV.
     */
    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
