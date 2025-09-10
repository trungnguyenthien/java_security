package vn.trungnguyen.helper;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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
 * SymmetricHelper - Utility class for symmetric encryption/decryption using AES-GCM-256.
 *
 * <p>Features:</p>
 * - AES-GCM with 256-bit key length (AES-256-GCM).
 * - Random 12-byte (96-bit) IV for each encryption.
 * - SecureRandom for cryptographic randomness.
 * - Uses Bouncy Castle provider for strong cryptographic support.
 *
 * <p>Typical usage:</p>
 * <pre>
 * SymmetricHelper helper = new SymmetricHelper();
 *
 * // 1. Generate AES-256 key
 * SecretKey key = helper.generateKey();
 * String keyBase64 = helper.keyToBase64(key);
 *
 * // 2. Encrypt a message
 * String plaintext = "Hello, this is a secret!";
 * String encrypted = helper.encrypt(plaintext, key);
 *
 * // 3. Decrypt the message
 * String decrypted = helper.decrypt(encrypted, key);
 *
 * System.out.println("Original : " + plaintext);
 * System.out.println("Encrypted: " + encrypted);
 * System.out.println("Decrypted: " + decrypted);
 * </pre>
 */
public class SymmetricHelper {

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
     * Generate a random AES-256 key using Bouncy Castle.
     *
     * @return SecretKey - A newly generated AES-256 key.
     * @throws NoSuchAlgorithmException if AES is not supported.
     * @throws NoSuchProviderException if Bouncy Castle provider is not available.
     */
    public SecretKey generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, "BC");
        keyGenerator.init(KEY_LENGTH);
        return keyGenerator.generateKey();
    }

    /**
     * Convert raw byte array into a SecretKey.
     *
     * @param keyBytes 32-byte array representing an AES-256 key.
     * @return SecretKey instance.
     */
    public SecretKey bytesToKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * Generate a random 12-byte IV (96 bits).
     *
     * @return byte[] IV of length 12.
     */
    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Encrypt raw byte data using AES-GCM-256.
     *
     * @param plaintext Data to be encrypted.
     * @param key AES SecretKey.
     * @return byte[] containing IV + ciphertext.
     * @throws Exception if encryption fails.
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext
        byte[] encryptedData = new byte[IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, IV_LENGTH);
        System.arraycopy(ciphertext, 0, encryptedData, IV_LENGTH, ciphertext.length);
        return encryptedData;
    }

    /**
     * Encrypt text and return Base64 encoded ciphertext.
     *
     * @param plaintext The string to encrypt.
     * @param key AES SecretKey.
     * @return Base64 encoded encrypted string.
     * @throws Exception if encryption fails.
     */
    public String encrypt(String plaintext, SecretKey key) throws Exception {
        byte[] encrypted = encrypt(plaintext.getBytes("UTF-8"), key);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypt raw byte data previously encrypted with AES-GCM-256.
     *
     * @param encryptedData Data containing IV + ciphertext.
     * @param key AES SecretKey.
     * @return Decrypted raw bytes.
     * @throws Exception if decryption fails.
     */
    public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        if (encryptedData.length < IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data format.");
        }

        byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, IV_LENGTH, encryptedData.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Decrypt Base64 encoded encrypted text.
     *
     * @param encryptedText Base64 string containing IV + ciphertext.
     * @param key AES SecretKey.
     * @return The decrypted plaintext string.
     * @throws Exception if decryption fails.
     */
    public String decrypt(String encryptedText, SecretKey key) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedText);
        byte[] decrypted = decrypt(encryptedData, key);
        return new String(decrypted, "UTF-8");
    }

    /**
     * Convert SecretKey to Base64 string.
     *
     * @param key AES SecretKey.
     * @return Base64 encoded key.
     */
    public String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Convert Base64 encoded string back to SecretKey.
     *
     * @param base64Key Base64 encoded AES key.
     * @return SecretKey instance.
     */
    public SecretKey base64ToKey(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return bytesToKey(keyBytes);
    }
}
