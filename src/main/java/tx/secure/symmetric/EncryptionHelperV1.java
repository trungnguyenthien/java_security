package tx.secure.symmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import tx.secure.type.Result;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Base64;
/**
 * SymmetricEncryptionHelperImpl - Implementation of SymmetricEncryptionHelper using AES-GCM-256 with Bouncy Castle
 * Random 12-byte (96-bit) IV
 */
public class EncryptionHelperV1 implements EncryptionHelper {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String PROVIDER = "BC"; // Bouncy Castle
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

    public EncryptionHelperV1() {
        // Add BouncyCastle provider if not already added
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Generate a random AES-256 key, returned as Base64 string */
    @Override
    public String generateKeyBase64() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /** Encrypt plaintext string -> EncryptResult */
    @Override
    public Result encrypt(String plaintext, String keyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Split encrypted data and tag
        byte[] cipherText = new byte[encryptedBytes.length - GCM_TAG_LENGTH];
        byte[] tag = new byte[GCM_TAG_LENGTH];
        System.arraycopy(encryptedBytes, 0, cipherText, 0, cipherText.length);
        System.arraycopy(encryptedBytes, cipherText.length, tag, 0, tag.length);

        return new Result(
            "AES-GCM",
            Base64.getEncoder().encodeToString(iv),
            Base64.getEncoder().encodeToString(cipherText),
            Base64.getEncoder().encodeToString(tag),
                null
        );
    }

    /** Decrypt EncryptResult -> plaintext string */
    @Override
    public String decrypt(Result result, String keyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

        byte[] iv = Base64.getDecoder().decode(result.getIv());
        byte[] cipherText = Base64.getDecoder().decode(result.getCt());
        byte[] tag = Base64.getDecoder().decode(result.getTag());

        // Combine ciphertext and tag
        byte[] encryptedWithTag = new byte[cipherText.length + tag.length];
        System.arraycopy(cipherText, 0, encryptedWithTag, 0, cipherText.length);
        System.arraycopy(tag, 0, encryptedWithTag, cipherText.length, tag.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        byte[] decryptedBytes = cipher.doFinal(encryptedWithTag);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}
