package vn.trungnguyen.helper;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * SymmetricHelper - Utility for AES-256-GCM encryption/decryption.
 *
 * <p>The encrypted output is a JSON string containing:</p>
 * <pre>
 * {
 *   "alg": "AES-GCM-256",
 *   "iv":  "Base64IV",
 *   "ct":  "Base64Ciphertext",
 *   "tag": "Base64Tag"
 * }
 * </pre>
 *
 * <p>Public API only uses Base64 string for keys, never exposes javax.crypto.SecretKey.</p>
 */
public class SymmetricHelper {

    public static class EncryptResult {
        private final String alg;
        private final String iv;
        private final String ct;
        private final String tag;
        public EncryptResult(String alg, String iv, String ct, String tag) {
            this.alg = alg;
            this.iv = iv;
            this.ct = ct;
            this.tag = tag;
        }

        public EncryptResult(JSONObject obj) throws JSONException {
            this.alg = obj.getString("alg");
            this.iv = obj.getString("iv");
            this.ct = obj.getString("ct");
            this.tag = obj.getString("tag");
        }

        public EncryptResult(String json) throws JSONException {
            this(new JSONObject(json));
        }

        public String getAlg() { return alg; }
        public String getIv() { return iv; }
        public String getCt() { return ct; }
        public String getTag() { return tag; }

        public JSONObject toJson() throws JSONException {
            JSONObject obj = new JSONObject();
            obj.put("alg", alg);
            obj.put("iv", iv);
            obj.put("ct", ct);
            obj.put("tag", tag);
            return obj;
        }
    }

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_LENGTH = 256;       // AES-256
    private static final int IV_LENGTH = 12;         // 96-bit IV
    private static final int GCM_TAG_LENGTH = 16;    // 128-bit tag

    private final SecureRandom secureRandom = new SecureRandom();

    /** Generate a random AES-256 key, returned as Base64 string */
    public String generateKeyBase64() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_LENGTH);
        byte[] keyBytes = keyGen.generateKey().getEncoded();
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    /** Encrypt plaintext string -> EncryptResult */
    public EncryptResult encrypt(String plaintext, String base64Key) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, toSecretKey(base64Key), gcmSpec);

        byte[] ciphertextWithTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Split ciphertext and tag
        int ctLength = ciphertextWithTag.length - GCM_TAG_LENGTH;
        byte[] ciphertext = Arrays.copyOfRange(ciphertextWithTag, 0, ctLength);
        byte[] tag = Arrays.copyOfRange(ciphertextWithTag, ctLength, ciphertextWithTag.length);

        return new EncryptResult(
                "AES-GCM-256",
                Base64.getEncoder().encodeToString(iv),
                Base64.getEncoder().encodeToString(ciphertext),
                Base64.getEncoder().encodeToString(tag)
        );
    }

    /** Decrypt EncryptResult -> plaintext string */
    public String decrypt(EncryptResult result, String base64Key) throws Exception {
        if (!"AES-GCM-256".equals(result.getAlg())) {
            throw new IllegalArgumentException("Unsupported algorithm: " + result.getAlg());
        }

        byte[] iv = Base64.getDecoder().decode(result.getIv());
        byte[] ciphertext = Base64.getDecoder().decode(result.getCt());
        byte[] tag = Base64.getDecoder().decode(result.getTag());

        // Merge ciphertext + tag
        byte[] ciphertextWithTag = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
        System.arraycopy(tag, 0, ciphertextWithTag, ciphertext.length, tag.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, toSecretKey(base64Key), gcmSpec);

        byte[] plaintext = cipher.doFinal(ciphertextWithTag);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /** Helper: convert Base64 key string -> SecretKeySpec */
    private SecretKeySpec toSecretKey(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (keyBytes.length != KEY_LENGTH / 8) {
            throw new IllegalArgumentException("AES-256 key must be 32 bytes.");
        }
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
}
