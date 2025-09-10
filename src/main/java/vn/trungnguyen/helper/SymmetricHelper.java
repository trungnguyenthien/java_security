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
 * SymmetricHelper - Lớp hỗ trợ mã hóa/giải mã đối xứng sử dụng AES-GCM-256 với Bouncy Castle
 * IV ngẫu nhiên 12 byte (96 bit)
 */
public class SymmetricHelper {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_LENGTH = 256; // 256 bit
    private static final int IV_LENGTH = 12;   // 96 bit
    private static final int GCM_TAG_LENGTH = 16; // 128 bit

    private final SecureRandom secureRandom;

    public SymmetricHelper() {
        this.secureRandom = new SecureRandom();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Tạo khóa AES-256 ngẫu nhiên sử dụng Bouncy Castle
     * @return SecretKey - khóa AES-256
     * @throws NoSuchAlgorithmException nếu thuật toán không được hỗ trợ
     * @throws NoSuchProviderException nếu nhà cung cấp Bouncy Castle không được tìm thấy
     */
    public SecretKey generateKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, "BC");
        keyGenerator.init(KEY_LENGTH);
        return keyGenerator.generateKey();
    }

    /**
     * Chuyển đổi byte array thành SecretKey
     * @param keyBytes mảng byte của khóa (32 byte cho AES-256)
     * @return SecretKey
     */
    public SecretKey bytesToKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * Tạo IV ngẫu nhiên 12 byte
     * @return mảng byte IV 12 byte
     */
    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /**
     * Mã hóa dữ liệu sử dụng AES-GCM-256 với Bouncy Castle
     * @param plaintext dữ liệu cần mã hóa
     * @param key khóa bí mật
     * @return mảng byte chứa IV + dữ liệu đã mã hóa
     * @throws Exception nếu có lỗi trong quá trình mã hóa
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] encryptedData = new byte[IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, IV_LENGTH);
        System.arraycopy(ciphertext, 0, encryptedData, IV_LENGTH, ciphertext.length);
        return encryptedData;
    }

    /**
     * Mã hóa chuỗi văn bản
     * @param plaintext chuỗi văn bản cần mã hóa
     * @param key khóa bí mật
     * @return chuỗi Base64 của dữ liệu đã mã hóa
     * @throws Exception nếu có lỗi trong quá trình mã hóa
     */
    public String encrypt(String plaintext, SecretKey key) throws Exception {
        byte[] encrypted = encrypt(plaintext.getBytes("UTF-8"), key);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Giải mã dữ liệu đã được mã hóa bằng AES-GCM-256 với Bouncy Castle
     * @param encryptedData dữ liệu đã mã hóa (IV + ciphertext)
     * @param key khóa bí mật
     * @return dữ liệu gốc sau khi giải mã
     * @throws Exception nếu có lỗi trong quá trình giải mã
     */
    public byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        if (encryptedData.length < IV_LENGTH) {
            throw new IllegalArgumentException("Dữ liệu mã hóa không hợp lệ");
        }
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, IV_LENGTH, encryptedData.length);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Giải mã chuỗi Base64
     * @param encryptedText chuỗi Base64 của dữ liệu đã mã hóa
     * @param key khóa bí mật
     * @return chuỗi văn bản gốc
     * @throws Exception nếu có lỗi trong quá trình giải mã
     */
    public String decrypt(String encryptedText, SecretKey key) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedText);
        byte[] decrypted = decrypt(encryptedData, key);
        return new String(decrypted, "UTF-8");
    }

    /**
     * Chuyển đổi khóa thành chuỗi Base64
     * @param key khóa bí mật
     * @return chuỗi Base64 của khóa
     */
    public String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Chuyển đổi chuỗi Base64 thành khóa
     * @param base64Key chuỗi Base64 của khóa
     * @return SecretKey
     */
    public SecretKey base64ToKey(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return bytesToKey(keyBytes);
    }

    // /**
    //  * Ví dụ sử dụng
    //  */
    // public static void main(String[] args) {
    //     try {
    //         SymmetricHelper helper = new SymmetricHelper();

    //         // 1. Tạo khóa
    //         SecretKey key = helper.generateKey();
    //         System.out.println("Khóa (Base64): " + helper.keyToBase64(key));

    //         // 2. Mã hóa
    //         String plaintext = "Xin chào, đây là tin nhắn bí mật!";
    //         String encrypted = helper.encrypt(plaintext, key);
    //         System.out.println("Bản rõ: " + plaintext);
    //         System.out.println("Đã mã hóa: " + encrypted);

    //         // 3. Giải mã
    //         String decrypted = helper.decrypt(encrypted, key);
    //         System.out.println("Sau giải mã: " + decrypted);

    //         // Kiểm tra
    //         System.out.println("Khớp với bản gốc: " + plaintext.equals(decrypted));

    //     } catch (Exception e) {
    //         e.printStackTrace();
    //     }
    // }
}