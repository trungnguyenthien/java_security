package vn.trungnguyen;

import vn.trungnguyen.helper.AsymmetricHelper;
import vn.trungnguyen.helper.SymmetricHelper;

import javax.crypto.SecretKey;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 SAMPLE SymmetricHelper");
        try {
            SymmetricHelper helper = new SymmetricHelper();

            // 1. Tạo khóa
            SecretKey key = helper.generateKey();
            System.out.println("Khóa (Base64): " + helper.keyToBase64(key));

            // 2. Mã hóa
            String plaintext = "Xin chào, đây là tin nhắn bí mật!";
            String encrypted = helper.encrypt(plaintext, key);
            System.out.println("Bản rõ: " + plaintext);
            System.out.println("Đã mã hóa: " + encrypted);

            // 3. Giải mã
            String decrypted = helper.decrypt(encrypted, key);
            System.out.println("Sau giải mã: " + decrypted);

            // Kiểm tra
            System.out.println("Khớp với bản gốc: " + plaintext.equals(decrypted));

        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("🚀 SAMPLE AsymmetricHelper");
        try {
            // Khởi tạo AsymmetricHelper
            AsymmetricHelper helper = new AsymmetricHelper();
            AsymmetricHelper.Encryption encryption = new AsymmetricHelper.Encryption();
            AsymmetricHelper.Signature signature = new AsymmetricHelper.Signature();

            // 1. Tạo cặp khóa cho mã hóa (ECDH)
            AsymmetricHelper.KeyPair encryptionKeyPair = encryption.generateKeyPair();

            // 2. Tạo cặp khóa cho chữ ký (Ed25519)
            AsymmetricHelper.KeyPair signatureKeyPair = signature.generateKeyPair();

            // 3. Dữ liệu mẫu
            String originalData = "Xin chào, đây là dữ liệu bí mật cần mã hóa và ký!";
            System.out.println("Dữ liệu gốc: " + originalData);

            // 4. Mã hóa dữ liệu
            AsymmetricHelper.EncryptedResult encryptedResult = encryption.encrypt(originalData, encryptionKeyPair.getPublicBase64());
            String encryptedData = encryptedResult.getEncryptedData();
            String ephemeralPublicKey = encryptedResult.getEphemeralPublicKey();
            System.out.println("Dữ liệu mã hóa (Base64): " + encryptedData);
            System.out.println("Khóa công khai tạm thời (Base64): " + ephemeralPublicKey);

            // 5. Giải mã dữ liệu
            String decryptedData = encryption.decrypt(encryptedData, encryptionKeyPair.getPrivateBase64(), ephemeralPublicKey);
            System.out.println("Dữ liệu giải mã: " + decryptedData);
            System.out.println("Khớp với bản gốc: " + originalData.equals(decryptedData));

            // 6. Ký dữ liệu
            String signedData = signature.sign(originalData, signatureKeyPair.getPrivateBase64());
            System.out.println("Chữ ký (Base64): " + signedData);

            // 7. Xác minh chữ ký
            boolean isVerified = signature.verify(originalData, signedData, signatureKeyPair.getPublicBase64());
            System.out.println("Chữ ký hợp lệ: " + isVerified);

            // 8. Kiểm tra xác minh với dữ liệu sai
            String wrongData = "Dữ liệu sai lệch!";
            boolean isVerifiedWrong = signature.verify(wrongData, signedData, signatureKeyPair.getPublicBase64());
            System.out.println("Xác minh với dữ liệu sai: " + isVerifiedWrong);

        } catch (Exception e) {
            System.err.println("Lỗi xảy ra: " + e.getMessage());
            e.printStackTrace();
        }
    }
}