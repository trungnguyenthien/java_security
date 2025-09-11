package vn.trungnguyen;

//import tx.secure.asymmetric.AsymmetricEncryptionResult;
import tx.secure.type.KeyPair;
import tx.secure.type.Result;
import tx.secure.symmetric.EncryptionHelper;
import tx.secure.symmetric.EncryptionHelperV1;
import tx.secure.RandomHelper;
import tx.secure.RandomHelperImpl;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 SAMPLE SymmetricHelper");
        try {
            EncryptionHelper helper = new EncryptionHelperV1();

            // 1. Generate a valid AES-256 key
            String keyBase64 = helper.generateKeyBase64();
            System.out.println("Key (Base64): " + keyBase64);

            // 2. Original plaintext
            String plaintext = "Xin chào, đây là thông điệp bí mật!";
            System.out.println("Plaintext: " + plaintext);

            // 3. Encrypt
            Result encrypted = helper.encrypt(plaintext, keyBase64);
            System.out.println("Encrypted JSON: " + encrypted.toJson());

            // 4. Decrypt successfully
            String decrypted = helper.decrypt(encrypted, keyBase64);
            System.out.println("Decrypted (success): " + decrypted);
            System.out.println("Match: " + plaintext.equals(decrypted));

            // 5. Generate wrong key
            String wrongKeyBase64 = helper.generateKeyBase64();
            System.out.println("\nWrong Key (Base64): " + wrongKeyBase64);

            // 6. Decrypt failure
            try {
                String decryptedWrong = helper.decrypt(encrypted, wrongKeyBase64);
                System.out.println("Decrypted with wrong key: " + decryptedWrong);
            } catch (Exception ex) {
                System.out.println("❌ Failed to decrypt with wrong key: " + ex.getMessage());
            }

        } catch (Exception e) {
            System.err.println("Error in SymmetricHelper demo: " + e.getMessage());
        }

        System.out.println("\n🚀 SAMPLE AsymmetricHelper with Hybrid Encryption (ECDH secp256r1)");
        try {
            // Create SymmetricEncryptionHelper instance (required dependency)
            EncryptionHelper symmetricHelper = new EncryptionHelperV1();

            // Create AsymmetricEncryptionHelper with SymmetricEncryptionHelper dependency
            tx.secure.asymmetric.EncryptionHelper encryption = new tx.secure.asymmetric.EncryptionHelperV1(symmetricHelper);

            // 1. Generate secp256r1 ECDH key pair for encryption
            KeyPair encryptionKeyPair = encryption.generateKeyPair();
            System.out.println("secp256r1 ECDH key pair generated successfully!");

            // 2. Test data
            String originalData = "Xin chào, đây là dữ liệu bí mật cần mã hóa bằng ECDH hybrid encryption!";
            System.out.println("Dữ liệu gốc: " + originalData);

            // 3. Encrypt data using ECDH hybrid encryption
            Result encryptedResult = encryption.encrypt(originalData, encryptionKeyPair.getPublicBase64());
            System.out.println("Dữ liệu đã được mã hóa thành công!");
            System.out.println("encryptedResult = " + encryptedResult.toJsonString());
            System.out.println("Ephemeral public key: " + encryptedResult.getEpub());
            System.out.println("Symmetric algorithm: " + encryptedResult.getAlg());

            // 4. Decrypt data using ECDH hybrid decryption
            String decryptedData = encryption.decrypt(encryptedResult.toJson().toString(), encryptedResult.getEpub(), encryptionKeyPair.getPrivateBase64());
            System.out.println("Dữ liệu giải mã: " + decryptedData);
            System.out.println("Khớp với bản gốc: " + originalData.equals(decryptedData));

        } catch (Exception e) {
            System.err.println("Lỗi trong AsymmetricHelper demo: " + e.getMessage());
        }

        System.out.println("\n🚀 SAMPLE RandomHelper");
        try {
            RandomHelper randomHelper = new RandomHelperImpl();
            // 1. Random bytes
            byte[] randomBytes = randomHelper.nextBytes(16);
            System.out.println("Random bytes (16): " + Arrays.toString(randomBytes));

            // 2. Random int trong khoảng [0, bound)
            int randomInt = randomHelper.nextInt(100);
            System.out.println("Random int [0,100): " + randomInt);

            // 3. Random int trong khoảng [origin, bound)
            int randomIntRange = randomHelper.nextInt(50, 60);
            System.out.println("Random int [50,60): " + randomIntRange);

            // 4. Random long trong khoảng [0, bound)
            long randomLong = randomHelper.nextLong(1000L);
            System.out.println("Random long [0,1000): " + randomLong);

            // 5. Random long trong khoảng [origin, bound)
            long randomLongRange = randomHelper.nextLong(500L, 600L);
            System.out.println("Random long [500,600): " + randomLongRange);

            // 6. Random double [0.0,1.0)
            double randomDouble = randomHelper.nextDouble();
            System.out.println("Random double [0,1): " + randomDouble);

            // 7. Random double trong khoảng [origin, bound)
            double randomDoubleRange = randomHelper.nextDouble(5.5, 9.9);
            System.out.println("Random double [5.5,9.9): " + randomDoubleRange);

        } catch (Exception e) {
            System.err.println("Error in RandomHelper demo: " + e.getMessage());
        }

        System.out.println("\n🚀 SUMMARY: Hybrid Encryption Architecture");
        System.out.println("✅ AsymmetricEncryptionHelper now uses dependency injection");
        System.out.println("   - Requires SymmetricEncryptionHelper for actual encryption/decryption");
        System.out.println("   - Focuses only on RSA key generation and key management");
        System.out.println("   - Implements secure hybrid encryption pattern");
        System.out.println("✅ SymmetricEncryptionHelper handles AES-GCM encryption");
        System.out.println("   - Fast and secure for large data");
        System.out.println("   - Used internally by AsymmetricEncryptionHelper");
        System.out.println("✅ RSA is used only for encrypting symmetric keys");
        System.out.println("   - Efficient and secure hybrid approach");
    }
}
