## Usage 

```java
public class Main {
    public static void main(String[] args) {
        System.out.println("🚀 SAMPLE SymmetricHelper");
        try {
            SymmetricHelper helper = new SymmetricHelper();

            // 1. Generate a valid AES-256 key
            String keyBase64 = helper.generateKeyBase64();
            System.out.println("Key (Base64): " + keyBase64);

            // 2. Original plaintext
            String plaintext = "Xin chào, đây là thông điệp bí mật!";
            System.out.println("Plaintext: " + plaintext);

            // 3. Encrypt
            SymmetricHelper.EncryptResult encrypted = helper.encrypt(plaintext, keyBase64);
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
            e.printStackTrace();
        }

        System.out.println("\n🚀 SAMPLE AsymmetricHelper");
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

        System.out.println("\n🚀 SAMPLE RandomHelper");
        try {
            // 1. Random bytes
            byte[] randomBytes = RandomHelper.nextBytes(16);
            System.out.println("Random bytes (16): " + Arrays.toString(randomBytes));

            // 2. Random int trong khoảng [0, bound)
            int randomInt = RandomHelper.nextInt(100);
            System.out.println("Random int [0,100): " + randomInt);

            // 3. Random int trong khoảng [origin, bound)
            int randomIntRange = RandomHelper.nextInt(50, 60);
            System.out.println("Random int [50,60): " + randomIntRange);

            // 4. Random long trong khoảng [0, bound)
            long randomLong = RandomHelper.nextLong(1000L);
            System.out.println("Random long [0,1000): " + randomLong);

            // 5. Random long trong khoảng [origin, bound)
            long randomLongRange = RandomHelper.nextLong(500L, 600L);
            System.out.println("Random long [500,600): " + randomLongRange);

            // 6. Random double [0.0,1.0)
            double randomDouble = RandomHelper.nextDouble();
            System.out.println("Random double [0,1): " + randomDouble);

            // 7. Random double trong khoảng [origin, bound)
            double randomDoubleRange = RandomHelper.nextDouble(5.5, 9.9);
            System.out.println("Random double [5.5,9.9): " + randomDoubleRange);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

```

## Output

```txt
🚀 SAMPLE SymmetricHelper
Key (Base64): dNAQE+DrzLu5lCb7nVtYXB/aRDG5wXQ5ypJjZIrb/Uo=
Plaintext: Xin chào, đây là thông điệp bí mật!
Encrypted JSON: {"ct":"T8c6G1MUoR0omM82nIRKXSVzDKj8VnJMFXZZMT5Jxz3Wpf6lBQ76e6jlDf5K6Q==","tag":"vWOcOTnprRHgMFOB70mHsA==","alg":"AES-GCM-256","iv":"pxQjCCDf+D/zCdtA"}
Decrypted (success): Xin chào, đây là thông điệp bí mật!
Match: true

Wrong Key (Base64): epBQYOMMo1fCV6C150RPPkb5gzka15xcs0tRiPZIh6Q=
❌ Failed to decrypt with wrong key: Tag mismatch!

🚀 SAMPLE AsymmetricHelper
Dữ liệu gốc: Xin chào, đây là dữ liệu bí mật cần mã hóa và ký!
Dữ liệu mã hóa (Base64): ZJMYkBAbWf1+P9L1NjVcDxoGhelM4a9zSGTa986/iDlSY46LV+XfFQkKj4qOr+D/by7X+cUXsDXOLy/3GIRXZy7u7aE7Yzr2WYDzzcsPQxM=
Khóa công khai tạm thời (Base64): MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4UP3Onycug/6cBhbyIhOOQ8ToapezUCwtmV9H3z1ic+sukE2HtwxXrO92TFLTGefAdsOtJ44niL9Mr16W5PU/g==
Dữ liệu giải mã: Xin chào, đây là dữ liệu bí mật cần mã hóa và ký!
Khớp với bản gốc: true
Chữ ký (Base64): h9827R57tX037ZwzEcQ22ZlCfFf0GFFxDvFlnozlsCqNzNaBjhbCM/3N5eQgV9UX4iHRFcntpdAlImB84J3xCg==
Chữ ký hợp lệ: true
Xác minh với dữ liệu sai: false

🚀 SAMPLE RandomHelper
Random bytes (16): [-111, -74, 99, -76, 89, -102, -14, 66, 82, 30, -36, 45, -108, 55, -7, -122]
Random int [0,100): 52
Random int [50,60): 59
Random long [0,1000): 397
Random long [500,600): 590
Random double [0,1): 0.3791096832361319
Random double [5.5,9.9): 5.974333766969892
```