package vn.trungnguyen.helper;

import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AsymmetricHelper {

    public static class KeyPair {
        private final java.security.KeyPair originKeyPair;
        private final String publicKeyBase64;
        private final String privateKeyBase64;

        public KeyPair(java.security.KeyPair originKeyPair) {
            this.originKeyPair = originKeyPair;
            publicKeyBase64 = Base64.getEncoder().encodeToString(originKeyPair.getPublic().getEncoded());
            privateKeyBase64 = Base64.getEncoder().encodeToString(originKeyPair.getPrivate().getEncoded());
        }

        public PrivateKey getPrivate() {
            return originKeyPair.getPrivate();
        }

        public PublicKey getPublic() {
            return originKeyPair.getPublic();
        }

        public String getPublicBase64() {
            return publicKeyBase64;
        }

        public String getPrivateBase64() {
            return privateKeyBase64;
        }
    }

    public AsymmetricHelper() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // Lớp để lưu trữ dữ liệu mã hóa và khóa công khai tạm thời
    public static class EncryptedResult {
        private final String encryptedData;
        private final String ephemeralPublicKey;

        public EncryptedResult(String encryptedData, String ephemeralPublicKey) {
            this.encryptedData = encryptedData;
            this.ephemeralPublicKey = ephemeralPublicKey;
        }

        public String getEncryptedData() {
            return encryptedData;
        }

        public String getEphemeralPublicKey() {
            return ephemeralPublicKey;
        }
    }
    private static final String PROVIDER = "BC"; // Bouncy Castle
    public static class Encryption {
        private final String KEY_AGREEMENT_ALGORITHM = "ECDH";
        private final String CURVE = "secp256r1";
        private final String SYMMETRIC_ALGORITHM = "AES";
        private final int AES_KEY_SIZE = 256;
        private final String KEY_SPEC_ALGORITHM = "EC"; // Elliptic Curve

        // Tạo cặp khóa ECDH
        public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_AGREEMENT_ALGORITHM, PROVIDER);
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE);
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            return new KeyPair(keyPairGenerator.generateKeyPair());
        }

        // Mã hóa dữ liệu dạng byte, trả về EncryptedData chứa dữ liệu mã hóa và khóa công khai tạm thời
        public EncryptedResult encrypt(byte[] data, String publicKey) throws Exception {
            PublicKey pubKey = decodePublicKey(publicKey);
            // Tạo cặp khóa tạm thời
            KeyPair ephemeralKeyPair = generateKeyPair();
            SecretKey secretKey = generateSharedSecret(ephemeralKeyPair.getPrivate(), pubKey);
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(data);
            String encryptedData = Base64.getEncoder().encodeToString(encrypted);
            String ephemeralPublicKey = Base64.getEncoder().encodeToString(ephemeralKeyPair.getPublic().getEncoded());
            return new EncryptedResult(encryptedData, ephemeralPublicKey);
        }

        // Mã hóa chuỗi văn bản
        public EncryptedResult encrypt(String data, String publicKey) throws Exception {
            return encrypt(data.getBytes(), publicKey);
        }

        // Giải mã dữ liệu dạng byte, sử dụng khóa công khai tạm thời
        public String decrypt(byte[] encryptedData, String privateKey, String ephemeralPublicKey) throws Exception {
            PrivateKey privKey = decodePrivateKey(privateKey);
            PublicKey ephPubKey = decodePublicKey(ephemeralPublicKey);
            SecretKey secretKey = generateSharedSecret(privKey, ephPubKey);
            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decrypted = cipher.doFinal(encryptedData);
            return new String(decrypted);
        }

        // Giải mã chuỗi Base64
        public String decrypt(String encryptedData, String privateKey, String ephemeralPublicKey) throws Exception {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
            return decrypt(encryptedBytes, privateKey, ephemeralPublicKey);
        }

        private PublicKey decodePublicKey(String publicKey) throws Exception {
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_SPEC_ALGORITHM, PROVIDER);
            return keyFactory.generatePublic(spec);
        }

        private PrivateKey decodePrivateKey(String privateKey) throws Exception {
            byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_SPEC_ALGORITHM, PROVIDER);
            return keyFactory.generatePrivate(spec);
        }

        private SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, PROVIDER);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();
            return new SecretKeySpec(sharedSecret, 0, AES_KEY_SIZE / 8, SYMMETRIC_ALGORITHM);
        }
    }

    public static class Signature {
        private final String ALGORITHM = "Ed25519";

        public KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
            return new KeyPair(keyPairGenerator.generateKeyPair());
        }

        public String sign(String data, String privateKey) throws Exception {
            return sign(data.getBytes(), privateKey);
        }

        public String sign(byte[] data, String privateKey) throws Exception {
            PrivateKey privKey = decodePrivateKey(privateKey);
            java.security.Signature signature = java.security.Signature.getInstance(ALGORITHM, PROVIDER);
            signature.initSign(privKey);
            signature.update(data);
            byte[] signed = signature.sign();
            return Base64.getEncoder().encodeToString(signed);
        }

        public boolean verify(String data, String signature, String publicKey) throws Exception {
            return verify(data.getBytes(), signature, publicKey);
        }

        public boolean verify(byte[] data, String signature, String publicKey) throws Exception {
            PublicKey pubKey = decodePublicKey(publicKey);
            java.security.Signature sig = java.security.Signature.getInstance(ALGORITHM, "BC");
            sig.initVerify(pubKey);
            sig.update(data);
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return sig.verify(signatureBytes);
        }

        private PublicKey decodePublicKey(String publicKey) throws Exception {
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, "BC");
            return keyFactory.generatePublic(spec);
        }

        private PrivateKey decodePrivateKey(String privateKey) throws Exception {
            byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, "BC");
            return keyFactory.generatePrivate(spec);
        }
    }
}