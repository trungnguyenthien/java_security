package vn.trungnguyen.helper;

import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * AsymmetricHelper provides utilities for performing asymmetric cryptographic
 * operations such as key generation, encryption/decryption (ECDH + AES),
 * and signing/verifying (Ed25519).
 *
 * <p>This helper is built on top of Bouncy Castle for strong cryptographic support.
 *
 * <h2>Sample usage:</h2>
 * <pre>{@code
 * // ===== Encryption / Decryption with ECDH + AES =====
 * AsymmetricHelper.Encryption enc = new AsymmetricHelper.Encryption();
 *
 * // Generate recipient key pair
 * AsymmetricHelper.KeyPair recipientKeyPair = enc.generateKeyPair();
 *
 * // Encrypt message using recipient's public key
 * String message = "Hello Secure World!";
 * AsymmetricHelper.EncryptedResult encrypted =
 *     enc.encrypt(message, recipientKeyPair.getPublicBase64());
 *
 * // Decrypt message using recipient's private key
 * String decrypted =
 *     enc.decrypt(encrypted.getEncryptedData(),
 *                 recipientKeyPair.getPrivateBase64(),
 *                 encrypted.getEphemeralPublicKey());
 *
 * System.out.println("Decrypted: " + decrypted);
 *
 *
 * // ===== Digital Signature with Ed25519 =====
 * AsymmetricHelper.Signature sig = new AsymmetricHelper.Signature();
 *
 * // Generate signing key pair
 * AsymmetricHelper.KeyPair signerKeyPair = sig.generateKeyPair();
 *
 * // Sign a message
 * String signature = sig.sign("Important data", signerKeyPair.getPrivateBase64());
 *
 * // Verify signature
 * boolean isValid = sig.verify("Important data", signature, signerKeyPair.getPublicBase64());
 *
 * System.out.println("Signature valid: " + isValid);
 * }</pre>
 */
public class AsymmetricHelper {

    /**
     * Wrapper class for holding a key pair along with its Base64 representations.
     */
    public static class KeyPair {
        private final java.security.KeyPair originKeyPair;
        private final String publicKeyBase64;
        private final String privateKeyBase64;

        public KeyPair(java.security.KeyPair originKeyPair) {
            this.originKeyPair = originKeyPair;
            this.publicKeyBase64 = Base64.getEncoder().encodeToString(originKeyPair.getPublic().getEncoded());
            this.privateKeyBase64 = Base64.getEncoder().encodeToString(originKeyPair.getPrivate().getEncoded());
        }

        /** @return the original private key object */
        public PrivateKey getPrivate() {
            return originKeyPair.getPrivate();
        }

        /** @return the original public key object */
        public PublicKey getPublic() {
            return originKeyPair.getPublic();
        }

        /** @return Base64-encoded public key */
        public String getPublicBase64() {
            return publicKeyBase64;
        }

        /** @return Base64-encoded private key */
        public String getPrivateBase64() {
            return privateKeyBase64;
        }
    }

    public AsymmetricHelper() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Holds encrypted data (Base64-encoded) along with the ephemeral public key (Base64-encoded)
     * generated during encryption.
     */
    public static class EncryptedResult {
        private final String encryptedData;
        private final String ephemeralPublicKey;

        public EncryptedResult(String encryptedData, String ephemeralPublicKey) {
            this.encryptedData = encryptedData;
            this.ephemeralPublicKey = ephemeralPublicKey;
        }

        /** @return Base64-encoded encrypted data */
        public String getEncryptedData() {
            return encryptedData;
        }

        /** @return Base64-encoded ephemeral public key used in encryption */
        public String getEphemeralPublicKey() {
            return ephemeralPublicKey;
        }
    }

    private static final String PROVIDER = "BC"; // Bouncy Castle

    /**
     * Provides encryption and decryption utilities using ECDH for key agreement
     * and AES for symmetric encryption.
     */
    public static class Encryption {
        private final String KEY_AGREEMENT_ALGORITHM = "ECDH";
        private final String CURVE = "secp256r1";
        private final String SYMMETRIC_ALGORITHM = "AES";
        private final int AES_KEY_SIZE = 256;
        private final String KEY_SPEC_ALGORITHM = "EC"; // Elliptic Curve

        /**
         * Generates an EC key pair using ECDH over secp256r1 curve.
         *
         * @return a new KeyPair containing both key objects and Base64 strings
         */
        public KeyPair generateKeyPair() throws Exception {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_SPEC_ALGORITHM, PROVIDER);
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(CURVE);
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            return new KeyPair(keyPairGenerator.generateKeyPair());
        }

        /**
         * Encrypts a byte array using recipient's public key and a newly generated ephemeral key pair.
         *
         * @param data the plaintext byte array
         * @param publicKey Base64-encoded recipient public key
         * @return EncryptedResult containing encrypted data and ephemeral public key
         */
        public EncryptedResult encrypt(byte[] data, String publicKey) throws Exception {
            PublicKey pubKey = decodePublicKey(publicKey);
            KeyPair ephemeralKeyPair = generateKeyPair();
            SecretKey secretKey = generateSharedSecret(ephemeralKeyPair.getPrivate(), pubKey);

            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encrypted = cipher.doFinal(data);
            String encryptedData = Base64.getEncoder().encodeToString(encrypted);
            String ephemeralPublicKey = Base64.getEncoder().encodeToString(ephemeralKeyPair.getPublic().getEncoded());

            return new EncryptedResult(encryptedData, ephemeralPublicKey);
        }

        /**
         * Encrypts a string using recipient's public key.
         *
         * @param data plaintext string
         * @param publicKey Base64-encoded recipient public key
         * @return EncryptedResult containing encrypted data and ephemeral public key
         */
        public EncryptedResult encrypt(String data, String publicKey) throws Exception {
            return encrypt(data.getBytes(), publicKey);
        }

        /**
         * Decrypts a byte array using recipient's private key and the provided ephemeral public key.
         *
         * @param encryptedData ciphertext byte array
         * @param privateKey Base64-encoded recipient private key
         * @param ephemeralPublicKey Base64-encoded ephemeral public key
         * @return decrypted plaintext string
         */
        public String decrypt(byte[] encryptedData, String privateKey, String ephemeralPublicKey) throws Exception {
            PrivateKey privKey = decodePrivateKey(privateKey);
            PublicKey ephPubKey = decodePublicKey(ephemeralPublicKey);
            SecretKey secretKey = generateSharedSecret(privKey, ephPubKey);

            Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decrypted = cipher.doFinal(encryptedData);
            return new String(decrypted);
        }

        /**
         * Decrypts a Base64-encoded string using recipient's private key and the provided ephemeral public key.
         *
         * @param encryptedData Base64-encoded ciphertext
         * @param privateKey Base64-encoded recipient private key
         * @param ephemeralPublicKey Base64-encoded ephemeral public key
         * @return decrypted plaintext string
         */
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

    /**
     * Provides digital signature utilities using Ed25519 algorithm.
     */
    public static class Signature {
        private final String ALGORITHM = "Ed25519";

        /**
         * Generates an Ed25519 key pair for signing and verifying.
         *
         * @return KeyPair containing both key objects and Base64 strings
         */
        public KeyPair generateKeyPair() throws Exception {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
            return new KeyPair(keyPairGenerator.generateKeyPair());
        }

        /**
         * Signs a string using the provided private key.
         *
         * @param data plaintext string
         * @param privateKey Base64-encoded private key
         * @return Base64-encoded signature
         */
        public String sign(String data, String privateKey) throws Exception {
            return sign(data.getBytes(), privateKey);
        }

        /**
         * Signs a byte array using the provided private key.
         *
         * @param data plaintext byte array
         * @param privateKey Base64-encoded private key
         * @return Base64-encoded signature
         */
        public String sign(byte[] data, String privateKey) throws Exception {
            PrivateKey privKey = decodePrivateKey(privateKey);
            java.security.Signature signature = java.security.Signature.getInstance(ALGORITHM, PROVIDER);
            signature.initSign(privKey);
            signature.update(data);
            byte[] signed = signature.sign();
            return Base64.getEncoder().encodeToString(signed);
        }

        /**
         * Verifies a string against a Base64-encoded signature using the provided public key.
         *
         * @param data plaintext string
         * @param signature Base64-encoded signature
         * @param publicKey Base64-encoded public key
         * @return true if valid, false otherwise
         */
        public boolean verify(String data, String signature, String publicKey) throws Exception {
            return verify(data.getBytes(), signature, publicKey);
        }

        /**
         * Verifies a byte array against a Base64-encoded signature using the provided public key.
         *
         * @param data plaintext byte array
         * @param signature Base64-encoded signature
         * @param publicKey Base64-encoded public key
         * @return true if valid, false otherwise
         */
        public boolean verify(byte[] data, String signature, String publicKey) throws Exception {
            PublicKey pubKey = decodePublicKey(publicKey);
            java.security.Signature sig = java.security.Signature.getInstance(ALGORITHM, PROVIDER);
            sig.initVerify(pubKey);
            sig.update(data);
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return sig.verify(signatureBytes);
        }

        private PublicKey decodePublicKey(String publicKey) throws Exception {
            byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
            return keyFactory.generatePublic(spec);
        }

        private PrivateKey decodePrivateKey(String privateKey) throws Exception {
            byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER);
            return keyFactory.generatePrivate(spec);
        }
    }
}
