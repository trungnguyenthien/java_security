package tx.secure.asymmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import tx.secure.type.KeyPair;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Provides digital signature utilities using Ed25519 algorithm.
 */
public class SignatureHelperV1 implements SignatureHelper {
    private final String PROVIDER = "BC"; // Bouncy Castle
    public SignatureHelperV1() {
        Security.addProvider(new BouncyCastleProvider());
    }
    private final String ALGORITHM = "Ed25519";

    /**
     * Generates an Ed25519 key pair for signing and verifying.
     *
     * @return KeyPair containing both key objects and Base64 strings
     */
    @Override
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        java.security.KeyPair pair = keyPairGenerator.generateKeyPair();
        return new KeyPair(pair.getPublic(), pair.getPrivate());
    }

    /**
     * Signs a string using the provided private key.
     *
     * @param data       plaintext string
     * @param privateKey Base64-encoded private key
     * @return Base64-encoded signature
     */
    @Override
    public String sign(String data, String privateKey) throws Exception {
        return sign(data.getBytes(), privateKey);
    }

    /**
     * Signs a byte array using the provided private key.
     *
     * @param data       plaintext byte array
     * @param privateKey Base64-encoded private key
     * @return Base64-encoded signature
     */
    @Override
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
     * @param data      plaintext string
     * @param signature Base64-encoded signature
     * @param publicKey Base64-encoded public key
     * @return true if valid, false otherwise
     */
    @Override
    public boolean verify(String data, String signature, String publicKey) throws Exception {
        return verify(data.getBytes(), signature, publicKey);
    }

    /**
     * Verifies a byte array against a Base64-encoded signature using the provided public key.
     *
     * @param data      plaintext byte array
     * @param signature Base64-encoded signature
     * @param publicKey Base64-encoded public key
     * @return true if valid, false otherwise
     */
    @Override
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
