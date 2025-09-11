package tx.secure.asymmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import tx.secure.symmetric.SymmetricEncryptionHelper;
import tx.secure.symmetric.SymmetricEncryptionResult;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncryptionHelper {
    private final SymmetricEncryptionHelper symmetricHelper;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public AsymmetricEncryptionHelper(SymmetricEncryptionHelper symmetricHelper) {
        this.symmetricHelper = symmetricHelper;
    }

    public AsymmetricKeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDH", "BC");
        gen.initialize(new ECNamedCurveGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        return new AsymmetricKeyPair(kp.getPublic(), kp.getPrivate());
    }

    public AsymmetricEncryptionResult encrypt(String plaintext, String base64PublicKey) throws Exception {
        PublicKey recipientPublicKey = KeyFactory.getInstance("ECDH", "BC")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey)));

        AsymmetricKeyPair ephemeral = generateKeyPair();
        String aesKey = deriveKey(ephemeral.getPrivate(), recipientPublicKey);
        SymmetricEncryptionResult encrypted = symmetricHelper.encrypt(plaintext, aesKey);
        String ephemeralPubKey = Base64.getEncoder().encodeToString(ephemeral.getPublic().getEncoded());

        return new AsymmetricEncryptionResult(ephemeralPubKey, encrypted);
    }

    public String decrypt(String encryptedJson, String base64PublicKey, String base64PrivateKey) throws Exception {
        PrivateKey privKey = KeyFactory.getInstance("ECDH", "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey)));

        PublicKey ephemeralPubKey = KeyFactory.getInstance("ECDH", "BC")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey)));

        String aesKey = deriveKey(privKey, ephemeralPubKey);
        return symmetricHelper.decrypt(new SymmetricEncryptionResult(encryptedJson), aesKey);
    }

    private String deriveKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);

        byte[] shared = ka.generateSecret();
        byte[] hash = MessageDigest.getInstance("SHA-256", "BC").digest(shared);
        return Base64.getEncoder().encodeToString(hash);
    }
}