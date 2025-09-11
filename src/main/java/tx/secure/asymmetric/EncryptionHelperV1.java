package tx.secure.asymmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import tx.secure.type.KeyPair;
import tx.secure.type.Result;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Provides encryption and decryption utilities using ECDH for key agreement
 * and AES for symmetric encryption.
 */
public class EncryptionHelperV1 implements EncryptionHelper {
    private final tx.secure.symmetric.EncryptionHelper symmetricHelper;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public EncryptionHelperV1(tx.secure.symmetric.EncryptionHelper symmetricHelper) {
        this.symmetricHelper = symmetricHelper;
    }

    @Override
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDH", "BC");
        gen.initialize(new ECNamedCurveGenParameterSpec("secp256r1"));
        java.security.KeyPair kp = gen.generateKeyPair();
        return new KeyPair(kp.getPublic(), kp.getPrivate());
    }

    @Override
    public Result encrypt(String plaintext, String base64RecipientPublicKey) throws Exception {
        PublicKey recipientPublicKey = keyFactory()
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64RecipientPublicKey)));
        KeyPair ephemeral = generateKeyPair();
        String aesKey = deriveKey(ephemeral.getPrivate(), recipientPublicKey);
        Result tempResult = symmetricHelper.encrypt(plaintext, aesKey);
        String ephemeralPubKey = Base64.getEncoder().encodeToString(ephemeral.getPublic().getEncoded());
        return new Result(tempResult.getAlg(), tempResult.getIv(), tempResult.getCt(), tempResult.getTag(), ephemeralPubKey);
    }

    private static KeyFactory keyFactory() throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyFactory.getInstance("ECDH", "BC");
    }

    @Override
    public String decrypt(String encryptedJson, String base64EphemeralPublicKey, String base64RecipientPrivateKey) throws Exception {
        PrivateKey recipientPrivateKey = keyFactory()
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64RecipientPrivateKey)));

        PublicKey ephemeralPublicKey = keyFactory()
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64EphemeralPublicKey)));

        String aesKey = deriveKey(recipientPrivateKey, ephemeralPublicKey);
        return symmetricHelper.decrypt(new Result(encryptedJson), aesKey);
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