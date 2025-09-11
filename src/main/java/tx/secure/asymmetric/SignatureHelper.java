package tx.secure.asymmetric;

import tx.secure.type.KeyPair;

public interface SignatureHelper {
    KeyPair generateKeyPair() throws Exception;

    String sign(String data, String privateKey) throws Exception;

    String sign(byte[] data, String privateKey) throws Exception;

    boolean verify(String data, String signature, String publicKey) throws Exception;

    boolean verify(byte[] data, String signature, String publicKey) throws Exception;
}
