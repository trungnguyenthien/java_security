package tx.secure.asymmetric;

import tx.secure.type.KeyPair;

// Interface for digital signature generation and verification
public interface SignatureHelper {
    // Generate a new asymmetric key pair for signing and verification
    KeyPair generateKeyPair() throws Exception;
    // Sign the given data using the provided private key, returning the signature as a Base64 string
    String sign(String data, String privateKey) throws Exception;
    // Sign the given byte array data using the provided private key, returning the signature as a Base64 string
    String sign(byte[] data, String privateKey) throws Exception;
    // Verify the given data against the provided Base64-encoded signature using the public key
    boolean verify(String data, String signature, String publicKey) throws Exception;
    // Verify the given byte array data against the provided Base64-encoded signature using the public key
    boolean verify(byte[] data, String signature, String publicKey) throws Exception;
}
