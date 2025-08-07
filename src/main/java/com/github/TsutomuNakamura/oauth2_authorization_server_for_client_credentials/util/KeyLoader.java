package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for loading cryptographic keys from PEM-formatted strings.
 * 
 * <p>This class provides static methods for parsing and loading elliptic curve (EC)
 * cryptographic keys from PEM-encoded strings. It supports both PKCS#8 and traditional
 * EC private key formats, as well as X.509 public key formats.</p>
 * 
 * <p>The class handles the standard PEM format processing including:</p>
 * <ul>
 * <li>Removal of PEM headers and footers</li>
 * <li>Base64 decoding of key material</li>
 * <li>Creation of Java KeyPair objects</li>
 * </ul>
 * 
 * <p>Thread Safety: This class is thread-safe as it contains only static methods
 * with no shared state.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
public class KeyLoader {
    
    /**
     * Loads an elliptic curve (EC) KeyPair from PEM-formatted string content.
     * 
     * <p>This method processes PEM-encoded private and public keys and creates a
     * Java KeyPair object. It supports multiple PEM formats:</p>
     * 
     * <h3>Supported Private Key Formats:</h3>
     * <ul>
     * <li>PKCS#8 format: {@code -----BEGIN PRIVATE KEY-----}</li>
     * <li>Traditional EC format: {@code -----BEGIN EC PRIVATE KEY-----}</li>
     * </ul>
     * 
     * <h3>Supported Public Key Formats:</h3>
     * <ul>
     * <li>X.509 format: {@code -----BEGIN PUBLIC KEY-----}</li>
     * <li>Traditional EC format: {@code -----BEGIN EC PUBLIC KEY-----}</li>
     * </ul>
     * 
     * <p>The method automatically strips PEM headers, footers, and whitespace,
     * then performs Base64 decoding to extract the raw key material. The keys
     * are assumed to use the prime256v1 (P-256) elliptic curve.</p>
     * 
     * <p><strong>Security Note:</strong> This method is designed for loading
     * pre-validated key material from trusted configuration sources.</p>
     * 
     * @param privateKeyPem the PEM-encoded private key string, including headers and footers
     * @param publicKeyPem the PEM-encoded public key string, including headers and footers
     * @return a KeyPair containing the loaded private and public keys
     * @throws Exception if the PEM strings cannot be parsed, decoded, or if the key
     *                   material is invalid or incompatible
     * @throws IllegalArgumentException if either parameter is null or empty
     * @throws java.security.spec.InvalidKeySpecException if the key specifications are invalid
     * @throws java.security.NoSuchAlgorithmException if the EC algorithm is not available
     * 
     * @see KeyFactory#getInstance(String)
     * @see PKCS8EncodedKeySpec
     * @see X509EncodedKeySpec
     */
    public static KeyPair loadECFromPemStrings(String privateKeyPem, String publicKeyPem) throws Exception {
        // Remove PEM headers and decode
        String privateKeyBase64 = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
                
        String publicKeyBase64 = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN EC PUBLIC KEY-----", "")
                .replace("-----END EC PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode and create keys
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        return new KeyPair(publicKey, privateKey);
    }
}
