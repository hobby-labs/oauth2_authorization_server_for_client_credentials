package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for loading cryptographic keys from PEM-formatted strings.
 * 
 * <p>This class provides static methods for parsing and loading elliptic curve (EC)
 * cryptographic keys from PEM-encoded strings. It supports both PKCS#8 and traditional
 * EC private key formats, as well as X.509 public key formats and X.509 certificates.</p>
 * 
 * <p>The class handles the standard PEM format processing including:</p>
 * <ul>
 * <li>Removal of PEM headers and footers</li>
 * <li>Base64 decoding of key material</li>
 * <li>Extraction of public keys from X.509 certificates</li>
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
     * <li>X.509 Certificate format: {@code -----BEGIN CERTIFICATE-----}</li>
     * </ul>
     * 
     * <p>The method automatically strips PEM headers, footers, and whitespace,
     * then performs Base64 decoding to extract the raw key material. For certificates,
     * the public key is extracted from the certificate structure. The keys
     * are assumed to use the prime256v1 (P-256) elliptic curve.</p>
     * 
     * <p><strong>Security Note:</strong> This method is designed for loading
     * pre-validated key material from trusted configuration sources.</p>
     * 
     * @param privateKeyPem the PEM-encoded private key string, including headers and footers
     * @param publicKeyPem the PEM-encoded public key or certificate string, including headers and footers
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
     * @see CertificateFactory#getInstance(String)
     */
    public static KeyPair loadECFromPemStrings(String privateKeyPem, String publicKeyPem) throws Exception {
        // Load private key
        PrivateKey privateKey = loadPrivateKey(privateKeyPem);
        
        // Load public key (from either certificate or public key)
        PublicKey publicKey = loadPublicKey(publicKeyPem);
        
        return new KeyPair(publicKey, privateKey);
    }
    
    /**
     * Loads a private key from PEM-formatted string.
     * 
     * @param privateKeyPem the PEM-encoded private key string
     * @return the loaded PrivateKey
     * @throws Exception if the key cannot be loaded
     */
    private static PrivateKey loadPrivateKey(String privateKeyPem) throws Exception {
        // Remove PEM headers and decode
        String privateKeyBase64 = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode and create private key
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }
    
    /**
     * Loads a public key from either a PEM certificate or PEM public key.
     * 
     * @param publicKeyPem the PEM-encoded certificate or public key string
     * @return the loaded PublicKey
     * @throws Exception if the key cannot be loaded
     */
    private static PublicKey loadPublicKey(String publicKeyPem) throws Exception {
        // Check if it's a certificate
        if (publicKeyPem.contains("-----BEGIN CERTIFICATE-----")) {
            return loadPublicKeyFromCertificate(publicKeyPem);
        } else {
            return loadPublicKeyFromPem(publicKeyPem);
        }
    }
    
    /**
     * Extracts public key from an X.509 certificate.
     * 
     * @param certificatePem the PEM-encoded certificate string
     * @return the public key extracted from the certificate
     * @throws Exception if the certificate cannot be parsed
     */
    private static PublicKey loadPublicKeyFromCertificate(String certificatePem) throws Exception {
        // Create certificate from PEM string
        byte[] certificateBytes = certificatePem.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        
        // Extract public key from certificate
        return certificate.getPublicKey();
    }
    
    /**
     * Loads a public key from PEM format.
     * 
     * @param publicKeyPem the PEM-encoded public key string
     * @return the loaded PublicKey
     * @throws Exception if the key cannot be loaded
     */
    private static PublicKey loadPublicKeyFromPem(String publicKeyPem) throws Exception {
        // Remove PEM headers and decode
        String publicKeyBase64 = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN EC PUBLIC KEY-----", "")
                .replace("-----END EC PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode and create public key
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }
}
