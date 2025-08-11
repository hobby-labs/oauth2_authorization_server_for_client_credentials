package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Utility class for building X.509 certificate chains for JWT x5c headers.
 * 
 * <p>This class provides functionality to build certificate chains from PEM-encoded
 * certificates and convert them to the Base64 DER format required for JWT x5c headers.</p>
 * 
 * <p>The x5c (X.509 Certificate Chain) header parameter contains a chain of one or more
 * PKIX certificates [RFC5280]. The certificate chain is represented as an array of
 * certificate value strings. Each string in the array is a base64-encoded DER
 * [ITU.X690.1994] PKIX certificate value.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
public class CertificateChainBuilder {
    
    /**
     * Builds an x5c certificate chain array from PEM certificates.
     * 
     * <p>The chain should be ordered from the end-entity certificate to the
     * intermediate CA certificate(s). The root CA certificate should NOT be included
     * as per RFC 7517 recommendations.</p>
     * 
     * @param endEntityCertPem the end-entity certificate in PEM format
     * @param intermediateCertPem the intermediate CA certificate in PEM format (optional)
     * @return List of Base64-encoded DER certificate strings for x5c header
     * @throws Exception if certificates cannot be parsed or encoded
     */
    public static List<String> buildX5cChain(String endEntityCertPem, String intermediateCertPem) throws Exception {
        List<String> x5cChain = new ArrayList<>();
        
        // Add end-entity certificate (first in chain)
        if (endEntityCertPem != null && !endEntityCertPem.trim().isEmpty()) {
            String derBase64 = convertPemToDerBase64(endEntityCertPem);
            x5cChain.add(derBase64);
        }
        
        // Add intermediate certificate (if provided)
        if (intermediateCertPem != null && !intermediateCertPem.trim().isEmpty()) {
            String derBase64 = convertPemToDerBase64(intermediateCertPem);
            x5cChain.add(derBase64);
        }
        
        return x5cChain;
    }
    
    /**
     * Builds an x5c certificate chain from multiple PEM certificates.
     * 
     * @param certificatePems array of PEM certificates in order (end-entity first)
     * @return List of Base64-encoded DER certificate strings for x5c header
     * @throws Exception if certificates cannot be parsed or encoded
     */
    public static List<String> buildX5cChain(String... certificatePems) throws Exception {
        List<String> x5cChain = new ArrayList<>();
        
        for (String certPem : certificatePems) {
            if (certPem != null && !certPem.trim().isEmpty()) {
                String derBase64 = convertPemToDerBase64(certPem);
                x5cChain.add(derBase64);
            }
        }
        
        return x5cChain;
    }
    
    /**
     * Converts a PEM certificate to Base64-encoded DER format.
     * 
     * @param pemCertificate the PEM-encoded certificate
     * @return Base64-encoded DER certificate string
     * @throws Exception if certificate cannot be parsed
     */
    private static String convertPemToDerBase64(String pemCertificate) throws Exception {
        // Parse the PEM certificate to X509Certificate
        byte[] certificateBytes = pemCertificate.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        
        // Get DER encoding and convert to Base64
        byte[] derEncoded = certificate.getEncoded();
        return Base64.getEncoder().encodeToString(derEncoded);
    }
    
    /**
     * Validates that a certificate chain is properly ordered.
     * 
     * @param x5cChain the certificate chain to validate
     * @return true if the chain appears to be properly ordered
     * @throws Exception if certificates cannot be parsed for validation
     */
    public static boolean validateChainOrder(List<String> x5cChain) throws Exception {
        if (x5cChain == null || x5cChain.size() < 2) {
            return true; // Single certificate or empty chain is valid
        }
        
        // Parse first two certificates to check if first is issued by second
        byte[] cert1Der = Base64.getDecoder().decode(x5cChain.get(0));
        byte[] cert2Der = Base64.getDecoder().decode(x5cChain.get(1));
        
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert1 = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert1Der));
        X509Certificate cert2 = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert2Der));
        
        // Check if cert1 is issued by cert2
        try {
            cert1.verify(cert2.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Extracts the issuer Common Name (CN) from a PEM certificate.
     * 
     * <p>This method parses the certificate and extracts the CN field from the
     * issuer's Distinguished Name. This is useful for automatically determining
     * which intermediate CA issued a certificate.</p>
     * 
     * @param pemCertificate the PEM-encoded certificate
     * @return the issuer's Common Name (CN) or null if not found
     * @throws Exception if certificate cannot be parsed
     */
    public static String extractIssuerCN(String pemCertificate) throws Exception {
        if (pemCertificate == null || pemCertificate.trim().isEmpty()) {
            return null;
        }
        
        // Parse the PEM certificate to X509Certificate
        byte[] certificateBytes = pemCertificate.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        
        // Get the issuer DN and extract CN
        String issuerDN = certificate.getIssuerX500Principal().getName();
        
        // Parse CN from Distinguished Name (format: "CN=name, ...")
        String[] dnComponents = issuerDN.split(",");
        for (String component : dnComponents) {
            String trimmed = component.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3); // Remove "CN=" prefix
            }
        }
        
        return null; // CN not found
    }
    
    /**
     * Extracts the subject Common Name (CN) from a PEM certificate.
     * 
     * <p>This method parses the certificate and extracts the CN field from the
     * subject's Distinguished Name. This is useful for matching certificates
     * by their subject names.</p>
     * 
     * @param pemCertificate the PEM-encoded certificate
     * @return the subject's Common Name (CN) or null if not found
     * @throws Exception if certificate cannot be parsed
     */
    public static String extractSubjectCN(String pemCertificate) throws Exception {
        if (pemCertificate == null || pemCertificate.trim().isEmpty()) {
            return null;
        }
        
        // Parse the PEM certificate to X509Certificate
        byte[] certificateBytes = pemCertificate.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        
        // Get the subject DN and extract CN
        String subjectDN = certificate.getSubjectX500Principal().getName();
        
        // Parse CN from Distinguished Name (format: "CN=name, ...")
        String[] dnComponents = subjectDN.split(",");
        for (String component : dnComponents) {
            String trimmed = component.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3); // Remove "CN=" prefix
            }
        }
        
        return null; // CN not found
    }
    
    /**
     * Extracts the Authority Key Identifier (AKI) from a PEM certificate.
     * 
     * <p>The Authority Key Identifier extension provides a means of identifying 
     * the public key corresponding to the private key used to sign a certificate.
     * This is the preferred method for certificate chain building as defined in RFC 5280.</p>
     * 
     * @param pemCertificate the PEM-encoded certificate
     * @return the Authority Key Identifier as a hex string or null if not found
     * @throws Exception if certificate cannot be parsed
     */
    public static String extractAuthorityKeyIdentifier(String pemCertificate) throws Exception {
        if (pemCertificate == null || pemCertificate.trim().isEmpty()) {
            return null;
        }
        
        // Parse the PEM certificate to X509Certificate
        byte[] certificateBytes = pemCertificate.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        
        // Get the Authority Key Identifier extension (OID: 2.5.29.35)
        byte[] akiBytes = certificate.getExtensionValue("2.5.29.35");
        if (akiBytes == null) {
            return null;
        }
        
        // The extension value is DER-encoded OCTET STRING containing the actual extension
        // We need to parse it to get the key identifier
        return parseKeyIdentifierFromExtension(akiBytes);
    }
    
    /**
     * Extracts the Subject Key Identifier (SKI) from a PEM certificate.
     * 
     * <p>The Subject Key Identifier extension provides a means of identifying 
     * certificates that contain the same subject public key. This is used to
     * match certificates in a chain as defined in RFC 5280.</p>
     * 
     * @param pemCertificate the PEM-encoded certificate
     * @return the Subject Key Identifier as a hex string or null if not found
     * @throws Exception if certificate cannot be parsed
     */
    public static String extractSubjectKeyIdentifier(String pemCertificate) throws Exception {
        if (pemCertificate == null || pemCertificate.trim().isEmpty()) {
            return null;
        }
        
        // Parse the PEM certificate to X509Certificate
        byte[] certificateBytes = pemCertificate.getBytes();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(certificateBytes);
        
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        
        // Get the Subject Key Identifier extension (OID: 2.5.29.14)
        byte[] skiBytes = certificate.getExtensionValue("2.5.29.14");
        if (skiBytes == null) {
            return null;
        }
        
        // The extension value is DER-encoded OCTET STRING containing the actual extension
        return parseKeyIdentifierFromExtension(skiBytes);
    }
    
    /**
     * Parses a key identifier from an X.509 extension value.
     * 
     * <p>X.509 extension values are DER-encoded OCTET STRINGs. For key identifier
     * extensions, the content is typically another OCTET STRING containing the
     * actual key identifier bytes.</p>
     * 
     * @param extensionBytes the DER-encoded extension value
     * @return the key identifier as a hex string or null if parsing fails
     */
    private static String parseKeyIdentifierFromExtension(byte[] extensionBytes) {
        try {
            // Skip the outer OCTET STRING wrapper (tag + length)
            int offset = 0;
            if (extensionBytes[offset] == 0x04) { // OCTET STRING tag
                offset++;
                int length = extensionBytes[offset] & 0xFF;
                offset++;
                if ((length & 0x80) != 0) {
                    // Long form length
                    int lengthBytes = length & 0x7F;
                    offset += lengthBytes;
                }
            }
            
            // For Authority Key Identifier, we may have a SEQUENCE containing the key ID
            // For Subject Key Identifier, it's usually just the OCTET STRING with the ID
            if (extensionBytes[offset] == 0x30) { // SEQUENCE tag (for AKI)
                offset++;
                int length = extensionBytes[offset] & 0xFF;
                offset++;
                if ((length & 0x80) != 0) {
                    int lengthBytes = length & 0x7F;
                    offset += lengthBytes;
                }
                
                // Look for key identifier tag (context-specific [0])
                if (extensionBytes[offset] == (byte) 0x80) {
                    offset++;
                    int keyIdLength = extensionBytes[offset] & 0xFF;
                    offset++;
                    
                    // Extract the key identifier bytes
                    byte[] keyIdBytes = new byte[keyIdLength];
                    System.arraycopy(extensionBytes, offset, keyIdBytes, 0, keyIdLength);
                    return bytesToHex(keyIdBytes);
                }
            } else if (extensionBytes[offset] == 0x04) { // OCTET STRING tag (for SKI)
                offset++;
                int keyIdLength = extensionBytes[offset] & 0xFF;
                offset++;
                
                // Extract the key identifier bytes
                byte[] keyIdBytes = new byte[keyIdLength];
                System.arraycopy(extensionBytes, offset, keyIdBytes, 0, keyIdLength);
                return bytesToHex(keyIdBytes);
            }
            
            return null;
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Converts a byte array to a hexadecimal string.
     * 
     * @param bytes the byte array to convert
     * @return the hexadecimal representation (lowercase)
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b & 0xFF));
        }
        return hex.toString();
    }
}
