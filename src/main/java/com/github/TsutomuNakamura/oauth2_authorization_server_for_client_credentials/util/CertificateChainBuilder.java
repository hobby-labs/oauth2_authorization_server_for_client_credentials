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
}
