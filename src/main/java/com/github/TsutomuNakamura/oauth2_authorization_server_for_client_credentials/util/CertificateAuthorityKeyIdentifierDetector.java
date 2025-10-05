package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Detector for identifying certificate authorities using X.509v3 Key Identifiers.
 * 
 * <p>This detector uses the preferred method as defined in RFC 5280 Section 4.2.1.1 and 4.2.1.2.
 * The Authority Key Identifier of the certificate should match the Subject Key Identifier
 * of the issuing CA certificate.</p>
 * 
 * <p>This approach is more robust than DN matching as it uses cryptographic identifiers
 * specifically designed for certificate chain building.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
@Component
public class CertificateAuthorityKeyIdentifierDetector implements CertificateAuthorityDetector {
    
    /** Logger for this detector. */
    private static final Logger logger = LoggerFactory.getLogger(CertificateAuthorityKeyIdentifierDetector.class);
    
    /**
     * Constructs a new CertificateAuthorityKeyIdentifierDetector instance.
     */
    public CertificateAuthorityKeyIdentifierDetector() {
        // Default constructor for Spring component
    }
    
    /**
     * Detects authority using X.509v3 Subject Key Identifier and Authority Key Identifier extensions.
     * 
     * <p>This method extracts the Authority Key Identifier (AKI) from the given certificate and
     * attempts to match it with the Subject Key Identifier (SKI) of available chain certificates.</p>
     * 
     * @param certificatePem the PEM-encoded certificate to analyze
     * @param chains the map of available chain configurations
     * @return the name of the matching authority or null if no match found
     */
    @Override
    public String detectAuthority(String certificatePem, Map<String, ?> chains) {
        try {
            // Extract the Authority Key Identifier from the certificate
            String authorityKeyId = CertificateChainBuilder.extractAuthorityKeyIdentifier(certificatePem);
            if (authorityKeyId == null) {
                logger.debug("Certificate does not contain Authority Key Identifier extension");
                return null;
            }
            
            // Get all available chains
            if (chains == null) {
                return null;
            }
            
            // Check each chain certificate to see if its SKI matches the certificate's AKI
            for (Map.Entry<String, ?> chainEntry : chains.entrySet()) {
                String chainName = chainEntry.getKey();
                Object chainData = chainEntry.getValue();
                String chainCertPem = extractPublicKey(chainData);
                
                if (chainCertPem != null) {
                    try {
                        String subjectKeyId = CertificateChainBuilder.extractSubjectKeyIdentifier(chainCertPem);
                        if (authorityKeyId.equals(subjectKeyId)) {
                            logger.debug("Auto-detected authority '{}' using X.509v3 Key Identifiers (AKI: {})", chainName, authorityKeyId);
                            return chainName;
                        }
                    } catch (Exception e) {
                        logger.warn("Error extracting SKI from chain certificate '{}': {}", chainName, e.getMessage());
                    }
                }
            }
            
            logger.debug("No matching authority found for Authority Key Identifier: {}", authorityKeyId);
            return null;
            
        } catch (Exception e) {
            logger.warn("Error during key identifier-based authority detection: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Extracts the public key from a chain configuration object.
     * 
     * <p>This method uses reflection to handle different types of chain configuration objects
     * that have a getPublicKey() method.</p>
     * 
     * @param chainData the chain configuration object
     * @return the public key PEM string or null if not found
     */
    private String extractPublicKey(Object chainData) {
        try {
            // Use reflection to call getPublicKey() method
            java.lang.reflect.Method method = chainData.getClass().getMethod("getPublicKey");
            Object result = method.invoke(chainData);
            return result instanceof String ? (String) result : null;
        } catch (Exception e) {
            logger.warn("Error extracting public key from chain data: {}", e.getMessage());
            return null;
        }
    }
}
