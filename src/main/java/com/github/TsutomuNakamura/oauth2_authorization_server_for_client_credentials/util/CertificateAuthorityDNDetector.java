package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.util.Map;

/**
 * Detector for identifying certificate authorities using Distinguished Names (DN).
 * 
 * <p>This detector uses Subject and Issuer Distinguished Names for certificate authority detection.
 * This method is kept for backward compatibility with certificates that may not have proper
 * X.509v3 key identifier extensions.</p>
 * 
 * <p>The detector extracts the issuer CN from the certificate and attempts to match it
 * with the subject CN of available chain certificates.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
@Component
public class CertificateAuthorityDNDetector implements CertificateAuthorityDetector {
    
    /** Logger for this detector. */
    private static final Logger logger = LoggerFactory.getLogger(CertificateAuthorityDNDetector.class);
    
    /**
     * Constructs a new CertificateAuthorityDNDetector instance.
     */
    public CertificateAuthorityDNDetector() {
        // Default constructor for Spring component
    }
    
    /**
     * Detects authority using Subject and Issuer Distinguished Names.
     * 
     * <p>This method extracts the issuer CN from the given certificate and attempts to
     * match it with the subject CN of available chain certificates.</p>
     * 
     * @param certificatePem the PEM-encoded certificate to analyze
     * @param chains the map of available chain configurations
     * @return the name of the matching authority or null if no match found
     */
    @Override
    public String detectAuthority(String certificatePem, Map<String, ?> chains) {
        try {
            // Extract the issuer CN from the certificate
            String issuerCN = CertificateChainBuilder.extractIssuerCN(certificatePem);
            if (issuerCN == null) {
                return null;
            }
            
            // Get all available chains
            if (chains == null) {
                return null;
            }
            
            // Check each chain certificate to see if its subject matches the issuer
            for (Map.Entry<String, ?> chainEntry : chains.entrySet()) {
                String chainName = chainEntry.getKey();
                Object chainData = chainEntry.getValue();
                String chainCertPem = extractPublicKey(chainData);
                
                if (chainCertPem != null) {
                    try {
                        String chainSubjectCN = CertificateChainBuilder.extractSubjectCN(chainCertPem);
                        if (issuerCN.equals(chainSubjectCN)) {
                            logger.debug("Auto-detected authority '{}' using DN matching (Issuer: {})", chainName, issuerCN);
                            return chainName;
                        }
                    } catch (Exception e) {
                        logger.warn("Error parsing chain certificate for '{}': {}", chainName, e.getMessage());
                    }
                }
            }
            
            return null;
            
        } catch (Exception e) {
            logger.warn("Error during DN-based authority detection: {}", e.getMessage());
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
            Method method = chainData.getClass().getMethod("getPublicKey");
            Object result = method.invoke(chainData);
            return result instanceof String ? (String) result : null;
        } catch (Exception e) {
            logger.warn("Error extracting public key from chain data: {}", e.getMessage());
            return null;
        }
    }
}
