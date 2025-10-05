package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import java.util.Map;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ChainConfiguration;

/**
 * Interface for certificate authority detection strategies.
 * 
 * <p>This interface defines the contract for different strategies to detect the
 * issuing certificate authority of a given certificate. Implementations may use
 * various methods such as X.509v3 Key Identifiers, Distinguished Names, or other
 * certificate properties.</p>
 * 
 * <p>This follows the Strategy pattern, allowing different detection algorithms
 * to be used interchangeably and making it easy to add new detection methods
 * without modifying existing code.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
public interface CertificateAuthorityDetector {
    
    /**
     * Detects the certificate authority that issued the given certificate.
     * 
     * <p>This method analyzes the provided certificate and attempts to match it
     * with one of the available chain certificates to identify its issuing authority.</p>
     * 
     * @param certificatePem the PEM-encoded certificate to analyze
     * @param chains the map of available chain configurations, where keys are authority
     *               names and values are chain configuration objects with a getPublicKey() method
     * @return the name of the matching authority or null if no match is found
     */
    String detectAuthority(String certificatePem, Map<String, ChainConfiguration> chains);
}
