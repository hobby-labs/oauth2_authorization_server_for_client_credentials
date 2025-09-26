package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Data Transfer Object representing a certificate chain configuration in the YAML keys file.
 * 
 * <p>This class provides type-safe access to certificate chain data, typically containing
 * intermediate CA certificates used for building X.509 certificate chains.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
public class ChainConfiguration {
    
    /** The certificate in PEM format (usually an intermediate CA certificate). */
    @JsonProperty("public")
    private String publicKey;
    
    /**
     * Default constructor for Jackson deserialization.
     */
    public ChainConfiguration() {
    }
    
    /**
     * Constructor with the public key/certificate.
     * 
     * @param publicKey the certificate PEM string
     */
    public ChainConfiguration(String publicKey) {
        this.publicKey = publicKey;
    }
    
    /**
     * Gets the certificate PEM string.
     * 
     * @return the certificate in PEM format
     */
    public String getPublicKey() {
        return publicKey;
    }
    
    /**
     * Sets the certificate PEM string.
     * 
     * @param publicKey the certificate in PEM format
     */
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
    
    @Override
    public String toString() {
        return "ChainConfiguration{" +
                "hasCertificate=" + (publicKey != null && !publicKey.trim().isEmpty()) +
                '}';
    }
}