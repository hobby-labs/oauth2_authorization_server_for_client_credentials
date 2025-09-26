package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Data Transfer Object representing an individual key configuration in the YAML keys file.
 * 
 * <p>This class provides type-safe access to key metadata and PEM strings for
 * cryptographic operations. Each key configuration contains private and public
 * key data along with associated metadata.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
public class KeyConfiguration {
    
    /** The private key in PEM format. */
    @JsonProperty("private")
    private String privateKey;
    
    /** The public key or certificate in PEM format. */
    @JsonProperty("public")
    private String publicKey;
    
    /** The unique identifier for this key. */
    private String keyId;
    
    /** The cryptographic algorithm used with this key (e.g., "ES256"). */
    private String algorithm;
    
    /** The elliptic curve type for EC keys (e.g., "P-256"). */
    private String curve;
    
    /** The name of the certificate authority that issued the certificate for this key. */
    private String authority;
    
    /**
     * Default constructor for Jackson deserialization.
     */
    public KeyConfiguration() {
    }
    
    /**
     * Constructor with all fields.
     * 
     * @param privateKey the private key PEM string
     * @param publicKey the public key/certificate PEM string
     * @param keyId the key identifier
     * @param algorithm the cryptographic algorithm
     * @param curve the elliptic curve type
     * @param authority the certificate authority name
     */
    public KeyConfiguration(String privateKey, String publicKey, String keyId, 
                          String algorithm, String curve, String authority) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.curve = curve;
        this.authority = authority;
    }
    
    /**
     * Gets the private key PEM string.
     * 
     * @return the private key in PEM format
     */
    public String getPrivateKey() {
        return privateKey;
    }
    
    /**
     * Sets the private key PEM string.
     * 
     * @param privateKey the private key in PEM format
     */
    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
    
    /**
     * Gets the public key or certificate PEM string.
     * 
     * @return the public key/certificate in PEM format
     */
    public String getPublicKey() {
        return publicKey;
    }
    
    /**
     * Sets the public key or certificate PEM string.
     * 
     * @param publicKey the public key/certificate in PEM format
     */
    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
    
    /**
     * Gets the key identifier.
     * 
     * @return the key ID
     */
    public String getKeyId() {
        return keyId;
    }
    
    /**
     * Sets the key identifier.
     * 
     * @param keyId the key ID
     */
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
    
    /**
     * Gets the cryptographic algorithm.
     * 
     * @return the algorithm (e.g., "ES256")
     */
    public String getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Sets the cryptographic algorithm.
     * 
     * @param algorithm the algorithm (e.g., "ES256")
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
    
    /**
     * Gets the elliptic curve type.
     * 
     * @return the curve type (e.g., "P-256")
     */
    public String getCurve() {
        return curve;
    }
    
    /**
     * Sets the elliptic curve type.
     * 
     * @param curve the curve type (e.g., "P-256")
     */
    public void setCurve(String curve) {
        this.curve = curve;
    }
    
    /**
     * Gets the certificate authority name.
     * 
     * @return the authority name
     */
    public String getAuthority() {
        return authority;
    }
    
    /**
     * Sets the certificate authority name.
     * 
     * @param authority the authority name
     */
    public void setAuthority(String authority) {
        this.authority = authority;
    }
    
    @Override
    public String toString() {
        return "KeyConfiguration{" +
                "keyId='" + keyId + '\'' +
                ", algorithm='" + algorithm + '\'' +
                ", curve='" + curve + '\'' +
                ", authority='" + authority + '\'' +
                ", hasPrivateKey=" + (privateKey != null && !privateKey.trim().isEmpty()) +
                ", hasPublicKey=" + (publicKey != null && !publicKey.trim().isEmpty()) +
                '}';
    }
}