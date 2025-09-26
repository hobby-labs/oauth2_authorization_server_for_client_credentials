package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Data Transfer Object representing the configuration section in the YAML keys file.
 * 
 * <p>This class provides type-safe access to the config section which contains
 * global configuration settings like the primary key name.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
public class ConfigSection {
    
    /** The name of the primary key to use for cryptographic operations. */
    @JsonProperty("primary-key")
    private String primaryKey;
    
    /**
     * Default constructor for Jackson deserialization.
     */
    public ConfigSection() {
    }
    
    /**
     * Constructor with all fields.
     * 
     * @param primaryKey the name of the primary key
     */
    public ConfigSection(String primaryKey) {
        this.primaryKey = primaryKey;
    }
    
    /**
     * Gets the primary key name.
     * 
     * @return the primary key name
     */
    public String getPrimaryKey() {
        return primaryKey;
    }
    
    /**
     * Sets the primary key name.
     * 
     * @param primaryKey the primary key name
     */
    public void setPrimaryKey(String primaryKey) {
        this.primaryKey = primaryKey;
    }
    
    @Override
    public String toString() {
        return "ConfigSection{" +
                "primaryKey='" + primaryKey + '\'' +
                '}';
    }
}