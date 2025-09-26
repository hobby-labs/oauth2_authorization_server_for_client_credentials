package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto;

import java.util.Map;

/**
 * Data Transfer Object representing the complete keys configuration from the YAML file.
 * 
 * <p>This class provides type-safe access to all sections of the keys configuration:
 * the config section with global settings, the keys section with individual key
 * configurations, and the chains section with certificate chain data.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
public class KeysConfiguration {
    
    /** Global configuration settings. */
    private ConfigSection config;
    
    /** Individual key configurations mapped by key name. */
    private Map<String, KeyConfiguration> keys;
    
    /** Certificate chain configurations mapped by authority name. */
    private Map<String, ChainConfiguration> chains;
    
    /**
     * Default constructor for Jackson deserialization.
     */
    public KeysConfiguration() {
    }
    
    /**
     * Constructor with all sections.
     * 
     * @param config the configuration section
     * @param keys the keys section
     * @param chains the chains section
     */
    public KeysConfiguration(ConfigSection config, Map<String, KeyConfiguration> keys, 
                           Map<String, ChainConfiguration> chains) {
        this.config = config;
        this.keys = keys;
        this.chains = chains;
    }
    
    /**
     * Gets the configuration section.
     * 
     * @return the config section
     */
    public ConfigSection getConfig() {
        return config;
    }
    
    /**
     * Sets the configuration section.
     * 
     * @param config the config section
     */
    public void setConfig(ConfigSection config) {
        this.config = config;
    }
    
    /**
     * Gets the keys section.
     * 
     * @return the keys mapped by key name
     */
    public Map<String, KeyConfiguration> getKeys() {
        return keys;
    }
    
    /**
     * Sets the keys section.
     * 
     * @param keys the keys mapped by key name
     */
    public void setKeys(Map<String, KeyConfiguration> keys) {
        this.keys = keys;
    }
    
    /**
     * Gets the chains section.
     * 
     * @return the certificate chains mapped by authority name
     */
    public Map<String, ChainConfiguration> getChains() {
        return chains;
    }
    
    /**
     * Sets the chains section.
     * 
     * @param chains the certificate chains mapped by authority name
     */
    public void setChains(Map<String, ChainConfiguration> chains) {
        this.chains = chains;
    }
    
    /**
     * Gets a specific key configuration by name.
     * 
     * @param keyName the name of the key to retrieve
     * @return the key configuration or null if not found
     */
    public KeyConfiguration getKey(String keyName) {
        return keys != null ? keys.get(keyName) : null;
    }
    
    /**
     * Gets a specific chain configuration by authority name.
     * 
     * @param authorityName the name of the authority to retrieve
     * @return the chain configuration or null if not found
     */
    public ChainConfiguration getChain(String authorityName) {
        return chains != null ? chains.get(authorityName) : null;
    }
    
    @Override
    public String toString() {
        return "KeysConfiguration{" +
                "config=" + config +
                ", keysCount=" + (keys != null ? keys.size() : 0) +
                ", chainsCount=" + (chains != null ? chains.size() : 0) +
                '}';
    }
}