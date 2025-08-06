package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.security.KeyPair;
import java.util.Map;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.KeyLoader;

/**
 * Service to load keys from YAML configuration
 */
@Service
public class KeysService {
    
    @Value("${keys.file.path:keys.yml}")
    private String keysFilePath;
    
    private Map<String, Object> yamlData;
    private volatile Map<String, Object> configCache;
    private volatile Map<String, Object> keysCache;
    private volatile boolean configurationLoaded = false;
    
    public KeysService() {
        // Configuration will be loaded lazily when first accessed
    }
    
    private void ensureConfigurationLoaded() {
        if (!configurationLoaded) {
            synchronized (this) {
                if (!configurationLoaded) {
                    loadYamlConfiguration();
                    configurationLoaded = true;
                }
            }
        }
    }
    
    private Resource getKeysResource() {
        // If the path starts with classpath: or is just a filename, use ClassPathResource
        if (keysFilePath.startsWith("classpath:") || !keysFilePath.contains("/")) {
            String resourcePath = keysFilePath.startsWith("classpath:") ? 
                keysFilePath.substring("classpath:".length()) : keysFilePath;
            return new ClassPathResource(resourcePath);
        } else {
            // Otherwise, treat it as a file system path
            return new FileSystemResource(keysFilePath);
        }
    }
    
    @SuppressWarnings("unchecked")
    private void loadYamlConfiguration() {
        try {
            Resource resource = getKeysResource();
            Yaml yaml = new Yaml();
            try (InputStream inputStream = resource.getInputStream()) {
                yamlData = yaml.load(inputStream);
                // Cache commonly used sections
                configCache = (Map<String, Object>) yamlData.get("config");
                keysCache = (Map<String, Object>) yamlData.get("keys");
            }
            System.out.println("Successfully loaded keys configuration from: " + keysFilePath);
        } catch (Exception e) {
            System.err.println("Failed to load keys from " + keysFilePath + ": " + e.getMessage());
            throw new RuntimeException("Could not load keys from " + keysFilePath, e);
        }
    }
    
    /**
     * Helper method to get config section
     */
    private Map<String, Object> getConfig() {
        ensureConfigurationLoaded();
        return configCache;
    }
    
    /**
     * Helper method to get keys section
     */
    private Map<String, Object> getKeys() {
        ensureConfigurationLoaded();
        return keysCache;
    }
    
    /**
     * Helper method to get primary key name
     */
    private String getPrimaryKeyNameInternal() {
        return (String) getConfig().get("primary-key");
    }
    
    /**
     * Helper method to get key configuration for a specific key
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> getKeyConfig(String keyName) {
        Map<String, Object> keys = getKeys();
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(keyName);
        if (keyConfig == null) {
            throw new IllegalArgumentException("Key not found: " + keyName);
        }
        return keyConfig;
    }
    
    /**
     * Helper method to get primary key configuration
     */
    private Map<String, Object> getPrimaryKeyConfig() {
        String primaryKeyName = getPrimaryKeyNameInternal();
        return getKeyConfig(primaryKeyName);
    }
    
    /**
     * Helper method to create KeyPair from key configuration
     */
    private KeyPair createKeyPairFromConfig(Map<String, Object> keyConfig) throws Exception {
        String privateKeyPem = (String) keyConfig.get("private");
        String publicKeyPem = (String) keyConfig.get("public");
        return KeyLoader.loadECFromPemStrings(privateKeyPem.trim(), publicKeyPem.trim());
    }
    
    /**
     * Helper method to get primary key attribute with optional default value
     */
    private String getPrimaryKeyAttribute(String attributeName, String defaultValue) {
        Map<String, Object> keyConfig = getPrimaryKeyConfig();
        String value = (String) keyConfig.get(attributeName);
        return value != null ? value : defaultValue;
    }
    
    public KeyPair getPrimaryKeyPair() throws Exception {
        Map<String, Object> keyConfig = getPrimaryKeyConfig();
        return createKeyPairFromConfig(keyConfig);
    }
    
    public String getPrimaryKeyId() {
        return getPrimaryKeyAttribute("keyId", "ec-key-from-yaml");
    }
    
    public String getPrimaryKeyAlgorithm() {
        return getPrimaryKeyAttribute("algorithm", null);
    }
    
    public String getPrimaryKeyCurve() {
        return getPrimaryKeyAttribute("curve", null);
    }
    
    public String getPrimaryKeyName() {
        return getPrimaryKeyNameInternal();
    }

    /**
     * Get all available key names
     */
    public java.util.Set<String> getAllKeyNames() {
        return getKeys().keySet();
    }
    
    /**
     * Get key pair for a specific key name
     */
    public KeyPair getKeyPair(String keyName) throws Exception {
        Map<String, Object> keyConfig = getKeyConfig(keyName);
        return createKeyPairFromConfig(keyConfig);
    }
    
    /**
     * Get key ID for a specific key name
     */
    public String getKeyId(String keyName) {
        try {
            Map<String, Object> keyConfig = getKeyConfig(keyName);
            String keyId = (String) keyConfig.get("keyId");
            return keyId != null ? keyId : keyName + "-default";
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
    
    /**
     * Get algorithm for a specific key name
     */
    public String getKeyAlgorithm(String keyName) {
        try {
            Map<String, Object> keyConfig = getKeyConfig(keyName);
            return (String) keyConfig.get("algorithm");
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
    
    /**
     * Get curve for a specific key name
     */
    public String getKeyCurve(String keyName) {
        try {
            Map<String, Object> keyConfig = getKeyConfig(keyName);
            return (String) keyConfig.get("curve");
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
