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
    
    // YAML configuration constants
    private static final String CONFIG_SECTION = "config";
    private static final String KEYS_SECTION = "keys";
    private static final String PRIMARY_KEY_FIELD = "primary-key";
    private static final String KEY_ID_FIELD = "keyId";
    private static final String ALGORITHM_FIELD = "algorithm";
    private static final String CURVE_FIELD = "curve";
    private static final String PRIVATE_KEY_FIELD = "private";
    private static final String PUBLIC_KEY_FIELD = "public";
    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final String DEFAULT_KEY_ID = "ec-key-from-yaml";
    private static final String DEFAULT_KEY_SUFFIX = "-default";
    
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
        if (keysFilePath.startsWith(CLASSPATH_PREFIX) || !keysFilePath.contains("/")) {
            String resourcePath = keysFilePath.startsWith(CLASSPATH_PREFIX) ? 
                keysFilePath.substring(CLASSPATH_PREFIX.length()) : keysFilePath;
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
                configCache = (Map<String, Object>) yamlData.get(CONFIG_SECTION);
                keysCache = (Map<String, Object>) yamlData.get(KEYS_SECTION);
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
        return (String) getConfig().get(PRIMARY_KEY_FIELD);
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
        String privateKeyPem = (String) keyConfig.get(PRIVATE_KEY_FIELD);
        String publicKeyPem = (String) keyConfig.get(PUBLIC_KEY_FIELD);
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
    
    /**
     * Helper method to get key attribute with optional default value and null-safe error handling
     */
    private String getKeyAttribute(String keyName, String attributeName, String defaultValue) {
        try {
            Map<String, Object> keyConfig = getKeyConfig(keyName);
            String value = (String) keyConfig.get(attributeName);
            return value != null ? value : defaultValue;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
    
    public KeyPair getPrimaryKeyPair() throws Exception {
        Map<String, Object> keyConfig = getPrimaryKeyConfig();
        return createKeyPairFromConfig(keyConfig);
    }
    
    public String getPrimaryKeyId() {
        return getPrimaryKeyAttribute(KEY_ID_FIELD, DEFAULT_KEY_ID);
    }
    
    public String getPrimaryKeyAlgorithm() {
        return getPrimaryKeyAttribute(ALGORITHM_FIELD, null);
    }
    
    public String getPrimaryKeyCurve() {
        return getPrimaryKeyAttribute(CURVE_FIELD, null);
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
        return getKeyAttribute(keyName, KEY_ID_FIELD, keyName + DEFAULT_KEY_SUFFIX);
    }
    
    /**
     * Get algorithm for a specific key name
     */
    public String getKeyAlgorithm(String keyName) {
        return getKeyAttribute(keyName, ALGORITHM_FIELD, null);
    }
    
    /**
     * Get curve for a specific key name
     */
    public String getKeyCurve(String keyName) {
        return getKeyAttribute(keyName, CURVE_FIELD, null);
    }
}
