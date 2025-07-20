package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.springframework.core.io.ClassPathResource;
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
    
    private Map<String, Object> yamlData;
    
    public KeysService() {
        loadYamlConfiguration();
    }
    
    @SuppressWarnings("unchecked")
    private void loadYamlConfiguration() {
        try {
            ClassPathResource resource = new ClassPathResource("keys.yml");
            Yaml yaml = new Yaml();
            try (InputStream inputStream = resource.getInputStream()) {
                yamlData = yaml.load(inputStream);
            }
            System.out.println("Successfully loaded keys.yml configuration");
        } catch (Exception e) {
            System.err.println("Failed to load keys.yml: " + e.getMessage());
            throw new RuntimeException("Could not load keys.yml", e);
        }
    }
    
    @SuppressWarnings("unchecked")
    public KeyPair getPrimaryKeyPair() throws Exception {
        Map<String, Object> config = (Map<String, Object>) yamlData.get("config");
        String primaryKeyName = (String) config.get("primary-key");
        
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(primaryKeyName);
        
        String privateKeyPem = (String) keyConfig.get("private");
        String publicKeyPem = (String) keyConfig.get("public");
        
        return KeyLoader.loadECFromPemStrings(privateKeyPem.trim(), publicKeyPem.trim());
    }
    
    @SuppressWarnings("unchecked")
    public String getPrimaryKeyId() {
        Map<String, Object> config = (Map<String, Object>) yamlData.get("config");
        String primaryKeyName = (String) config.get("primary-key");
        
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(primaryKeyName);
        
        String keyId = (String) keyConfig.get("keyId");
        return keyId != null ? keyId : "ec-key-from-yaml";
    }
    
    @SuppressWarnings("unchecked")
    public String getPrimaryKeyAlgorithm() {
        Map<String, Object> config = (Map<String, Object>) yamlData.get("config");
        String primaryKeyName = (String) config.get("primary-key");
        
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(primaryKeyName);
        
        return (String) keyConfig.get("algorithm");
    }
    
    @SuppressWarnings("unchecked")
    public String getPrimaryKeyCurve() {
        Map<String, Object> config = (Map<String, Object>) yamlData.get("config");
        String primaryKeyName = (String) config.get("primary-key");
        
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(primaryKeyName);
        
        return (String) keyConfig.get("curve");
    }
    
    @SuppressWarnings("unchecked")
    public String getPrimaryKeyName() {
        Map<String, Object> config = (Map<String, Object>) yamlData.get("config");
        return (String) config.get("primary-key");
    }

    /**
     * Get all available key names
     */
    @SuppressWarnings("unchecked")
    public java.util.Set<String> getAllKeyNames() {
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        return keys.keySet();
    }
    
    /**
     * Get key pair for a specific key name
     */
    @SuppressWarnings("unchecked")
    public KeyPair getKeyPair(String keyName) throws Exception {
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(keyName);
        
        if (keyConfig == null) {
            throw new IllegalArgumentException("Key not found: " + keyName);
        }
        
        String privateKeyPem = (String) keyConfig.get("private");
        String publicKeyPem = (String) keyConfig.get("public");
        
        return KeyLoader.loadECFromPemStrings(privateKeyPem.trim(), publicKeyPem.trim());
    }
    
    /**
     * Get key ID for a specific key name
     */
    @SuppressWarnings("unchecked")
    public String getKeyId(String keyName) {
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(keyName);
        
        if (keyConfig == null) {
            return null;
        }
        
        String keyId = (String) keyConfig.get("keyId");
        return keyId != null ? keyId : keyName + "-default";
    }
    
    /**
     * Get algorithm for a specific key name
     */
    @SuppressWarnings("unchecked")
    public String getKeyAlgorithm(String keyName) {
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(keyName);
        
        if (keyConfig == null) {
            return null;
        }
        
        return (String) keyConfig.get("algorithm");
    }
    
    /**
     * Get curve for a specific key name
     */
    @SuppressWarnings("unchecked")
    public String getKeyCurve(String keyName) {
        Map<String, Object> keys = (Map<String, Object>) yamlData.get("keys");
        Map<String, Object> keyConfig = (Map<String, Object>) keys.get(keyName);
        
        if (keyConfig == null) {
            return null;
        }
        
        return (String) keyConfig.get("curve");
    }
}
