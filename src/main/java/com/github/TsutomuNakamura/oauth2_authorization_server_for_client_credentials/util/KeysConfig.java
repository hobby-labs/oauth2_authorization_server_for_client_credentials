package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

/**
 * Configuration class to read keys from keys.yml
 */
@ConfigurationProperties(prefix = "")
public class KeysConfig {
    
    private Map<String, KeyPairConfig> keys;
    private ConfigSection config;
    
    public Map<String, KeyPairConfig> getKeys() {
        return keys;
    }
    
    public void setKeys(Map<String, KeyPairConfig> keys) {
        this.keys = keys;
    }
    
    public ConfigSection getConfig() {
        return config;
    }
    
    public void setConfig(ConfigSection config) {
        this.config = config;
    }
    
    public static class KeyPairConfig {
        private String privateKey;
        private String publicKey;
        private String keyId;
        private String algorithm;
        private String curve;
        
        // Getters and setters with proper YAML mapping
        public String getPrivateKey() {
            return privateKey;
        }
        
        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
        
        // Map "private" from YAML to privateKey
        public void setPrivate(String privateKey) {
            this.privateKey = privateKey;
        }
        
        public String getPublicKey() {
            return publicKey;
        }
        
        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }
        
        // Map "public" from YAML to publicKey  
        public void setPublic(String publicKey) {
            this.publicKey = publicKey;
        }
        
        public String getKeyId() {
            return keyId;
        }
        
        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }
        
        public String getAlgorithm() {
            return algorithm;
        }
        
        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
        
        public String getCurve() {
            return curve;
        }
        
        public void setCurve(String curve) {
            this.curve = curve;
        }
    }
    
    public static class ConfigSection {
        private String primaryKey;
        private boolean keyRotation;
        
        public String getPrimaryKey() {
            return primaryKey;
        }
        
        public void setPrimaryKey(String primaryKey) {
            this.primaryKey = primaryKey;
        }
        
        // Map "primary-key" from YAML to primaryKey
        public void setPrimary_key(String primaryKey) {
            this.primaryKey = primaryKey;
        }
        
        public boolean isKeyRotation() {
            return keyRotation;
        }
        
        public void setKeyRotation(boolean keyRotation) {
            this.keyRotation = keyRotation;
        }
        
        // Map "key-rotation" from YAML to keyRotation
        public void setKey_rotation(boolean keyRotation) {
            this.keyRotation = keyRotation;
        }
    }
}
