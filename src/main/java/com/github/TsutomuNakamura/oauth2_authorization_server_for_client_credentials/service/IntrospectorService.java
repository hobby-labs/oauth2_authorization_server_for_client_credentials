package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.time.Duration;
import java.util.Map;
import java.util.List;

/**
 * Service to load OAuth2 introspector configurations from YAML configuration
 */
@Service
public class IntrospectorService {
    
    @Value("${introspectors.file.path:introspector.yml}")
    private String introspectorsFilePath;
    
    private Map<String, Object> yamlData;
    private boolean configurationLoaded = false;
    
    public IntrospectorService() {
        // Configuration will be loaded lazily when first accessed
    }
    
    private void ensureConfigurationLoaded() {
        if (!configurationLoaded) {
            loadYamlConfiguration();
            configurationLoaded = true;
        }
    }
    
    private Resource getIntrospectorsResource() {
        // If the path starts with classpath: or is just a filename, use ClassPathResource
        if (introspectorsFilePath.startsWith("classpath:") || !introspectorsFilePath.contains("/")) {
            String resourcePath = introspectorsFilePath.startsWith("classpath:") ? 
                introspectorsFilePath.substring("classpath:".length()) : introspectorsFilePath;
            return new ClassPathResource(resourcePath);
        } else {
            // Otherwise, treat it as a file system path
            return new FileSystemResource(introspectorsFilePath);
        }
    }
    
    @SuppressWarnings("unchecked")
    private void loadYamlConfiguration() {
        try {
            Resource resource = getIntrospectorsResource();
            Yaml yaml = new Yaml();
            try (InputStream inputStream = resource.getInputStream()) {
                yamlData = yaml.load(inputStream);
            }
            System.out.println("Successfully loaded introspectors configuration from: " + introspectorsFilePath);
        } catch (Exception e) {
            System.err.println("Failed to load introspectors from " + introspectorsFilePath + ": " + e.getMessage());
            throw new RuntimeException("Could not load introspectors from " + introspectorsFilePath, e);
        }
    }
    
    /**
     * Get all introspectors configurations
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getAllIntrospectors() {
        ensureConfigurationLoaded();
        Map<String, Object> introspectors = (Map<String, Object>) yamlData.get("introspectors");
        return introspectors != null ? introspectors : Map.of();
    }
    
    /**
     * Get introspector configuration by introspector name
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getIntrospectorConfig(String introspectorName) {
        ensureConfigurationLoaded();
        Map<String, Object> introspectors = (Map<String, Object>) yamlData.get("introspectors");
        if (introspectors == null) {
            return null;
        }
        return (Map<String, Object>) introspectors.get(introspectorName);
    }
    
    /**
     * Get introspector ID for a specific introspector name
     */
    public String getIntrospectorId(String introspectorName) {
        Map<String, Object> introspectorConfig = getIntrospectorConfig(introspectorName);
        return introspectorConfig != null ? (String) introspectorConfig.get("introspector-id") : null;
    }
    
    /**
     * Get introspector secret for a specific introspector name
     */
    public String getIntrospectorSecret(String introspectorName) {
        Map<String, Object> introspectorConfig = getIntrospectorConfig(introspectorName);
        return introspectorConfig != null ? (String) introspectorConfig.get("introspector-secret") : null;
    }
    
    /**
     * Get introspector display name for a specific introspector name
     */
    public String getIntrospectorDisplayName(String introspectorName) {
        Map<String, Object> introspectorConfig = getIntrospectorConfig(introspectorName);
        return introspectorConfig != null ? (String) introspectorConfig.get("introspector-name") : introspectorName;
    }
    
    /**
     * Get scopes for a specific introspector name
     */
    @SuppressWarnings("unchecked")
    public List<String> getIntrospectorScopes(String introspectorName) {
        Map<String, Object> introspectorConfig = getIntrospectorConfig(introspectorName);
        if (introspectorConfig == null) {
            return List.of("read"); // Default scope
        }
        
        Object scopes = introspectorConfig.get("scopes");
        if (scopes instanceof List) {
            return (List<String>) scopes;
        }
        return List.of("read"); // Default scope
    }
    
    /**
     * Get access token TTL for a specific introspector name (in minutes)
     */
    public Duration getAccessTokenTtl(String introspectorName) {
        Map<String, Object> introspectorConfig = getIntrospectorConfig(introspectorName);
        if (introspectorConfig == null) {
            return Duration.ofMinutes(5); // Default TTL
        }
        
        Object ttl = introspectorConfig.get("access-token-ttl");
        if (ttl instanceof Integer) {
            return Duration.ofMinutes((Integer) ttl);
        }
        return Duration.ofMinutes(5); // Default TTL
    }
}
