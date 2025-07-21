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
 * Service to load OAuth2 client configurations from YAML configuration
 */
@Service
public class ClientsService {
    
    @Value("${clients.file.path:secrets.yml}")
    private String clientsFilePath;
    
    private Map<String, Object> yamlData;
    private boolean configurationLoaded = false;
    
    public ClientsService() {
        // Configuration will be loaded lazily when first accessed
    }
    
    private void ensureConfigurationLoaded() {
        if (!configurationLoaded) {
            loadYamlConfiguration();
            configurationLoaded = true;
        }
    }
    
    private Resource getClientsResource() {
        // If the path starts with classpath: or is just a filename, use ClassPathResource
        if (clientsFilePath.startsWith("classpath:") || !clientsFilePath.contains("/")) {
            String resourcePath = clientsFilePath.startsWith("classpath:") ? 
                clientsFilePath.substring("classpath:".length()) : clientsFilePath;
            return new ClassPathResource(resourcePath);
        } else {
            // Otherwise, treat it as a file system path
            return new FileSystemResource(clientsFilePath);
        }
    }
    
    @SuppressWarnings("unchecked")
    private void loadYamlConfiguration() {
        try {
            Resource resource = getClientsResource();
            Yaml yaml = new Yaml();
            try (InputStream inputStream = resource.getInputStream()) {
                yamlData = yaml.load(inputStream);
            }
            System.out.println("Successfully loaded clients configuration from: " + clientsFilePath);
        } catch (Exception e) {
            System.err.println("Failed to load clients from " + clientsFilePath + ": " + e.getMessage());
            throw new RuntimeException("Could not load clients from " + clientsFilePath, e);
        }
    }
    
    /**
     * Get all client configurations
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getAllClients() {
        ensureConfigurationLoaded();
        Map<String, Object> clients = (Map<String, Object>) yamlData.get("clients");
        return clients != null ? clients : Map.of();
    }
    
    /**
     * Get client configuration by client name
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getClientConfig(String clientName) {
        ensureConfigurationLoaded();
        Map<String, Object> clients = (Map<String, Object>) yamlData.get("clients");
        if (clients == null) {
            return null;
        }
        return (Map<String, Object>) clients.get(clientName);
    }
    
    /**
     * Get client ID for a specific client name
     */
    public String getClientId(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        return clientConfig != null ? (String) clientConfig.get("client-id") : null;
    }
    
    /**
     * Get client secret for a specific client name
     */
    public String getClientSecret(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        return clientConfig != null ? (String) clientConfig.get("client-secret") : null;
    }
    
    /**
     * Get client display name for a specific client name
     */
    public String getClientDisplayName(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        return clientConfig != null ? (String) clientConfig.get("client-name") : clientName;
    }
    
    /**
     * Get scopes for a specific client name
     */
    @SuppressWarnings("unchecked")
    public List<String> getClientScopes(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            return List.of("read"); // Default scope
        }
        
        Object scopes = clientConfig.get("scopes");
        if (scopes instanceof List) {
            return (List<String>) scopes;
        }
        return List.of("read"); // Default scope
    }
    
    /**
     * Get access token TTL for a specific client name (in minutes)
     */
    public Duration getAccessTokenTtl(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            return Duration.ofMinutes(5); // Default TTL
        }
        
        Object ttl = clientConfig.get("access-token-ttl");
        if (ttl instanceof Integer) {
            return Duration.ofMinutes((Integer) ttl);
        }
        return Duration.ofMinutes(5); // Default TTL
    }
}
