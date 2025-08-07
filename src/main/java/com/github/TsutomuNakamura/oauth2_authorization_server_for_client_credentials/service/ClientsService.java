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
    
    // YAML configuration constants
    private static final String CLIENTS_SECTION = "clients";
    private static final String CLIENT_ID_FIELD = "client-id";
    private static final String CLIENT_SECRET_FIELD = "client-secret";
    private static final String CLIENT_NAME_FIELD = "client-name";
    private static final String SCOPES_FIELD = "scopes";
    private static final String ACCESS_TOKEN_TTL_FIELD = "access-token-ttl";
    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final String DEFAULT_SCOPE = "read";
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    
    @Value("${clients.file.path:clients.yml}")
    private String clientsFilePath;
    
    private Map<String, Object> yamlData;
    private volatile boolean configurationLoaded = false;
    
    public ClientsService() {
        // Configuration will be loaded lazily when first accessed
    }
    
    /**
     * Ensures the YAML configuration is loaded using double-checked locking pattern.
     * 
     * <p>This method implements thread-safe lazy initialization of the configuration.
     * The double-checked locking pattern ensures that even in multi-threaded 
     * environments, the configuration is loaded exactly once.</p>
     * 
     * <p>Thread Safety: Uses synchronized block with volatile boolean flag.</p>
     */
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
    
    private Resource getClientsResource() {
        // If the path starts with classpath: or is just a filename, use ClassPathResource
        if (clientsFilePath.startsWith(CLASSPATH_PREFIX) || !clientsFilePath.contains("/")) {
            String resourcePath = clientsFilePath.startsWith(CLASSPATH_PREFIX) ? 
                clientsFilePath.substring(CLASSPATH_PREFIX.length()) : clientsFilePath;
            return new ClassPathResource(resourcePath);
        } else {
            // Otherwise, treat it as a file system path
            return new FileSystemResource(clientsFilePath);
        }
    }
    
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
     * Helper method to get clients section from YAML data
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> getClientsSection() {
        ensureConfigurationLoaded();
        return (Map<String, Object>) yamlData.get(CLIENTS_SECTION);
    }

    /**
     * Get all client configurations
     */
    public Map<String, Object> getAllClients() {
        Map<String, Object> clients = getClientsSection();
        return clients != null ? clients : Map.of();
    }
    
    /**
     * Get client configuration by client name
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getClientConfig(String clientName) {
        Map<String, Object> clients = getClientsSection();
        if (clients == null) {
            return null;
        }
        return (Map<String, Object>) clients.get(clientName);
    }
    
    /**
     * Helper method to get client attribute with optional default value
     */
    private String getClientAttribute(String clientName, String attributeName, String defaultValue) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        return clientConfig != null ? (String) clientConfig.get(attributeName) : defaultValue;
    }

    /**
     * Get client ID for a specific client name
     */
    public String getClientId(String clientName) {
        return getClientAttribute(clientName, CLIENT_ID_FIELD, null);
    }
    
    /**
     * Get client secret for a specific client name
     */
    public String getClientSecret(String clientName) {
        return getClientAttribute(clientName, CLIENT_SECRET_FIELD, null);
    }
    
    /**
     * Get client display name for a specific client name
     */
    public String getClientDisplayName(String clientName) {
        return getClientAttribute(clientName, CLIENT_NAME_FIELD, clientName);
    }
    
    /**
     * Get scopes for a specific client name
     */
    @SuppressWarnings("unchecked")
    public List<String> getClientScopes(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            return List.of(DEFAULT_SCOPE); // Default scope
        }
        
        Object scopes = clientConfig.get(SCOPES_FIELD);
        if (scopes instanceof List) {
            return (List<String>) scopes;
        }
        return List.of(DEFAULT_SCOPE); // Default scope
    }
    
    /**
     * Get access token TTL for a specific client name (in minutes)
     */
    public Duration getAccessTokenTtl(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            return DEFAULT_TTL; // Default TTL
        }
        
        Object ttl = clientConfig.get(ACCESS_TOKEN_TTL_FIELD);
        if (ttl instanceof Integer) {
            return Duration.ofMinutes((Integer) ttl);
        }
        return DEFAULT_TTL; // Default TTL
    }
}
