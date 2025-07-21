package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Map;
import java.util.Set;

/**
 * Service for managing introspection credentials from YAML configuration.
 * This service handles credentials specifically for the /oauth2/introspect endpoint,
 * separate from regular OAuth2 clients for enhanced security.
 */
@Service
public class IntrospectionCredentialsService {

    private Map<String, Object> introspectorConfig;

    public IntrospectionCredentialsService() {
        loadIntrospectorConfig();
    }

    private void loadIntrospectorConfig() {
        try {
            ClassPathResource resource = new ClassPathResource("introspector.yml");
            Yaml yaml = new Yaml();
            
            try (InputStream inputStream = resource.getInputStream()) {
                Map<String, Object> config = yaml.load(inputStream);
                Object introspectorsObj = config.get("introspectors");
                if (introspectorsObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> introspectors = (Map<String, Object>) introspectorsObj;
                    this.introspectorConfig = introspectors;
                } else {
                    this.introspectorConfig = null;
                }
                
                if (this.introspectorConfig == null) {
                    throw new RuntimeException("No 'introspectors' section found in introspector.yml");
                }
                
                System.out.println("Loaded " + this.introspectorConfig.size() + " introspection services from introspector.yml");
                
            }
        } catch (Exception e) {
            System.err.println("Failed to load introspector.yml: " + e.getMessage());
            throw new RuntimeException("Could not load introspection credentials configuration", e);
        }
    }

    /**
     * Get all introspector service names
     */
    public Set<String> getAllIntrospectorNames() {
        return introspectorConfig.keySet();
    }

    /**
     * Get all introspector configurations
     */
    public Map<String, Object> getAllIntrospectors() {
        return introspectorConfig;
    }

    /**
     * Get client ID for a specific introspector service
     */
    public String getClientId(String introspectorName) {
        Map<String, Object> introspector = getIntrospectorConfig(introspectorName);
        return (String) introspector.get("client-id");
    }

    /**
     * Get client secret for a specific introspector service
     */
    public String getClientSecret(String introspectorName) {
        Map<String, Object> introspector = getIntrospectorConfig(introspectorName);
        return (String) introspector.get("client-secret");
    }

    /**
     * Get display name for a specific introspector service
     */
    public String getClientName(String introspectorName) {
        Map<String, Object> introspector = getIntrospectorConfig(introspectorName);
        return (String) introspector.get("client-name");
    }

    /**
     * Get description for a specific introspector service
     */
    public String getDescription(String introspectorName) {
        Map<String, Object> introspector = getIntrospectorConfig(introspectorName);
        return (String) introspector.get("description");
    }

    /**
     * Validate introspector credentials
     */
    public boolean validateCredentials(String clientId, String clientSecret) {
        for (String introspectorName : introspectorConfig.keySet()) {
            try {
                String configClientId = getClientId(introspectorName);
                String configClientSecret = getClientSecret(introspectorName);
                
                if (clientId.equals(configClientId) && clientSecret.equals(configClientSecret)) {
                    System.out.println("Valid introspection credentials for service: " + introspectorName + " (client: " + clientId + ")");
                    return true;
                }
            } catch (Exception e) {
                System.err.println("Error validating credentials for introspector: " + introspectorName + " - " + e.getMessage());
                // Continue checking other introspectors
            }
        }
        
        System.out.println("Invalid introspection credentials for client: " + clientId);
        return false;
    }

    /**
     * Find introspector service by client ID
     */
    public String findIntrospectorByClientId(String clientId) {
        for (String introspectorName : introspectorConfig.keySet()) {
            try {
                String configClientId = getClientId(introspectorName);
                if (clientId.equals(configClientId)) {
                    return introspectorName;
                }
            } catch (Exception e) {
                System.err.println("Error checking introspector: " + introspectorName + " - " + e.getMessage());
                // Continue checking other introspectors
            }
        }
        return null;
    }

    private Map<String, Object> getIntrospectorConfig(String introspectorName) {
        Object introspectorObj = introspectorConfig.get(introspectorName);
        if (introspectorObj instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> introspector = (Map<String, Object>) introspectorObj;
            return introspector;
        }
        throw new RuntimeException("Introspector '" + introspectorName + "' not found in configuration");
    }
}
