package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.model.ClientConfiguration;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Map;
import java.util.List;

/**
 * Service for managing OAuth2 client configurations from YAML configuration files.
 * 
 * <p>This service loads and provides access to OAuth2 client configurations 
 * defined in YAML configuration files. It supports both classpath and filesystem 
 * resources, with eager loading at application startup for fail-fast behavior.</p>
 * 
 * <p>The expected YAML structure includes:</p>
 * <ul>
 * <li>A {@code clients} section containing individual client definitions</li>
 * <li>Each client containing OAuth2 metadata such as client-id, client-secret, scopes, etc.</li>
 * <li>Optional configuration for access token TTL and display names</li>
 * </ul>
 * 
 * <p>Example YAML structure:</p>
 * <pre>{@code
 * clients:
 *   my-client:
 *     client-id: "my-client-id"
 *     client-secret: "my-client-secret"
 *     client-name: "My Application"
 *     scopes: ["read", "write"]
 *     access-token-ttl: 60
 *     roles: ["CLIENT", "INTROSPECTOR"]
 * }</pre>
 * 
 * <p>Initialization: Configuration is loaded once during application startup using 
 * {@code @PostConstruct}. Any configuration errors will prevent application startup,
 * ensuring fail-fast behavior.</p>
 * 
 * @author TsutomuNakamura
 * @since 1.0
 */
@Service
public class ClientsService {
    
    private static final Logger logger = LoggerFactory.getLogger(ClientsService.class);
    
    // YAML configuration constants
    
    /** The name of the clients section in the YAML file. */
    private static final String CLIENTS_SECTION = "clients";
    
    /** The field name for client ID in client configurations. */
    private static final String CLIENT_ID_FIELD = "client-id";
    
    /** The field name for client secret in client configurations. */
    private static final String CLIENT_SECRET_FIELD = "client-secret";
    
    /** The field name for client display name in client configurations. */
    private static final String CLIENT_NAME_FIELD = "client-name";
    
    /** The field name for OAuth2 scopes in client configurations. */
    private static final String SCOPES_FIELD = "scopes";
    
    /** The field name for access token time-to-live in client configurations. */
    private static final String ACCESS_TOKEN_TTL_FIELD = "access-token-ttl";
    
    /** The field name for client roles in client configurations. */
    private static final String ROLES_FIELD = "roles";
    
    /** The prefix used to identify classpath resources in file paths. */
    private static final String CLASSPATH_PREFIX = "classpath:";
    
    /** The default OAuth2 scope when no scopes are specified. */
    private static final String DEFAULT_SCOPE = "read";
    
    /** The default access token time-to-live duration when not specified. */
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
    
    /**
     * The path to the clients configuration file.
     * Defaults to "clients.yml" if not specified via application properties.
     * Supports both classpath and filesystem paths.
     */
    @Value("${clients.file.path:clients.yml}")
    private String clientsFilePath;
    
    /** Raw YAML data loaded from the configuration file. */
    private Map<String, Object> yamlData;
    
    /** Cached clients section for efficient access. */
    private Map<String, Object> clientsSection;
    
    /**
     * Validates that a required string field is not null or empty.
     * 
     * @param clientName the name of the client being validated
     * @param fieldValue the field value to validate
     * @param fieldName the name of the field for error messages
     * @throws IllegalStateException if the field is null or empty
     */
    private void validateRequiredStringField(String clientName, String fieldValue, String fieldName) {
        if (fieldValue == null || fieldValue.trim().isEmpty()) {
            throw new IllegalStateException(
                "Client '" + clientName + "' is missing required field '" + fieldName + "'");
        }
    }
    
    /**
     * Validates that an optional field has the expected type.
     * 
     * @param clientName the name of the client being validated
     * @param fieldValue the field value to validate (can be null)
     * @param fieldName the name of the field for error messages
     * @param expectedType the expected type of the field
     * @throws IllegalStateException if the field exists but has wrong type
     */
    private void validateFieldType(String clientName, Object fieldValue, String fieldName, Class<?> expectedType) {
        if (fieldValue != null && !expectedType.isInstance(fieldValue)) {
            String expectedTypeName = expectedType.getSimpleName().toLowerCase();
            if (expectedType == List.class) {
                expectedTypeName = "list";
            } else if (expectedType == Integer.class) {
                expectedTypeName = "integer";
            }
            throw new IllegalStateException(
                "Client '" + clientName + "' has invalid '" + fieldName + "' field. Expected " + expectedTypeName + ".");
        }
    }
    
    /**
     * Validates that a configuration object is a Map type.
     * 
     * @param configData the configuration data to validate
     * @param description description of what the configuration represents
     * @param contextInfo additional context information for error messages
     * @throws IllegalStateException if the configuration is not a Map
     */
    private void validateMapConfiguration(Object configData, String description, String contextInfo) {
        if (!(configData instanceof Map)) {
            throw new IllegalStateException(
                "Invalid " + description + " in " + contextInfo + ". Expected a map of configuration properties.");
        }
    }
    
    /**
     * Initializes the service by loading and validating client configurations.
     * 
     * <p>This method is called automatically after dependency injection during
     * application startup. It ensures that:</p>
     * <ul>
     * <li>The configuration file exists and is readable</li>
     * <li>The YAML structure is valid</li>
     * <li>At least one client is configured</li>
     * <li>All clients have required fields (client-id and client-secret)</li>
     * </ul>
     * 
     * <p>Fail-Fast Behavior: If any validation fails, the application will not start,
     * preventing runtime configuration errors.</p>
     * 
     * @throws IllegalStateException if configuration cannot be loaded or is invalid
     */
    @PostConstruct
    public void init() {
        logger.info("Initializing ClientsService with configuration from: {}", clientsFilePath);
        loadYamlConfiguration();
        extractClientsSection();
        validateConfiguration();
        logger.info("ClientsService initialization completed successfully");
    }
    
    /**
     * Loads and parses the YAML configuration file containing client definitions.
     * 
     * <p>This method is called once during initialization and loads the entire
     * YAML configuration into memory for efficient access.</p>
     * 
     * @throws IllegalStateException if the configuration file cannot be loaded or parsed
     */
    private void loadYamlConfiguration() {
        try {
            Resource resource = getClientsResource();
            logger.debug("Loading configuration from resource: {}", resource.getDescription());
            
            Yaml yaml = new Yaml();
            try (InputStream inputStream = resource.getInputStream()) {
                yamlData = yaml.load(inputStream);
            }
            
            if (yamlData == null) {
                throw new IllegalStateException("Configuration file is empty or contains invalid YAML");
            }
            
            logger.info("Successfully loaded YAML configuration");
            
        } catch (IllegalStateException e) {
            // Re-throw IllegalStateException to preserve specific validation messages
            throw e;
        } catch (IOException e) {
            logger.error("Failed to read clients configuration file {}: {}", clientsFilePath, e.getMessage());
            throw new IllegalStateException(
                "Could not read clients configuration from " + clientsFilePath + 
                ". Check if the file exists and is readable.", e);
        } catch (YAMLException e) {
            logger.error("Invalid YAML syntax in clients configuration file {}: {}", clientsFilePath, e.getMessage());
            throw new IllegalStateException(
                "Invalid YAML syntax in clients configuration file " + clientsFilePath + 
                ". Please check the YAML format and syntax.", e);
        }
    }
    
    /**
     * Extracts and caches the clients section from the loaded YAML data.
     * 
     * <p>This method is called once during initialization to cache the clients
     * section for efficient repeated access.</p>
     * 
     * @throws IllegalStateException if the clients section is not found in the configuration
     */
    @SuppressWarnings("unchecked")
    private void extractClientsSection() {
        Object clientsData = yamlData.get(CLIENTS_SECTION);
        if (clientsData == null) {
            throw new IllegalStateException(
                "No 'clients' section found in configuration file " + clientsFilePath + 
                ". Expected a 'clients:' section containing client definitions.");
        }
        
        validateMapConfiguration(clientsData, "'clients' section", "configuration file " + clientsFilePath);
        
        clientsSection = (Map<String, Object>) clientsData;
        logger.debug("Extracted clients section with {} entries", clientsSection.size());
    }
    
    /**
     * Validates the loaded configuration to ensure all required fields are present.
     * 
     * <p>This method performs comprehensive validation including:</p>
     * <ul>
     * <li>At least one client must be configured</li>
     * <li>Each client must have a client-id</li>
     * <li>Each client must have a client-secret</li>
     * <li>Validates data types for optional fields</li>
     * </ul>
     * 
     * @throws IllegalStateException if validation fails
     */
    private void validateConfiguration() {
        if (clientsSection.isEmpty()) {
            throw new IllegalStateException(
                "No clients configured in " + clientsFilePath + 
                ". At least one client must be configured.");
        }
        
        for (Map.Entry<String, Object> entry : clientsSection.entrySet()) {
            String clientName = entry.getKey();
            validateClient(clientName);
        }
        
        logger.info("Validated {} client configuration(s)", clientsSection.size());
    }
    
    /**
     * Validates an individual client configuration.
     * 
     * @param clientName the name of the client to validate
     * @throws IllegalStateException if the client configuration is invalid
     */
    @SuppressWarnings("unchecked")
    private void validateClient(String clientName) {
        Object clientData = clientsSection.get(clientName);
        validateMapConfiguration(clientData, "configuration for client '" + clientName + "'", "clients section");
        
        Map<String, Object> clientConfig = (Map<String, Object>) clientData;
        
        // Validate required fields using utility method
        String clientId = (String) clientConfig.get(CLIENT_ID_FIELD);
        validateRequiredStringField(clientName, clientId, CLIENT_ID_FIELD);
        
        String clientSecret = (String) clientConfig.get(CLIENT_SECRET_FIELD);
        validateRequiredStringField(clientName, clientSecret, CLIENT_SECRET_FIELD);
        
        // Validate optional fields have correct types
        validateOptionalFields(clientName, clientConfig);
        
        logger.debug("Validated client '{}' (ID: {})", clientName, clientId);
    }
    
    /**
     * Validates optional fields in a client configuration.
     * 
     * @param clientName the name of the client being validated
     * @param clientConfig the client configuration map
     */
    private void validateOptionalFields(String clientName, Map<String, Object> clientConfig) {
        // Validate scopes field type using utility method
        Object scopes = clientConfig.get(SCOPES_FIELD);
        if (scopes != null) {
            validateFieldType(clientName, scopes, SCOPES_FIELD, List.class);
        }
        
        // Validate roles field type using utility method
        Object roles = clientConfig.get(ROLES_FIELD);
        if (roles != null) {
            validateFieldType(clientName, roles, ROLES_FIELD, List.class);
        }
        
        // Validate access-token-ttl field type using utility method
        Object ttl = clientConfig.get(ACCESS_TOKEN_TTL_FIELD);
        if (ttl != null) {
            validateFieldType(clientName, ttl, ACCESS_TOKEN_TTL_FIELD, Integer.class);
        }
    }
    
    /**
     * Resolves the appropriate Resource for the clients configuration file.
     * 
     * <p>This method supports both classpath and filesystem resources:</p>
     * <ul>
     * <li>Paths starting with "classpath:" are treated as classpath resources</li>
     * <li>Simple filenames (no "/") are treated as classpath resources</li>
     * <li>All other paths are treated as filesystem resources</li>
     * </ul>
     * 
     * @return a Resource pointing to the clients configuration file
     */
    private Resource getClientsResource() {
        if (clientsFilePath.startsWith(CLASSPATH_PREFIX) || !clientsFilePath.contains("/")) {
            String resourcePath = clientsFilePath.startsWith(CLASSPATH_PREFIX) ? 
                clientsFilePath.substring(CLASSPATH_PREFIX.length()) : clientsFilePath;
            return new ClassPathResource(resourcePath);
        } else {
            return new FileSystemResource(clientsFilePath);
        }
    }
    
    /**
     * Retrieves all OAuth2 client configurations from the YAML file.
     * 
     * @return a Map of all client configurations, never null
     */
    public Map<String, Object> getAllClients() {
        return clientsSection != null ? clientsSection : Map.of();
    }
    
    /**
     * Retrieves the configuration for a specific OAuth2 client by name.
     * 
     * @param clientName the name of the client to retrieve configuration for
     * @return the client configuration as a Map, or null if not found
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getClientConfig(String clientName) {
        if (clientsSection == null) {
            return null;
        }
        return (Map<String, Object>) clientsSection.get(clientName);
    }
    
    /**
     * Retrieves a string attribute from a client configuration.
     * 
     * @param clientName the name of the client
     * @param attributeName the name of the attribute
     * @param defaultValue the default value if not found
     * @return the attribute value or default
     */
    private String getClientAttribute(String clientName, String attributeName, String defaultValue) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            return defaultValue;
        }
        Object value = clientConfig.get(attributeName);
        return value != null ? value.toString() : defaultValue;
    }

    /**
     * Retrieves the OAuth2 client ID for a specific client.
     * 
     * @param clientName the name of the client
     * @return the client ID, or null if not found
     */
    public String getClientId(String clientName) {
        return getClientAttribute(clientName, CLIENT_ID_FIELD, null);
    }
    
    /**
     * Retrieves the OAuth2 client secret for a specific client.
     * 
     * @param clientName the name of the client
     * @return the client secret, or null if not found
     */
    public String getClientSecret(String clientName) {
        return getClientAttribute(clientName, CLIENT_SECRET_FIELD, null);
    }
    
    /**
     * Retrieves the display name for a specific client.
     * 
     * @param clientName the name of the client
     * @return the display name, or the client name if not configured
     */
    public String getClientDisplayName(String clientName) {
        return getClientAttribute(clientName, CLIENT_NAME_FIELD, clientName);
    }
    
    /**
     * Retrieves the OAuth2 scopes for a specific client.
     * 
     * @param clientName the name of the client
     * @return a List of scopes, or default scope if not configured
     */
    @SuppressWarnings("unchecked")
    public List<String> getClientScopes(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            return List.of(DEFAULT_SCOPE);
        }
        
        Object scopes = clientConfig.get(SCOPES_FIELD);
        if (scopes instanceof List) {
            return (List<String>) scopes;
        }
        return List.of(DEFAULT_SCOPE);
    }
    
    /**
     * Retrieves the access token TTL for a specific client.
     * 
     * @param clientName the name of the client
     * @return the TTL as Duration, or default if not configured
     */
    public Duration getAccessTokenTtl(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            return DEFAULT_TTL;
        }
        
        Object ttl = clientConfig.get(ACCESS_TOKEN_TTL_FIELD);
        if (ttl instanceof Integer) {
            return Duration.ofMinutes((Integer) ttl);
        }
        return DEFAULT_TTL;
    }
    
    /**
     * Retrieves the roles for a specific client.
     * 
     * @param clientName the name of the client
     * @return a List of roles, or empty list if not configured
     */
    @SuppressWarnings("unchecked")
    public List<String> getClientRoles(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            return List.of();
        }
        
        Object roles = clientConfig.get(ROLES_FIELD);
        if (roles instanceof List) {
            return (List<String>) roles;
        }
        return List.of();
    }
    
    /**
     * Checks if a client has a specific role.
     * 
     * @param clientName the name of the client
     * @param role the role to check
     * @return true if the client has the role
     */
    public boolean clientHasRole(String clientName, String role) {
        return getClientRoles(clientName).contains(role);
    }
    
    /**
     * Creates a complete ClientConfiguration object for a client.
     * 
     * @param clientName the name of the client
     * @return a ClientConfiguration object
     * @throws IllegalArgumentException if client not found or invalid
     */
    public ClientConfiguration getClientConfiguration(String clientName) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        if (clientConfig == null) {
            throw new IllegalArgumentException("Client '" + clientName + "' not found in configuration");
        }
        
        try {
            return new ClientConfiguration(
                getClientId(clientName),
                getClientSecret(clientName),
                getClientDisplayName(clientName),
                getClientScopes(clientName),
                getAccessTokenTtl(clientName),
                getClientRoles(clientName)
            );
        } catch (Exception e) {
            throw new IllegalArgumentException(
                "Invalid configuration for client '" + clientName + "': " + e.getMessage(), e);
        }
    }
}
