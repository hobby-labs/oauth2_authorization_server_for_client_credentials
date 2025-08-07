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
 * Service for managing OAuth2 client configurations from YAML configuration files.
 * 
 * <p>This service provides thread-safe loading and access to OAuth2 client configurations 
 * defined in YAML configuration files. It supports both classpath and filesystem 
 * resources, with lazy loading and caching for optimal performance.</p>
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
 * }</pre>
 * 
 * <p>Thread Safety: This class is thread-safe through the use of volatile fields
 * and double-checked locking pattern for configuration loading.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
@Service
public class ClientsService {
    
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
    
    /** Flag to ensure configuration is loaded only once using double-checked locking. */
    private volatile boolean configurationLoaded = false;
    
    /**
     * Constructs a new ClientsService instance.
     * 
     * <p>Configuration loading is deferred until the first access to maintain
     * lazy initialization and improve startup performance.</p>
     */
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
    
    /**
     * Loads and parses the YAML configuration file containing client definitions.
     * 
     * <p>This method loads the YAML configuration from the resource determined by
     * {@link #getClientsResource()} and stores the parsed data for subsequent access.</p>
     * 
     * <p>Error Handling: Wraps any loading exceptions in RuntimeException with
     * descriptive error messages including the file path.</p>
     * 
     * @throws RuntimeException if the configuration file cannot be loaded or parsed
     */
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
     * Retrieves the clients section from the YAML configuration data.
     * 
     * <p>This method ensures the configuration is loaded and returns the clients
     * section for efficient repeated access. The clients section contains all
     * OAuth2 client definitions.</p>
     * 
     * @return the clients section as a Map, or null if not present
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> getClientsSection() {
        ensureConfigurationLoaded();
        return (Map<String, Object>) yamlData.get(CLIENTS_SECTION);
    }

    /**
     * Retrieves all OAuth2 client configurations from the YAML file.
     * 
     * <p>This method returns a Map containing all client definitions, where
     * keys are client names and values are client configuration objects.</p>
     * 
     * @return a Map of all client configurations, or an empty Map if no clients are defined
     */
    public Map<String, Object> getAllClients() {
        Map<String, Object> clients = getClientsSection();
        return clients != null ? clients : Map.of();
    }
    
    /**
     * Retrieves the configuration for a specific OAuth2 client by name.
     * 
     * <p>This method looks up a client configuration in the clients section and
     * returns the complete configuration object for the specified client.</p>
     * 
     * @param clientName the name of the client to retrieve configuration for
     * @return the client configuration as a Map containing all client metadata,
     *         or null if the client is not found
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
     * Retrieves a string attribute from a client configuration with optional default value.
     * 
     * <p>This helper method safely looks up a string attribute in a client's configuration.
     * It handles null client configurations gracefully by returning the specified default value.</p>
     * 
     * @param clientName the name of the client to retrieve the attribute from
     * @param attributeName the name of the attribute to retrieve
     * @param defaultValue the default value to return if the attribute is not found or client doesn't exist
     * @return the attribute value, or the default value if not found or client doesn't exist
     */
    private String getClientAttribute(String clientName, String attributeName, String defaultValue) {
        Map<String, Object> clientConfig = getClientConfig(clientName);
        return clientConfig != null ? (String) clientConfig.get(attributeName) : defaultValue;
    }

    /**
     * Retrieves the OAuth2 client ID for a specific client.
     * 
     * <p>The client ID is used for OAuth2 authentication and authorization flows.
     * This is a required field for OAuth2 client registration.</p>
     * 
     * @param clientName the name of the client to retrieve the ID for
     * @return the client ID, or null if the client doesn't exist or no ID is configured
     */
    public String getClientId(String clientName) {
        return getClientAttribute(clientName, CLIENT_ID_FIELD, null);
    }
    
    /**
     * Retrieves the OAuth2 client secret for a specific client.
     * 
     * <p>The client secret is used for OAuth2 client authentication.
     * This is a required field for confidential OAuth2 clients.</p>
     * 
     * @param clientName the name of the client to retrieve the secret for
     * @return the client secret, or null if the client doesn't exist or no secret is configured
     */
    public String getClientSecret(String clientName) {
        return getClientAttribute(clientName, CLIENT_SECRET_FIELD, null);
    }
    
    /**
     * Retrieves the display name for a specific client.
     * 
     * <p>The display name provides a human-readable name for the client,
     * useful for user interfaces and logging. If no display name is configured,
     * the client name itself is returned as a fallback.</p>
     * 
     * @param clientName the name of the client to retrieve the display name for
     * @return the client display name, or the client name if no display name is configured
     */
    public String getClientDisplayName(String clientName) {
        return getClientAttribute(clientName, CLIENT_NAME_FIELD, clientName);
    }
    
    /**
     * Retrieves the OAuth2 scopes for a specific client.
     * 
     * <p>OAuth2 scopes define the permissions that the client can request.
     * If no scopes are configured or the client doesn't exist, returns a list
     * containing the default scope.</p>
     * 
     * <p>Expected YAML format:</p>
     * <pre>{@code
     * scopes: ["read", "write", "admin"]
     * }</pre>
     * 
     * @param clientName the name of the client to retrieve scopes for
     * @return a List of OAuth2 scopes, or a list containing the default scope if not configured
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
     * Retrieves the access token time-to-live (TTL) for a specific client.
     * 
     * <p>The access token TTL determines how long access tokens issued for this
     * client will remain valid. The value should be specified in minutes in the
     * YAML configuration.</p>
     * 
     * <p>Expected YAML format:</p>
     * <pre>{@code
     * access-token-ttl: 60  # 60 minutes
     * }</pre>
     * 
     * @param clientName the name of the client to retrieve the TTL for
     * @return the access token TTL as a Duration, or the default TTL if not configured
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
