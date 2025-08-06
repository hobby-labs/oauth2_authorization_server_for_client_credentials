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
 * Service for managing cryptographic keys from YAML configuration files.
 * 
 * <p>This service provides thread-safe loading and access to cryptographic keys 
 * defined in YAML configuration files. It supports both classpath and filesystem 
 * resources, with lazy loading and caching for optimal performance.</p>
 * 
 * <p>The expected YAML structure includes:</p>
 * <ul>
 * <li>A {@code config} section with the primary key configuration</li>
 * <li>A {@code keys} section with individual key definitions</li>
 * <li>Each key containing private/public PEM strings and metadata</li>
 * </ul>
 * 
 * <p>Thread Safety: This class is thread-safe through the use of volatile fields
 * and double-checked locking pattern for configuration loading.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
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
    
    /**
     * The path to the keys configuration file.
     * Defaults to "keys.yml" if not specified via application properties.
     * Supports both classpath and filesystem paths.
     */
    @Value("${keys.file.path:keys.yml}")
    private String keysFilePath;
    
    /** Raw YAML data loaded from the configuration file. */
    private Map<String, Object> yamlData;
    
    /** Cached config section for performance optimization. */
    private volatile Map<String, Object> configCache;
    
    /** Cached keys section for performance optimization. */
    private volatile Map<String, Object> keysCache;
    
    /** Flag to ensure configuration is loaded only once. */
    private volatile boolean configurationLoaded = false;
    
    /**
     * Constructs a new KeysService instance.
     * 
     * <p>Configuration loading is deferred until the first access to maintain
     * lazy initialization and improve startup performance.</p>
     */
    public KeysService() {
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
     * Resolves the appropriate Resource for the keys configuration file.
     * 
     * <p>This method supports both classpath and filesystem resources:</p>
     * <ul>
     * <li>Paths starting with "classpath:" are treated as classpath resources</li>
     * <li>Simple filenames (no "/") are treated as classpath resources</li>
     * <li>All other paths are treated as filesystem resources</li>
     * </ul>
     * 
     * @return a Resource pointing to the keys configuration file
     */
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
    
    /**
     * Loads and parses the YAML configuration file.
     * 
     * <p>This method loads the YAML configuration from the resource determined by
     * {@link #getKeysResource()} and caches the commonly used sections (config and keys)
     * for performance optimization.</p>
     * 
     * <p>Error Handling: Wraps any loading exceptions in RuntimeException with
     * descriptive error messages including the file path.</p>
     * 
     * @throws RuntimeException if the configuration file cannot be loaded or parsed
     */
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
     * Retrieves the configuration section from the YAML data.
     * 
     * <p>This method ensures the configuration is loaded and returns the cached
     * config section for efficient repeated access.</p>
     * 
     * @return the configuration section as a Map
     */
    private Map<String, Object> getConfig() {
        ensureConfigurationLoaded();
        return configCache;
    }
    
    /**
     * Retrieves the keys section from the YAML data.
     * 
     * <p>This method ensures the configuration is loaded and returns the cached
     * keys section for efficient repeated access.</p>
     * 
     * @return the keys section as a Map
     */
    private Map<String, Object> getKeys() {
        ensureConfigurationLoaded();
        return keysCache;
    }
    
    /**
     * Retrieves the name of the primary key from the configuration.
     * 
     * <p>The primary key is defined in the config section under the "primary-key" field
     * and serves as the default key for cryptographic operations.</p>
     * 
     * @return the primary key name as configured in the YAML file
     */
    public String getPrimaryKeyName() {
        return (String) getConfig().get(PRIMARY_KEY_FIELD);
    }
    
    /**
     * Retrieves the configuration for a specific key by name.
     * 
     * <p>This method looks up a key configuration in the keys section and
     * validates that the key exists.</p>
     * 
     * @param keyName the name of the key to retrieve configuration for
     * @return the key configuration as a Map containing key metadata and PEM strings
     * @throws IllegalArgumentException if the specified key is not found
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
     * Retrieves the configuration for the primary key.
     * 
     * <p>This is a convenience method that combines {@link #getPrimaryKeyName()}
     * and {@link #getKeyConfig(String)} to get the primary key's configuration.</p>
     * 
     * @return the primary key configuration as a Map
     * @throws IllegalArgumentException if the primary key is not found
     */
    private Map<String, Object> getPrimaryKeyConfig() {
        String primaryKeyName = getPrimaryKeyName();
        return getKeyConfig(primaryKeyName);
    }
    
    /**
     * Creates a KeyPair from key configuration containing PEM strings.
     * 
     * <p>This method extracts the private and public key PEM strings from the
     * configuration and uses {@link KeyLoader} to create a KeyPair instance.</p>
     * 
     * @param keyConfig the key configuration containing "private" and "public" PEM strings
     * @return a KeyPair instance created from the PEM strings
     * @throws Exception if the PEM strings cannot be parsed or loaded
     */
    private KeyPair createKeyPairFromConfig(Map<String, Object> keyConfig) throws Exception {
        String privateKeyPem = (String) keyConfig.get(PRIVATE_KEY_FIELD);
        String publicKeyPem = (String) keyConfig.get(PUBLIC_KEY_FIELD);
        return KeyLoader.loadECFromPemStrings(privateKeyPem.trim(), publicKeyPem.trim());
    }
    
    /**
     * Retrieves an attribute from the primary key configuration with optional default value.
     * 
     * <p>This method looks up a specific attribute in the primary key's configuration
     * and returns either the found value or the provided default value if not found.</p>
     * 
     * @param attributeName the name of the attribute to retrieve
     * @param defaultValue the default value to return if the attribute is not found or null
     * @return the attribute value or the default value if not found
     */
    private String getPrimaryKeyAttribute(String attributeName, String defaultValue) {
        Map<String, Object> keyConfig = getPrimaryKeyConfig();
        String value = (String) keyConfig.get(attributeName);
        return value != null ? value : defaultValue;
    }
    
    /**
     * Retrieves an attribute from a specific key configuration with null-safe error handling.
     * 
     * <p>This method safely looks up an attribute in a named key's configuration.
     * If the key doesn't exist, it returns null instead of throwing an exception,
     * making it suitable for optional key lookups.</p>
     * 
     * @param keyName the name of the key to retrieve the attribute from
     * @param attributeName the name of the attribute to retrieve
     * @param defaultValue the default value to return if the attribute is not found or null
     * @return the attribute value, the default value if not found, or null if the key doesn't exist
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
    
    /**
     * Retrieves the KeyPair for the primary key.
     * 
     * <p>This method delegates to {@link #getKeyPair(String)} using the primary key name,
     * providing a convenient way to access the primary cryptographic key pair.</p>
     * 
     * @return the primary KeyPair instance
     * @throws Exception if the primary key cannot be loaded or parsed
     */
    public KeyPair getPrimaryKeyPair() throws Exception {
        return getKeyPair(getPrimaryKeyName());
    }
    
    /**
     * Retrieves the KeyPair for a specific key name.
     * 
     * <p>This method loads the key configuration and creates a KeyPair instance
     * from the PEM strings stored in the configuration.</p>
     * 
     * @param keyName the name of the key to retrieve
     * @return the KeyPair instance for the specified key
     * @throws Exception if the key cannot be found, loaded, or parsed
     * @throws IllegalArgumentException if the key name is not found in configuration
     */
    public KeyPair getKeyPair(String keyName) throws Exception {
        Map<String, Object> keyConfig = getKeyConfig(keyName);
        return createKeyPairFromConfig(keyConfig);
    }

    /**
     * Retrieves the key ID for the primary key.
     * 
     * <p>The key ID is used for identifying the key in JWT headers and other
     * cryptographic contexts. If not specified in configuration, returns the
     * default key ID.</p>
     * 
     * @return the primary key ID or default value if not configured
     */
    public String getPrimaryKeyId() {
        return getPrimaryKeyAttribute(KEY_ID_FIELD, DEFAULT_KEY_ID);
    }
    
    /**
     * Retrieves the algorithm for the primary key.
     * 
     * <p>The algorithm specifies the cryptographic algorithm used with this key,
     * such as "ES256" for ECDSA with SHA-256.</p>
     * 
     * @return the primary key algorithm or null if not configured
     */
    public String getPrimaryKeyAlgorithm() {
        return getPrimaryKeyAttribute(ALGORITHM_FIELD, null);
    }
    
    /**
     * Retrieves the curve type for the primary key.
     * 
     * <p>For elliptic curve keys, this specifies the curve type such as "P-256".</p>
     * 
     * @return the primary key curve type or null if not configured
     */
    public String getPrimaryKeyCurve() {
        return getPrimaryKeyAttribute(CURVE_FIELD, null);
    }

    /**
     * Retrieves all available key names from the configuration.
     * 
     * <p>This method returns a Set containing all the key names defined in the
     * keys section of the YAML configuration, useful for key enumeration and
     * validation purposes.</p>
     * 
     * @return a Set of all available key names
     */
    public java.util.Set<String> getAllKeyNames() {
        return getKeys().keySet();
    }
        
    /**
     * Retrieves the key ID for a specific key name.
     * 
     * <p>If the key ID is not explicitly configured, generates a default ID
     * by appending the default suffix to the key name.</p>
     * 
     * @param keyName the name of the key to retrieve the ID for
     * @return the key ID or a generated default ID if not configured, 
     *         or null if the key doesn't exist
     */
    public String getKeyId(String keyName) {
        return getKeyAttribute(keyName, KEY_ID_FIELD, keyName + DEFAULT_KEY_SUFFIX);
    }
    
    /**
     * Retrieves the algorithm for a specific key name.
     * 
     * <p>The algorithm specifies the cryptographic algorithm used with the key,
     * such as "ES256" for ECDSA with SHA-256.</p>
     * 
     * @param keyName the name of the key to retrieve the algorithm for
     * @return the key algorithm or null if not configured or key doesn't exist
     */
    public String getKeyAlgorithm(String keyName) {
        return getKeyAttribute(keyName, ALGORITHM_FIELD, null);
    }
    
    /**
     * Retrieves the curve type for a specific key name.
     * 
     * <p>For elliptic curve keys, this specifies the curve type such as "P-256".</p>
     * 
     * @param keyName the name of the key to retrieve the curve for
     * @return the key curve type or null if not configured or key doesn't exist
     */
    public String getKeyCurve(String keyName) {
        return getKeyAttribute(keyName, CURVE_FIELD, null);
    }
}
