package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.security.KeyPair;
import java.util.Map;
import java.util.Set;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.KeysConfiguration;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ConfigSection;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.KeyConfiguration;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ChainConfiguration;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.KeyLoader;

/**
 * Service for managing cryptographic keys from YAML configuration files.
 * 
 * <p>This service provides access to cryptographic keys defined in YAML configuration 
 * files. It supports both classpath and filesystem resources, with eager loading at 
 * application startup for fail-fast behavior.</p>
 * 
 * <p>The expected YAML structure includes:</p>
 * <ul>
 * <li>A {@code config} section with the primary key configuration</li>
 * <li>A {@code keys} section with individual key definitions</li>
 * <li>Each key containing private/public PEM strings and metadata</li>
 * </ul>
 * 
 * <p>Initialization: Configuration is loaded once during application startup using 
 * {@code @PostConstruct}. Any configuration errors will prevent application startup,
 * ensuring fail-fast behavior.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 */
@Service
public class KeysService {
    
    /** Logger for this service. */
    private static final Logger logger = LoggerFactory.getLogger(KeysService.class);
    
    // YAML configuration constants (for attribute name matching)
    
    /** The field name for key ID in key configurations. */
    private static final String KEY_ID_FIELD = "keyId";
    
    /** The field name for algorithm specification in key configurations. */
    private static final String ALGORITHM_FIELD = "algorithm";
    
    /** The field name for curve type specification in key configurations. */
    private static final String CURVE_FIELD = "curve";
    
    /** The field name for authority reference in key configurations. */
    private static final String AUTHORITY_FIELD = "authority";
    
    /** The prefix used to identify classpath resources in file paths. */
    private static final String CLASSPATH_PREFIX = "classpath:";
    
    /** The default key ID used when no key ID is specified in configuration. */
    private static final String DEFAULT_KEY_ID = "ec-key-from-yaml";
    
    /** The suffix appended to key names when generating default key IDs. */
    private static final String DEFAULT_KEY_SUFFIX = "-default";
    
    /**
     * The path to the keys configuration file.
     * Defaults to "keys.yml" if not specified via application properties.
     * Supports both classpath and filesystem paths.
     */
    @Value("${keys.file.path:keys.yml}")
    private String keysFilePath;
    
    /** Type-safe configuration loaded from the YAML file. */
    private KeysConfiguration keysConfiguration;
    
    /**
     * Constructs a new KeysService instance.
     * 
     * <p>Configuration loading is performed during application startup via
     * the {@code @PostConstruct} method for fail-fast initialization.</p>
     */
    public KeysService() {
        // Configuration will be loaded during @PostConstruct initialization
    }
    
    /**
     * Initializes the KeysService by loading the YAML configuration.
     * 
     * <p>This method is called automatically by Spring after the bean is constructed
     * and all dependencies are injected. Any configuration errors will prevent
     * application startup, ensuring fail-fast behavior.</p>
     * 
     * @throws RuntimeException if configuration cannot be loaded or is invalid
     */
    @PostConstruct
    public void init() {
        logger.info("Initializing KeysService with configuration from: {}", keysFilePath);
        loadYamlConfiguration();
        logger.info("KeysService initialization completed successfully");
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
     * Loads and parses the YAML configuration file into type-safe DTOs.
     * 
     * <p>This method loads the YAML configuration from the resource determined by
     * {@link #getKeysResource()} and converts it to type-safe DTOs using Jackson's
     * ObjectMapper for reliable type conversion.</p>
     * 
     * <p>Error Handling: Wraps any loading exceptions in RuntimeException with
     * descriptive error messages including the file path.</p>
     * 
     * @throws RuntimeException if the configuration file cannot be loaded or parsed
     */
    private void loadYamlConfiguration() {
        try {
            Resource resource = getKeysResource();
            logger.debug("Loading keys configuration from resource: {}", resource);
            
            // Load YAML data using SnakeYAML
            Yaml yaml = new Yaml();
            Object yamlData;
            try (InputStream inputStream = resource.getInputStream()) {
                yamlData = yaml.load(inputStream);
                if (yamlData == null) {
                    throw new RuntimeException("Configuration file is empty or contains invalid YAML");
                }
            }
            
            // Convert to type-safe DTOs using Jackson
            ObjectMapper mapper = new ObjectMapper();
            keysConfiguration = mapper.convertValue(yamlData, KeysConfiguration.class);
            
            if (keysConfiguration == null) {
                throw new RuntimeException("Failed to parse configuration into type-safe structure");
            }
            
            int keysCount = keysConfiguration.getKeys() != null ? keysConfiguration.getKeys().size() : 0;
            logger.debug("Successfully loaded keys configuration with {} keys", keysCount);
            
        } catch (Exception e) {
            logger.error("Failed to load keys from {}: {}", keysFilePath, e.getMessage());
            throw new RuntimeException("Could not load keys from " + keysFilePath, e);
        }
    }
    
    /**
     * Retrieves the configuration section from the YAML data.
     * 
     * <p>This method returns the type-safe config section for efficient repeated access.
     * Configuration is guaranteed to be loaded since it's loaded during initialization.</p>
     * 
     * @return the configuration section
     */
    private ConfigSection getConfig() {
        return keysConfiguration.getConfig();
    }
    
    /**
     * Retrieves the keys section from the YAML data.
     * 
     * <p>This method returns the type-safe keys section for efficient repeated access.
     * Configuration is guaranteed to be loaded since it's loaded during initialization.</p>
     * 
     * @return the keys section as a Map
     */
    private Map<String, KeyConfiguration> getKeys() {
        return keysConfiguration.getKeys();
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
        return getConfig().getPrimaryKey();
    }
    
    /**
     * Retrieves the configuration for a specific key by name.
     * 
     * <p>This method looks up a key configuration in the keys section and
     * validates that the key exists.</p>
     * 
     * @param keyName the name of the key to retrieve configuration for
     * @return the key configuration containing key metadata and PEM strings
     * @throws IllegalArgumentException if the specified key is not found
     */
    private KeyConfiguration getKeyConfig(String keyName) {
        Map<String, KeyConfiguration> keys = getKeys();
        KeyConfiguration keyConfig = keys.get(keyName);
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
     * @return the primary key configuration
     * @throws IllegalArgumentException if the primary key is not found
     */
    private KeyConfiguration getPrimaryKeyConfig() {
        String primaryKeyName = getPrimaryKeyName();
        return getKeyConfig(primaryKeyName);
    }
    
    /**
     * Creates a KeyPair from key configuration containing PEM strings.
     * 
     * <p>This method extracts the private and public key PEM strings from the
     * configuration and uses {@link KeyLoader} to create a KeyPair instance.</p>
     * 
     * @param keyConfig the key configuration containing private and public PEM strings
     * @return a KeyPair instance created from the PEM strings
     * @throws Exception if the PEM strings cannot be parsed or loaded
     */
    private KeyPair createKeyPairFromConfig(KeyConfiguration keyConfig) throws Exception {
        String privateKeyPem = keyConfig.getPrivateKey();
        String publicKeyPem = keyConfig.getPublicKey();
        return KeyLoader.loadECFromPemStrings(privateKeyPem.trim(), publicKeyPem.trim());
    }
    
    /**
     * Retrieves an attribute from the primary key configuration with optional default value.
     * 
     * <p>This method looks up a specific attribute in the primary key's configuration
     * and returns either the found value or the provided default value if not found.</p>
     * 
     * @param attributeName the name of the attribute to retrieve (keyId, algorithm, curve, authority)
     * @param defaultValue the default value to return if the attribute is not found or null
     * @return the attribute value or the default value if not found
     */
    private String getPrimaryKeyAttribute(String attributeName, String defaultValue) {
        KeyConfiguration keyConfig = getPrimaryKeyConfig();
        String value = switch (attributeName) {
            case KEY_ID_FIELD -> keyConfig.getKeyId();
            case ALGORITHM_FIELD -> keyConfig.getAlgorithm();
            case CURVE_FIELD -> keyConfig.getCurve();
            case AUTHORITY_FIELD -> keyConfig.getAuthority();
            default -> throw new IllegalArgumentException("Unknown attribute: " + attributeName);
        };
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
     * @param attributeName the name of the attribute to retrieve (keyId, algorithm, curve, authority)
     * @param defaultValue the default value to return if the attribute is not found or null
     * @return the attribute value, the default value if not found, or null if the key doesn't exist
     */
    private String getKeyAttribute(String keyName, String attributeName, String defaultValue) {
        try {
            KeyConfiguration keyConfig = getKeyConfig(keyName);
            String value = switch (attributeName) {
                case KEY_ID_FIELD -> keyConfig.getKeyId();
                case ALGORITHM_FIELD -> keyConfig.getAlgorithm();
                case CURVE_FIELD -> keyConfig.getCurve();
                case AUTHORITY_FIELD -> keyConfig.getAuthority();
                default -> throw new IllegalArgumentException("Unknown attribute: " + attributeName);
            };
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
        KeyConfiguration keyConfig = getKeyConfig(keyName);
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
    public Set<String> getAllKeyNames() {
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
    
    /**
     * Retrieves the authority (issuing CA) for a specific key name.
     * 
     * <p>This returns the name of the certificate authority that issued the
     * certificate for this key, which can be used to build certificate chains.</p>
     * 
     * @param keyName the name of the key to retrieve the authority for
     * @return the authority name or null if not configured or key doesn't exist
     */
    public String getKeyAuthority(String keyName) {
        return getKeyAttribute(keyName, AUTHORITY_FIELD, null);
    }
    
    /**
     * Retrieves the certificate chain for a given authority name.
     * 
     * <p>This returns the certificate (usually intermediate CA) from the chains
     * section that can be used to build certificate chains for JWT x5c headers.</p>
     * 
     * @param authorityName the name of the authority/CA
     * @return the certificate PEM string or null if not found
     */
    public String getChainCertificate(String authorityName) {
        if (authorityName == null) {
            return null;
        }
        
        Map<String, ChainConfiguration> chains = keysConfiguration.getChains();
        if (chains == null) {
            return null;
        }
        
        ChainConfiguration chainData = chains.get(authorityName);
        if (chainData == null) {
            return null;
        }
        
        return chainData.getPublicKey();
    }
    
    /**
     * Retrieves the public key PEM string for a specific key name.
     * 
     * <p>This method extracts the public key or certificate from the key configuration.</p>
     * 
     * @param keyName the name of the key to retrieve the public key for
     * @return the public key PEM string or null if not found
     */
    public String getPublicKey(String keyName) {
        try {
            KeyConfiguration keyConfig = getKeyConfig(keyName);
            return keyConfig.getPublicKey();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
    
    /**
     * Builds an X.509 certificate chain for the given key name.
     * 
     * <p>This method constructs the certificate chain by including the end-entity
     * certificate and the intermediate CA certificate (if available) based on the
     * authority reference. The chain is suitable for use in JWT x5c headers.</p>
     * 
     * @param keyName the name of the key to build the chain for
     * @return List of certificate PEM strings [end-entity, intermediate] or empty list
     */
    public java.util.List<String> getCertificateChain(String keyName) {
        java.util.List<String> chain = new java.util.ArrayList<>();
        
        // Get the end-entity certificate
        String endEntityCert = getPublicKey(keyName);
        if (endEntityCert != null && endEntityCert.contains("-----BEGIN CERTIFICATE-----")) {
            chain.add(endEntityCert);
            
            // Try to get the intermediate certificate based on configured authority first
            String authority = getKeyAuthority(keyName);
            if (authority != null) {
                String intermediateCert = getChainCertificate(authority);
                if (intermediateCert != null) {
                    chain.add(intermediateCert);
                }
            } else {
                // If no authority is configured, try to auto-detect it
                String autoDetectedAuthority = autoDetectAuthority(endEntityCert);
                if (autoDetectedAuthority != null) {
                    String intermediateCert = getChainCertificate(autoDetectedAuthority);
                    if (intermediateCert != null) {
                        chain.add(intermediateCert);
                    }
                }
            }
        }
        
        return chain;
    }
    
    /**
     * Automatically detects the issuing authority for a certificate by comparing
     * the certificate's Authority Key Identifier with available chain certificates'
     * Subject Key Identifiers.
     * 
     * <p>This method uses the X.509v3 extensions as defined in RFC 5280:</p>
     * <ul>
     * <li>Authority Key Identifier (AKI) - identifies the public key used to sign the certificate</li>
     * <li>Subject Key Identifier (SKI) - identifies the certificate's public key</li>
     * </ul>
     * 
     * <p>This approach is more robust than DN matching as it uses cryptographic
     * identifiers specifically designed for certificate chain building.</p>
     * 
     * @param certificatePem the PEM-encoded certificate to analyze
     * @return the name of the matching authority or null if no match found
     */
    private String autoDetectAuthority(String certificatePem) {
        try {
            // First try using X.509v3 Key Identifiers (preferred method)
            String authorityByKeyId = autoDetectAuthorityByKeyIdentifiers(certificatePem);
            if (authorityByKeyId != null) {
                return authorityByKeyId;
            }
            
            // Fall back to Subject/Issuer DN matching for compatibility
            String authorityByDN = autoDetectAuthorityByDN(certificatePem);
            if (authorityByDN != null) {
                logger.debug("Fallback: Using DN-based authority detection for certificate");
                return authorityByDN;
            }
            
            logger.debug("No matching authority found using any detection method");
            return null;
            
        } catch (Exception e) {
            logger.warn("Error during authority auto-detection: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Detects authority using X.509v3 Subject Key Identifier and Authority Key Identifier extensions.
     * 
     * <p>This is the preferred method as defined in RFC 5280 Section 4.2.1.1 and 4.2.1.2.
     * The Authority Key Identifier of the certificate should match the Subject Key Identifier
     * of the issuing CA certificate.</p>
     * 
     * @param certificatePem the PEM-encoded certificate to analyze
     * @return the name of the matching authority or null if no match found
     */
    private String autoDetectAuthorityByKeyIdentifiers(String certificatePem) {
        try {
            // Extract the Authority Key Identifier from the certificate
            String authorityKeyId = com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.CertificateChainBuilder.extractAuthorityKeyIdentifier(certificatePem);
            if (authorityKeyId == null) {
                logger.debug("Certificate does not contain Authority Key Identifier extension");
                return null;
            }
            
            // Get all available chains
            Map<String, ChainConfiguration> chains = keysConfiguration.getChains();
            if (chains == null) {
                return null;
            }
            
            // Check each chain certificate to see if its SKI matches the certificate's AKI
            for (Map.Entry<String, ChainConfiguration> chainEntry : chains.entrySet()) {
                String chainName = chainEntry.getKey();
                ChainConfiguration chainData = chainEntry.getValue();
                String chainCertPem = chainData.getPublicKey();
                
                if (chainCertPem != null) {
                    try {
                        String subjectKeyId = com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.CertificateChainBuilder.extractSubjectKeyIdentifier(chainCertPem);
                        if (authorityKeyId.equals(subjectKeyId)) {
                            logger.debug("Auto-detected authority '{}' using X.509v3 Key Identifiers (AKI: {})", chainName, authorityKeyId);
                            return chainName;
                        }
                    } catch (Exception e) {
                        logger.warn("Error extracting SKI from chain certificate '{}': {}", chainName, e.getMessage());
                    }
                }
            }
            
            logger.debug("No matching authority found for Authority Key Identifier: {}", authorityKeyId);
            return null;
            
        } catch (Exception e) {
            logger.warn("Error during key identifier-based authority detection: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Detects authority using Subject and Issuer Distinguished Names (fallback method).
     * 
     * <p>This method is kept for backward compatibility with certificates that may not
     * have proper X.509v3 key identifier extensions.</p>
     * 
     * @param certificatePem the PEM-encoded certificate to analyze
     * @return the name of the matching authority or null if no match found
     */
    private String autoDetectAuthorityByDN(String certificatePem) {
        try {
            // Extract the issuer CN from the certificate
            String issuerCN = com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.CertificateChainBuilder.extractIssuerCN(certificatePem);
            if (issuerCN == null) {
                return null;
            }
            
            // Get all available chains
            Map<String, ChainConfiguration> chains = keysConfiguration.getChains();
            if (chains == null) {
                return null;
            }
            
            // Check each chain certificate to see if its subject matches the issuer
            for (Map.Entry<String, ChainConfiguration> chainEntry : chains.entrySet()) {
                String chainName = chainEntry.getKey();
                ChainConfiguration chainData = chainEntry.getValue();
                String chainCertPem = chainData.getPublicKey();
                
                if (chainCertPem != null) {
                    try {
                        String chainSubjectCN = com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.CertificateChainBuilder.extractSubjectCN(chainCertPem);
                        if (issuerCN.equals(chainSubjectCN)) {
                            logger.debug("Auto-detected authority '{}' using DN matching (Issuer: {})", chainName, issuerCN);
                            return chainName;
                        }
                    } catch (Exception e) {
                        logger.warn("Error parsing chain certificate for '{}': {}", chainName, e.getMessage());
                    }
                }
            }
            
            return null;
            
        } catch (Exception e) {
            logger.warn("Error during DN-based authority detection: {}", e.getMessage());
            return null;
        }
    }
}
