package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;
import java.util.function.Consumer;

/**
 * Configuration class for loading cryptographic keys from YAML configuration files.
 * 
 * <p>This Spring Boot configuration class automatically binds YAML configuration data
 * to Java objects using the {@code @ConfigurationProperties} annotation. It provides
 * structured access to cryptographic keys, certificate chains, and key management
 * configuration stored in {@code keys.yml} or similar configuration files.</p>
 * 
 * <p>The configuration supports multiple key formats and management strategies:</p>
 * <ul>
 * <li><strong>Key Pairs</strong>: Private/public key pairs with metadata (algorithm, curve, key ID)</li>
 * <li><strong>Certificate Chains</strong>: CA certificates for certificate authority operations</li>
 * <li><strong>Key Management</strong>: Primary key selection and rotation policies</li>
 * </ul>
 * 
 * <h3>YAML Structure Example:</h3>
 * <pre>
 * keys:
 *   key1:
 *     private: "-----BEGIN PRIVATE KEY-----..."
 *     public: "-----BEGIN PUBLIC KEY-----..."
 *     keyId: "unique-key-identifier"
 *     algorithm: "ES256"
 *     curve: "P-256"
 *     authority: "intermediate-ca"
 * 
 * chains:
 *   intermediate-ca:
 *     public: "-----BEGIN CERTIFICATE-----..."
 * 
 * config:
 *   primary-key: "key1"
 *   key-rotation: true
 * </pre>
 * 
 * <p><strong>Thread Safety:</strong> This configuration class is typically instantiated
 * as a Spring singleton and should be considered thread-safe for read operations after
 * initialization.</p>
 * 
 * <p><strong>Security Note:</strong> Private keys are loaded as plain strings in memory.
 * Ensure proper memory management and consider using secure string handling in
 * production environments.</p>
 * 
 * @author OAuth2 Authorization Server
 * @since 1.0
 * @see org.springframework.boot.context.properties.ConfigurationProperties
 * @see KeyPairConfig
 * @see ChainConfig
 * @see ConfigSection
 */
@ConfigurationProperties(prefix = "")
public class KeysConfig {
    
    /** Map of key pair configurations indexed by key identifier */
    private Map<String, KeyPairConfig> keys;
    
    /** Map of certificate chain configurations indexed by authority name */
    private Map<String, ChainConfig> chains;
    
    /** General configuration settings for key management */
    private ConfigSection config;
    
    /**
     * Gets the map of configured key pairs.
     * 
     * @return map of key pair configurations indexed by key identifier, or null if not set
     */
    public Map<String, KeyPairConfig> getKeys() {
        return keys;
    }
    
    /**
     * Sets the map of key pair configurations.
     * 
     * <p>This method is typically called by Spring Boot's configuration property binding
     * during application startup to populate the keys from YAML configuration.</p>
     * 
     * @param keys map of key pair configurations indexed by key identifier
     */
    public void setKeys(Map<String, KeyPairConfig> keys) {
        this.keys = keys;
    }
    
    /**
     * Gets the map of certificate chain configurations.
     * 
     * @return map of certificate chain configurations indexed by authority name, or null if not set
     */
    public Map<String, ChainConfig> getChains() {
        return chains;
    }
    
    /**
     * Sets the map of certificate chain configurations.
     * 
     * <p>This method is typically called by Spring Boot's configuration property binding
     * during application startup to populate the chains from YAML configuration.</p>
     * 
     * @param chains map of certificate chain configurations indexed by authority name
     */
    public void setChains(Map<String, ChainConfig> chains) {
        this.chains = chains;
    }
    
    /**
     * Gets the general configuration settings for key management.
     * 
     * @return configuration settings, or null if not set
     */
    public ConfigSection getConfig() {
        return config;
    }
    
    /**
     * Sets the general configuration settings for key management.
     * 
     * <p>This method is typically called by Spring Boot's configuration property binding
     * during application startup to populate the config from YAML configuration.</p>
     * 
     * @param config configuration settings for key management
     */
    public void setConfig(ConfigSection config) {
        this.config = config;
    }
    
    /**
     * Interface for classes that support YAML "public" property mapping to publicKey fields.
     * 
     * <p>This interface provides a common contract for configuration classes that need to map
     * the YAML property name "public" to a Java field named "publicKey". This is commonly
     * needed for backward compatibility with YAML configurations that use reserved keywords
     * or different naming conventions.</p>
     * 
     * <p>The default implementation delegates to the standard {@code setPublicKey(String)}
     * method, eliminating code duplication across multiple configuration classes while
     * maintaining YAML compatibility.</p>
     * 
     * @since 1.0
     * @see KeyPairConfig
     * @see ChainConfig
     */
    interface YamlPublicKeyMapper {
        /**
         * Sets the public key material using standard method name.
         * 
         * @param publicKey the public key material in PEM format
         */
        void setPublicKey(String publicKey);
        
        /**
         * Maps "public" YAML property to publicKey field.
         * This provides backward compatibility for YAML configurations using "public" property name.
         * 
         * @param publicKey the public key material in PEM format
         */
        default void setPublic(String publicKey) {
            setPublicKey(publicKey);
        }
    }
    
    /**
     * Interface for classes that support hyphenated YAML property mapping to camelCase fields.
     * 
     * <p>This interface provides a generic contract for configuration classes that need to map
     * hyphenated YAML property names (e.g., "primary-key", "key-rotation") to camelCase Java
     * field names (e.g., "primaryKey", "keyRotation"). This eliminates code duplication when
     * implementing backward compatibility for YAML configurations.</p>
     * 
     * <p>The interface uses Java 8 functional programming to provide type-safe, generic
     * mapping methods that delegate to the standard setter methods, maintaining DRY principles
     * while supporting various property types (String, boolean, int, etc.).</p>
     * 
     * @since 1.0
     * @see ConfigSection
     */
    interface YamlHyphenatedPropertyMapper {
        /**
         * Creates a generic hyphenated property setter that delegates to the standard setter.
         * 
         * <p>This method provides a type-safe way to create YAML compatibility methods
         * without code duplication. It uses method references to delegate to existing
         * setter methods.</p>
         * 
         * @param <T> the type of the property value
         * @param standardSetter method reference to the standard camelCase setter
         * @return a consumer that can be used as a hyphenated property setter
         */
        default <T> Consumer<T> createHyphenatedSetter(Consumer<T> standardSetter) {
            return standardSetter;
        }
    }
    
    /**
     * Configuration class for individual key pair settings.
     * 
     * <p>This class represents a single cryptographic key pair configuration including
     * both the key material (private/public keys) and metadata (algorithm, curve, key ID).
     * It supports multiple key formats and provides YAML property mapping for both
     * standard property names and hyphenated YAML keys.</p>
     * 
     * <p>The class handles YAML-to-Java property mapping for common cases where YAML
     * uses different naming conventions:</p>
     * <ul>
     * <li>{@code private} → {@code privateKey}</li>
     * <li>{@code public} → {@code publicKey}</li>
     * </ul>
     * 
     * <p><strong>Supported Key Formats:</strong></p>
     * <ul>
     * <li>PEM-encoded private keys (PKCS#8 or traditional EC format)</li>
     * <li>PEM-encoded public keys (X.509 or traditional EC format)</li>
     * <li>X.509 certificates (for public key material)</li>
     * </ul>
     * 
     * <p><strong>Security Note:</strong> Private key material should be properly 
     * protected in production environments. Consider using encrypted configuration
     * files or external secret management systems.</p>
     * 
     * @since 1.0
     * @see KeysConfig
     */
    @Getter
    @Setter
    public static class KeyPairConfig implements YamlPublicKeyMapper {
        /** The private key material in PEM format (PKCS#8 or traditional EC format) */
        private String privateKey;
        
        /** The public key material in PEM format or X.509 certificate format */
        private String publicKey;
        
        /** Unique identifier for this key pair within the OAuth2 server */
        private String keyId;
        
        /** The cryptographic algorithm used (e.g., "ES256", "RS256") */
        private String algorithm;
        
        /** The elliptic curve name for EC keys (e.g., "P-256", "secp256r1") */
        private String curve;
        
        /** Reference to the certificate authority that issued this certificate */
        private String authority;
        
        // YAML compatibility methods for backward compatibility
        
        /**
         * Maps "private" YAML property to privateKey field.
         * This provides backward compatibility for YAML configurations.
         * 
         * @param privateKey the private key in PEM format
         */
        public void setPrivate(String privateKey) {
            this.privateKey = privateKey;
        }
    }
    
    /**
     * Configuration class for certificate chain settings.
     * 
     * <p>This class represents certificate authority (CA) configurations used for 
     * building and validating certificate chains in the JWT x5c header. It contains
     * the CA certificate material needed to establish trust relationships.</p>
     * 
     * <p>Certificate chains are crucial for JWT validation when using x5c headers,
     * as they allow recipients to verify the authenticity of the signing certificate
     * by tracing it back to a trusted root authority.</p>
     * 
     * <p><strong>Security Note:</strong> CA certificates should be obtained from
     * trusted sources and their integrity should be verified before deployment.</p>
     * 
     * @since 1.0
     * @see KeysConfig
     * @see KeyPairConfig
     */
    @Getter
    @Setter
    public static class ChainConfig implements YamlPublicKeyMapper {
        /** The CA certificate in PEM format or X.509 certificate format */
        private String publicKey;
    }
    
    /**
     * Configuration class for general key management settings.
     * 
     * <p>This class contains global configuration options that affect the overall
     * behavior of the key management system, such as which key should be used as
     * the primary signing key and whether key rotation is enabled.</p>
     * 
     * <p>The primary key setting is crucial for OAuth2 token signing, as it determines
     * which configured key pair will be used for signing new JWT tokens. The key rotation
     * setting controls whether the system should automatically rotate keys based on
     * configured policies.</p>
     * 
     * <p><strong>Configuration Mapping:</strong> This class supports YAML property mapping
     * for hyphenated property names (e.g., "primary-key" → "primaryKey").</p>
     * 
     * @since 1.0
     * @see KeysConfig
     * @see KeyPairConfig
     */
    @Getter
    @Setter
    public static class ConfigSection implements YamlHyphenatedPropertyMapper {
        /** The key ID that should be used as the primary signing key */
        private String primaryKey;
        
        /** Whether automatic key rotation is enabled */
        private boolean keyRotation;
        
        // YAML compatibility methods using the generic interface
        
        /**
         * Maps "primary-key" YAML property to primaryKey field.
         * This provides backward compatibility for hyphenated YAML keys.
         * 
         * @param primaryKey the key ID to use for primary token signing
         */
        public void setPrimary_key(String primaryKey) {
            createHyphenatedSetter(this::setPrimaryKey).accept(primaryKey);
        }
        
        /**
         * Maps "key-rotation" YAML property to keyRotation field.
         * This provides backward compatibility for hyphenated YAML keys.
         * 
         * @param keyRotation true to enable automatic key rotation, false to disable
         */
        public void setKey_rotation(boolean keyRotation) {
            createHyphenatedSetter(this::setKeyRotation).accept(keyRotation);
        }
    }
}
