package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.KeysService;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.CertificateChainBuilder;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Configuration class for JWT token management in OAuth2 Authorization Server.
 * 
 * <p>This configuration handles the complete JWT lifecycle including key management,
 * token encoding/decoding, and JWT customization with certificate chain integration.
 * It supports key rotation with multiple keys and implements ES256 (ECDSA using P-256 curve
 * and SHA-256 hash) algorithm for enhanced security.</p>
 * 
 * <h3>Key Features:</h3>
 * <ul>
 *   <li><strong>Multi-Key Support:</strong> Loads and manages multiple EC keys for rotation</li>
 *   <li><strong>Primary/Secondary Key Distinction:</strong> Primary key for signing, others for verification only</li>
 *   <li><strong>X.509 Certificate Chain:</strong> Adds x5c header with certificate chains for JWT verification</li>
 *   <li><strong>ES256 Algorithm:</strong> Uses ECDSA P-256 curve with SHA-256 for optimal security and performance</li>
 *   <li><strong>Token Customization:</strong> Adds custom claims and headers to JWT tokens</li>
 *   <li><strong>Graceful Error Handling:</strong> Continues operation even if certificate chain fails</li>
 * </ul>
 * 
 * <h3>Security Considerations:</h3>
 * <ul>
 *   <li>Private keys are only added to primary signing keys</li>
 *   <li>Certificate chains are validated before inclusion in JWT headers</li>
 *   <li>All keys must be valid for application startup (fail-fast approach)</li>
 *   <li>JWT tokens include client identification and version information</li>
 * </ul>
 * 
 * <h3>Dependencies:</h3>
 * <ul>
 *   <li>{@link KeysService} - For loading and managing cryptographic keys</li>
 *   <li>{@link CertificateChainBuilder} - For X.509 certificate chain processing</li>
 * </ul>
 * 
 * <h3>Configuration Properties:</h3>
 * <ul>
 *   <li>{@code jwt.jwks-uri} - JWKS endpoint URI for JWT verification</li>
 *   <li>{@code jwt.type} - JWT token type (default: "JWT")</li>
 *   <li>{@code jwt.version} - Custom version claim for tokens</li>
 * </ul>
 * 
 * @author TsutomuNakamura
 * @since 0.0.1-SNAPSHOT
 * @see KeysService
 * @see CertificateChainBuilder
 * @see org.springframework.security.oauth2.jwt.JwtEncoder
 * @see org.springframework.security.oauth2.jwt.JwtDecoder
 */
@Configuration
public class JwtConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtConfig.class);
    
    /**
     * Elliptic Curve used for ECDSA cryptographic operations.
     * P-256 provides optimal balance of security and performance.
     */
    private static final Curve DEFAULT_CURVE = Curve.P_256;
    
    /**
     * JSON Web Signature algorithm used for JWT signing.
     * ES256 uses ECDSA with P-256 curve and SHA-256 hash.
     */
    private static final JWSAlgorithm JWS_ALGORITHM = JWSAlgorithm.ES256;
    
    /**
     * Spring Security signature algorithm constant for JWT header customization.
     */
    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.ES256;
    
    /**
     * Key usage designation for cryptographic keys.
     * All keys are designated for digital signature operations.
     */
    private static final KeyUse KEY_USE = KeyUse.SIGNATURE;
    
    /**
     * Human-readable algorithm information string for logging purposes.
     */
    private static final String ALGORITHM_INFO = "Algorithm: ES256, Curve: P-256";
    
    /**
     * JWKS (JSON Web Key Set) endpoint URI for JWT token verification.
     * This endpoint provides public keys for JWT signature validation.
     */
    
    /**
     * JWKS (JSON Web Key Set) endpoint URI for JWT token verification.
     * This endpoint provides public keys for JWT signature validation.
     */
    @Value("${jwt.jwks-uri}")
    private String jwksUri;
    
    /**
     * JWT token type identifier added to the 'typ' header claim.
     * Typically set to "JWT" to indicate JSON Web Token format.
     */
    @Value("${jwt.type}")
    private String jwtType;
    
    /**
     * Custom version identifier added to JWT payload claims.
     * Used for token versioning and compatibility tracking.
     */
    @Value("${jwt.version}")
    private String jwtVersion;
    
    /**
     * Service for cryptographic key management and certificate operations.
     */
    private final KeysService keysService;
    
    /**
     * Constructs JwtConfig with required KeysService dependency.
     * 
     * @param keysService the service for managing cryptographic keys and certificates
     */
    
    public JwtConfig(KeysService keysService) {
        this.keysService = keysService;
    }
    
    /**
     * Creates and configures the JWK (JSON Web Key) source for JWT operations.
     * 
     * <p>This bean provides the cryptographic keys used for JWT token signing and verification.
     * It loads all configured keys from the KeysService, with support for key rotation by
     * maintaining multiple keys simultaneously. Primary keys are used for signing new tokens,
     * while secondary keys are available for verifying existing tokens during rotation periods.</p>
     * 
     * <h4>Key Loading Process:</h4>
     * <ol>
     *   <li>Retrieves all key names from KeysService</li>
     *   <li>Creates JWK objects for each key with appropriate operations (SIGN/VERIFY)</li>
     *   <li>Validates that at least one key was loaded successfully</li>
     *   <li>Creates immutable JWK set for thread-safe access</li>
     * </ol>
     * 
     * <h4>Error Handling:</h4>
     * <ul>
     *   <li>Fails fast if any key cannot be loaded (application startup failure)</li>
     *   <li>Preserves original IllegalStateException for specific error handling</li>
     *   <li>Wraps other exceptions with descriptive messages</li>
     * </ul>
     * 
     * @return an immutable JWK source containing all configured cryptographic keys
     * @throws IllegalStateException if no keys could be loaded or any key is invalid
     * @see KeysService#getAllKeyNames()
     * @see #loadAllKeys()
     * @see #validateKeys(List)
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            logger.info("Loading EC keys from YAML configuration for key rotation...");
            
            List<JWK> jwkList = loadAllKeys();
            validateKeys(jwkList);
            
            JWKSet jwkSet = new JWKSet(jwkList);
            logJwkSourceInitialization(jwkList.size());
            
            return new ImmutableJWKSet<>(jwkSet);
            
        } catch (IllegalStateException e) {
            // Re-throw IllegalStateException as-is
            throw e;
        } catch (Exception e) {
            logger.error("Failed to load EC key pair from YAML: {}", e.getMessage(), e);
            throw new IllegalStateException("Could not load keys from YAML configuration", e);
        }
    }
    
    /**
     * Loads all configured cryptographic keys and converts them to JWK format.
     * 
     * <p>This method iterates through all key names provided by the KeysService
     * and creates corresponding JWK objects. It implements a fail-fast approach
     * where any key loading failure stops the entire application startup process,
     * ensuring system integrity.</p>
     * 
     * <h4>Key Processing:</h4>
     * <ul>
     *   <li>Retrieves key names from KeysService</li>
     *   <li>Creates JWK object for each key using {@link #createJWKForKey(String)}</li>
     *   <li>Logs successful key loading for debugging</li>
     *   <li>Terminates application startup on any key loading failure</li>
     * </ul>
     * 
     * @return list of JWK objects representing all loaded cryptographic keys
     * @throws IllegalStateException if any key fails to load with detailed error message
     * @see KeysService#getAllKeyNames()
     * @see #createJWKForKey(String)
     */
    private List<JWK> loadAllKeys() {
        List<JWK> jwkList = new ArrayList<>();
        Set<String> allKeyNames = keysService.getAllKeyNames();
        
        logger.info("Loading multiple keys for rotation: {}", allKeyNames);
        
        for (String keyName : allKeyNames) {
            try {
                JWK jwk = createJWKForKey(keyName);
                jwkList.add(jwk);
                logger.debug("Successfully loaded key: {}", keyName);
            } catch (Exception e) {
                logger.error("Failed to load key: {} - {}", keyName, e.getMessage());
                // Stop application if any key fails to load
                throw new IllegalStateException(
                    String.format("Critical error: Failed to load key '%s'. All configured keys must be valid for the application to start. Reason: %s", 
                        keyName, e.getMessage()), e);
            }
        }
        
        return jwkList;
    }
    
    /**
     * Creates a JSON Web Key (JWK) object from a named cryptographic key.
     * 
     * <p>This method constructs a JWK with appropriate key operations based on whether
     * the key is designated as primary (signing + verification) or secondary (verification only).
     * Primary keys include private key material for signing operations, while secondary keys
     * contain only public key material for verification during key rotation periods.</p>
     * 
     * <h4>Key Operations Assignment:</h4>
     * <ul>
     *   <li><strong>Primary Key:</strong> SIGN and VERIFY operations (includes private key)</li>
     *   <li><strong>Secondary Keys:</strong> VERIFY operation only (public key only)</li>
     * </ul>
     * 
     * <h4>JWK Properties:</h4>
     * <ul>
     *   <li>Algorithm: ES256 (ECDSA with P-256 curve and SHA-256)</li>
     *   <li>Key Use: Signature operations</li>
     *   <li>Curve: P-256 for optimal security and performance</li>
     *   <li>Key ID: Unique identifier from configuration</li>
     * </ul>
     * 
     * @param keyName the name of the key to load from KeysService
     * @return JWK object configured for the specified key
     * @throws Exception if key loading or JWK creation fails
     * @see #extractKeyConfiguration(String)
     * @see KeysService#getKeyPair(String)
     * @see KeysService#getKeyId(String)
     */
    private JWK createJWKForKey(String keyName) throws Exception {
        KeyConfiguration keyConfig = extractKeyConfiguration(keyName);
        
        Set<KeyOperation> keyOps = keyConfig.isPrimary() ? 
            Set.of(KeyOperation.SIGN, KeyOperation.VERIFY) :
            Set.of(KeyOperation.VERIFY);
            
        ECKey.Builder ecKeyBuilder = new ECKey.Builder(DEFAULT_CURVE, keyConfig.publicKey())
                .keyID(keyConfig.keyId())
                .algorithm(JWS_ALGORITHM)
                .keyUse(KEY_USE)
                .keyOperations(keyOps);
        
        // Only add private key to primary key for signing
        if (keyConfig.isPrimary()) {
            ecKeyBuilder.privateKey(keyConfig.privateKey());
        }
        
        logger.info("Loaded key: {} (ID: {}, Primary: {})", keyName, keyConfig.keyId(), keyConfig.isPrimary());
        
        return ecKeyBuilder.build();
    }
    
    /**
     * Extracts and organizes key configuration data from KeysService.
     * 
     * <p>This method retrieves all necessary information about a cryptographic key
     * and packages it into a convenient record format. It determines whether the
     * key is primary by comparing its name with the configured primary key name.</p>
     * 
     * <h4>Extracted Information:</h4>
     * <ul>
     *   <li>Public and private key pair from KeysService</li>
     *   <li>Unique key identifier for JWK key ID field</li>
     *   <li>Primary status for operation assignment</li>
     * </ul>
     * 
     * @param keyName the name of the key to extract configuration for
     * @return KeyConfiguration record containing all key-related information
     * @throws Exception if key retrieval from KeysService fails
     * @see KeysService#getKeyPair(String)
     * @see KeysService#getKeyId(String)
     * @see KeysService#getPrimaryKeyName()
     */
    private KeyConfiguration extractKeyConfiguration(String keyName) throws Exception {
        KeyPair keyPair = keysService.getKeyPair(keyName);
        String keyId = keysService.getKeyId(keyName);
        boolean isPrimary = keyName.equals(keysService.getPrimaryKeyName());
        
        return new KeyConfiguration(
            (ECPublicKey) keyPair.getPublic(),
            (ECPrivateKey) keyPair.getPrivate(),
            keyId,
            isPrimary
        );
    }
    
    /**
     * Validates that at least one cryptographic key was successfully loaded.
     * 
     * <p>This validation ensures the JWT configuration has at least one usable key
     * for token operations. An empty key set would prevent the authorization server
     * from functioning properly.</p>
     * 
     * @param jwkList the list of loaded JWK objects to validate
     * @throws IllegalStateException if no keys were successfully loaded
     */
    private void validateKeys(List<JWK> jwkList) {
        if (jwkList.isEmpty()) {
            throw new IllegalStateException("No valid keys could be loaded. At least one key must be configured.");
        }
    }
    
    /**
     * Logs successful JWK source initialization with configuration summary.
     * 
     * <p>This method provides comprehensive logging about the JWT configuration
     * including the number of loaded keys, primary key identification, and
     * algorithm information for operational monitoring and debugging.</p>
     * 
     * @param keyCount the total number of keys loaded into the JWK source
     */
    private void logJwkSourceInitialization(int keyCount) {
        logger.info("JWK Source initialized with {} key(s)", keyCount);
        logger.info("Primary key: {}", keysService.getPrimaryKeyName());
        logger.info(ALGORITHM_INFO);
    }
    
    /**
     * Creates and configures the JWT encoder for token generation.
     * 
     * <p>This bean is responsible for creating and signing JWT tokens using the
     * primary cryptographic key. It includes custom key selection logic to ensure
     * only the designated primary key is used for signing operations, maintaining
     * consistent token signatures during key rotation periods.</p>
     * 
     * <h4>Key Selection Strategy:</h4>
     * <ul>
     *   <li>Uses custom selector {@link #selectPrimarySigningKey(List)} for key choice</li>
     *   <li>Ensures only primary key with private key material is used for signing</li>
     *   <li>Provides deterministic key selection for consistent token generation</li>
     * </ul>
     * 
     * @param jwkSource the JWK source containing all available cryptographic keys
     * @return configured JWT encoder with custom key selection logic
     * @see #selectPrimarySigningKey(List)
     */
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        encoder.setJwkSelector(this::selectPrimarySigningKey);
        return encoder;
    }
    
    /**
     * Selects the primary signing key from available candidate keys.
     * 
     * <p>This method implements custom key selection logic for JWT signing operations.
     * It ensures that only the designated primary key with private key material
     * is used for token signing, providing consistent and secure token generation.</p>
     * 
     * <h4>Selection Criteria:</h4>
     * <ul>
     *   <li>Key ID must match the configured primary key identifier</li>
     *   <li>Key must be an ECKey instance (Elliptic Curve key)</li>
     *   <li>Key must contain private key material for signing operations</li>
     * </ul>
     * 
     * <h4>Error Handling:</h4>
     * <ul>
     *   <li>Preserves IllegalStateException for specific error conditions</li>
     *   <li>Wraps other exceptions with descriptive error messages</li>
     *   <li>Provides detailed logging for troubleshooting key selection issues</li>
     * </ul>
     * 
     * @param candidateKeys list of available JWK keys for selection
     * @return the primary JWK key suitable for JWT signing operations
     * @throws IllegalStateException if primary key is not found or unavailable for signing
     * @see KeysService#getPrimaryKeyId()
     * @see #isPrimarySigningKey(JWK, String)
     */
    private JWK selectPrimarySigningKey(List<JWK> candidateKeys) {
        try {
            String primaryKeyId = keysService.getPrimaryKeyId();
            
            for (JWK jwk : candidateKeys) {
                if (isPrimarySigningKey(jwk, primaryKeyId)) {
                    logger.debug("Selected primary key for signing: {}", jwk.getKeyID());
                    return jwk;
                }
            }
            
            String errorMsg = String.format("Primary signing key '%s' not found or not available for signing", primaryKeyId);
            logger.error(errorMsg);
            throw new IllegalStateException(errorMsg);
            
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Error selecting JWK for signing: {}", e.getMessage());
            throw new IllegalStateException("Error selecting JWK for signing", e);
        }
    }
    
    /**
     * Determines if a JWK qualifies as the primary signing key.
     * 
     * <p>This helper method validates that a JWK meets all requirements for
     * use as the primary signing key: correct key ID, proper key type (ECKey),
     * and availability of private key material for signing operations.</p>
     * 
     * @param jwk the JWK to evaluate for primary signing key suitability
     * @param primaryKeyId the expected key ID for the primary signing key
     * @return true if the JWK qualifies as the primary signing key, false otherwise
     */
    private boolean isPrimarySigningKey(JWK jwk, String primaryKeyId) {
        return primaryKeyId.equals(jwk.getKeyID()) && 
               jwk instanceof ECKey && 
               ((ECKey) jwk).isPrivate();
    }
    
    /**
     * Creates and configures the JWT decoder for token introspection and validation.
     * 
     * <p>This bean provides JWT token decoding and validation capabilities using
     * the configured JWKS endpoint. It enables token introspection services and
     * other components to verify and extract information from JWT tokens issued
     * by this authorization server.</p>
     * 
     * <h4>Configuration:</h4>
     * <ul>
     *   <li>Uses JWKS URI from configuration for public key retrieval</li>
     *   <li>Supports automatic key rotation through JWKS endpoint</li>
     *   <li>Validates token signatures using available public keys</li>
     * </ul>
     * 
     * @return configured JWT decoder for token validation operations
     * @see NimbusJwtDecoder#withJwkSetUri(String)
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        logger.info("Configuring JWT Decoder for token introspection");
        return NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
    }
    
    /**
     * Creates JWT token customizer for adding custom headers and claims.
     * 
     * <p>This bean provides comprehensive JWT token customization including
     * algorithm specification, certificate chain integration (x5c header),
     * and custom payload claims. It enhances token security and provides
     * additional metadata for token validation and client identification.</p>
     * 
     * <h4>Customizations Applied:</h4>
     * <ul>
     *   <li><strong>Header Customization:</strong> Algorithm, type, and x5c certificate chain</li>
     *   <li><strong>Payload Customization:</strong> Version, client ID, and client name claims</li>
     *   <li><strong>Certificate Integration:</strong> X.509 certificate chain for enhanced verification</li>
     * </ul>
     * 
     * @return OAuth2 token customizer for JWT encoding context
     * @see #customizeJwtHeader(JwtEncodingContext)
     * @see #customizeJwtPayload(JwtEncodingContext)
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            customizeJwtHeader(context);
            customizeJwtPayload(context);
        };
    }
    
    /**
     * Customizes JWT header with algorithm, type, and certificate chain information.
     * 
     * <p>This method configures the JWT header with essential cryptographic and
     * identification information. It sets the signature algorithm, token type,
     * and attempts to include X.509 certificate chain (x5c header) for enhanced
     * token verification capabilities.</p>
     * 
     * <h4>Header Fields Set:</h4>
     * <ul>
     *   <li><strong>alg:</strong> Signature algorithm (ES256)</li>
     *   <li><strong>typ:</strong> Token type from configuration</li>
     *   <li><strong>x5c:</strong> X.509 certificate chain (if available)</li>
     * </ul>
     * 
     * @param context the JWT encoding context containing header builder
     * @see #addX5cCertificateChain(JwtEncodingContext)
     */
    private void customizeJwtHeader(JwtEncodingContext context) {
        context.getJwsHeader().algorithm(SIGNATURE_ALGORITHM);
        context.getJwsHeader().type(jwtType);
        
        addX5cCertificateChain(context);
    }
    
    /**
     * Adds X.509 certificate chain to JWT header for enhanced token verification.
     * 
     * <p>This method attempts to retrieve and include the certificate chain
     * associated with the primary signing key in the JWT header as an x5c claim.
     * The x5c header allows JWT verifiers to validate not just the signature
     * but also the certificate chain trust path.</p>
     * 
     * <h4>Certificate Chain Processing:</h4>
     * <ol>
     *   <li>Retrieves certificate chain for primary key from KeysService</li>
     *   <li>Converts PEM certificates to DER format for x5c header</li>
     *   <li>Adds x5c header with Base64-encoded DER certificates</li>
     *   <li>Gracefully continues if certificate chain is unavailable</li>
     * </ol>
     * 
     * <h4>Error Handling:</h4>
     * <p>This method implements graceful error handling - if certificate chain
     * processing fails, JWT signing continues without the x5c header. This
     * ensures token generation remains functional even if certificate
     * configuration is incomplete.</p>
     * 
     * @param context the JWT encoding context for header modification
     * @see KeysService#getCertificateChain(String)
     * @see #convertToX5cFormat(List)
     */
    private void addX5cCertificateChain(JwtEncodingContext context) {
        try {
            String primaryKeyName = keysService.getPrimaryKeyName();
            List<String> certificateChain = keysService.getCertificateChain(primaryKeyName);
            
            if (!certificateChain.isEmpty()) {
                List<String> x5cChain = convertToX5cFormat(certificateChain);
                
                if (!x5cChain.isEmpty()) {
                    context.getJwsHeader().header("x5c", x5cChain);
                    logger.debug("Added x5c header with {} certificate(s)", x5cChain.size());
                }
            } else {
                logger.debug("No certificate chain found for primary key: {}", primaryKeyName);
            }
        } catch (Exception e) {
            logger.error("Failed to build x5c certificate chain: {}", e.getMessage());
            // Continue without x5c header - JWT signing will still work
        }
    }
    
    /**
     * Converts PEM certificate chain to x5c header format.
     * 
     * <p>This method transforms PEM-encoded X.509 certificates into the Base64 DER
     * format required for JWT x5c headers. Each certificate is processed individually
     * to ensure proper encoding, with error handling for individual certificate
     * conversion failures.</p>
     * 
     * <h4>Conversion Process:</h4>
     * <ol>
     *   <li>Iterates through each PEM certificate in the chain</li>
     *   <li>Converts PEM format to DER (Distinguished Encoding Rules)</li>
     *   <li>Encodes DER bytes as Base64 for x5c header</li>
     *   <li>Continues processing remaining certificates if one fails</li>
     * </ol>
     * 
     * @param certificateChain list of PEM-encoded X.509 certificates
     * @return list of Base64 DER-encoded certificates for x5c header
     * @see CertificateChainBuilder#buildX5cChain(String)
     */
    private List<String> convertToX5cFormat(List<String> certificateChain) {
        List<String> x5cChain = new ArrayList<>();
        
        for (String certPem : certificateChain) {
            try {
                String derBase64 = CertificateChainBuilder.buildX5cChain(certPem).get(0);
                x5cChain.add(derBase64);
            } catch (Exception e) {
                logger.error("Failed to convert certificate to DER format: {}", e.getMessage());
            }
        }
        
        return x5cChain;
    }
    
    /**
     * Customizes JWT payload with version information and client details.
     * 
     * <p>This method adds custom claims to JWT tokens that provide additional
     * context about the token version and the client for which the token was
     * issued. These claims assist in token management, debugging, and client
     * identification.</p>
     * 
     * <h4>Custom Claims Added:</h4>
     * <ul>
     *   <li><strong>ver:</strong> Token version from configuration for compatibility tracking</li>
     *   <li><strong>client_id:</strong> OAuth2 client identifier</li>
     *   <li><strong>client_name:</strong> Human-readable client name (with fallback to ID)</li>
     * </ul>
     * 
     * @param context the JWT encoding context containing claims builder
     * @see #getClientDisplayName(RegisteredClient)
     */
    private void customizeJwtPayload(JwtEncodingContext context) {
        context.getClaims().claim("ver", jwtVersion);
        
        RegisteredClient registeredClient = context.getRegisteredClient();
        context.getClaims()
            .claim("client_id", registeredClient.getClientId())
            .claim("client_name", getClientDisplayName(registeredClient));
    }
    
    /**
     * Retrieves a display-friendly name for the OAuth2 client.
     * 
     * <p>This method provides a fallback mechanism for client naming in JWT tokens.
     * It prefers the configured client name but falls back to the client ID if
     * no explicit name is configured, ensuring tokens always contain meaningful
     * client identification.</p>
     * 
     * @param client the registered OAuth2 client
     * @return client name if available, otherwise client ID as fallback
     */
    private String getClientDisplayName(RegisteredClient client) {
        return client.getClientName() != null ? 
            client.getClientName() : client.getClientId();
    }
    
    /**
     * Record to hold cryptographic key configuration data for JWK creation.
     * 
     * <p>This record encapsulates all information needed to create a JWK from
     * a configured cryptographic key. It includes the key material, identifier,
     * and primary status to determine appropriate key operations.</p>
     * 
     * <h4>Record Components:</h4>
     * <ul>
     *   <li><strong>publicKey:</strong> EC public key for signature verification</li>
     *   <li><strong>privateKey:</strong> EC private key for signature generation (primary keys only)</li>
     *   <li><strong>keyId:</strong> Unique identifier for the key in JWK format</li>
     *   <li><strong>isPrimary:</strong> Flag indicating if key is used for signing operations</li>
     * </ul>
     * 
     * @param publicKey the EC public key component
     * @param privateKey the EC private key component  
     * @param keyId unique identifier for the cryptographic key
     * @param isPrimary true if this is the primary key used for signing operations
     */
    private record KeyConfiguration(
        ECPublicKey publicKey,
        ECPrivateKey privateKey,
        String keyId,
        boolean isPrimary
    ) {}
}