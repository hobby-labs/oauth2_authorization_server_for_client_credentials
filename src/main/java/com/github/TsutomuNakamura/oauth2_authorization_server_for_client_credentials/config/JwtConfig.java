package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * Configuration for JWT encoding, decoding, and key management
 * Handles JWK source creation, JWT encoder/decoder setup, and token customization
 */
@Configuration
public class JwtConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtConfig.class);
    private static final String JWKS_URI = "http://localhost:9000/oauth2/jwks";
    private static final String JWT_TYPE = "JWT";
    private static final String JWT_VERSION = "1";
    
    private final KeysService keysService;
    
    public JwtConfig(KeysService keysService) {
        this.keysService = keysService;
    }
    
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
    
    private JWK createJWKForKey(String keyName) throws Exception {
        KeyConfiguration keyConfig = extractKeyConfiguration(keyName);
        
        Set<KeyOperation> keyOps = keyConfig.isPrimary() ? 
            Set.of(KeyOperation.SIGN, KeyOperation.VERIFY) :
            Set.of(KeyOperation.VERIFY);
            
        ECKey.Builder ecKeyBuilder = new ECKey.Builder(Curve.P_256, keyConfig.publicKey())
                .keyID(keyConfig.keyId())
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(keyOps);
        
        // Only add private key to primary key for signing
        if (keyConfig.isPrimary()) {
            ecKeyBuilder.privateKey(keyConfig.privateKey());
        }
        
        logger.info("Loaded key: {} (ID: {}, Primary: {})", keyName, keyConfig.keyId(), keyConfig.isPrimary());
        
        return ecKeyBuilder.build();
    }
    
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
    
    private void validateKeys(List<JWK> jwkList) {
        if (jwkList.isEmpty()) {
            throw new IllegalStateException("No valid keys could be loaded. At least one key must be configured.");
        }
    }
    
    private void logJwkSourceInitialization(int keyCount) {
        logger.info("JWK Source initialized with {} key(s)", keyCount);
        logger.info("Primary key: {}", keysService.getPrimaryKeyName());
        logger.info("Algorithm: ES256, Curve: P-256");
    }
    
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        encoder.setJwkSelector(this::selectPrimarySigningKey);
        return encoder;
    }
    
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
    
    private boolean isPrimarySigningKey(JWK jwk, String primaryKeyId) {
        return primaryKeyId.equals(jwk.getKeyID()) && 
               jwk instanceof ECKey && 
               ((ECKey) jwk).isPrivate();
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        logger.info("Configuring JWT Decoder for token introspection");
        return NimbusJwtDecoder.withJwkSetUri(JWKS_URI).build();
    }
    
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            customizeJwtHeader(context);
            customizeJwtPayload(context);
        };
    }
    
    private void customizeJwtHeader(JwtEncodingContext context) {
        context.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
        context.getJwsHeader().type(JWT_TYPE);
        
        addX5cCertificateChain(context);
    }
    
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
    
    private void customizeJwtPayload(JwtEncodingContext context) {
        context.getClaims().claim("ver", JWT_VERSION);
        
        RegisteredClient registeredClient = context.getRegisteredClient();
        context.getClaims()
            .claim("client_id", registeredClient.getClientId())
            .claim("client_name", getClientDisplayName(registeredClient));
    }
    
    private String getClientDisplayName(RegisteredClient client) {
        return client.getClientName() != null ? 
            client.getClientName() : client.getClientId();
    }
    
    /**
     * Record to hold key configuration data
     */
    private record KeyConfiguration(
        ECPublicKey publicKey,
        ECPrivateKey privateKey,
        String keyId,
        boolean isPrimary
    ) {}
}