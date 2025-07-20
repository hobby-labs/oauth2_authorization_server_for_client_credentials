package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.KeysService;

@Configuration
public class AuthorizationServerConfig {
    
    private final KeysService keysService;
    
    public AuthorizationServerConfig(KeysService keysService) {
        this.keysService = keysService;
    }
    
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // org.springframework.security:spring-security-oauth2-authorization-server:1.4.0
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        
        http
            .oauth2ResourceServer((resourceServer) -> resourceServer
                .jwt(Customizer.withDefaults()));

        System.out.println("Authorization Server Security Filter Chain initialized");
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("my-client")
                .clientSecret("{noop}my-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .scope("write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .build())
                .build();

        System.out.println("Registered client 'my-client' with CLIENT_CREDENTIALS grant type");
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            System.out.println("Loading EC keys from YAML configuration...");
            
            // Check if key rotation is enabled
            boolean keyRotationEnabled = keysService.isKeyRotationEnabled();
            System.out.println("Key rotation enabled: " + keyRotationEnabled);
            
            java.util.List<com.nimbusds.jose.jwk.JWK> jwkList = new java.util.ArrayList<>();
            
            if (keyRotationEnabled) {
                // Load all keys when rotation is enabled
                java.util.Set<String> allKeyNames = keysService.getAllKeyNames();
                System.out.println("Loading multiple keys for rotation: " + allKeyNames);
                
                for (String keyName : allKeyNames) {
                    try {
                        KeyPair keyPair = keysService.getKeyPair(keyName);
                        String keyId = keysService.getKeyId(keyName);
                        
                        java.security.interfaces.ECPublicKey ecPublicKey = (java.security.interfaces.ECPublicKey) keyPair.getPublic();
                        java.security.interfaces.ECPrivateKey ecPrivateKey = (java.security.interfaces.ECPrivateKey) keyPair.getPrivate();
                        
                        // For non-primary keys, only include public key operations
                        boolean isPrimary = keyName.equals(keysService.getPrimaryKeyName());
                        java.util.Set<KeyOperation> keyOps = isPrimary ? 
                            java.util.Set.of(KeyOperation.SIGN, KeyOperation.VERIFY) :
                            java.util.Set.of(KeyOperation.VERIFY);
                            
                        ECKey.Builder ecKeyBuilder = new ECKey.Builder(Curve.P_256, ecPublicKey)
                                .keyID(keyId)
                                .algorithm(JWSAlgorithm.ES256)
                                .keyUse(KeyUse.SIGNATURE)
                                .keyOperations(keyOps);
                        
                        // Only add private key to primary key for signing
                        if (isPrimary) {
                            ecKeyBuilder.privateKey(ecPrivateKey);
                        }
                        
                        ECKey ecKey = ecKeyBuilder.build();
                        jwkList.add(ecKey);
                        
                        System.out.println("Loaded key: " + keyName + " (ID: " + keyId + ", Primary: " + isPrimary + ")");
                        
                    } catch (Exception e) {
                        System.err.println("Failed to load key: " + keyName + " - " + e.getMessage());
                        // Continue loading other keys
                    }
                }
                
            } else {
                // Load only primary key when rotation is disabled
                KeyPair ecKeyPair = keysService.getPrimaryKeyPair();
                String keyId = keysService.getPrimaryKeyId();
                
                java.security.interfaces.ECPublicKey ecPublicKey = (java.security.interfaces.ECPublicKey) ecKeyPair.getPublic();
                java.security.interfaces.ECPrivateKey ecPrivateKey = (java.security.interfaces.ECPrivateKey) ecKeyPair.getPrivate();
                
                ECKey ecKey = new ECKey.Builder(Curve.P_256, ecPublicKey)
                        .privateKey(ecPrivateKey)
                        .keyID(keyId)
                        .algorithm(JWSAlgorithm.ES256)
                        .keyUse(KeyUse.SIGNATURE)
                        .keyOperations(java.util.Set.of(
                            KeyOperation.SIGN,
                            KeyOperation.VERIFY
                        ))
                        .build();
                        
                jwkList.add(ecKey);
                System.out.println("Loaded primary key only: " + keysService.getPrimaryKeyName());
            }
            
            if (jwkList.isEmpty()) {
                throw new RuntimeException("No valid keys could be loaded");
            }
            
            JWKSet jwkSet = new JWKSet(jwkList);
            
            System.out.println("JWK Source initialized with " + jwkList.size() + " key(s)");
            System.out.println("Primary key: " + keysService.getPrimaryKeyName());
            System.out.println("Algorithm: ES256, Curve: P-256");
            
            return new ImmutableJWKSet<>(jwkSet);
            
        } catch (Exception e) {
            System.err.println("Failed to load EC key pair from YAML: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Could not load keys from YAML configuration", e);
        }
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        System.out.println("Authorization Server Settings initialized with issuer: http://localhost:9000");
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            // Customize JWT header
            context.getJwsHeader().algorithm(SignatureAlgorithm.ES256);
            context.getJwsHeader().type("JWT");  // Add "typ": "JWT" to the header
            
            // Option 1: Static certificate (replace with your actual certificate)
            java.util.List<String> x5c = java.util.Arrays.asList(
                "MIICdTCCAhugAwIBAgIJAOExample1...", // Your actual certificate in Base64 DER format
                "MIICdTCCAhugAwIBAgIJAOExample2..."  // Optional: Additional certificates in the chain
            );
            
            // Option 2: Generate self-signed certificate for testing (uncomment to use)
            /*
            try {
                java.util.List<String> x5c = generateSelfSignedCertificate();
                context.getJwsHeader().header("x5c", x5c);
                return;
            } catch (Exception e) {
                System.err.println("Failed to generate self-signed certificate: " + e.getMessage());
                // Fall back to static certificate
            }
            */
            
            context.getJwsHeader().header("x5c", x5c);
            
            // Customize JWT payload (claims)
            context.getClaims().claim("ver", "1");  // Add "ver": "1" to the payload
            
            // Add client information to JWT payload
            RegisteredClient registeredClient = context.getRegisteredClient();
            context.getClaims()
                .claim("client_id", registeredClient.getClientId())
                .claim("client_name", registeredClient.getClientName() != null ? 
                    registeredClient.getClientName() : registeredClient.getClientId());
        };
    }
}
