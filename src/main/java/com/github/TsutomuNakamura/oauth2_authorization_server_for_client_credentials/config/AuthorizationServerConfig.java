package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import java.security.KeyPair;
import java.util.UUID;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.jwk.JWK;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;

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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.KeysService;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.ClientsService;

@Configuration
public class AuthorizationServerConfig {
    
    private final KeysService keysService;
    private final ClientsService clientsService;
    
    public AuthorizationServerConfig(KeysService keysService, ClientsService clientsService) {
        this.keysService = keysService;
        this.clientsService = clientsService;
    }
    
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Configure OAuth2 Authorization Server with modern approach
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = 
            OAuth2AuthorizationServerConfigurer.authorizationServer()
                .oidc(Customizer.withDefaults()); // Enable OIDC if needed
        
        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, Customizer.withDefaults())
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults()));

        System.out.println("Authorization Server Security Filter Chain initialized");
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        System.out.println("Loading OAuth2 clients from YAML configuration...");
        
        List<RegisteredClient> clients = new ArrayList<>();
        Map<String, Object> allClients = clientsService.getAllClients();
        
        if (allClients.isEmpty()) {
            System.err.println("ERROR: No clients found in configuration file!");
            System.err.println("Please ensure clients.yml contains proper client entries.");
            System.err.println("Application startup will be aborted.");
            throw new IllegalStateException("No OAuth2 clients configured in clients.yml. " +
                "Application requires at least one client to be defined in the configuration file.");
        }
        
        for (String clientName : allClients.keySet()) {
            try {
                String clientId = clientsService.getClientId(clientName);
                String clientSecret = clientsService.getClientSecret(clientName);
                String displayName = clientsService.getClientDisplayName(clientName);
                List<String> scopes = clientsService.getClientScopes(clientName);
                Duration tokenTtl = clientsService.getAccessTokenTtl(clientName);
                
                RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(clientId)
                        .clientSecret("{noop}" + clientSecret)  // {noop} for plain text passwords in development
                        .clientName(displayName)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                
                // Add scopes
                for (String scope : scopes) {
                    clientBuilder.scope(scope);
                }
                
                // Set token settings
                clientBuilder.tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(tokenTtl)
                        .build());
                
                RegisteredClient registeredClient = clientBuilder.build();
                clients.add(registeredClient);
                
                System.out.println("Registered client '" + clientId + "' (" + displayName + ") with scopes: " + scopes + ", TTL: " + tokenTtl.toMinutes() + "min");
                
            } catch (Exception e) {
                System.err.println("Failed to register client '" + clientName + "': " + e.getMessage());
                // Continue with other clients
            }
        }
        
        System.out.println("Total registered clients: " + clients.size());
        return new InMemoryRegisteredClientRepository(clients);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            System.out.println("Loading EC keys from YAML configuration for key rotation...");
            
            List<JWK> jwkList = new ArrayList<>();
            
            // Load all keys for rotation
            Set<String> allKeyNames = keysService.getAllKeyNames();
            System.out.println("Loading multiple keys for rotation: " + allKeyNames);
            
            for (String keyName : allKeyNames) {
                try {
                    KeyPair keyPair = keysService.getKeyPair(keyName);
                    String keyId = keysService.getKeyId(keyName);
                    
                    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
                    ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
                    
                    // For non-primary keys, only include public key operations
                    boolean isPrimary = keyName.equals(keysService.getPrimaryKeyName());
                    Set<KeyOperation> keyOps = isPrimary ? 
                        Set.of(KeyOperation.SIGN, KeyOperation.VERIFY) :
                        Set.of(KeyOperation.VERIFY);
                        
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
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        // Create a custom JWT encoder that selects the primary key for signing
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        
        // Set a custom JWK selector that picks the primary key for signing
        encoder.setJwkSelector(candidateKeys -> {
            try {
                // Find the primary key (the one with private key for signing)
                String primaryKeyId = keysService.getPrimaryKeyId();
                for (JWK jwk : candidateKeys) {
                    if (primaryKeyId.equals(jwk.getKeyID()) && jwk instanceof ECKey) {
                        ECKey ecKey = (ECKey) jwk;
                        // Only return keys that have private key (can sign)
                        if (ecKey.isPrivate()) {
                            System.out.println("Selected primary key for signing: " + jwk.getKeyID());
                            return jwk;
                        }
                    }
                }
                
                System.err.println("Primary signing key '" + primaryKeyId + "' not found or not available for signing!");
                throw new RuntimeException("Primary signing key '" + primaryKeyId + "' not found or not available for signing");
                
            } catch (Exception e) {
                System.err.println("Error selecting JWK for signing: " + e.getMessage());
                throw new RuntimeException("Error selecting JWK for signing", e);
            }
        });
        
        return encoder;
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
            
            // Build x5c certificate chain dynamically
            try {
                String primaryKeyName = keysService.getPrimaryKeyName();
                List<String> certificateChain = keysService.getCertificateChain(primaryKeyName);
                
                if (!certificateChain.isEmpty()) {
                    // Convert PEM certificates to Base64 DER format for x5c header
                    List<String> x5cChain = new ArrayList<>();
                    
                    for (String certPem : certificateChain) {
                        try {
                            String derBase64 = com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.CertificateChainBuilder
                                .buildX5cChain(certPem).get(0);
                            x5cChain.add(derBase64);
                        } catch (Exception e) {
                            System.err.println("Failed to convert certificate to DER format: " + e.getMessage());
                        }
                    }
                    
                    if (!x5cChain.isEmpty()) {
                        context.getJwsHeader().header("x5c", x5cChain);
                        System.out.println("Added x5c header with " + x5cChain.size() + " certificate(s)");
                    }
                } else {
                    System.out.println("No certificate chain found for primary key: " + primaryKeyName);
                }
            } catch (Exception e) {
                System.err.println("Failed to build x5c certificate chain: " + e.getMessage());
                // Continue without x5c header - JWT signing will still work
            }
            
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
    
    /**
     * JWT Decoder for token introspection
     * Uses the same JWK source as the encoder for consistent validation
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        System.out.println("Configuring JWT Decoder for token introspection");
        return NimbusJwtDecoder.withJwkSetUri("http://localhost:9000/oauth2/jwks").build();
    }
}
