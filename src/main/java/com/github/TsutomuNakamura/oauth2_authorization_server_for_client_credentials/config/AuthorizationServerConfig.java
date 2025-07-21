package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import java.security.KeyPair;
import java.util.UUID;

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
import org.springframework.security.oauth2.jwt.JwtEncoder;
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
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.IntrospectorService;

@Configuration
public class AuthorizationServerConfig {
    
    private final KeysService keysService;
    private final ClientsService clientsService;
    private final IntrospectorService introspectorService;
    
    public AuthorizationServerConfig(KeysService keysService, ClientsService clientsService, IntrospectorService introspectorService) {
        this.keysService = keysService;
        this.clientsService = clientsService;
        this.introspectorService = introspectorService;
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
    @Order(2)
    public SecurityFilterChain introspectionSecurityFilterChain(HttpSecurity http) throws Exception {
        // Create custom client repository for introspection using introspector.yml
        RegisteredClientRepository introspectorClientRepository = createIntrospectorClientRepository();
        
        http.securityMatcher("/oauth2/introspect", "/oauth2/introspect/health")
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/oauth2/introspect").authenticated()
                .requestMatchers("/oauth2/introspect/health").permitAll()
                .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults())
            .with(OAuth2AuthorizationServerConfigurer.authorizationServer()
                .registeredClientRepository(introspectorClientRepository), Customizer.withDefaults());

        System.out.println("Introspection Security Filter Chain initialized with custom introspector client repository");
        return http.build();
    }
    
    /**
     * Creates a separate RegisteredClientRepository for introspection endpoints
     * using credentials from introspector.yml instead of clients.yml
     */
    private RegisteredClientRepository createIntrospectorClientRepository() {
        try {
            System.out.println("Loading introspector clients from YAML configuration...");
            
            java.util.List<RegisteredClient> introspectorClients = new java.util.ArrayList<>();
            java.util.Map<String, Object> allIntrospectors = introspectorService.getAllIntrospectors();
            
            if (allIntrospectors.isEmpty()) {
                System.err.println("WARNING: No introspector clients found in introspector.yml");
                throw new RuntimeException("No introspector clients configured in introspector.yml");
            }
            
            for (String introspectorName : allIntrospectors.keySet()) {
                try {
                    @SuppressWarnings("unchecked")
                    java.util.Map<String, Object> introspector = (java.util.Map<String, Object>) allIntrospectors.get(introspectorName);
                    
                    String clientId = (String) introspector.get("client-id");
                    String clientSecret = (String) introspector.get("client-secret");
                    String clientName = (String) introspector.get("client-name");
                    
                    RegisteredClient introspectorClient = RegisteredClient.withId(UUID.randomUUID().toString())
                            .clientId(clientId)
                            .clientSecret("{noop}" + clientSecret)  // {noop} for plain text passwords
                            .clientName(clientName)
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                            .scope("introspect") // Special scope for introspection
                            .tokenSettings(TokenSettings.builder()
                                    .accessTokenTimeToLive(Duration.ofMinutes(60)) // Longer TTL for introspection services
                                    .build())
                            .build();
                    
                    introspectorClients.add(introspectorClient);
                    
                    System.out.println("Registered introspector client '" + clientId + "' (" + clientName + ") for introspection");
                    
                } catch (Exception e) {
                    System.err.println("Failed to register introspector '" + introspectorName + "': " + e.getMessage());
                    // Continue with other introspectors
                }
            }
            
            System.out.println("Total registered introspector clients: " + introspectorClients.size());
            return new InMemoryRegisteredClientRepository(introspectorClients);
            
        } catch (Exception e) {
            System.err.println("Failed to load introspector configuration: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Could not load introspector clients from introspector.yml", e);
        }
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        try {
            System.out.println("Loading OAuth2 clients from YAML configuration...");
            
            java.util.List<RegisteredClient> clients = new java.util.ArrayList<>();
            java.util.Map<String, Object> allClients = clientsService.getAllClients();
            
            if (allClients.isEmpty()) {
                System.err.println("FATAL: No clients found in configuration!");
                System.err.println("Please ensure clients.yml contains at least one valid OAuth2 client configuration.");
                throw new RuntimeException("Application startup failed: No OAuth2 clients configured in clients.yml. " +
                    "At least one client must be defined for the authorization server to function properly.");
            }

            for (String clientName : allClients.keySet()) {
                try {
                    String clientId = clientsService.getClientId(clientName);
                    String clientSecret = clientsService.getClientSecret(clientName);
                    String displayName = clientsService.getClientDisplayName(clientName);
                    java.util.List<String> scopes = clientsService.getClientScopes(clientName);
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
            
        } catch (Exception e) {
            System.err.println("Failed to load clients configuration: " + e.getMessage());
            e.printStackTrace();
            
            // Fallback to default client configuration
            System.out.println("Falling back to default client configuration");
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

            System.out.println("Registered fallback client 'my-client' with CLIENT_CREDENTIALS grant type");
            return new InMemoryRegisteredClientRepository(registeredClient);
        }
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            System.out.println("Loading EC keys from YAML configuration for key rotation...");
            
            java.util.List<com.nimbusds.jose.jwk.JWK> jwkList = new java.util.ArrayList<>();
            
            // Load all keys for rotation
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
                for (com.nimbusds.jose.jwk.JWK jwk : candidateKeys) {
                    if (primaryKeyId.equals(jwk.getKeyID()) && jwk instanceof ECKey) {
                        ECKey ecKey = (ECKey) jwk;
                        // Only return keys that have private key (can sign)
                        if (ecKey.isPrivate()) {
                            System.out.println("Selected primary key for signing: " + jwk.getKeyID());
                            return jwk;
                        }
                    }
                }
                
                // Fallback: return the first key with private key
                for (com.nimbusds.jose.jwk.JWK jwk : candidateKeys) {
                    if (jwk instanceof ECKey) {
                        ECKey ecKey = (ECKey) jwk;
                        if (ecKey.isPrivate()) {
                            System.out.println("Selected fallback key for signing: " + jwk.getKeyID());
                            return jwk;
                        }
                    }
                }
                
                System.err.println("No suitable signing key found!");
                throw new RuntimeException("No suitable signing key found");
                
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
