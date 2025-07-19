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
// import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.KeyLoader;

@Configuration
public class AuthorizationServerConfig {
    
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
        // Option 1: Generate RSA key pair (current approach - works with most clients)
        // KeyPair rsaKeyPair = generateRsaKey();
        // RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        // RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        // RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
        //         .privateKey(rsaPrivateKey)
        //         .keyID("rsa-key-" + UUID.randomUUID().toString())
        //         .build();
        
        // Option 2: Generate EC key pair (prime256v1/P-256)
        KeyPair ecKeyPair = generateEcKey();
        java.security.interfaces.ECPublicKey ecPublicKey = (java.security.interfaces.ECPublicKey) ecKeyPair.getPublic();
        java.security.interfaces.ECPrivateKey ecPrivateKey = (java.security.interfaces.ECPrivateKey) ecKeyPair.getPrivate();
        ECKey ecKey = new ECKey.Builder(Curve.P_256, ecPublicKey)
                .privateKey(ecPrivateKey)
                .keyID("ec-key-" + UUID.randomUUID().toString())
                .algorithm(JWSAlgorithm.ES256)
                .keyUse(KeyUse.SIGNATURE)
                .keyOperations(java.util.Set.of(
                    KeyOperation.SIGN,
                    KeyOperation.VERIFY
                ))
                .build();
        
        // Option 3: Load EC keys from files (uncomment to use)
        // try {
        //     KeyPair ecKeyPair = KeyLoader.loadECFromFiles(
        //         "/path/to/ec-private-key.pem", 
        //         "/path/to/ec-public-key.pem"
        //     );
        //     java.security.interfaces.ECPublicKey ecPublicKey = (java.security.interfaces.ECPublicKey) ecKeyPair.getPublic();
        //     java.security.interfaces.ECPrivateKey ecPrivateKey = (java.security.interfaces.ECPrivateKey) ecKeyPair.getPrivate();
        //     ECKey ecKey = new ECKey.Builder(Curve.P_256, ecPublicKey)
        //             .privateKey(ecPrivateKey)
        //             .keyID("ec-key-from-file")
        //             .build();
        // } catch (Exception e) {
        //     throw new RuntimeException("Failed to load EC key pair from files", e);
        // }
        
        // // Create JWK Set with both RSA and EC keys (or just one)
        // JWKSet jwkSet = new JWKSet(java.util.Arrays.asList(rsaKey, ecKey));

        // Create JWK Set with both RSA and EC keys (or just one)
        JWKSet jwkSet = new JWKSet(java.util.Arrays.asList(ecKey));


        // Alternatively, use only EC key:
        // JWKSet jwkSet = new JWKSet(ecKey);
        
        System.out.println("JWK Source initialized with RSA and EC keys");
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateEcKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            java.security.spec.ECGenParameterSpec ecSpec = new java.security.spec.ECGenParameterSpec("secp256r1"); // prime256v1
            keyPairGenerator.initialize(ecSpec);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
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
    
    // Helper method to generate self-signed certificate for testing
    @SuppressWarnings("unused")
    private java.util.List<String> generateSelfSignedCertificate() throws Exception {
        // Generate EC key pair
        KeyPair keyPair = generateEcKey();
        
        // This is a simplified example - in production, use a proper certificate library
        // For now, return a placeholder certificate
        String exampleCert = "MIIBkTCB+wIJAMExample..."; // Placeholder
        
        return java.util.Arrays.asList(exampleCert);
    }

}
