package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.factory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.test.util.ReflectionTestUtils;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.model.ClientConfiguration;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RegisteredClientFactoryTest {

    private RegisteredClientFactory factory;
    
    @BeforeEach
    void setUp() {
        factory = new RegisteredClientFactory();
        // Set the password encoder prefix to the default value
        ReflectionTestUtils.setField(factory, "passwordEncoderPrefix", "{noop}");
    }

    // ========== createRegisteredClient(ClientConfiguration) Tests ==========
    
    @Test
    @DisplayName("createRegisteredClient() with valid configuration should return properly configured RegisteredClient")
    void createRegisteredClient_WithValidConfiguration_ShouldReturnProperlyConfiguredClient() {
        // Given: A valid client configuration
        ClientConfiguration config = new ClientConfiguration(
                "test-client-id",
                "test-client-secret",
                "Test Application",
                List.of("read", "write", "delete"),
                Duration.ofMinutes(30),
                List.of("CLIENT", "SERVICE")
        );
        
        // When: Create a RegisteredClient
        RegisteredClient result = factory.createRegisteredClient(config);
        
        // Then: The RegisteredClient should be properly configured
        assertNotNull(result, "RegisteredClient should not be null");
        assertNotNull(result.getId(), "Client ID should be generated");
        assertEquals("test-client-id", result.getClientId(), "Client ID should match configuration");
        assertEquals("{noop}test-client-secret", result.getClientSecret(), "Client secret should have password encoder prefix");
        assertEquals("Test Application", result.getClientName(), "Client name should match display name");
        
        // Verify authentication methods
        assertTrue(result.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                "Should support CLIENT_SECRET_BASIC authentication");
        assertTrue(result.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_POST),
                "Should support CLIENT_SECRET_POST authentication");
        assertEquals(2, result.getClientAuthenticationMethods().size(),
                "Should have exactly 2 authentication methods");
        
        // Verify grant type
        assertTrue(result.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS),
                "Should support CLIENT_CREDENTIALS grant type");
        assertEquals(1, result.getAuthorizationGrantTypes().size(),
                "Should have exactly 1 grant type");
        
        // Verify scopes
        assertTrue(result.getScopes().contains("read"), "Should have 'read' scope");
        assertTrue(result.getScopes().contains("write"), "Should have 'write' scope");
        assertTrue(result.getScopes().contains("delete"), "Should have 'delete' scope");
        assertEquals(3, result.getScopes().size(), "Should have exactly 3 scopes");
        
        // Verify token settings
        assertNotNull(result.getTokenSettings(), "Token settings should not be null");
        assertEquals(Duration.ofMinutes(30), result.getTokenSettings().getAccessTokenTimeToLive(),
                "Token TTL should match configuration");
    }

    @Test
    @DisplayName("createRegisteredClient() shoulw throw IllegalArgumentException when configuration is null")
    void createRegisteredClient_WithNullConfiguration_ShouldThrowException() {
        // Given: A null client configuration
        ClientConfiguration config = null;
        
        // When & Then: Creating a RegisteredClient should throw IllegalArgumentException
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            factory.createRegisteredClient(config);
        }, "Expected createRegisteredClient() to throw, but it didn't");
        
        assertEquals("Client configuration cannot be null", exception.getMessage(),
                "Exception message should indicate null configuration");
    }

    // ========== createRegisteredClient(ClientConfiguration config, TokenSettings tokenSettings) Tests ==========

    @Test
    @DisplayName("createRegisteredClient() should return registered client when called with valid parameters")
    void createRegisteredClient_WithValidParameters_ShouldReturnRegisteredClient() {
        // Given: A valid client configuration and token settings
        ClientConfiguration config = new ClientConfiguration(
                "custom-client-id",
                "custom-client-secret",
                "Custom App",
                List.of("custom-scope"),
                Duration.ofHours(1),
                List.of("CUSTOM")
        );
        TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1))
                .build();
        
        // When: Create a RegisteredClient with custom token settings
        RegisteredClient result = (RegisteredClient) factory.createRegisteredClient(config, tokenSettings);
        
        // Then: The RegisteredClient should be properly configured
        assertNotNull(result, "RegisteredClient should not be null");
        assertNotNull(result.getId(), "Client ID should be generated");
        assertEquals("custom-client-id", result.getClientId(), "Client ID should match configuration");
        assertEquals("{noop}custom-client-secret", result.getClientSecret(), "Client secret should have password encoder prefix");
        assertEquals("Custom App", result.getClientName(), "Client name should match display name");
        
        // Verify authentication methods
        assertTrue(result.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                "Should support CLIENT_SECRET_BASIC authentication");
        assertTrue(result.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.CLIENT_SECRET_POST),
                "Should support CLIENT_SECRET_POST authentication");
        assertEquals(2, result.getClientAuthenticationMethods().size(),
                "Should have exactly 2 authentication methods");
        
        // Verify grant type
        assertTrue(result.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS),
                "Should support CLIENT_CREDENTIALS grant type");
        assertEquals(1, result.getAuthorizationGrantTypes().size(),
                "Should have exactly 1 grant type");
        
        // Verify scopes
        assertTrue(result.getScopes().contains("custom-scope"), "Should have 'custom-scope'");
        assertEquals(1, result.getScopes().size(), "Should have exactly 1 scope");
        
        // Verify token settings
        assertNotNull(result.getTokenSettings(), "Token settings should not be null");
        assertEquals(Duration.ofHours(1), result.getTokenSettings().getAccessTokenTimeToLive(),
                "Token TTL should match provided token settings");
    }
}
