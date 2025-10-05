package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.model;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ClientConfigurationTest {

    // ========== hasRole() Tests ==========
    
    @Test
    @DisplayName("hasRole() should return true when client has the specified role")
    void hasRole_WithExistingRole_ShouldReturnTrue() {
        // Given: A ClientConfiguration with multiple roles including "ADMIN"
        ClientConfiguration config = new ClientConfiguration(
                "test-client-id",
                "test-client-secret",
                "Test Application",
                List.of("read", "write"),
                Duration.ofMinutes(30),
                List.of("CLIENT", "ADMIN", "SERVICE")
        );
        
        // When: Check if client has the "ADMIN" role
        boolean result = config.hasRole("ADMIN");
        
        // Then: Should return true
        assertTrue(result, "Client should have the ADMIN role");
    }

    // ========== getTokenTtlMinutes() Tests ==========

    @Test
    @DisplayName("getTokenTtlMinutes() should return the correct token TTL in minutes")
    void getTokenTtlMinutes_ShouldReturnCorrectMinutes() {
        // Given: A ClientConfiguration with a token TTL of 45 minutes
        ClientConfiguration config = new ClientConfiguration(
                "test-client-id",
                "test-client-secret",
                "Test Application",
                List.of("read", "write"),
                Duration.ofMinutes(45),
                List.of("CLIENT", "SERVICE")
        );
        
        // When: Retrieve the token TTL in minutes
        long ttlMinutes = config.getTokenTtlMinutes();
        
        // Then: Should return 45
        assertEquals(45, ttlMinutes, "Token TTL should be 45 minutes");
    }

    // ========== Constructor Validation Tests ==========

    @Test
    @DisplayName("Constructor should throw NullPointerException when clientId is null")
    void constructor_NullClientId_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with null clientId should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    null,
                    "test-client-secret",
                    "Test Application",
                    List.of("read", "write"),
                    Duration.ofMinutes(30),
                    List.of("CLIENT", "SERVICE")
            );
        });
        assertEquals("Client ID cannot be null or blank", exception.getMessage());
    }

    @Test
    @DisplayName("Constructor should throw IllegalArgumentException when clientId is blank")
    void constructor_BlankClientId_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with blank clientId should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    "   ",
                    "test-client-secret",
                    "Test Application",
                    List.of("read", "write"),
                    Duration.ofMinutes(30),
                    List.of("CLIENT", "SERVICE")
            );
        });
        assertEquals("Client ID cannot be null or blank", exception.getMessage());
    }

    @Test
    @DisplayName("Constructor should throw NullPointerException when clientSecret is null")
    void constructor_NullClientSecret_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with null clientSecret should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    "test-client-id",
                    null,
                    "Test Application",
                    List.of("read", "write"),
                    Duration.ofMinutes(30),
                    List.of("CLIENT", "SERVICE")
            );
        });
        assertEquals("Client secret cannot be null or blank", exception.getMessage());
    }

    @Test
    @DisplayName("Constructor should throw IllegalArgumentException when clientSecret is blank")
    void constructor_BlankClientSecret_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with blank clientSecret should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    "test-client-id",
                    "   ",
                    "Test Application",
                    List.of("read", "write"),
                    Duration.ofMinutes(30),
                    List.of("CLIENT", "SERVICE")
            );
        });
        assertEquals("Client secret cannot be null or blank", exception.getMessage());
    }

    @Test
    @DisplayName("Constructor should throw IllegalArgumentException when displayName is null")
    void constructor_NullDisplayName_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with null displayName should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    "test-client-id",
                    "test-client-secret",
                    null,
                    List.of("read", "write"),
                    Duration.ofMinutes(30),
                    List.of("CLIENT", "SERVICE")
            );
        });
        assertEquals("Display name cannot be null", exception.getMessage());
    }

    @Test
    @DisplayName("Constructor should throw IllegalArgumentException when scopes is null")
    void constructor_NullScopes_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with null scopes should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    "test-client-id",
                    "test-client-secret",
                    "Test Application",
                    null,
                    Duration.ofMinutes(30),
                    List.of("CLIENT", "SERVICE")
            );
        });
        assertEquals("Scopes list cannot be null", exception.getMessage());
    }

    @Test
    @DisplayName("Constructor should throw IllegalArgumentException when tokenTtl is null")
    void constructor_NullTokenTtl_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with null tokenTtl should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    "test-client-id",
                    "test-client-secret",
                    "Test Application",
                    List.of("read", "write"),
                    null,
                    List.of("CLIENT", "SERVICE")
            );
        });
        assertEquals("Token TTL cannot be null or negative", exception.getMessage());
    }

    @Test
    @DisplayName("Constructor should throw IllegalArgumentException when tokenTtl is negative")
    void constructor_NegativeTokenTtl_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with negative tokenTtl should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    "test-client-id",
                    "test-client-secret",
                    "Test Application",
                    List.of("read", "write"),
                    Duration.ofMinutes(-10),
                    List.of("CLIENT", "SERVICE")
            );
        });
        assertEquals("Token TTL cannot be null or negative", exception.getMessage());
    }
    
    @Test
    @DisplayName("Constructor should throw IllegalArgumentException when roles is null")
    void constructor_NullRoles_ShouldThrowException() {
        // When & Then: Creating ClientConfiguration with null roles should throw exception
        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new ClientConfiguration(
                    "test-client-id",
                    "test-client-secret",
                    "Test Application",
                    List.of("read", "write"),
                    Duration.ofMinutes(30),
                    null
            );
        });
        assertEquals("Roles list cannot be null", exception.getMessage());
    }
}
