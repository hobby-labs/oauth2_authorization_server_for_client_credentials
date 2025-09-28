package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ClientsServiceTest {

    private ClientsService clientsService;
    
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        clientsService = new ClientsService();
    }

    @Test
    void init_WithValidConfiguration_ShouldInitializeSuccessfully() throws IOException {
        // Given: Create a valid clients.yml configuration file
        String validYamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret"
                client-name: "Test Client"
                scopes: ["read", "write"]
                access-token-ttl: 30
                roles: ["CLIENT"]
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        
        // Set the file path using reflection (since it's @Value injected)
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // When: Call init method
        assertDoesNotThrow(() -> clientsService.init());
        
        // Then: Verify the service is properly initialized
        // Check that we can retrieve the configured client
        assertEquals("test-client-id", clientsService.getClientId("test-client"));
        assertEquals("test-client-secret", clientsService.getClientSecret("test-client"));
        assertEquals("Test Client", clientsService.getClientDisplayName("test-client"));
        
        // Verify the clients section was loaded
        assertFalse(clientsService.getAllClients().isEmpty());
        assertEquals(1, clientsService.getAllClients().size());
        assertTrue(clientsService.getAllClients().containsKey("test-client"));
    }
}