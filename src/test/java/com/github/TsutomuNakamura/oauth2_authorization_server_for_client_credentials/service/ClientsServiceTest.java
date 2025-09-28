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

    @Test
    void init_WithEmptyYamlFile_ShouldThrowIllegalStateException() throws IOException {
        // Given: Create an empty YAML file (results in null yamlData)
        String emptyYamlContent = "";
        
        Path configFile = tempDir.resolve("empty-clients.yml");
        Files.writeString(configFile, emptyYamlContent);
        
        // Set the file path using reflection
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // When & Then: Call init method and expect IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> clientsService.init());
        
        // Verify the exception message indicates the issue with YAML configuration
        assertTrue(exception.getMessage().contains("Configuration file is empty or contains invalid YAML"));
    }

    @Test
    void init_WithInvalidYamlSyntax_ShouldThrowIllegalStateException() throws IOException {
        // Given: Create a YAML file with invalid syntax
        String invalidYamlContent = """
                clients:
                  - client-id: test-client
                    invalid-syntax: [unclosed bracket
                    scopes: ["read"]
                """;
        
        Path configFile = tempDir.resolve("invalid-clients.yml");
        Files.writeString(configFile, invalidYamlContent);
        
        // Set the file path using reflection
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // When & Then: Call init method and expect IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> clientsService.init());
        
        // Verify the exception message indicates YAML syntax error
        assertTrue(exception.getMessage().contains("Invalid YAML syntax"));
    }

    @Test
    void init_WithNonExistentFile_ShouldThrowIllegalStateException() throws IOException {
        // Given: Point to a non-existent file to trigger IOException
        String nonExistentFilePath = tempDir.resolve("non-existent-directory")
                                           .resolve("missing-file.yml").toString();
        
        // Set the file path using reflection
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", nonExistentFilePath);
        
        // When & Then: Call init method and expect IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> clientsService.init());
        
        // Verify the exception message indicates file access error
        assertTrue(exception.getMessage().contains("Could not read clients configuration from"));
        assertTrue(exception.getMessage().contains("Check if the file exists and is readable"));
        
        // Verify the original IOException is preserved as the cause
        assertNotNull(exception.getCause());
        assertTrue(exception.getCause() instanceof IOException);
    }
}