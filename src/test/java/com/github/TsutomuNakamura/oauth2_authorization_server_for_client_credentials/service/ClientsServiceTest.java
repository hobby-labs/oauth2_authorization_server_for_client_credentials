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

    @Test
    void init_WithMissingClientsSection_ShouldThrowIllegalStateException() throws IOException {
        // Given: Create a YAML file without 'clients' section (only other content)
        String yamlWithoutClientsSection = """
                config:
                  settings: "some value"
                other:
                  data: "another value"
                """;
        
        Path configFile = tempDir.resolve("no-clients-section.yml");
        Files.writeString(configFile, yamlWithoutClientsSection);
        
        // Set the file path using reflection
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // When & Then: Call init method and expect IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> clientsService.init());
        
        // Verify the exception message indicates missing clients section
        assertTrue(exception.getMessage().contains("No 'clients' section found"));
        assertTrue(exception.getMessage().contains("Expected a 'clients:' section containing client definitions"));
    }

    @Test
    void init_WithClientHavingNullConfiguration_ShouldThrowIllegalStateException() throws IOException {
        // Given: Create a YAML file with a client name but null configuration
        // This targets the validateClient() method at lines 259-261
        String yamlWithNullClientConfig = """
                clients:
                  valid-client:
                    client-id: "valid-client-id"
                    client-secret: "valid-client-secret"
                  null-client: null
                """;
        
        Path configFile = tempDir.resolve("null-client-config.yml");
        Files.writeString(configFile, yamlWithNullClientConfig);
        
        // Set the file path using reflection
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // When & Then: Call init method and expect IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> clientsService.init());
        
        // Verify the exception message targets the specific client validation at lines 259-261
        assertTrue(exception.getMessage().contains("Client 'null-client' not found in configuration"));
    }

    @Test
    void init_WithClientHavingEmptyConfiguration_ShouldThrowIllegalStateException() throws IOException {
        // Given: Create a YAML file with a client name but empty configuration
        // This also targets the validateClient() method at lines 259-261
        String yamlWithEmptyClientConfig = """
                clients:
                  valid-client:
                    client-id: "valid-client-id"
                    client-secret: "valid-client-secret"
                  empty-client: {}
                """;
        
        Path configFile = tempDir.resolve("empty-client-config.yml");
        Files.writeString(configFile, yamlWithEmptyClientConfig);
        
        // Set the file path using reflection
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // When & Then: Call init method and expect IllegalStateException
        // This should fail during validation when empty-client has missing required fields
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> clientsService.init());
        
        // The exception should be about missing required field since empty config leads to null values
        assertTrue(exception.getMessage().contains("empty-client") && 
                  exception.getMessage().contains("missing required field"));
    }

    @Test
    void init_WithMultipleClientsWhereOneIsNull_ShouldThrowIllegalStateException() throws IOException {
        // Given: Create a YAML file with multiple clients where one has null configuration
        // This targets the validateClient() method at lines 259-261 in a multi-client scenario
        String yamlWithMixedClientConfigs = """
                clients:
                  good-client-1:
                    client-id: "good-client-1-id"
                    client-secret: "good-client-1-secret"
                  bad-client: null
                  good-client-2:
                    client-id: "good-client-2-id" 
                    client-secret: "good-client-2-secret"
                """;
        
        Path configFile = tempDir.resolve("mixed-client-config.yml");
        Files.writeString(configFile, yamlWithMixedClientConfigs);
        
        // Set the file path using reflection
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // When & Then: Call init method and expect IllegalStateException from lines 259-261
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> clientsService.init());
        
        // Verify the exception message targets the specific client validation at lines 259-261
        assertTrue(exception.getMessage().contains("Client 'bad-client' not found in configuration"));
        
        // Verify this is specifically the exception from the validateClient method, not from earlier steps
        assertFalse(exception.getMessage().contains("clients section"));
        assertFalse(exception.getMessage().contains("YAML"));
    }

    
}