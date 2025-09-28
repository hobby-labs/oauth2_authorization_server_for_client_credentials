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

    @Test
    void getClientConfig_WithNullClientsConfiguration_ShouldReturnNull() {
        // Given: ClientsService with null clientsConfiguration (not initialized)
        // This directly targets line 316: return null when clientsConfiguration is null
        
        // When: Call getClientConfig without calling init() first
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto result = 
            clientsService.getClientConfig("any-client-name");
        
        // Then: Should return null as per line 316
        assertNull(result, "getClientConfig should return null when clientsConfiguration is null");
    }

    @Test
    void getClientConfig_WithInitializedServiceAndNonExistentClient_ShouldReturnNull() throws IOException {
        // Given: Initialized service but asking for a client that doesn't exist
        String validYamlContent = """
            clients:
              existing-client:
                client-id: "existing-client-id"
                client-secret: "existing-client-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // Initialize the service
        clientsService.init();
        
        // When: Call getClientConfig with non-existent client name
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto result = 
            clientsService.getClientConfig("non-existent-client");
        
        // Then: Should return null when client doesn't exist
        assertNull(result, "getClientConfig should return null for non-existent client");
        
        // But should return valid config for existing client
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto existingClient = 
            clientsService.getClientConfig("existing-client");
        assertNotNull(existingClient, "getClientConfig should return valid config for existing client");
    }

    @Test
    void getClientConfig_WithCorruptedInternalState_ShouldReturnNull() {
        // Given: Simulate corrupted internal state where clientsConfiguration.getClients() is null
        // This tests the second condition at line 314-315: getClients() == null
        
        // Use reflection to set up a scenario where clientsConfiguration exists but getClients() would return null
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration mockConfig = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        // Note: ClientsConfiguration with null clients map will trigger the null check
        
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", mockConfig);
        
        // When: Call getClientConfig
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto result = 
            clientsService.getClientConfig("any-client");
        
        // Then: Should return null as per line 316 when getClients() returns null
        assertNull(result, "getClientConfig should return null when clientsConfiguration.getClients() is null");
    }

    @Test
    void getClientId_WithUninitializedService_ShouldReturnDefaultValue() {
        // Given: ClientsService not initialized (clientsConfiguration is null)
        // This targets line 332: return defaultValue when getClientConfig() returns null
        
        // When: Call getClientId without initializing the service first
        String result = clientsService.getClientId("any-client-name");
        
        // Then: Should return null (the defaultValue passed to getClientAttribute)
        assertNull(result, "getClientId should return null (defaultValue) when service is not initialized");
    }

    @Test
    void getClientId_WithNonExistentClient_ShouldReturnDefaultValue() throws IOException {
        // Given: Initialized service but requesting a non-existent client
        String validYamlContent = """
            clients:
              existing-client:
                client-id: "existing-client-id"
                client-secret: "existing-client-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // Initialize the service
        clientsService.init();
        
        // When: Call getClientId for non-existent client
        String result = clientsService.getClientId("non-existent-client");
        
        // Then: Should return null (defaultValue) since getClientConfig returns null
        assertNull(result, "getClientId should return null (defaultValue) for non-existent client");
        
        // But should return actual value for existing client
        String existingClientId = clientsService.getClientId("existing-client");
        assertEquals("existing-client-id", existingClientId, "getClientId should return actual client-id for existing client");
    }

    @Test
    void getClientId_WithCorruptedClientConfiguration_ShouldReturnDefaultValue() {
        // Given: Corrupted state where clientsConfiguration exists but getClients() returns null
        // This ensures getClientConfig() returns null, triggering line 332 in getClientAttribute()
        
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration mockConfig = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", mockConfig);
        
        // When: Call getClientId
        String result = clientsService.getClientId("any-client");
        
        // Then: Should return null (defaultValue) because getClientConfig() returns null
        assertNull(result, "getClientId should return null (defaultValue) when clientsConfiguration.getClients() is null");
    }

    @Test
    void getClientId_WithClientHavingNullClientId_ShouldReturnDefaultValue() throws IOException {
        // Given: Client exists but has null client-id field
        // This tests the case where getClientConfig() returns non-null but clientConfig.getClientId() returns null
        String yamlWithNullClientId = """
            clients:
              client-with-null-id:
                client-secret: "some-secret"
                client-name: "Test Client"
            """;
        
        Path configFile = tempDir.resolve("null-client-id.yml");
        Files.writeString(configFile, yamlWithNullClientId);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // This will fail during init() due to validation, so we need to bypass validation
        // Use reflection to set up the state manually
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration config = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto clientDto = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto();
        // clientDto.setClientId(null) - if there were setters, but since clientId is null by default
        
        java.util.Map<String, com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto> clientsMap = 
            new java.util.HashMap<>();
        clientsMap.put("client-with-null-id", clientDto);
        
        // Use reflection to set the clients map
        ReflectionTestUtils.setField(config, "clients", clientsMap);
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", config);
        
        // When: Call getClientId for client with null client-id
        String result = clientsService.getClientId("client-with-null-id");
        
        // Then: Should return null (defaultValue) because clientConfig.getClientId() returns null
        assertNull(result, "getClientId should return null (defaultValue) when client-id field is null");
    }

    @Test
    void getClientId_MultipleScenarios_ShouldHandleAllDefaultValueCases() throws IOException {
        // Given: Test multiple scenarios that should all return defaultValue (null)
        
        // Scenario 1: Uninitialized service
        String uninitializedResult = clientsService.getClientId("any-client");
        assertNull(uninitializedResult, "Uninitialized service should return null");
        
        // Scenario 2: Initialize service and test non-existent client  
        String validYamlContent = """
            clients:
              valid-client:
                client-id: "valid-id"
                client-secret: "valid-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        String nonExistentResult = clientsService.getClientId("non-existent-client");
        assertNull(nonExistentResult, "Non-existent client should return null");
        
        // Scenario 3: Valid client should return actual value (not defaultValue)
        String validResult = clientsService.getClientId("valid-client");
        assertEquals("valid-id", validResult, "Valid client should return actual client-id, not defaultValue");
        
        // Scenario 4: Corrupt state
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration corruptConfig = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", corruptConfig);
        
        String corruptResult = clientsService.getClientId("any-client");
        assertNull(corruptResult, "Corrupt configuration should return null");
    }

    @Test
    void getClientSecret_WithUninitializedService_ShouldReturnDefaultValue() {
        // Given: ClientsService not initialized (clientsConfiguration is null)
        // This targets line 332: return defaultValue when getClientConfig() returns null
        // Tests the CLIENT_SECRET_FIELD case in the switch statement of getClientAttribute()
        
        // When: Call getClientSecret without initializing the service first
        String result = clientsService.getClientSecret("any-client-name");
        
        // Then: Should return null (the defaultValue passed to getClientAttribute for CLIENT_SECRET_FIELD)
        assertNull(result, "getClientSecret should return null (defaultValue) when service is not initialized");
    }

    @Test
    void getClientSecret_WithNonExistentClient_ShouldReturnDefaultValue() throws IOException {
        // Given: Initialized service but requesting a non-existent client
        // This tests the CLIENT_SECRET_FIELD branch in getClientAttribute() switch statement
        String validYamlContent = """
            clients:
              existing-client:
                client-id: "existing-client-id"
                client-secret: "existing-client-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // Initialize the service
        clientsService.init();
        
        // When: Call getClientSecret for non-existent client
        String result = clientsService.getClientSecret("non-existent-client");
        
        // Then: Should return null (defaultValue) since getClientConfig returns null
        assertNull(result, "getClientSecret should return null (defaultValue) for non-existent client");
        
        // But should return actual value for existing client
        String existingClientSecret = clientsService.getClientSecret("existing-client");
        assertEquals("existing-client-secret", existingClientSecret, "getClientSecret should return actual client-secret for existing client");
    }

    @Test
    void getClientSecret_WithCorruptedClientConfiguration_ShouldReturnDefaultValue() {
        // Given: Corrupted state where clientsConfiguration exists but getClients() returns null
        // This ensures getClientConfig() returns null, triggering line 332 in getClientAttribute()
        // Specifically tests the CLIENT_SECRET_FIELD case
        
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration mockConfig = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", mockConfig);
        
        // When: Call getClientSecret
        String result = clientsService.getClientSecret("any-client");
        
        // Then: Should return null (defaultValue) because getClientConfig() returns null
        assertNull(result, "getClientSecret should return null (defaultValue) when clientsConfiguration.getClients() is null");
    }

    @Test
    void getClientSecret_WithClientHavingNullClientSecret_ShouldReturnDefaultValue() throws IOException {
        // Given: Client exists but has null client-secret field
        // This tests the CLIENT_SECRET_FIELD branch where clientConfig.getClientSecret() returns null
        
        // Use reflection to set up the state manually (since validation would prevent this in normal init)
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration config = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto clientDto = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto();
        // clientDto.setClientSecret(null) - if there were setters, but since clientSecret is null by default
        
        java.util.Map<String, com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto> clientsMap = 
            new java.util.HashMap<>();
        clientsMap.put("client-with-null-secret", clientDto);
        
        // Use reflection to set the clients map
        ReflectionTestUtils.setField(config, "clients", clientsMap);
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", config);
        
        // When: Call getClientSecret for client with null client-secret
        String result = clientsService.getClientSecret("client-with-null-secret");
        
        // Then: Should return null (defaultValue) because clientConfig.getClientSecret() returns null
        // This tests the CLIENT_SECRET_FIELD -> ... != null ? ... : defaultValue logic
        assertNull(result, "getClientSecret should return null (defaultValue) when client-secret field is null");
    }

    @Test
    void getClientSecret_WithValidClientSecret_ShouldReturnActualValue() throws IOException {
        // Given: Properly configured client with valid client-secret
        // This tests the successful path of the CLIENT_SECRET_FIELD case
        String validYamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret-value"
                client-name: "Test Client"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // Initialize the service
        clientsService.init();
        
        // When: Call getClientSecret for valid client
        String result = clientsService.getClientSecret("test-client");
        
        // Then: Should return the actual client-secret value (not defaultValue)
        assertEquals("test-client-secret-value", result, "getClientSecret should return actual client-secret value for valid client");
    }

    @Test
    void getClientSecret_MultipleScenarios_ShouldHandleAllClientSecretCases() throws IOException {
        // Given: Test multiple scenarios for CLIENT_SECRET_FIELD coverage
        
        // Scenario 1: Uninitialized service
        String uninitializedResult = clientsService.getClientSecret("any-client");
        assertNull(uninitializedResult, "Uninitialized service should return null for getClientSecret");
        
        // Scenario 2: Initialize service and test non-existent client  
        String validYamlContent = """
            clients:
              valid-client:
                client-id: "valid-id"
                client-secret: "valid-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        String nonExistentResult = clientsService.getClientSecret("non-existent-client");
        assertNull(nonExistentResult, "Non-existent client should return null for getClientSecret");
        
        // Scenario 3: Valid client should return actual value (not defaultValue)
        String validResult = clientsService.getClientSecret("valid-client");
        assertEquals("valid-secret", validResult, "Valid client should return actual client-secret, not defaultValue");
        
        // Scenario 4: Corrupt state
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration corruptConfig = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", corruptConfig);
        
        String corruptResult = clientsService.getClientSecret("any-client");
        assertNull(corruptResult, "Corrupt configuration should return null for getClientSecret");
    }

    
}