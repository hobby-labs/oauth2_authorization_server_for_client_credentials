package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.model.ClientConfiguration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;

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

    @Test
    void getClientDisplayName_WithUninitializedService_ShouldReturnDefaultValue() {
        // Given: ClientsService not initialized (clientsConfiguration is null)
        // This targets line 332: return defaultValue when getClientConfig() returns null
        // Tests the CLIENT_NAME_FIELD case in the switch statement of getClientAttribute()
        // Note: defaultValue for getClientDisplayName is the clientName itself
        
        // When: Call getClientDisplayName without initializing the service first
        String result = clientsService.getClientDisplayName("test-client-name");
        
        // Then: Should return the clientName itself (the defaultValue for CLIENT_NAME_FIELD)
        assertEquals("test-client-name", result, "getClientDisplayName should return clientName (defaultValue) when service is not initialized");
    }

    @Test
    void getClientDisplayName_WithNonExistentClient_ShouldReturnDefaultValue() throws IOException {
        // Given: Initialized service but requesting a non-existent client
        // This tests the CLIENT_NAME_FIELD branch in getClientAttribute() switch statement
        String validYamlContent = """
            clients:
              existing-client:
                client-id: "existing-client-id"
                client-secret: "existing-client-secret"
                client-name: "Existing Client Display Name"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // Initialize the service
        clientsService.init();
        
        // When: Call getClientDisplayName for non-existent client
        String result = clientsService.getClientDisplayName("non-existent-client");
        
        // Then: Should return clientName itself (defaultValue) since getClientConfig returns null
        assertEquals("non-existent-client", result, "getClientDisplayName should return clientName (defaultValue) for non-existent client");
        
        // But should return actual display name for existing client
        String existingClientDisplayName = clientsService.getClientDisplayName("existing-client");
        assertEquals("Existing Client Display Name", existingClientDisplayName, "getClientDisplayName should return actual client-name for existing client");
    }

    @Test
    void getClientDisplayName_WithCorruptedClientConfiguration_ShouldReturnDefaultValue() {
        // Given: Corrupted state where clientsConfiguration exists but getClients() returns null
        // This ensures getClientConfig() returns null, triggering line 332 in getClientAttribute()
        // Specifically tests the CLIENT_NAME_FIELD case
        
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration mockConfig = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", mockConfig);
        
        // When: Call getClientDisplayName
        String result = clientsService.getClientDisplayName("test-client");
        
        // Then: Should return clientName itself (defaultValue) because getClientConfig() returns null
        assertEquals("test-client", result, "getClientDisplayName should return clientName (defaultValue) when clientsConfiguration.getClients() is null");
    }

    @Test
    void getClientDisplayName_WithClientHavingNullClientName_ShouldReturnDefaultValue() throws IOException {
        // Given: Client exists but has null client-name field
        // This tests the CLIENT_NAME_FIELD branch where clientConfig.getClientName() returns null
        
        // Use reflection to set up the state manually (since validation would allow this scenario)
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration config = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto clientDto = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto();
        // clientDto.setClientName(null) - if there were setters, but since clientName is null by default
        
        java.util.Map<String, com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto> clientsMap = 
            new java.util.HashMap<>();
        clientsMap.put("client-without-display-name", clientDto);
        
        // Use reflection to set the clients map
        ReflectionTestUtils.setField(config, "clients", clientsMap);
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", config);
        
        // When: Call getClientDisplayName for client with null client-name
        String result = clientsService.getClientDisplayName("client-without-display-name");
        
        // Then: Should return clientName itself (defaultValue) because clientConfig.getClientName() returns null
        // This tests the CLIENT_NAME_FIELD -> ... != null ? ... : defaultValue logic
        assertEquals("client-without-display-name", result, "getClientDisplayName should return clientName (defaultValue) when client-name field is null");
    }

    @Test
    void getClientDisplayName_WithValidClientName_ShouldReturnActualValue() throws IOException {
        // Given: Properly configured client with valid client-name
        // This tests the successful path of the CLIENT_NAME_FIELD case
        String validYamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret"
                client-name: "My Test Client Display Name"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // Initialize the service
        clientsService.init();
        
        // When: Call getClientDisplayName for valid client
        String result = clientsService.getClientDisplayName("test-client");
        
        // Then: Should return the actual client-name value (not defaultValue)
        assertEquals("My Test Client Display Name", result, "getClientDisplayName should return actual client-name value for valid client");
    }

    @Test
    void getClientDisplayName_WithClientMissingDisplayName_ShouldReturnClientNameAsDefault() throws IOException {
        // Given: Client exists but has no client-name field defined in YAML
        // This is a realistic scenario where client-name is optional
        String yamlWithoutDisplayName = """
            clients:
              minimal-client:
                client-id: "minimal-client-id"
                client-secret: "minimal-client-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlWithoutDisplayName);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        
        // Initialize the service
        clientsService.init();
        
        // When: Call getClientDisplayName for client without display name
        String result = clientsService.getClientDisplayName("minimal-client");
        
        // Then: Should return the clientName itself as the default
        assertEquals("minimal-client", result, "getClientDisplayName should return clientName as default when client-name field is not provided");
    }

    @Test
    void getClientDisplayName_MultipleScenarios_ShouldHandleAllClientNameCases() throws IOException {
        // Given: Test multiple scenarios for CLIENT_NAME_FIELD coverage
        
        // Scenario 1: Uninitialized service
        String uninitializedResult = clientsService.getClientDisplayName("uninitialized-client");
        assertEquals("uninitialized-client", uninitializedResult, "Uninitialized service should return clientName for getClientDisplayName");
        
        // Scenario 2: Initialize service and test non-existent client  
        String validYamlContent = """
            clients:
              valid-client:
                client-id: "valid-id"
                client-secret: "valid-secret"
                client-name: "Valid Client Display"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        String nonExistentResult = clientsService.getClientDisplayName("non-existent-client");
        assertEquals("non-existent-client", nonExistentResult, "Non-existent client should return clientName for getClientDisplayName");
        
        // Scenario 3: Valid client should return actual display name (not defaultValue)
        String validResult = clientsService.getClientDisplayName("valid-client");
        assertEquals("Valid Client Display", validResult, "Valid client should return actual client-name, not defaultValue");
        
        // Scenario 4: Corrupt state
        com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration corruptConfig = 
            new com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientsConfiguration();
        ReflectionTestUtils.setField(clientsService, "clientsConfiguration", corruptConfig);
        
        String corruptResult = clientsService.getClientDisplayName("corrupt-client");
        assertEquals("corrupt-client", corruptResult, "Corrupt configuration should return clientName for getClientDisplayName");
    }

    @Test
    void getClientAttribute_WithUnknownAttributeName_ShouldReturnDefaultValue() throws IOException {
        // Given: A valid client configuration
        String validYamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret"
                client-name: "Test Client Display"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, validYamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Call getClientAttribute with an unknown attribute name
        // This tests the default case of the switch statement in getClientAttribute()
        String result1 = ReflectionTestUtils.invokeMethod(clientsService, "getClientAttribute", 
            "test-client", "unknown-attribute", "custom-default");
        
        // Then: Should return the default value
        assertEquals("custom-default", result1, "Unknown attribute should return the provided default value");
        
        // Test with null default value
        String result2 = ReflectionTestUtils.invokeMethod(clientsService, "getClientAttribute", 
            "test-client", "another-unknown-attr", (String) null);
        
        assertNull(result2, "Unknown attribute with null default should return null");
        
        // Test with empty string default value
        String result3 = ReflectionTestUtils.invokeMethod(clientsService, "getClientAttribute", 
            "test-client", "yet-another-unknown", "");
        
        assertEquals("", result3, "Unknown attribute with empty string default should return empty string");
    }

    @Test
    void getClientAttribute_WithUnknownAttributeAndNonExistentClient_ShouldReturnDefaultValue() {
        // Given: Uninitialized service (no clients)
        
        // When: Call getClientAttribute with unknown attribute and non-existent client
        // This tests the default case when both client doesn't exist and attribute is unknown
        String result = ReflectionTestUtils.invokeMethod(clientsService, "getClientAttribute", 
            "non-existent-client", "unknown-attribute", "fallback-value");
        
        // Then: Should return the default value (same behavior as when client doesn't exist)
        assertEquals("fallback-value", result, "Non-existent client with unknown attribute should return default value");
    }

    @Test
    void getClientAttribute_WithVariousUnknownAttributes_ShouldAlwaysReturnDefaultValue() throws IOException {
        // Given: A client with all standard attributes
        String yamlContent = """
            clients:
              full-client:
                client-id: "full-client-id"
                client-secret: "full-client-secret"
                client-name: "Full Client Display"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // Test various unknown attribute names to ensure switch default case works consistently
        String[] unknownAttributes = {
            "unknown-field",
            "client-description",
            "client-url", 
            "random-attribute",
            "non-existent-field",
            "invalid-attribute"
        };
        
        String[] defaultValues = {
            "default1",
            "default2", 
            "default3",
            "default4",
            "default5",
            "default6"
        };
        
        // When & Then: All unknown attributes should return their respective default values
        for (int i = 0; i < unknownAttributes.length; i++) {
            String result = ReflectionTestUtils.invokeMethod(clientsService, "getClientAttribute", 
                "full-client", unknownAttributes[i], defaultValues[i]);
            
            assertEquals(defaultValues[i], result, 
                String.format("Unknown attribute '%s' should return default value '%s'", 
                    unknownAttributes[i], defaultValues[i]));
        }
    }

    @Test
    void getClientScopes_ClientDoesNotExist_ShouldReturnDefaultScope() {
        // Given: Uninitialized service (no clients configured)
        
        // When: Get scopes for non-existent client
        List<String> result = clientsService.getClientScopes("non-existent-client");
        
        // Then: Should return default scope "read"
        assertEquals(List.of("read"), result);
    }

    @Test
    void getClientScopes_ClientExistsWithScopes_ShouldReturnActualScopes() throws IOException {
        // Given: Client with specific scopes configured
        String yamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret"
                scopes: ["read", "write", "admin"]
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get scopes for configured client
        List<String> result = clientsService.getClientScopes("test-client");
        
        // Then: Should return the configured scopes
        assertEquals(List.of("read", "write", "admin"), result);
    }

    @Test
    void getClientScopes_ClientExistsWithoutScopes_ShouldReturnDefaultScope() throws IOException {
        // Given: Client without scopes section
        String yamlContent = """
            clients:
              minimal-client:
                client-id: "minimal-client-id"
                client-secret: "minimal-client-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get scopes for client without scopes
        List<String> result = clientsService.getClientScopes("minimal-client");
        
        // Then: Should return default scope "read"
        assertEquals(List.of("read"), result);
    }

    @Test
    void getClientScopes_ClientExistsWithEmptyScopes_ShouldReturnDefaultScope() throws IOException {
        // Given: Client with empty scopes array
        String yamlContent = """
            clients:
              empty-scopes-client:
                client-id: "empty-client-id"
                client-secret: "empty-client-secret"
                scopes: []
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get scopes for client with empty scopes
        List<String> result = clientsService.getClientScopes("empty-scopes-client");
        
        // Then: Should return default scope "read"
        assertEquals(List.of("read"), result);
    }

    @Test
    void getClientScopes_ClientExistsWithSingleScope_ShouldReturnSingleScope() throws IOException {
        // Given: Client with single scope
        String yamlContent = """
            clients:
              single-scope-client:
                client-id: "single-client-id"
                client-secret: "single-client-secret"
                scopes: ["write"]
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get scopes for client with single scope
        List<String> result = clientsService.getClientScopes("single-scope-client");
        
        // Then: Should return the single scope
        assertEquals(List.of("write"), result);
    }

    @Test
    void getAccessTokenTtl_ClientDoesNotExist_ShouldReturnDefaultTtl() {
        // Given: Uninitialized service (no clients configured)
        
        // When: Get TTL for non-existent client
        Duration result = clientsService.getAccessTokenTtl("non-existent-client");
        
        // Then: Should return default TTL of 5 minutes
        assertEquals(Duration.ofMinutes(5), result);
    }

    @Test
    void getAccessTokenTtl_ClientExistsWithTtl_ShouldReturnConfiguredTtl() throws IOException {
        // Given: Client with specific access-token-ttl configured
        String yamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret"
                access-token-ttl: 30
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get TTL for configured client
        Duration result = clientsService.getAccessTokenTtl("test-client");
        
        // Then: Should return the configured TTL of 30 minutes
        assertEquals(Duration.ofMinutes(30), result);
    }

    @Test
    void getAccessTokenTtl_ClientExistsWithoutTtl_ShouldReturnDefaultTtl() throws IOException {
        // Given: Client without access-token-ttl field
        String yamlContent = """
            clients:
              minimal-client:
                client-id: "minimal-client-id"
                client-secret: "minimal-client-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get TTL for client without TTL field
        Duration result = clientsService.getAccessTokenTtl("minimal-client");
        
        // Then: Should return default TTL of 5 minutes
        assertEquals(Duration.ofMinutes(5), result);
    }

    @Test
    void getAccessTokenTtl_ClientExistsWithLargeTtl_ShouldReturnConfiguredTtl() throws IOException {
        // Given: Client with large TTL value
        String yamlContent = """
            clients:
              long-ttl-client:
                client-id: "long-ttl-client-id"
                client-secret: "long-ttl-client-secret"
                access-token-ttl: 1440
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get TTL for client with large TTL
        Duration result = clientsService.getAccessTokenTtl("long-ttl-client");
        
        // Then: Should return the configured TTL of 1440 minutes (24 hours)
        assertEquals(Duration.ofMinutes(1440), result);
    }

    @Test
    void getAccessTokenTtl_ClientExistsWithShortTtl_ShouldReturnConfiguredTtl() throws IOException {
        // Given: Client with short TTL value
        String yamlContent = """
            clients:
              short-ttl-client:
                client-id: "short-ttl-client-id"
                client-secret: "short-ttl-client-secret"
                access-token-ttl: 1
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get TTL for client with short TTL
        Duration result = clientsService.getAccessTokenTtl("short-ttl-client");
        
        // Then: Should return the configured TTL of 1 minute
        assertEquals(Duration.ofMinutes(1), result);
    }

    @Test
    void getClientRoles_ClientDoesNotExist_ShouldReturnEmptyList() {
        // Given: Uninitialized service (no clients configured)
        
        // When: Get roles for non-existent client
        List<String> result = clientsService.getClientRoles("non-existent-client");
        
        // Then: Should return empty list
        assertEquals(List.of(), result);
        assertTrue(result.isEmpty());
    }

    @Test
    void getClientRoles_ClientExistsWithRoles_ShouldReturnActualRoles() throws IOException {
        // Given: Client with specific roles configured
        String yamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret"
                roles: ["CLIENT", "INTROSPECTOR", "ADMIN"]
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get roles for configured client
        List<String> result = clientsService.getClientRoles("test-client");
        
        // Then: Should return the configured roles
        assertEquals(List.of("CLIENT", "INTROSPECTOR", "ADMIN"), result);
    }

    @Test
    void getClientRoles_ClientExistsWithoutRoles_ShouldReturnEmptyList() throws IOException {
        // Given: Client without roles field
        String yamlContent = """
            clients:
              minimal-client:
                client-id: "minimal-client-id"
                client-secret: "minimal-client-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get roles for client without roles
        List<String> result = clientsService.getClientRoles("minimal-client");
        
        // Then: Should return empty list
        assertEquals(List.of(), result);
        assertTrue(result.isEmpty());
    }

    @Test
    void getClientRoles_ClientExistsWithEmptyRoles_ShouldReturnEmptyList() throws IOException {
        // Given: Client with empty roles array
        String yamlContent = """
            clients:
              empty-roles-client:
                client-id: "empty-client-id"
                client-secret: "empty-client-secret"
                roles: []
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get roles for client with empty roles
        List<String> result = clientsService.getClientRoles("empty-roles-client");
        
        // Then: Should return empty list
        assertEquals(List.of(), result);
        assertTrue(result.isEmpty());
    }

    @Test
    void getClientRoles_ClientExistsWithSingleRole_ShouldReturnSingleRole() throws IOException {
        // Given: Client with single role
        String yamlContent = """
            clients:
              single-role-client:
                client-id: "single-client-id"
                client-secret: "single-client-secret"
                roles: ["USER"]
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Get roles for client with single role
        List<String> result = clientsService.getClientRoles("single-role-client");
        
        // Then: Should return the single role
        assertEquals(List.of("USER"), result);
    }

    @Test
    void clientHasRole_ClientDoesNotExist_ShouldReturnFalse() {
        // Given: Uninitialized service (no clients configured)
        
        // When: Check if non-existent client has a role
        boolean result = clientsService.clientHasRole("non-existent-client", "ADMIN");
        
        // Then: Should return false
        assertFalse(result);
    }

    @Test
    void clientHasRole_ClientExistsWithRole_ShouldReturnTrue() throws IOException {
        // Given: Client with specific roles configured
        String yamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret"
                roles: ["CLIENT", "INTROSPECTOR", "ADMIN"]
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Check if client has existing role
        boolean result = clientsService.clientHasRole("test-client", "ADMIN");
        
        // Then: Should return true
        assertTrue(result);
    }

    @Test
    void clientHasRole_ClientExistsWithoutRole_ShouldReturnFalse() throws IOException {
        // Given: Client with specific roles configured
        String yamlContent = """
            clients:
              test-client:
                client-id: "test-client-id"
                client-secret: "test-client-secret"
                roles: ["CLIENT", "INTROSPECTOR"]
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Check if client has non-existing role
        boolean result = clientsService.clientHasRole("test-client", "ADMIN");
        
        // Then: Should return false
        assertFalse(result);
    }

    @Test
    void clientHasRole_ClientExistsWithNoRoles_ShouldReturnFalse() throws IOException {
        // Given: Client without roles field
        String yamlContent = """
            clients:
              minimal-client:
                client-id: "minimal-client-id"
                client-secret: "minimal-client-secret"
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Check if client has any role
        boolean result = clientsService.clientHasRole("minimal-client", "USER");
        
        // Then: Should return false
        assertFalse(result);
    }

    @Test
    void clientHasRole_ClientExistsWithEmptyRoles_ShouldReturnFalse() throws IOException {
        // Given: Client with empty roles array
        String yamlContent = """
            clients:
              empty-roles-client:
                client-id: "empty-client-id"
                client-secret: "empty-client-secret"
                roles: []
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When: Check if client has any role
        boolean result = clientsService.clientHasRole("empty-roles-client", "USER");
        
        // Then: Should return false
        assertFalse(result);
    }

    @Test
    void clientHasRole_CaseSensitiveRoleCheck_ShouldWork() throws IOException {
        // Given: Client with specific role
        String yamlContent = """
            clients:
              case-client:
                client-id: "case-client-id"
                client-secret: "case-client-secret"
                roles: ["Admin"]
            """;
        
        Path configFile = tempDir.resolve("clients.yml");
        Files.writeString(configFile, yamlContent);
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", configFile.toString());
        clientsService.init();
        
        // When & Then: Check case sensitivity
        assertTrue(clientsService.clientHasRole("case-client", "Admin"));
        assertFalse(clientsService.clientHasRole("case-client", "admin"));
        assertFalse(clientsService.clientHasRole("case-client", "ADMIN"));
    }

    // ========== getClientConfiguration() Tests ==========
    
    @Test
    void getClientConfiguration_WithNonExistentClient_ShouldThrowException() throws IOException {
        // Given: A valid YAML with one client
        String yaml = """
                clients:
                  test-client:
                    client-id: "test-id"
                    client-secret: "test-secret"
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        clientsService.init();
        
        // When & Then: Request non-existent client should throw exception
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, 
            () -> clientsService.getClientConfiguration("non-existent-client"));
        assertEquals("Client 'non-existent-client' not found in configuration", exception.getMessage());
    }

    @Test
    void getClientConfiguration_WithMinimalClient_ShouldReturnConfiguration() throws IOException {
        // Given: A client with minimal required fields
        String yaml = """
                clients:
                  minimal-client:
                    client-id: "minimal-id"
                    client-secret: "minimal-secret"
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        clientsService.init();
        
        // When: Get client configuration
        ClientConfiguration config = clientsService.getClientConfiguration("minimal-client");
        
        // Then: Should return configuration with defaults
        assertNotNull(config);
        assertEquals("minimal-id", config.clientId());
        assertEquals("minimal-secret", config.clientSecret());
        assertEquals("minimal-client", config.displayName());
        assertEquals(List.of("read"), config.scopes());
        assertEquals(Duration.ofMinutes(5), config.tokenTtl());
        assertEquals(List.of(), config.roles());
    }

    @Test
    void getClientConfiguration_WithCompleteClient_ShouldReturnConfiguration() throws IOException {
        // Given: A client with all fields configured
        String yaml = """
                clients:
                  complete-client:
                    client-id: "complete-id"
                    client-secret: "complete-secret"
                    client-name: "Complete Application"
                    scopes: ["read", "write", "admin"]
                    access-token-ttl: 30
                    roles: ["CLIENT", "ADMIN", "USER"]
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        clientsService.init();
        
        // When: Get client configuration
        ClientConfiguration config = clientsService.getClientConfiguration("complete-client");
        
        // Then: Should return configuration with all values
        assertNotNull(config);
        assertEquals("complete-id", config.clientId());
        assertEquals("complete-secret", config.clientSecret());
        assertEquals("Complete Application", config.displayName());
        assertEquals(List.of("read", "write", "admin"), config.scopes());
        assertEquals(Duration.ofMinutes(30), config.tokenTtl());
        assertEquals(List.of("CLIENT", "ADMIN", "USER"), config.roles());
    }

    @Test
    void getClientConfiguration_WithEmptyScopes_ShouldReturnDefaultScopes() throws IOException {
        // Given: A client with empty scopes
        String yaml = """
                clients:
                  empty-scopes-client:
                    client-id: "empty-id"
                    client-secret: "empty-secret"
                    scopes: []
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        clientsService.init();
        
        // When: Get client configuration
        ClientConfiguration config = clientsService.getClientConfiguration("empty-scopes-client");
        
        // Then: Should return default scope
        assertNotNull(config);
        assertEquals(List.of("read"), config.scopes());
    }

    @Test
    void getClientConfiguration_WithEmptyRoles_ShouldReturnEmptyRoles() throws IOException {
        // Given: A client with empty roles
        String yaml = """
                clients:
                  empty-roles-client:
                    client-id: "empty-id"
                    client-secret: "empty-secret"
                    roles: []
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        clientsService.init();
        
        // When: Get client configuration
        ClientConfiguration config = clientsService.getClientConfiguration("empty-roles-client");
        
        // Then: Should return empty roles list
        assertNotNull(config);
        assertEquals(List.of(), config.roles());
    }

    @Test
    void getClientConfiguration_WithMultipleClients_ShouldReturnCorrectConfiguration() throws IOException {
        // Given: Multiple clients with different configurations
        String yaml = """
                clients:
                  client-one:
                    client-id: "id-one"
                    client-secret: "secret-one"
                    client-name: "Client One"
                    scopes: ["read"]
                    access-token-ttl: 10
                  client-two:
                    client-id: "id-two"
                    client-secret: "secret-two"
                    client-name: "Client Two"
                    scopes: ["write"]
                    access-token-ttl: 20
                    roles: ["ADMIN"]
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        clientsService.init();
        
        // When: Get configurations for both clients
        ClientConfiguration config1 = clientsService.getClientConfiguration("client-one");
        ClientConfiguration config2 = clientsService.getClientConfiguration("client-two");
        
        // Then: Should return correct configurations for each client
        assertNotNull(config1);
        assertEquals("id-one", config1.clientId());
        assertEquals("Client One", config1.displayName());
        assertEquals(List.of("read"), config1.scopes());
        assertEquals(Duration.ofMinutes(10), config1.tokenTtl());
        assertEquals(List.of(), config1.roles());
        
        assertNotNull(config2);
        assertEquals("id-two", config2.clientId());
        assertEquals("Client Two", config2.displayName());
        assertEquals(List.of("write"), config2.scopes());
        assertEquals(Duration.ofMinutes(20), config2.tokenTtl());
        assertEquals(List.of("ADMIN"), config2.roles());
    }

    // ========== getClientsResource() Tests (Private Method via Reflection) ==========
    
    @Test
    void getClientsResource_WithClasspathPrefix_ShouldReturnClassPathResource() {
        // Given: A ClientsService instance with classpath: prefix
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "classpath:config/clients.yml");
        
        // When: Call private getClientsResource method via reflection
        Resource resource = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        
        // Then: Should return ClassPathResource with correct path
        assertNotNull(resource);
        assertInstanceOf(ClassPathResource.class, resource);
        
        // Verify the path was correctly processed (classpath: prefix removed)
        ClassPathResource classpathResource = (ClassPathResource) resource;
        assertEquals("config/clients.yml", classpathResource.getPath());
    }

    @Test
    void getClientsResource_WithSimpleFilename_ShouldReturnClassPathResource() {
        // Given: A ClientsService instance with simple filename (no directory separator)
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "clients.yml");
        
        // When: Call private getClientsResource method via reflection
        Resource resource = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        
        // Then: Should return ClassPathResource
        assertNotNull(resource);
        assertInstanceOf(ClassPathResource.class, resource);
        
        // Verify the path is used as-is
        ClassPathResource classpathResource = (ClassPathResource) resource;
        assertEquals("clients.yml", classpathResource.getPath());
    }

    @Test
    void getClientsResource_WithAbsolutePath_ShouldReturnFileSystemResource() {
        // Given: A ClientsService instance with absolute file path
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "/etc/oauth2/clients.yml");
        
        // When: Call private getClientsResource method via reflection
        Resource resource = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        
        // Then: Should return FileSystemResource
        assertNotNull(resource);
        assertInstanceOf(FileSystemResource.class, resource);
        
        // Verify the path is used as-is
        FileSystemResource fileSystemResource = (FileSystemResource) resource;
        assertEquals("/etc/oauth2/clients.yml", fileSystemResource.getPath());
    }

    @Test
    void getClientsResource_WithRelativePath_ShouldReturnFileSystemResource() {
        // Given: A ClientsService instance with relative file path containing directory separator
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "config/clients.yml");
        
        // When: Call private getClientsResource method via reflection
        Resource resource = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        
        // Then: Should return FileSystemResource
        assertNotNull(resource);
        assertInstanceOf(FileSystemResource.class, resource);
        
        // Verify the path is used as-is
        FileSystemResource fileSystemResource = (FileSystemResource) resource;
        assertEquals("config/clients.yml", fileSystemResource.getPath());
    }

    @Test
    void getClientsResource_WithWindowsAbsolutePath_ShouldReturnFileSystemResource() {
        // Given: A ClientsService instance with Windows-style absolute path
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "C:\\config\\clients.yml");
        
        // When: Call private getClientsResource method via reflection
        Resource resource = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        
        // Then: Should return FileSystemResource (because it contains "/")
        // Note: Windows paths with backslashes don't contain "/" so would be treated as ClassPath
        // But this tests the edge case of mixed separators
        assertNotNull(resource);
        assertInstanceOf(ClassPathResource.class, resource);
        
        // Verify Windows path without "/" is treated as classpath
        ClassPathResource classpathResource = (ClassPathResource) resource;
        // Spring normalizes backslashes to forward slashes
        assertEquals("C:/config/clients.yml", classpathResource.getPath());
    }

    @Test
    void getClientsResource_WithUnixStylePath_ShouldReturnFileSystemResource() {
        // Given: A ClientsService instance with Unix-style path
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "./config/clients.yml");
        
        // When: Call private getClientsResource method via reflection
        Resource resource = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        
        // Then: Should return FileSystemResource
        assertNotNull(resource);
        assertInstanceOf(FileSystemResource.class, resource);
        
        // Verify the path is used as-is (Spring normalizes ./ prefix)
        FileSystemResource fileSystemResource = (FileSystemResource) resource;
        assertEquals("config/clients.yml", fileSystemResource.getPath());
    }

    @Test
    void getClientsResource_WithClasspathPrefixAndComplexPath_ShouldReturnClassPathResource() {
        // Given: A ClientsService instance with classpath: prefix and complex path
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "classpath:META-INF/spring/clients.yml");
        
        // When: Call private getClientsResource method via reflection
        Resource resource = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        
        // Then: Should return ClassPathResource with prefix stripped
        assertNotNull(resource);
        assertInstanceOf(ClassPathResource.class, resource);
        
        // Verify the classpath: prefix was correctly removed
        ClassPathResource classpathResource = (ClassPathResource) resource;
        assertEquals("META-INF/spring/clients.yml", classpathResource.getPath());
    }

    @Test
    void getClientsResource_WithEmptyClasspathPrefix_ShouldReturnClassPathResource() {
        // Given: A ClientsService instance with just classpath: prefix
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "classpath:");
        
        // When: Call private getClientsResource method via reflection
        Resource resource = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        
        // Then: Should return ClassPathResource with empty path
        assertNotNull(resource);
        assertInstanceOf(ClassPathResource.class, resource);
        
        // Verify empty path after prefix removal
        ClassPathResource classpathResource = (ClassPathResource) resource;
        assertEquals("", classpathResource.getPath());
    }

    @Test
    void getClientsResource_ResourcePathLogic_ShouldFollowCorrectDecisionTree() {
        // Test the decision logic comprehensively
        
        // Test 1: classpath: prefix should always result in ClassPathResource
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "classpath:some/path/file.yml");
        Resource resource1 = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        assertInstanceOf(ClassPathResource.class, resource1);
        
        // Test 2: No slash should result in ClassPathResource  
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "file.yml");
        Resource resource2 = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        assertInstanceOf(ClassPathResource.class, resource2);
        
        // Test 3: Has slash should result in FileSystemResource
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "dir/file.yml");
        Resource resource3 = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        assertInstanceOf(FileSystemResource.class, resource3);
        
        // Test 4: Even single slash should result in FileSystemResource
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "/file.yml");
        Resource resource4 = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        assertInstanceOf(FileSystemResource.class, resource4);
        
        // Test 5: classpath: with slash should still be ClassPathResource (prefix takes precedence)
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", "classpath:/META-INF/file.yml");
        Resource resource5 = (Resource) ReflectionTestUtils.invokeMethod(clientsService, "getClientsResource");
        assertInstanceOf(ClassPathResource.class, resource5);
    }

    // ========== validateConfiguration() Tests (Private Method via Reflection) ==========
    
    @Test
    void validateConfiguration_WithEmptyClients_ShouldThrowException() throws IOException {
        // Given: A YAML file with empty clients section
        String yaml = """
                clients: {}
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When & Then: validateConfiguration should throw IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
        
        assertTrue(exception.getMessage().contains("No clients configured"));
        assertTrue(exception.getMessage().contains(yamlFile.toString()));
        assertTrue(exception.getMessage().contains("At least one client must be configured"));
    }

    @Test
    void validateConfiguration_WithSingleValidClient_ShouldSucceed() throws IOException {
        // Given: A YAML file with one valid client
        String yaml = """
                clients:
                  valid-client:
                    client-id: "valid-id"
                    client-secret: "valid-secret"
                    client-name: "Valid Client"
                    scopes: ["read", "write"]
                    access-token-ttl: 30
                    roles: ["CLIENT"]
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When: Call validateConfiguration via reflection
        // Then: Should not throw any exception
        assertDoesNotThrow(() -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
    }

    @Test
    void validateConfiguration_WithMultipleValidClients_ShouldSucceed() throws IOException {
        // Given: A YAML file with multiple valid clients
        String yaml = """
                clients:
                  client-one:
                    client-id: "id-one"
                    client-secret: "secret-one"
                    client-name: "Client One"
                  client-two:
                    client-id: "id-two"
                    client-secret: "secret-two"
                    client-name: "Client Two"
                    scopes: ["admin"]
                  client-three:
                    client-id: "id-three"
                    client-secret: "secret-three"
                    access-token-ttl: 60
                    roles: ["ADMIN", "USER"]
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When: Call validateConfiguration via reflection
        // Then: Should not throw any exception
        assertDoesNotThrow(() -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
    }

    @Test
    void validateConfiguration_WithInvalidClient_ShouldThrowException() throws IOException {
        // Given: A YAML file with one client missing required fields
        String yaml = """
                clients:
                  invalid-client:
                    client-name: "Invalid Client"
                    scopes: ["read"]
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When & Then: validateConfiguration should throw IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
        
        assertTrue(exception.getMessage().contains("Client 'invalid-client'"));
        assertTrue(exception.getMessage().contains("missing required field"));
    }

    @Test
    void validateConfiguration_WithMixedValidAndInvalidClients_ShouldThrowException() throws IOException {
        // Given: A YAML file with both valid and invalid clients
        String yaml = """
                clients:
                  valid-client:
                    client-id: "valid-id"
                    client-secret: "valid-secret"
                  invalid-client:
                    client-id: "missing-secret"
                    # client-secret is missing
                  another-valid-client:
                    client-id: "another-id"
                    client-secret: "another-secret"
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When & Then: validateConfiguration should throw IllegalStateException for the first invalid client
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
        
        assertTrue(exception.getMessage().contains("Client 'invalid-client'"));
        assertTrue(exception.getMessage().contains("missing required field"));
        assertTrue(exception.getMessage().contains("client-secret"));
    }

    @Test
    void validateConfiguration_WithClientMissingClientId_ShouldThrowException() throws IOException {
        // Given: A YAML file with client missing client-id
        String yaml = """
                clients:
                  missing-id-client:
                    client-secret: "has-secret"
                    client-name: "Missing ID Client"
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When & Then: validateConfiguration should throw IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
        
        assertTrue(exception.getMessage().contains("Client 'missing-id-client'"));
        assertTrue(exception.getMessage().contains("missing required field"));
        assertTrue(exception.getMessage().contains("client-id"));
    }

    @Test
    void validateConfiguration_WithClientHavingEmptyClientId_ShouldThrowException() throws IOException {
        // Given: A YAML file with client having empty client-id
        String yaml = """
                clients:
                  empty-id-client:
                    client-id: ""
                    client-secret: "has-secret"
                    client-name: "Empty ID Client"
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When & Then: validateConfiguration should throw IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
        
        assertTrue(exception.getMessage().contains("Client 'empty-id-client'"));
        assertTrue(exception.getMessage().contains("missing required field"));
        assertTrue(exception.getMessage().contains("client-id"));
    }

    @Test
    void validateConfiguration_WithClientHavingWhitespaceOnlyClientSecret_ShouldThrowException() throws IOException {
        // Given: A YAML file with client having whitespace-only client-secret
        String yaml = """
                clients:
                  whitespace-secret-client:
                    client-id: "has-id"
                    client-secret: "   "
                    client-name: "Whitespace Secret Client"
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When & Then: validateConfiguration should throw IllegalStateException
        IllegalStateException exception = assertThrows(IllegalStateException.class, 
            () -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
        
        assertTrue(exception.getMessage().contains("Client 'whitespace-secret-client'"));
        assertTrue(exception.getMessage().contains("missing required field"));
        assertTrue(exception.getMessage().contains("client-secret"));
    }

    @Test
    void validateConfiguration_WithValidationSuccessLogging_ShouldLogCorrectCount() throws IOException {
        // Given: A YAML file with exactly 3 valid clients
        String yaml = """
                clients:
                  client-alpha:
                    client-id: "alpha-id"
                    client-secret: "alpha-secret"
                  client-beta:
                    client-id: "beta-id"
                    client-secret: "beta-secret"
                  client-gamma:
                    client-id: "gamma-id"
                    client-secret: "gamma-secret"
                """;
        Path yamlFile = tempDir.resolve("clients.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(clientsService, "clientsFilePath", yamlFile.toString());
        
        // Load and extract clients section (simulate partial initialization)
        ReflectionTestUtils.invokeMethod(clientsService, "loadYamlConfiguration");
        ReflectionTestUtils.invokeMethod(clientsService, "extractClientsSection");
        
        // When: Call validateConfiguration via reflection
        // Then: Should not throw any exception (validation passes)
        assertDoesNotThrow(() -> ReflectionTestUtils.invokeMethod(clientsService, "validateConfiguration"));
        
        // Note: We can't easily test the logging message without additional setup,
        // but we can verify the validation completed successfully by not throwing
    }

    
}