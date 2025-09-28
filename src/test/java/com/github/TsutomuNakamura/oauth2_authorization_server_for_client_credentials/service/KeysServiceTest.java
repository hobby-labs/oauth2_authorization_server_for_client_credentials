package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class KeysServiceTest {

    private KeysService keysService;
    
    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        keysService = new KeysService();
    }

    // ========== getPrimaryKeyName() Tests ==========
    
    @Test
    void getPrimaryKeyName_WithValidConfiguration_ShouldReturnPrimaryKeyName() throws IOException {
        // Given: A YAML file with valid keys configuration
        String yaml = """
                config:
                  primary-key: "main-signing-key"
                keys:
                  main-signing-key:
                    keyId: "main-key-id"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdef
                      -----END PUBLIC KEY-----
                  secondary-key:
                    keyId: "secondary-key-id"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9876543210fedcba
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9876543210fedcba
                      -----END PUBLIC KEY-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getPrimaryKeyName
        String result = keysService.getPrimaryKeyName();
        
        // Then: Should return the configured primary key name
        assertEquals("main-signing-key", result);
    }

    // ========== getPrimaryKeyPair() Tests ==========
    
    @Test
    void getPrimaryKeyPair_WithValidConfiguration_ShouldReturnKeyPair() throws Exception {
        // Given: A YAML file with valid EC key data (using real key from alice)
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcED3Y6jFH7w7TXUl
                      uo8RDu9a9MzqWFc8Pw5y6ySE5gGhRANCAAQUd3SadD1hR0WKn3FssQw9IC/Olexb
                      CDFCcneMiatm4M6D0rhNWXL9j338nmmR+VqLprEZqcCc2s/AlXmUkVEO
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN CERTIFICATE-----
                      MIIB/jCCAYSgAwIBAgICIAEwCgYIKoZIzj0EAwIwIzEhMB8GA1UEAwwYdHJlbnQu
                      aW50ZXJtLmV4YW1wbGUuY29tMB4XDTI1MDgxMTAzMjk0MFoXDTI3MDgxMTAzMjk0
                      MFowHzEdMBsGA1UEAwwUYWxpY2UuZWUuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIB
                      BggqhkjOPQMBBwNCAAQUd3SadD1hR0WKn3FssQw9IC/OlexbCDFCcneMiatm4M6D
                      0rhNWXL9j338nmmR+VqLprEZqcCc2s/AlXmUkVEOo4GrMIGoMAwGA1UdEwEB/wQC
                      MAAwHQYDVR0OBBYEFOJN5pu3nku0m1fLfzD+oYsBzJWAMB8GA1UdIwQYMBaAFLBj
                      tm8nryugZ+1tt5sHrmVHnWXaMA4GA1UdDwEB/wQEAwIHgDAnBgNVHSUEIDAeBggr
                      BgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDMB8GA1UdEQQYMBaCFGFsaWNlLmVl
                      LmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA2gAMGUCMD6aRJr3O5fBkHJx14D+DhuJ
                      bBrGywkZlcULLGd7AWDbiPLaODKd2TcIjA128z9KagIxAPXRfzxiLX/vlEnJK2AZ
                      uJUCxFmqiKqkgwMjm6xhVpyiSNSztvo5JQUkKC6a6lrSTg==
                      -----END CERTIFICATE-----
                    keyId: "ec-key-from-yaml"
                    algorithm: "ES256"
                    curve: "P-256"
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getPrimaryKeyPair
        KeyPair result = keysService.getPrimaryKeyPair();
        
        // Then: Should return a valid KeyPair
        assertNotNull(result);
        assertNotNull(result.getPrivate());
        assertNotNull(result.getPublic());
        assertEquals("EC", result.getPrivate().getAlgorithm());
        assertEquals("EC", result.getPublic().getAlgorithm());
    }

    // ========== getPrimaryKeyId() Tests ==========
    
    @Test
    void getPrimaryKeyId_WithValidConfiguration_ShouldReturnPrimaryKeyId() throws IOException {
        // Given: A YAML file with valid keys configuration including keyId
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "ec-key-from-yaml"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdef
                      -----END PUBLIC KEY-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getPrimaryKeyId
        String result = keysService.getPrimaryKeyId();
        
        // Then: Should return the configured primary key ID
        assertEquals("ec-key-from-yaml", result);
    }

    // ========== getPrimaryKeyAlgorithm() Tests ==========
    
    @Test
    void getPrimaryKeyAlgorithm_WithValidConfiguration_ShouldReturnPrimaryKeyAlgorithm() throws IOException {
        // Given: A YAML file with valid keys configuration including algorithm
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "ec-key-from-yaml"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdef
                      -----END PUBLIC KEY-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getPrimaryKeyAlgorithm
        String result = keysService.getPrimaryKeyAlgorithm();
        
        // Then: Should return the configured primary key algorithm
        assertEquals("ES256", result);
    }

    // ========== getPrimaryKeyCurve() Tests ==========
    
    @Test
    void getPrimaryKeyCurve_WithValidConfiguration_ShouldReturnPrimaryKeyCurve() throws IOException {
        // Given: A YAML file with valid keys configuration including curve
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "ec-key-from-yaml"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdef
                      -----END PUBLIC KEY-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getPrimaryKeyCurve
        String result = keysService.getPrimaryKeyCurve();
        
        // Then: Should return the configured primary key curve
        assertEquals("P-256", result);
    }

    // ========== getAllKeyNames() Tests ==========
    
    @Test
    void getAllKeyNames_WithValidConfiguration_ShouldReturnAllKeyNames() throws IOException {
        // Given: A YAML file with multiple keys configuration
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "alice-key-id"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdef
                      -----END PUBLIC KEY-----
                  bob:
                    keyId: "bob-key-id"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9876543210fedcba
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9876543210fedcba
                      -----END PUBLIC KEY-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getAllKeyNames
        Set<String> result = keysService.getAllKeyNames();
        
        // Then: Should return all configured key names
        assertNotNull(result);
        assertEquals(2, result.size());
        assertTrue(result.contains("alice"));
        assertTrue(result.contains("bob"));
    }

    // ========== getKeyId() Tests ==========
    
    @Test
    void getKeyId_WithValidConfiguration_ShouldReturnKeyId() throws IOException {
        // Given: A YAML file with valid keys configuration including keyId
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "alice-specific-key-id"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdef
                      -----END PUBLIC KEY-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getKeyId with specific key name
        String result = keysService.getKeyId("alice");
        
        // Then: Should return the configured key ID
        assertEquals("alice-specific-key-id", result);
    }

    // ========== getKeyAlgorithm() Tests ==========
    
    @Test
    void getKeyAlgorithm_WithValidConfiguration_ShouldReturnKeyAlgorithm() throws IOException {
        // Given: A YAML file with valid keys configuration including algorithm
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "alice-key-id"
                    algorithm: "ES256"
                    curve: "P-256"
                    private: |
                      -----BEGIN PRIVATE KEY-----
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
                      -----END PRIVATE KEY-----
                    public: |
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1234567890abcdef
                      -----END PUBLIC KEY-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getKeyAlgorithm with specific key name
        String result = keysService.getKeyAlgorithm("alice");
        
        // Then: Should return the configured key algorithm
        assertEquals("ES256", result);
    }

    
}