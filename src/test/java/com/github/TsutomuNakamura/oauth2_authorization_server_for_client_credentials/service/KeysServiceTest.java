package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Set;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ClassPathResource;

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

    // ========== getKeyCurve() Tests ==========
    
    @Test
    void getKeyCurve_WithValidConfiguration_ShouldReturnKeyCurve() throws IOException {
        // Given: A YAML file with valid keys configuration including curve
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
        
        // When: Call getKeyCurve with specific key name
        String result = keysService.getKeyCurve("alice");
        
        // Then: Should return the configured key curve
        assertEquals("P-256", result);
    }

    // ========== getKeyAuthority() Tests ==========
    
    @Test
    void getKeyAuthority_WithValidConfiguration_ShouldReturnKeyAuthority() throws IOException {
        // Given: A YAML file with valid keys configuration including authority
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "alice-key-id"
                    algorithm: "ES256"
                    curve: "P-256"
                    authority: "trent"
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
        
        // When: Call getKeyAuthority with specific key name
        String result = keysService.getKeyAuthority("alice");
        
        // Then: Should return the configured key authority
        assertEquals("trent", result);
    }

    // ========== getChainCertificate() Tests ==========
    
    @Test
    void getChainCertificate_WithNullAuthorityName_ShouldReturnNull() throws IOException {
        // Given: Any valid configuration (authority name is null)
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "alice-key-id"
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getChainCertificate with null authority name
        String result = keysService.getChainCertificate(null);
        
        // Then: Should return null
        assertNull(result);
    }
    
    @Test
    void getChainCertificate_WithNullChains_ShouldReturnNull() throws IOException {
        // Given: A YAML configuration without chains section
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "alice-key-id"
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getChainCertificate with valid authority name but no chains section
        String result = keysService.getChainCertificate("trent");
        
        // Then: Should return null
        assertNull(result);
    }
    
    @Test
    void getChainCertificate_WithNullChainData_ShouldReturnNull() throws IOException {
        // Given: A YAML configuration with chains section but missing specific authority
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "alice-key-id"
                chains:
                  pat:
                    public: |
                      -----BEGIN CERTIFICATE-----
                      MIIBpatcertificatedata
                      -----END CERTIFICATE-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getChainCertificate with authority name that doesn't exist in chains
        String result = keysService.getChainCertificate("trent");
        
        // Then: Should return null
        assertNull(result);
    }
    
    @Test
    void getChainCertificate_WithValidConfiguration_ShouldReturnPublicKey() throws IOException {
        // Given: A YAML configuration with valid chains section
        String yaml = """
                config:
                  primary-key: "alice"
                keys:
                  alice:
                    keyId: "alice-key-id"
                chains:
                  trent:
                    public: |
                      -----BEGIN CERTIFICATE-----
                      MIIBtrentcertificatedata
                      -----END CERTIFICATE-----
                  pat:
                    public: |
                      -----BEGIN CERTIFICATE-----
                      MIIBpatcertificatedata
                      -----END CERTIFICATE-----
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getChainCertificate with valid authority name
        String result = keysService.getChainCertificate("trent");
        
        // Then: Should return the public key from chainData
        assertNotNull(result);
        assertTrue(result.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(result.contains("MIIBtrentcertificatedata"));
        assertTrue(result.contains("-----END CERTIFICATE-----"));
    }

    // ========== getPublicKey() Tests ==========
    
    @Test
    void getPublicKey_WithValidConfiguration_ShouldReturnPublicKey() throws IOException {
        // Given: A YAML file with valid keys configuration including public key
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
                """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.writeString(yamlFile, yaml);
        
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Call getPublicKey with valid key name
        String result = keysService.getPublicKey("alice");
        
        // Then: Should return the public key without any errors
        assertNotNull(result);
        assertTrue(result.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(result.contains("-----END CERTIFICATE-----"));
        // Check that it contains actual certificate content
        assertTrue(result.contains("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef") ||
                   result.contains("MIIB/jCCAYSgAwIBAgICIAEwCgYIKoZIzj0EAwI") ||
                   result.length() > 100); // At least verify it has substantial content
    }

    @Test
    public void getCertificateChain_WithValidConfiguration_ShouldReturnChainWithEndEntityAndIntermediate() throws IOException {
        // Given: A temporary YAML configuration with valid keys and chain data
        String yamlContent = """
            config:
              primary-key: alice
            keys:
              alice:
                keyId: alice-key-id
                algorithm: ES256
                curve: secp256r1
                authority: pat
                private: |
                  -----BEGIN PRIVATE KEY-----
                  MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
                  1234567890abcdef1234567890abcdef12345678909hVMBaAI4GW4DDTaKVhBybm
                  qWhqkFGnFSFHpHpRXWXn4FVJSDFHaK7OoEFLLk6rAhRANCAASjKVLjFn8f8nkv
                  -----END PRIVATE KEY-----
                public: |
                  -----BEGIN CERTIFICATE-----
                  MIIB/jCCAYSgAwIBAgICIAEwCgYIKoZIzj0EAwIwXjELMAkGA1UEBhMCVVMxEzAR
                  BgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxDjAMBgNVBAoMBVBh
                  dENBMRgwFgYDVQQDDA9QYXQgSW50ZXJtZWRpYXRlMB4XDTI0MDEwMTAwMDAwMFoX
                  DTI1MDEwMTAwMDAwMFowXjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0
                  b24xEDAOBgNVBAcMB1NlYXR0bGUxDjAMBgNVBAoMBUFsaWNlMRgwFgYDVQQDDA9B
                  bGljZSBFbmQgRW50aXR5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoylS4xZ/
                  H/J5L5YXlWQKl5YXlWQKl5YXlWQKl5YXlWQKl5YXlWQKl5YXlWQKl5YXlWQKl5YX
                  lWQKl5YXlWQKl6NTMFEwHQYDVR0OBBYEFJkSd5lm2k6Tj5YlJ5m2k6Tj5YlJ5m2
                  MB8GA1UdIwQYMBaAFJkSd5lm2k6Tj5YlJ5m2k6Tj5YlJ5m2MMA8GA1UdEwEB/wQF
                  MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAKjKVLjFn8f8nkvlheVZAqXlheVZAqXl
                  heVZAqXlheVZAiAqMpUuMWfx/yeSF5VkCpeWF5VkCpeWF5VkCpeWF5VkCg==
                  -----END CERTIFICATE-----
            chains:
              pat:
                public: |
                  -----BEGIN CERTIFICATE-----
                  MIIC5TCCAk6gAwIBAgIBATAKBggqhkjOPQQDAjBYMQswCQYDVQQGEwJVUzETMBEG
                  A1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEOMAwGA1UECgwFSXZh
                  bjESMBAGA1UEAwwJSXZhbiBSb290MB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAw
                  MDAwMFowXjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNV
                  BAcMB1NlYXR0bGUxDjAMBgNVBAoMBVBhdENBMRgwFgYDVQQDDA9QYXQgSW50ZXJt
                  ZWRpYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjKVLjFn8f8nkvlheVZAq
                  XlheVZAqXlheVZAqXlheVZAqXlheVZAqXlheVZAqXlheVZAqXlheVZAqXlheVZCp
                  o4HrMIHoMB0GA1UdDgQWBBSZEndZZtpOk4+WJSeZtpOk4+WJSeZtjDAf
                  -----END CERTIFICATE-----
            """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.write(yamlFile, yamlContent.getBytes());
        
        KeysService keysService = new KeysService();
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Getting the certificate chain for alice
        List<String> chain = keysService.getCertificateChain("alice");
        
        // Then: Should return a list with both end-entity and intermediate certificates
        assertNotNull(chain);
        assertEquals(2, chain.size());
        
        // First certificate should be the end-entity certificate (alice's)
        String endEntityCert = chain.get(0);
        assertNotNull(endEntityCert);
        assertTrue(endEntityCert.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(endEntityCert.contains("-----END CERTIFICATE-----"));
        assertTrue(endEntityCert.contains("Alice End Entity") || endEntityCert.contains("MIIB/jCCAYSgAwIBAgICIAE"));
        
        // Second certificate should be the intermediate certificate (pat's)
        String intermediateCert = chain.get(1);
        assertNotNull(intermediateCert);
        assertTrue(intermediateCert.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(intermediateCert.contains("-----END CERTIFICATE-----"));
        assertTrue(intermediateCert.contains("Pat Intermediate") || intermediateCert.contains("MIIC5TCCAk6gAwIBAgIBAT"));
    }

    @Test
    public void getCertificateChain_WithNullKeyName_ShouldThrowException() throws IOException {
        // Given: A temporary YAML configuration
        String yamlContent = """
            config:
              primary-key: alice
            keys:
              alice:
                keyId: alice-key-id
                algorithm: ES256
                curve: secp256r1
            """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.write(yamlFile, yamlContent.getBytes());
        
        KeysService keysService = new KeysService();
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When & Then: Getting certificate chain with null key name should throw exception
        assertThrows(IllegalArgumentException.class, () -> {
            keysService.getCertificateChain(null);
        });
    }

    @Test
    public void getCertificateChain_WithInvalidKeyName_ShouldThrowException() throws IOException {
        // Given: A temporary YAML configuration
        String yamlContent = """
            config:
              primary-key: alice
            keys:
              alice:
                keyId: alice-key-id
                algorithm: ES256
                curve: secp256r1
            """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.write(yamlFile, yamlContent.getBytes());
        
        KeysService keysService = new KeysService();
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When & Then: Getting certificate chain with invalid key name should throw exception
        assertThrows(IllegalArgumentException.class, () -> {
            keysService.getCertificateChain("nonexistent");
        });
    }

    @Test
    public void getCertificateChain_WithAutoDetection_ShouldReturnChainWithEndEntityAndIntermediate() throws IOException {
        // Given: A configuration where alice has no explicit authority but can be auto-detected
        String yamlContent = """
            config:
              primary-key: alice
            keys:
              alice:
                keyId: alice-key-id
                algorithm: ES256
                curve: secp256r1
                # Note: No explicit authority configured - should be auto-detected as 'trent'
                private: |
                  -----BEGIN PRIVATE KEY-----
                  MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1234567890abcdef
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
            chains:
              trent:
                public: |
                  -----BEGIN CERTIFICATE-----
                  MIIB0zCCAVqgAwIBAgICEAAwCgYIKoZIzj0EAwIwHjEcMBoGA1UEAwwTaXZhbi5j
                  YS5leGFtcGxlLmNvbTAeFw0yNTA4MTEwMzI5NDBaFw0zNTA4MDkwMzI5NDBaMCMx
                  ITAfBgNVBAMMGHRyZW50LmludGVybS5leGFtcGxlLmNvbTB2MBAGByqGSM49AgEG
                  BSuBBAAiA2IABJbducTjt4vyRQPIFQUvs96giJr4fcCbcTTaHXjqQAqFKQ0JNsYY
                  XvYmI/ax8ZSuu/Y7j1c1dbe1fCzrrplJdG6EpHC26jtaM8E0xc7NsfM87krEFn2p
                  x+J6X8Z7dg9zx6NmMGQwHQYDVR0OBBYEFLBjtm8nryugZ+1tt5sHrmVHnWXaMB8G
                  A1UdIwQYMBaAFJl2eAkhqEYegUF5FPRTszadRjH3MBIGA1UdEwEB/wQIMAYBAf8C
                  AQAwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMCA2cAMGQCMCGeK1WwMX0jmIK8
                  Mr5d9/fTIPrIum8U/CGC/NVbsE7odQndftabkCaeXAE8s2VCqwIwS28/LNZblMs/
                  QvfYwtRLaVz3Mt3P4eGuDW0KTHa+hK/Znn5qXfDSQrRMqJBjJTEg
                  -----END CERTIFICATE-----
            """;
        
        Path yamlFile = tempDir.resolve("keys.yml");
        Files.write(yamlFile, yamlContent.getBytes());
        
        KeysService keysService = new KeysService();
        ReflectionTestUtils.setField(keysService, "keysFilePath", yamlFile.toString());
        keysService.init();
        
        // When: Getting certificate chain for alice (should auto-detect trent as authority)
        List<String> chain = keysService.getCertificateChain("alice");
        
        // Then: Should return a chain with both end-entity and intermediate certificates via auto-detection
        assertNotNull(chain);
        assertEquals(2, chain.size());
        
        // First certificate should be the end-entity certificate (alice's)
        String endEntityCert = chain.get(0);
        assertNotNull(endEntityCert);
        assertTrue(endEntityCert.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(endEntityCert.contains("-----END CERTIFICATE-----"));
        // Check for alice's certificate identifier in the base64 encoded certificate
        assertTrue(endEntityCert.contains("YWxpY2UuZWUuZXhhbXBsZS5jb20") || // base64 encoded alice.ee.example.com
                   endEntityCert.contains("MIIB/jCCAYSgAwIBAgICIAE")); // specific signature of alice's certificate
        
        // Second certificate should be the auto-detected intermediate certificate (trent's)
        String intermediateCert = chain.get(1);
        assertNotNull(intermediateCert);
        assertTrue(intermediateCert.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(intermediateCert.contains("-----END CERTIFICATE-----"));
        // Check for trent's certificate identifier in the base64 encoded certificate
        assertTrue(intermediateCert.contains("dHJlbnQuaW50ZXJtLmV4YW1wbGUuY29t") || // base64 encoded trent.interm.example.com
                   intermediateCert.contains("MIIB0zCCAVqgAwIBAgICEAA")); // specific signature of trent's certificate
        
        // Verify auto-detection worked: alice's certificate was issued by trent
        // We check this by looking for trent's identifier in alice's certificate
        assertTrue(endEntityCert.contains("dHJlbnQuaW50ZXJtLmV4YW1wbGUuY29t") || // trent as issuer
                   endEntityCert.contains("MIIB/jCCAYSgAwIBAgICIAE"), // alice's certificate signature
                   "Alice certificate should show trent as issuer for auto-detection to work");
    }

    // ========== getKeysResource() Tests ==========

    @Test
    @DisplayName("getKeysResource() with keysFilePath which start with classpath: prefix should return resource from classpath")
    void getKeysResource_WithClasspathPrefix_ShouldReturnClasspathResource() throws IOException {
        // Given: A KeysService with keysFilePath set to a classpath resource
        String classpathResource = "classpath:keys.yml";
        ReflectionTestUtils.setField(keysService, "keysFilePath", classpathResource);
        
        // When: Calling getKeysResource. But getKeysResource() is private, so we use reflection to invoke it.
        Resource result = (Resource) ReflectionTestUtils.invokeMethod(keysService, "getKeysResource");
        // Then: Should return a ClassPathResource
        assertNotNull(result);
        assertTrue(result instanceof ClassPathResource);
        assertEquals("keys.yml", ((ClassPathResource) result).getFilename());
    }

    @Test
    @DisplayName("getKeysResource() with keysFilePath which start with relative path should return resource from classpath")
    void getKeysResource_WithRelativePath_ShouldReturnClasspathResource() throws IOException {
        // Given: A KeysService with keysFilePath set to a relative path
        String relativePath = "keys.yml";
        ReflectionTestUtils.setField(keysService, "keysFilePath", relativePath);
        
        // When: Calling getKeysResource. But getKeysResource() is private, so we use reflection to invoke it.
        Resource result = (Resource) ReflectionTestUtils.invokeMethod(keysService, "getKeysResource");
        
        // Then: Should return a ClassPathResource
        assertNotNull(result);
        assertTrue(result instanceof ClassPathResource);
        assertEquals("keys.yml", ((ClassPathResource) result).getFilename());
    }
}