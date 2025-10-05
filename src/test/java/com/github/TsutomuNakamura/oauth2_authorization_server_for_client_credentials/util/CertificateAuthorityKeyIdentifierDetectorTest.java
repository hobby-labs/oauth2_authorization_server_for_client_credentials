package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ChainConfiguration;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CertificateAuthorityKeyIdentifierDetectorTest {

    private CertificateAuthorityKeyIdentifierDetector detector;
    
    // Real certificate data from test fixtures (alice's certificate issued by trent)
    // This certificate contains Authority Key Identifier extension pointing to trent
    private static final String ALICE_CERT = """
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
    
    // Trent's certificate (intermediate CA)
    // This certificate contains Subject Key Identifier extension that matches alice's AKI
    private static final String TRENT_CERT = """
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
    
    @BeforeEach
    void setUp() {
        detector = new CertificateAuthorityKeyIdentifierDetector();
    }

    // ========== detectAuthority() Tests ==========
    
    @Test
    @DisplayName("detectAuthority() should return authority name when AKI matches chain SKI")
    void detectAuthority_WithMatchingKeyIdentifiers_ShouldReturnAuthorityName() {
        // Given: Alice's certificate (issued by trent) and chains containing trent's certificate
        // Alice's cert has AKI that matches Trent's SKI
        Map<String, ChainConfiguration> chains = new HashMap<>();
        ChainConfiguration trentChain = new ChainConfiguration(TRENT_CERT);
        chains.put("trent", trentChain);
        
        // When: Detect authority for alice's certificate using X.509v3 Key Identifiers
        String result = detector.detectAuthority(ALICE_CERT, chains);
        
        // Then: Should return "trent" as the authority
        assertNotNull(result, "Authority should be detected using key identifiers");
        assertEquals("trent", result, "Should detect 'trent' as the issuing authority using AKI/SKI matching");
    }
}
