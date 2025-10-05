package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ChainConfiguration;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockStatic;

class CertificateAuthorityDNDetectorTest {

    private CertificateAuthorityDNDetector detector;
    
    // Real certificate data from test fixtures (alice's certificate issued by trent)
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
        detector = new CertificateAuthorityDNDetector();
    }

    // ========== detectAuthority() Tests ==========
    
    @Test
    @DisplayName("detectAuthority() should return authority name when issuer DN matches chain subject DN")
    void detectAuthority_WithMatchingIssuerAndSubject_ShouldReturnAuthorityName() {
        // Given: Alice's certificate (issued by trent) and chains containing trent's certificate
        Map<String, ChainConfiguration> chains = new HashMap<>();
        ChainConfiguration trentChain = new ChainConfiguration(TRENT_CERT);
        chains.put("trent", trentChain);
        
        // When: Detect authority for alice's certificate
        String result = detector.detectAuthority(ALICE_CERT, chains);
        
        // Then: Should return "trent" as the authority
        assertNotNull(result, "Authority should be detected");
        assertEquals("trent", result, "Should detect 'trent' as the issuing authority");
    }

    @Test
    @DisplayName("detectAuthority() should return null when issuerCN is not present in the certificate")
    void detectAuthority_NoIssuerCN_ShouldReturnNull() {
        // Given: A certificate without issuer CN (self-signed or malformed)
        String certWithoutIssuerCN = """
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
        Map<String, ChainConfiguration> chains = new HashMap<>();
        ChainConfiguration trentChain = new ChainConfiguration(TRENT_CERT);
        chains.put("trent", trentChain);

        // Mock CertificateChainBuilder.extractIssuerCN to return null for this test
        // This can be done using a mocking framework like Mockito, but here we will
        // just rely on the actual implementation which should return null for this malformed cert.
        try (MockedStatic<CertificateChainBuilder> mockedStatic = mockStatic(CertificateChainBuilder.class)) {
            mockedStatic.when(() -> CertificateChainBuilder.extractIssuerCN(certWithoutIssuerCN)).thenReturn(null);

            // When: Detect authority for the certificate without issuer CN
            String result = detector.detectAuthority(certWithoutIssuerCN, chains);
            // Then: Should return null as no issuer CN is present
            assertNull(result, "Authority should not be detected when issuer CN is missing");
        }
    }

    @Test
    @DisplayName("detectAuthority() should return null when no chains are provided")
    void detectAuthority_NoChains_ShouldReturnNull() {
        // Given: Alice's certificate and no chains
        Map<String, ChainConfiguration> chains = null;
        
        // When: Detect authority for alice's certificate
        String result = detector.detectAuthority(ALICE_CERT, chains);
        
        // Then: Should return null as no chains are available
        assertNull(result, "Authority should not be detected when no chains are provided");
    }

    @Test
    @DisplayName("detectAuthority() should return null when CertificateChainBuilder.extractSubjectCN() throws an exception")
    void detectAuthority_ChainCertParsingError_ShouldReturnNull() {
        // Given: Alice's certificate and a chain that will cause parsing error
        Map<String, ChainConfiguration> chains = new HashMap<>();
        ChainConfiguration invalidChain = new ChainConfiguration("invalid-cert-data");
        chains.put("invalid-chain", invalidChain);

        // Mock CertificateChainBuilder.extractSubjectCN to throw an exception for this test
        try (MockedStatic<CertificateChainBuilder> mockedStatic = mockStatic(CertificateChainBuilder.class)) {
            mockedStatic.when(() -> CertificateChainBuilder.extractIssuerCN(ALICE_CERT)).thenReturn("trent.example.com");
            mockedStatic.when(() -> CertificateChainBuilder.extractSubjectCN("invalid-cert-data"))
                        .thenThrow(new RuntimeException("Parsing error"));

            // When: Detect authority for alice's certificate
            String result = detector.detectAuthority(ALICE_CERT, chains);
            // Then: Should return null as parsing the chain certificate fails
            assertNull(result, "Authority should not be detected when chain certificate parsing fails");
        }
    }

    @Test
    @DisplayName("detectAuthority() should return null when CertificateChainBuilder.extractIssuerCN() throws an exception")
    void detectAuthority_IssuerCNExtractionError_ShouldReturnNull() {
        // Given: Alice's certificate and a valid chain
        Map<String, ChainConfiguration> chains = new HashMap<>();
        ChainConfiguration trentChain = new ChainConfiguration(TRENT_CERT);
        chains.put("trent", trentChain);

        // Mock CertificateChainBuilder.extractIssuerCN to throw an exception for this test
        try (MockedStatic<CertificateChainBuilder> mockedStatic = mockStatic(CertificateChainBuilder.class)) {
            mockedStatic.when(() -> CertificateChainBuilder.extractIssuerCN(ALICE_CERT))
                        .thenThrow(new RuntimeException("Extraction error"));

            // When: Detect authority for alice's certificate
            String result = detector.detectAuthority(ALICE_CERT, chains);
            // Then: Should return null as extracting issuer CN fails
            assertNull(result, "Authority should not be detected when issuer CN extraction fails");
        }
    }
}
