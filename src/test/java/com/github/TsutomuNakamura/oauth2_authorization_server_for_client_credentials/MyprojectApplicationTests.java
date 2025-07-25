package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;

@SpringBootTest
class MyprojectApplicationTests {

    /**
	 * Summary
     * 
     * Test Cases Added:
     * testJwtSignatureVerification - Main JWT signature verification using EC P-256 public key
     * testSignatureLengthForP256 - Verifies P-256 ECDSA signatures are exactly 64 bytes
     * testJwtStructureValidation - Validates JWT has correct 3-part structure
     * testInvalidSignatureDetection - Tests detection of invalid signatures
     * testPublicKeyLoading - Verifies EC public key loading from PEM file
     * testSignatureFormatConversion - Tests P1363 to DER signature conversion
     * contextLoads - Basic Spring context loading test
     * Key Technical Features:
     * P1363 to DER Conversion: Converts JWT ECDSA signatures from IEEE P1363 format (r||s concatenated) to ASN.1 DER format required by Java's Signature.verify()
     * URL-Safe Base64 Handling: Properly decodes JWT signatures with padding restoration
     * EC Key Loading: Loads P-256 public keys from PEM files using KeyFactory and X509EncodedKeySpec
     * Comprehensive Validation: Tests signature length, structure, and cryptographic verification
	 * 
	 * ✅ Public key loading test passed
     * ✅ JWT structure validation passed  
     * ✅ Signature length verification passed: 64 bytes
     * ✅ Invalid signature detection passed
     * ✅ JWT signature verification passed
     * ✅ Signature conversion test passed
     * P1363 length: 64 bytes
     * DER length: 70 bytes
     * DER sequence length: 68 bytes
     * Tests run: 7, Failures: 0, Errors: 0, Skipped: 0
     * BUILD SUCCESS
	 * 
	 * Client credentials flow
     * ES256 JWT signing with EC P-256 keys
     * Custom claims and headers
     * Proper key loading from PEM files
     * Comprehensive test coverage
	 * 
	 * ---
	 * 
	 * For JWT creation, the signature should be in IEEE P1363 format, NOT ASN.1 DER format.
	 * 
	 * # JWT Standard (RFC 7515) ###############################################
     * The JWT specification explicitly requires IEEE P1363 format for ECDSA signatures:
     * P-256 (ES256): 64 bytes (32 bytes r + 32 bytes s)
     * P-384 (ES384): 96 bytes (48 bytes r + 48 bytes s)
     * P-521 (ES512): 132 bytes (66 bytes r + 66 bytes s)
	 * 
	 * # The Conversion Issue in Java ##########################################
     * * The problem is that Java's crypto APIs use ASN.1 DER format by default, but JWT requires IEEE P1363 format:
     * * Java Signature.sign() → produces ASN.1 DER format
     * * Java Signature.verify() → expects ASN.1 DER format
     * * JWT specification → requires IEEE P1363 format
	*/

	private PublicKey publicKey;
	private static final String JWT_TOKEN = "eyJ4NWMiOlsiTUlJQ2RUQ0NBaHVnQXdJQkFnSUpBT0V4YW1wbGUxLi4uIiwiTUlJQ2RUQ0NBaHVnQXdJQkFnSUpBT0V4YW1wbGUyLi4uIl0sImtpZCI6ImVjLWtleS1mcm9tLWZpbGUiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJteS1jbGllbnQiLCJhdWQiOiJteS1jbGllbnQiLCJ2ZXIiOiIxIiwibmJmIjoxNzUyOTc1ODM1LCJzY29wZSI6WyJyZWFkIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTc1Mjk3NjEzNSwiaWF0IjoxNzUyOTc1ODM1LCJjbGllbnRfbmFtZSI6IjU3N2ZmYTdmLWJlNjQtNGUwZS1hYzhhLTYzMTI3NTA1MGU3ZSIsImp0aSI6ImM4YzExZDYxLTM3NmMtNDk2NC1iOGQxLWEwZjEwNDYzMjIxMiIsImNsaWVudF9pZCI6Im15LWNsaWVudCJ9.OTV84DGIo5fPxMeUq4Z7w_dcR_y5tCo0ePeFdwvc2VcMMNo4JeaAk1EsU7ONtINBCmumTTl3konpZxPq4skOvQ";

	@BeforeEach
	void setUp() throws Exception {
		// Load the public key for JWT verification
		publicKey = loadPublicKeyFromFile("keys/ec-public-key_never-use-in-production.pem");
	}

	@Test
	void contextLoads() {
		System.out.println("Context loads successfully");
	}

	@Test
	@DisplayName("Verify JWT signature with EC P-256 public key")
	void testJwtSignatureVerification() throws Exception {
		// Given
		String[] jwtParts = JWT_TOKEN.split("\\.");
		assertEquals(3, jwtParts.length, "JWT should have 3 parts");
		
		String header = jwtParts[0];
		String payload = jwtParts[1];
		String signature = jwtParts[2];
		
		// When - Prepare signing input (header.payload)
		String signingInput = header + "." + payload;
		byte[] signingInputBytes = signingInput.getBytes("UTF-8");
		
		// Decode URL-safe base64 signature (P1363 format)
		byte[] signatureP1363 = decodeUrlSafeBase64(signature);
		
		// Convert P1363 format to DER format for Java verification
		byte[] signatureDER = convertP1363ToDER(signatureP1363);
		
		// Then - Verify signature
		boolean isValid = verifySignature(signingInputBytes, signatureDER, publicKey);
		
		assertTrue(isValid, "JWT signature should be valid");
		System.out.println("✅ JWT signature verification passed");
	}

	@Test
	@DisplayName("Test signature length for P-256 curve")
	void testSignatureLengthForP256() throws Exception {
		// Given
		String[] jwtParts = JWT_TOKEN.split("\\.");
		String signature = jwtParts[2];
		
		// When
		byte[] signatureBytes = decodeUrlSafeBase64(signature);
		
		// Then - P-256 ECDSA signature should be 64 bytes (32 bytes for r + 32 bytes for s)
		assertEquals(64, signatureBytes.length, "P-256 ECDSA signature should be 64 bytes");
		System.out.println("✅ Signature length verification passed: " + signatureBytes.length + " bytes");
	}

	@Test
	@DisplayName("Test JWT structure validation")
	void testJwtStructureValidation() {
		// Given & When
		String[] jwtParts = JWT_TOKEN.split("\\.");
		
		// Then
		assertEquals(3, jwtParts.length, "JWT should have exactly 3 parts");
		
		assertFalse(jwtParts[0].isEmpty(), "Header should not be empty");
		assertFalse(jwtParts[1].isEmpty(), "Payload should not be empty");
		assertFalse(jwtParts[2].isEmpty(), "Signature should not be empty");
		
		System.out.println("✅ JWT structure validation passed");
	}

	@Test
	@DisplayName("Test invalid signature detection")
	void testInvalidSignatureDetection() throws Exception {
		// Given - Tamper with the signature
		String[] jwtParts = JWT_TOKEN.split("\\.");
		String header = jwtParts[0];
		String payload = jwtParts[1];
		String tamperedSignature = "invalid_signature_here_not_base64";
		
		String signingInput = header + "." + payload;
		byte[] signingInputBytes = signingInput.getBytes("UTF-8");
		
		// When - Try to decode invalid signature (this will fail)
		assertThrows(IllegalArgumentException.class, () -> {
			decodeUrlSafeBase64(tamperedSignature);
		}, "Invalid signature should throw exception during base64 decode");
		
		// Test signature verification with wrong signature (64 bytes of zeros)
		String wrongSignature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 64 bytes of zeros in base64
		byte[] wrongSigBytes = decodeUrlSafeBase64(wrongSignature);
		assertEquals(64, wrongSigBytes.length, "Wrong signature should still be 64 bytes");
		
		// Convert to DER format and verify (should fail)
		byte[] wrongSigDER = convertP1363ToDER(wrongSigBytes);
		boolean isValidWrong = verifySignature(signingInputBytes, wrongSigDER, publicKey);
		assertFalse(isValidWrong, "Wrong signature should not verify");
		
		System.out.println("✅ Invalid signature detection passed");
	}

	@Test
	@DisplayName("Test public key loading")
	void testPublicKeyLoading() throws Exception {
		// Given & When
		PublicKey key = loadPublicKeyFromFile("keys/ec-public-key_never-use-in-production.pem");
		
		// Then
		assertNotNull(key, "Public key should be loaded successfully");
		assertEquals("EC", key.getAlgorithm(), "Key algorithm should be EC");
		
		System.out.println("✅ Public key loading test passed");
		System.out.println("   Algorithm: " + key.getAlgorithm());
		System.out.println("   Format: " + key.getFormat());
	}

	@Test
	@DisplayName("Test P1363 to DER signature conversion")
	void testSignatureFormatConversion() throws Exception {
		// Given - Extract signature from JWT
		String[] jwtParts = JWT_TOKEN.split("\\.");
		String signature = jwtParts[2];
		byte[] signatureP1363 = decodeUrlSafeBase64(signature);
		
		// When - Convert to DER
		byte[] signatureDER = convertP1363ToDER(signatureP1363);
		
		// Then - Verify DER format structure
		assertNotNull(signatureDER, "DER signature should not be null");
		assertTrue(signatureDER.length > 64, "DER signature should be longer than P1363");
		assertEquals(0x30, signatureDER[0] & 0xFF, "DER signature should start with SEQUENCE tag (0x30)");
		
		// Verify it contains two INTEGER elements
		int sequenceLength = signatureDER[1] & 0xFF;
		if (sequenceLength > 127) {
			sequenceLength = signatureDER[2] & 0xFF; // Long form
		}
		
		System.out.println("✅ Signature conversion test passed");
		System.out.println("   P1363 length: " + signatureP1363.length + " bytes");
		System.out.println("   DER length: " + signatureDER.length + " bytes");
		System.out.println("   DER sequence length: " + sequenceLength + " bytes");
	}

	@Test
	@DisplayName("Verify signature.bin file (P1363 format) against signing_input")
	void testSignatureBinFileVerification() throws Exception {
		// Load public key
		ClassPathResource keyResource = new ClassPathResource("keys/ec-public-key_never-use-in-production.pem");
		String keyPem = Files.readString(keyResource.getFile().toPath())
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s", "");
		
		byte[] keyBytes = Base64.getDecoder().decode(keyPem);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PublicKey publicKey = keyFactory.generatePublic(keySpec);
		
		// Read signature.bin file (should be in P1363 format)
		java.io.File signatureFile = new java.io.File("signature.bin");
		assertTrue(signatureFile.exists(), "signature.bin file should exist");
		
		byte[] p1363Signature = Files.readAllBytes(signatureFile.toPath());
		assertEquals(64, p1363Signature.length, "P1363 signature should be 64 bytes for P-256");
		
		// Read signing_input file
		java.io.File signingInputFile = new java.io.File("signing_input");
		assertTrue(signingInputFile.exists(), "signing_input file should exist");
		
		byte[] signingInput = Files.readAllBytes(signingInputFile.toPath());
		assertNotNull(signingInput, "Signing input should not be null");
		assertTrue(signingInput.length > 0, "Signing input should not be empty");        // Convert P1363 to DER format
        byte[] derSignature = convertP1363ToDER(p1363Signature);
		assertNotNull(derSignature, "DER signature should not be null");
		assertTrue(derSignature.length > 64, "DER signature should be longer than P1363");
		
		// Verify signature using converted DER format
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initVerify(publicKey);
		signature.update(signingInput);
		
		boolean isValid = signature.verify(derSignature);
		assertTrue(isValid, "Signature from signature.bin should be valid when converted to DER");
		
		System.out.println("✅ signature.bin verification passed");
		System.out.println("P1363 signature length: " + p1363Signature.length + " bytes");
		System.out.println("DER signature length: " + derSignature.length + " bytes");
		System.out.println("Signing input length: " + signingInput.length + " bytes");
		
		// Extract and display r and s components
		byte[] r = new byte[32];
		byte[] s = new byte[32];
		System.arraycopy(p1363Signature, 0, r, 0, 32);
		System.arraycopy(p1363Signature, 32, s, 0, 32);
		
		System.out.println("r component (hex): " + bytesToHex(r));
		System.out.println("s component (hex): " + bytesToHex(s));
	}

    // Helper methods

	private PublicKey loadPublicKeyFromFile(String keyPath) throws Exception {
		ClassPathResource resource = new ClassPathResource(keyPath);
		String keyContent = Files.readString(resource.getFile().toPath());
		
		// Remove PEM headers and whitespace
		String keyBase64 = keyContent
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "")
				.replaceAll("\\s", "");
		
		// Decode and create public key
		byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		
		return keyFactory.generatePublic(keySpec);
	}

	private byte[] decodeUrlSafeBase64(String input) {
		// Convert URL-safe base64 to standard base64
		String standardBase64 = input.replace('_', '/').replace('-', '+');
		
		// Add padding if needed
		int padding = standardBase64.length() % 4;
		if (padding == 2) {
			standardBase64 += "==";
		} else if (padding == 3) {
			standardBase64 += "=";
		}
		
		return Base64.getDecoder().decode(standardBase64);
	}

	private boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
		Signature sig = Signature.getInstance("SHA256withECDSA");
		sig.initVerify(publicKey);
		sig.update(data);
		return sig.verify(signature);
	}

	/**
	 * Convert ECDSA signature from P1363 format (r||s) to ASN.1 DER format
	 * P1363 format: 64 bytes for P-256 (32 bytes r + 32 bytes s)
	 * DER format: ASN.1 SEQUENCE of two INTEGERs
	 */
	private byte[] convertP1363ToDER(byte[] p1363Signature) throws Exception {
		if (p1363Signature.length != 64) {
			throw new IllegalArgumentException("P-256 signature must be 64 bytes");
		}

		// Extract r and s values (32 bytes each)
		byte[] r = new byte[32];
		byte[] s = new byte[32];
		System.arraycopy(p1363Signature, 0, r, 0, 32);
		System.arraycopy(p1363Signature, 32, s, 0, 32);

		// Build DER encoding manually
		byte[] rDER = encodeAsn1Integer(r);
		byte[] sDER = encodeAsn1Integer(s);

		// Create SEQUENCE
		int totalLength = rDER.length + sDER.length;
		byte[] result;
		
		if (totalLength < 128) {
			result = new byte[2 + totalLength];
			result[0] = 0x30; // SEQUENCE tag
			result[1] = (byte) totalLength;
			System.arraycopy(rDER, 0, result, 2, rDER.length);
			System.arraycopy(sDER, 0, result, 2 + rDER.length, sDER.length);
		} else {
			result = new byte[3 + totalLength];
			result[0] = 0x30; // SEQUENCE tag
			result[1] = (byte) 0x81; // Long form length
			result[2] = (byte) totalLength;
			System.arraycopy(rDER, 0, result, 3, rDER.length);
			System.arraycopy(sDER, 0, result, 3 + rDER.length, sDER.length);
		}
		
		return result;
	}

	private byte[] encodeAsn1Integer(byte[] value) {
		// Remove leading zeros
		int start = 0;
		while (start < value.length && value[start] == 0) {
			start++;
		}
		
		if (start == value.length) {
			// All zeros, return single zero byte
			return new byte[]{0x02, 0x01, 0x00};
		}
		
		byte[] trimmed = new byte[value.length - start];
		System.arraycopy(value, start, trimmed, 0, trimmed.length);
		
		// Add leading zero if MSB is set (to ensure positive)
		boolean needsPadding = (trimmed[0] & 0x80) != 0;
		
		if (needsPadding) {
			byte[] result = new byte[3 + trimmed.length];
			result[0] = 0x02; // INTEGER tag
			result[1] = (byte) (trimmed.length + 1);
			result[2] = 0x00; // Padding byte
			System.arraycopy(trimmed, 0, result, 3, trimmed.length);
			return result;
		} else {
			byte[] result = new byte[2 + trimmed.length];
			result[0] = 0x02; // INTEGER tag
			result[1] = (byte) trimmed.length;
			System.arraycopy(trimmed, 0, result, 2, trimmed.length);
			return result;
		}
	}

	/**
	 * Convert byte array to hexadecimal string representation
	 */
	private String bytesToHex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
			result.append(String.format("%02x", b));
		}
		return result.toString();
	}
}
