package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

public class KeyLoader {
    
    /**
     * Load EC (prime256v1) key pair from PEM files in classpath
     */
    public static KeyPair loadECFromClasspath(String privateKeyPath, String publicKeyPath) throws Exception {
        Resource privateResource = new ClassPathResource(privateKeyPath);
        Resource publicResource = new ClassPathResource(publicKeyPath);
        
        String privateKeyContent = Files.readString(privateResource.getFile().toPath());
        String publicKeyContent = Files.readString(publicResource.getFile().toPath());
        
        return loadECFromPemStrings(privateKeyContent, publicKeyContent);
    }
    
    /**
     * Load EC (prime256v1) key pair from PEM files on filesystem
     */
    public static KeyPair loadECFromFiles(String privateKeyPath, String publicKeyPath) throws Exception {
        Path privatePath = Paths.get(privateKeyPath);
        Path publicPath = Paths.get(publicKeyPath);
        
        String privateKeyContent = Files.readString(privatePath);
        String publicKeyContent = Files.readString(publicPath);
        
        return loadECFromPemStrings(privateKeyContent, publicKeyContent);
    }
    
    /**
     * Load EC (prime256v1) key pair from PEM string content
     */
    public static KeyPair loadECFromPemStrings(String privateKeyPem, String publicKeyPem) throws Exception {
        // Remove PEM headers and decode
        String privateKeyBase64 = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replace("-----END EC PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
                
        String publicKeyBase64 = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN EC PUBLIC KEY-----", "")
                .replace("-----END EC PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode and create keys
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        return new KeyPair(publicKey, privateKey);
    }
    
    /**
     * Generate and save EC (prime256v1) key pair to PEM files
     */
    public static void generateAndSaveECKeyPair(String privateKeyPath, String publicKeyPath) throws Exception {
        // Generate EC key pair with prime256v1 curve
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // prime256v1
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Save private key
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()) +
                "\n-----END PRIVATE KEY-----";
        Files.writeString(Paths.get(privateKeyPath), privateKeyPem);
        
        // Save public key
        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        Files.writeString(Paths.get(publicKeyPath), publicKeyPem);
        
        System.out.println("Generated and saved EC (prime256v1) key pair:");
        System.out.println("Private key: " + privateKeyPath);
        System.out.println("Public key: " + publicKeyPath);
    }
    
    /**
     * Generate EC (prime256v1) key pair in memory
     */
    public static KeyPair generateECKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // prime256v1
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }
    
    // Legacy RSA methods for backward compatibility
    
    /**
     * Load RSA key pair from PEM files in classpath
     */
    public static KeyPair loadRSAFromClasspath(String privateKeyPath, String publicKeyPath) throws Exception {
        Resource privateResource = new ClassPathResource(privateKeyPath);
        Resource publicResource = new ClassPathResource(publicKeyPath);
        
        String privateKeyContent = Files.readString(privateResource.getFile().toPath());
        String publicKeyContent = Files.readString(publicResource.getFile().toPath());
        
        return loadRSAFromPemStrings(privateKeyContent, publicKeyContent);
    }
    
    /**
     * Load RSA key pair from PEM files on filesystem
     */
    public static KeyPair loadRSAFromFiles(String privateKeyPath, String publicKeyPath) throws Exception {
        Path privatePath = Paths.get(privateKeyPath);
        Path publicPath = Paths.get(publicKeyPath);
        
        String privateKeyContent = Files.readString(privatePath);
        String publicKeyContent = Files.readString(publicPath);
        
        return loadRSAFromPemStrings(privateKeyContent, publicKeyContent);
    }
    
    /**
     * Load RSA key pair from PEM string content
     */
    public static KeyPair loadRSAFromPemStrings(String privateKeyPem, String publicKeyPem) throws Exception {
        // Remove PEM headers and decode
        String privateKeyBase64 = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
                
        String publicKeyBase64 = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        
        // Decode and create keys
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        return new KeyPair(publicKey, privateKey);
    }
    
    /**
     * Generate and save RSA key pair to PEM files
     */
    public static void generateAndSaveRSAKeyPair(String privateKeyPath, String publicKeyPath) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        // Save private key
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()) +
                "\n-----END PRIVATE KEY-----";
        Files.writeString(Paths.get(privateKeyPath), privateKeyPem);
        
        // Save public key
        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        Files.writeString(Paths.get(publicKeyPath), publicKeyPem);
        
        System.out.println("Generated and saved RSA key pair:");
        System.out.println("Private key: " + privateKeyPath);
        System.out.println("Public key: " + publicKeyPath);
    }
}
