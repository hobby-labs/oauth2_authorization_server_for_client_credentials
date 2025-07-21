package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

/**
 * OAuth2 Token Introspection Controller (RFC 7662)
 * Provides /oauth2/introspect endpoint for token validation
 */
@RestController
public class OAuth2IntrospectionController {

    @Autowired
    private JwtDecoder jwtDecoder;
    
    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    /**
     * OAuth2 Token Introspection Endpoint
     * POST /oauth2/introspect
     * 
     * Request: token=<JWT_TOKEN>&token_type_hint=access_token
     * Response: JSON with token information or {"active": false}
     */
    @PostMapping("/oauth2/introspect")
    public ResponseEntity<Map<String, Object>> introspect(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint,
            Authentication authentication) {
        
        Map<String, Object> response = new HashMap<>();
        
        try {
            // Validate that the requesting client is authenticated
            if (authentication == null || !authentication.isAuthenticated()) {
                System.out.println("Introspection request without proper authentication");
                response.put("active", false);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
            
            System.out.println("Introspection request for token from client: " + authentication.getName());
            
            // Decode and validate the JWT token
            Jwt jwt = jwtDecoder.decode(token);
            
            // Check if token is expired
            Instant now = Instant.now();
            Instant expiration = jwt.getExpiresAt();
            
            if (expiration != null && expiration.isBefore(now)) {
                System.out.println("Token is expired. Exp: " + expiration + ", Now: " + now);
                response.put("active", false);
                return ResponseEntity.ok(response);
            }
            
            // Token is valid, build introspection response
            response.put("active", true);
            
            // Standard RFC 7662 claims
            response.put("client_id", jwt.getClaimAsString("client_id"));
            response.put("username", jwt.getClaimAsString("sub")); // Subject
            response.put("scope", jwt.getClaimAsString("scope"));
            response.put("token_type", "Bearer");
            
            // Token timing information
            if (jwt.getIssuedAt() != null) {
                response.put("iat", jwt.getIssuedAt().getEpochSecond());
            }
            if (jwt.getExpiresAt() != null) {
                response.put("exp", jwt.getExpiresAt().getEpochSecond());
            }
            if (jwt.getNotBefore() != null) {
                response.put("nbf", jwt.getNotBefore().getEpochSecond());
            }
            
            // Issuer and audience
            response.put("iss", jwt.getClaimAsString("iss"));
            
            Object audClaim = jwt.getClaim("aud");
            if (audClaim instanceof List) {
                response.put("aud", audClaim);
            } else if (audClaim instanceof String) {
                response.put("aud", List.of((String) audClaim));
            }
            
            // JWT ID if present
            String jti = jwt.getClaimAsString("jti");
            if (jti != null) {
                response.put("jti", jti);
            }
            
            // Additional custom claims
            String clientName = jwt.getClaimAsString("client_name");
            if (clientName != null) {
                response.put("client_name", clientName);
            }
            
            String version = jwt.getClaimAsString("ver");
            if (version != null) {
                response.put("ver", version);
            }
            
            // Add revocation status (always false for now, can be enhanced with token store)
            response.put("revoked", false);
            
            System.out.println("Token introspection successful for client: " + jwt.getClaimAsString("client_id"));
            
            return ResponseEntity.ok(response);
            
        } catch (JwtException e) {
            // Invalid JWT token (signature verification failed, malformed, etc.)
            System.out.println("JWT validation failed during introspection: " + e.getMessage());
            response.put("active", false);
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            // Any other error
            System.err.println("Error during token introspection: " + e.getMessage());
            e.printStackTrace();
            response.put("active", false);
            return ResponseEntity.ok(response);
        }
    }
    
    /**
     * Health check endpoint to verify introspection service is running
     */
    @PostMapping("/oauth2/introspect/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "healthy");
        response.put("service", "OAuth2 Token Introspection");
        response.put("timestamp", Instant.now().toString());
        return ResponseEntity.ok(response);
    }
}
