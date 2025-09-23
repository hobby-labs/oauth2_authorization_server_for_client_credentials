package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.model;

import java.time.Duration;
import java.util.List;

/**
 * Configuration model for OAuth2 client data.
 * 
 * <p>This record encapsulates all the necessary configuration information for an OAuth2 client,
 * providing a type-safe way to pass client configuration data between different components
 * of the authorization server.</p>
 * 
 * <h3>Design Rationale:</h3>
 * <ul>
 *   <li><strong>Immutable:</strong> All fields are final, ensuring thread safety and preventing accidental modification</li>
 *   <li><strong>Type-safe:</strong> Strongly typed fields reduce configuration errors</li>
 *   <li><strong>Centralized:</strong> Single source of truth for client configuration structure</li>
 *   <li><strong>Reusable:</strong> Can be used across different configuration and service classes</li>
 * </ul>
 * 
 * <h3>Usage Examples:</h3>
 * <pre>{@code
 * // Creating a client configuration
 * ClientConfiguration config = new ClientConfiguration(
 *     "my-client-id",
 *     "my-client-secret", 
 *     "My Application",
 *     List.of("read", "write"),
 *     Duration.ofMinutes(30),
 *     List.of("CLIENT", "SERVICE")
 * );
 * 
 * // Accessing configuration values
 * String clientId = config.clientId();
 * Duration ttl = config.tokenTtl();
 * List<String> roles = config.roles();
 * }</pre>
 * 
 * @param clientId the OAuth2 client identifier used for authentication
 * @param clientSecret the OAuth2 client secret used for authentication
 * @param displayName the human-readable name for the client
 * @param scopes the list of OAuth2 scopes this client can request
 * @param tokenTtl the access token time-to-live for this client
 * @param roles the list of roles assigned to this client for endpoint access control
 * 
 * @author TsutomuNakamura
 * @since 0.0.1-SNAPSHOT
 */
public record ClientConfiguration(
    String clientId,
    String clientSecret,
    String displayName,
    List<String> scopes,
    Duration tokenTtl,
    List<String> roles
) {
    /**
     * Creates a ClientConfiguration with validation.
     * 
     * @param clientId the OAuth2 client identifier (must not be null or blank)
     * @param clientSecret the OAuth2 client secret (must not be null or blank)
     * @param displayName the human-readable name for the client (must not be null)
     * @param scopes the list of OAuth2 scopes (must not be null, can be empty)
     * @param tokenTtl the access token time-to-live (must not be null or negative)
     * @param roles the list of roles (must not be null, can be empty)
     * 
     * @throws IllegalArgumentException if any required field is null or invalid
     */
    public ClientConfiguration {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("Client ID cannot be null or blank");
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalArgumentException("Client secret cannot be null or blank");
        }
        if (displayName == null) {
            throw new IllegalArgumentException("Display name cannot be null");
        }
        if (scopes == null) {
            throw new IllegalArgumentException("Scopes list cannot be null");
        }
        if (tokenTtl == null || tokenTtl.isNegative()) {
            throw new IllegalArgumentException("Token TTL cannot be null or negative");
        }
        if (roles == null) {
            throw new IllegalArgumentException("Roles list cannot be null");
        }
    }
    
    /**
     * Checks if this client has a specific role.
     * 
     * @param role the role to check for
     * @return true if the client has the specified role, false otherwise
     */
    public boolean hasRole(String role) {
        return roles.contains(role);
    }
    
    /**
     * Gets the token TTL in minutes for logging and display purposes.
     * 
     * @return the token TTL in minutes
     */
    public long getTokenTtlMinutes() {
        return tokenTtl.toMinutes();
    }
}