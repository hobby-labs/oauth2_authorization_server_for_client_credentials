package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.factory;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.model.ClientConfiguration;

/**
 * Factory for creating Spring Security RegisteredClient instances from ClientConfiguration.
 * 
 * <p>This factory encapsulates the logic for converting application-specific client configurations
 * into Spring Security's RegisteredClient format. It centralizes the client creation logic and
 * makes it reusable across different parts of the application.</p>
 * 
 * <h3>Key Benefits:</h3>
 * <ul>
 *   <li><strong>Centralized Logic:</strong> Single place for RegisteredClient creation</li>
 *   <li><strong>Consistent Configuration:</strong> All clients are created with the same settings</li>
 *   <li><strong>Externalized Settings:</strong> Uses application.yml for configurable values</li>
 *   <li><strong>Type Safety:</strong> Strongly typed configuration input</li>
 * </ul>
 * 
 * <h3>Configuration:</h3>
 * <p>The factory uses externalized configuration for password encoding and error handling:</p>
 * <ul>
 *   <li>{@code oauth2.client.password-encoder-prefix} - Password encoder prefix (default: {noop})</li>
 * </ul>
 * 
 * @author TsutomuNakamura
 * @since 0.0.1-SNAPSHOT
 * @see RegisteredClient
 * @see ClientConfiguration
 */
@Component
public class RegisteredClientFactory {
    
    /**
     * Default client authentication methods supported by this factory.
     * Includes both BASIC and POST authentication methods for client flexibility.
     */
    private static final ClientAuthenticationMethod[] DEFAULT_AUTH_METHODS = {
        ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        ClientAuthenticationMethod.CLIENT_SECRET_POST
    };
    
    /**
     * Default authorization grant type for OAuth2 client credentials flow.
     */
    private static final AuthorizationGrantType DEFAULT_GRANT_TYPE = AuthorizationGrantType.CLIENT_CREDENTIALS;
    
    /**
     * Password encoder prefix for client secrets.
     * Injected from application.yml configuration.
     */
    @Value("${oauth2.client.password-encoder-prefix:{noop}}")
    private String passwordEncoderPrefix;
    
    /**
     * Creates a RegisteredClient from a ClientConfiguration.
     * 
     * <p>This method transforms application-specific client configuration into Spring Security's
     * RegisteredClient format with consistent OAuth2 settings.</p>
     * 
     * <h4>Client Configuration:</h4>
     * <ul>
     *   <li><strong>Authentication Methods:</strong> CLIENT_SECRET_BASIC and CLIENT_SECRET_POST</li>
     *   <li><strong>Grant Type:</strong> CLIENT_CREDENTIALS</li>
     *   <li><strong>Password Encoding:</strong> Uses configured prefix (default: {noop})</li>
     *   <li><strong>Token Settings:</strong> Custom TTL from configuration</li>
     * </ul>
     * 
     * @param config the client configuration containing all necessary client metadata
     * @return a fully configured RegisteredClient ready for OAuth2 operations
     * @throws IllegalArgumentException if the configuration is invalid
     */
    public RegisteredClient createRegisteredClient(ClientConfiguration config) {
        if (config == null) {
            throw new IllegalArgumentException("Client configuration cannot be null");
        }
        
        TokenSettings defaultTokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(config.tokenTtl())
                .build();
        
        return createRegisteredClientWithTokenSettings(config, defaultTokenSettings);
    }
    
    /**
     * Creates a RegisteredClient with custom token settings.
     * 
     * <p>This overloaded method allows for custom token settings to be applied,
     * useful for special client configurations that need different token behavior.</p>
     * 
     * @param config the client configuration
     * @param tokenSettings custom token settings to apply
     * @return a RegisteredClient with custom token settings
     * @throws IllegalArgumentException if any parameter is null
     */
    public RegisteredClient createRegisteredClient(ClientConfiguration config, TokenSettings tokenSettings) {
        if (config == null) {
            throw new IllegalArgumentException("Client configuration cannot be null");
        }
        if (tokenSettings == null) {
            throw new IllegalArgumentException("Token settings cannot be null");
        }
        
        return createRegisteredClientWithTokenSettings(config, tokenSettings);
    }
    
    /**
     * Creates the base RegisteredClient builder with common configuration.
     * 
     * <p>This method contains all the common logic for creating RegisteredClient instances,
     * eliminating code duplication between the public factory methods.</p>
     * 
     * @param config the client configuration
     * @param tokenSettings the token settings to apply
     * @return fully configured RegisteredClient
     */
    private RegisteredClient createRegisteredClientWithTokenSettings(ClientConfiguration config, TokenSettings tokenSettings) {
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(config.clientId())
                .clientSecret(passwordEncoderPrefix + config.clientSecret())
                .clientName(config.displayName())
                .authorizationGrantType(DEFAULT_GRANT_TYPE)
                .tokenSettings(tokenSettings);
        
        // Add authentication methods
        for (ClientAuthenticationMethod method : DEFAULT_AUTH_METHODS) {
            builder.clientAuthenticationMethod(method);
        }
        
        // Add all scopes from configuration
        config.scopes().forEach(builder::scope);
        
        return builder.build();
    }
}