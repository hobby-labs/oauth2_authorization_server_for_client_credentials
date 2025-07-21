package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.stereotype.Component;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.IntrospectionCredentialsService;

/**
 * Custom OAuth2 Token Introspection Authentication Provider.
 * This provider handles authentication for the built-in OAuth2 introspection endpoint
 * using credentials from introspector.yml instead of regular OAuth2 clients.
 */
@Component
public class OAuth2TokenIntrospectionAuthenticationProvider implements AuthenticationProvider {

    private final IntrospectionCredentialsService introspectionCredentialsService;

    public OAuth2TokenIntrospectionAuthenticationProvider(
            IntrospectionCredentialsService introspectionCredentialsService) {
        this.introspectionCredentialsService = introspectionCredentialsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2TokenIntrospectionAuthenticationToken introspectionAuthentication = 
            (OAuth2TokenIntrospectionAuthenticationToken) authentication;

        System.out.println("=== OAUTH2 TOKEN INTROSPECTION AUTHENTICATION ===");
        System.out.println("Client ID from authentication: " + introspectionAuthentication.getName());

        // Check if it's a valid introspection service client
        String clientId = introspectionAuthentication.getName();
        String introspectorName = introspectionCredentialsService.findIntrospectorByClientId(clientId);
        
        if (introspectorName != null) {
            System.out.println("✅ Found introspection service: " + introspectorName);
            String clientName = introspectionCredentialsService.getClientName(introspectorName);
            System.out.println("✅ Introspection authentication successful for: " + clientName);
            
            // Return the same authentication token to indicate success
            return introspectionAuthentication;
        } else {
            System.out.println("❌ Invalid introspection client: " + clientId);
            OAuth2Error error = new OAuth2Error("invalid_client", "Invalid introspection credentials", null);
            throw new OAuth2AuthenticationException(error);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
