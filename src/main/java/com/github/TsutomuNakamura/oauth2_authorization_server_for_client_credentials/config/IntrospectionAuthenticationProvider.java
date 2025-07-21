package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.IntrospectionCredentialsService;

import java.util.Collections;

/**
 * Custom authentication provider for introspection endpoint.
 * Validates credentials against the introspector.yml configuration instead of regular clients.yml.
 * This provides separation of concerns and enhanced security for the introspection service.
 */
@Component
public class IntrospectionAuthenticationProvider implements AuthenticationProvider {

    private final IntrospectionCredentialsService introspectionCredentialsService;

    public IntrospectionAuthenticationProvider(IntrospectionCredentialsService introspectionCredentialsService) {
        this.introspectionCredentialsService = introspectionCredentialsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String clientId = authentication.getName();
        String clientSecret = (String) authentication.getCredentials();

        System.out.println("=== INTROSPECTION AUTHENTICATION ===");
        System.out.println("Attempting introspection authentication for client: " + clientId);
        System.out.println("Credentials provided: " + (clientSecret != null ? "[PRESENT]" : "[MISSING]"));

        // Validate credentials against introspector.yml
        if (introspectionCredentialsService.validateCredentials(clientId, clientSecret)) {
            // Find the introspector service name for logging
            String introspectorName = introspectionCredentialsService.findIntrospectorByClientId(clientId);
            String clientName = introspectionCredentialsService.getClientName(introspectorName);
            
            System.out.println("✅ Introspection authentication successful for: " + introspectorName + " (" + clientName + ")");
            
            // Create authenticated token with INTROSPECTION_CLIENT role
            return new UsernamePasswordAuthenticationToken(
                clientId, 
                clientSecret,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_INTROSPECTION_CLIENT"))
            );
        } else {
            System.out.println("❌ Introspection authentication failed for client: " + clientId);
            throw new BadCredentialsException("Invalid introspection credentials");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
