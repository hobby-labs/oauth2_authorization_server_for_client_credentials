package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.filter.ClientRoleAuthorizationFilter;

/**
 * Main configuration for OAuth2 Authorization Server
 * Focuses on security filter chain configuration and server settings
 */
@Configuration
public class AuthorizationServerConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationServerConfig.class);
    private static final String DEFAULT_ISSUER = "http://localhost:9000";
    
    private final ClientRoleAuthorizationFilter clientRoleAuthorizationFilter;
    
    public AuthorizationServerConfig(ClientRoleAuthorizationFilter clientRoleAuthorizationFilter) {
        this.clientRoleAuthorizationFilter = clientRoleAuthorizationFilter;
    }
    
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = 
            OAuth2AuthorizationServerConfigurer.authorizationServer()
                .oidc(Customizer.withDefaults());
        
        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .with(authorizationServerConfigurer, Customizer.withDefaults())
            .addFilterBefore(clientRoleAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(Customizer.withDefaults()));

        logger.info("Authorization Server Security Filter Chain initialized");
        return http.build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        logger.info("Authorization Server Settings initialized with issuer: {}", DEFAULT_ISSUER);
        return AuthorizationServerSettings.builder()
                .issuer(DEFAULT_ISSUER)
                .build();
    }
}
