package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationServerConfig {
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .apply(new OAuth2AuthorizationServerConfigurer<>());
        return http.build();
    }
}
