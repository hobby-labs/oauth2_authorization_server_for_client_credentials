package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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
 * Main configuration for OAuth2 Authorization Server.
 * 
 * <p>This configuration class is responsible for setting up the core OAuth2 Authorization Server
 * components including security filter chains and server settings. It focuses on the fundamental
 * authorization server infrastructure while delegating specific concerns to other configuration
 * classes following the DRY principle.</p>
 * 
 * <h3>Key Responsibilities:</h3>
 * <ul>
 *   <li>Configure the main OAuth2 Authorization Server security filter chain</li>
 *   <li>Integrate role-based authorization filtering for endpoint access control</li>
 *   <li>Set up OAuth2 resource server for JWT token validation</li>
 *   <li>Configure authorization server settings including issuer URI</li>
 * </ul>
 * 
 * <h3>Security Architecture:</h3>
 * <p>The configuration implements a layered security approach:</p>
 * <ul>
 *   <li><strong>Filter Chain Order:</strong> Highest priority (@Order(1)) to handle OAuth2 endpoints first</li>
 *   <li><strong>Role-Based Access Control:</strong> Custom filter enforces endpoint-specific role requirements</li>
 *   <li><strong>JWT Resource Server:</strong> Validates incoming JWT tokens using configured keys</li>
 *   <li><strong>OIDC Support:</strong> Enables OpenID Connect capabilities with default settings</li>
 * </ul>
 * 
 * <h3>Configuration Externalization:</h3>
 * <p>Uses Spring's {@code @Value} annotation to inject configuration from application.yml:</p>
 * <ul>
 *   <li>{@code oauth2.authorization-server.issuer} - The OAuth2 issuer URI</li>
 * </ul>
 * 
 * <h3>Related Components:</h3>
 * <ul>
 *   <li>{@link ClientRepositoryConfig} - Manages OAuth2 client registration and configuration</li>
 *   <li>{@link JwtConfig} - Handles JWT encoding, decoding, and key management</li>
 *   <li>{@link ClientRoleAuthorizationFilter} - Implements role-based endpoint authorization</li>
 * </ul>
 * 
 * @author TsutomuNakamura
 * @since 0.0.1-SNAPSHOT
 * @see org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
 * @see org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
 */
@Configuration
public class AuthorizationServerConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationServerConfig.class);
    
    /**
     * The OAuth2 Authorization Server issuer URI.
     * 
     * <p>This value is injected from the application.yml configuration property
     * {@code oauth2.authorization-server.issuer}. The issuer URI is used to identify
     * this authorization server in issued JWT tokens and must be accessible to
     * resource servers for token validation.</p>
     * 
     * <p>Example configuration in application.yml:</p>
     * <pre>
     * oauth2:
     *   authorization-server:
     *     issuer: http://localhost:9000
     * </pre>
     * 
     * @see #authorizationServerSettings()
     */
    @Value("${oauth2.authorization-server.issuer}")
    private String issuer;
    
    /**
     * Custom authorization filter for role-based endpoint access control.
     * 
     * <p>This filter is injected as a dependency and integrated into the security
     * filter chain to enforce role-based authorization rules on OAuth2 endpoints.</p>
     * 
     * @see ClientRoleAuthorizationFilter
     */
    private final ClientRoleAuthorizationFilter clientRoleAuthorizationFilter;
    
    /**
     * Constructor for dependency injection.
     * 
     * @param clientRoleAuthorizationFilter the role-based authorization filter
     *        that enforces endpoint access control based on client roles
     */
    public AuthorizationServerConfig(ClientRoleAuthorizationFilter clientRoleAuthorizationFilter) {
        this.clientRoleAuthorizationFilter = clientRoleAuthorizationFilter;
    }
    
    /**
     * Configures the main OAuth2 Authorization Server security filter chain.
     * 
     * <p>This method sets up the primary security configuration for the OAuth2 Authorization Server,
     * including endpoint routing, authentication, and authorization. The filter chain is configured
     * with the highest priority (Order 1) to ensure OAuth2 endpoints are handled before other
     * security configurations.</p>
     * 
     * <h3>Configuration Details:</h3>
     * <ul>
     *   <li><strong>Endpoint Matching:</strong> Applies only to OAuth2 authorization server endpoints</li>
     *   <li><strong>OIDC Support:</strong> Enables OpenID Connect with default configuration</li>
     *   <li><strong>Role-Based Filter:</strong> Integrates custom authorization filter for endpoint access control</li>
     *   <li><strong>JWT Resource Server:</strong> Configures JWT token validation for resource server functionality</li>
     * </ul>
     * 
     * <h3>Security Filter Order:</h3>
     * <p>The custom {@link ClientRoleAuthorizationFilter} is positioned before
     * {@code UsernamePasswordAuthenticationFilter} to ensure role-based authorization
     * occurs early in the filter chain, preventing unauthorized access to endpoints
     * based on client roles.</p>
     * 
     * <h3>Supported Endpoints:</h3>
     * <ul>
     *   <li>{@code /oauth2/token} - Token endpoint (requires CLIENT role)</li>
     *   <li>{@code /oauth2/introspect} - Token introspection endpoint (requires INTROSPECTOR role)</li>
     *   <li>{@code /oauth2/jwks} - JSON Web Key Set endpoint (public)</li>
     *   <li>{@code /.well-known/openid_configuration} - OIDC discovery endpoint (public)</li>
     * </ul>
     * 
     * @param http the {@link HttpSecurity} object for configuration
     * @return the configured {@link SecurityFilterChain}
     * @throws Exception if configuration fails
     * 
     * @see OAuth2AuthorizationServerConfigurer
     * @see ClientRoleAuthorizationFilter
     */
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

    /**
     * Configures the OAuth2 Authorization Server settings.
     * 
     * <p>This method creates and configures the {@link AuthorizationServerSettings}
     * bean that defines the fundamental settings for the OAuth2 Authorization Server.
     * The most critical setting is the issuer URI, which is used to identify this
     * authorization server in JWT tokens and OIDC discovery.</p>
     * 
     * <h3>Configuration Details:</h3>
     * <ul>
     *   <li><strong>Issuer URI:</strong> Externalized configuration from application.yml</li>
     *   <li><strong>Default Endpoints:</strong> Uses Spring Security OAuth2's default endpoint paths</li>
     *   <li><strong>OIDC Discovery:</strong> Enables automatic discovery document generation</li>
     * </ul>
     * 
     * <h3>Issuer URI Importance:</h3>
     * <p>The issuer URI serves multiple critical functions:</p>
     * <ul>
     *   <li>Included in the "iss" claim of all issued JWT tokens</li>
     *   <li>Used by resource servers to discover this authorization server</li>
     *   <li>Required for OIDC discovery document generation</li>
     *   <li>Must be accessible to all clients and resource servers</li>
     * </ul>
     * 
     * <h3>Environment Configuration:</h3>
     * <p>The issuer URI is externalized to application.yml for easy environment-specific
     * configuration without code changes:</p>
     * <pre>
     * # Development
     * oauth2.authorization-server.issuer: http://localhost:9000
     * 
     * # Production
     * oauth2.authorization-server.issuer: https://auth.example.com
     * </pre>
     * 
     * @return the configured {@link AuthorizationServerSettings}
     * 
     * @see AuthorizationServerSettings
     * @see <a href="https://tools.ietf.org/html/rfc7519#section-4.1.1">JWT iss Claim</a>
     * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OIDC Discovery</a>
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        logger.info("Authorization Server Settings initialized with issuer: {}", issuer);
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }
}
