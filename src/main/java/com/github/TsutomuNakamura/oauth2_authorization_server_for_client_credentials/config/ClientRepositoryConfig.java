package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.ClientsService;

/**
 * Configuration for OAuth2 client repository
 * Handles loading and registration of OAuth2 clients from YAML configuration
 */
@Configuration
public class ClientRepositoryConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(ClientRepositoryConfig.class);
    private static final String PASSWORD_ENCODER_PREFIX = "{noop}";
    
    private final ClientsService clientsService;
    
    public ClientRepositoryConfig(ClientsService clientsService) {
        this.clientsService = clientsService;
    }
    
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        logger.info("Loading OAuth2 clients from YAML configuration...");
        
        Map<String, Object> allClients = clientsService.getAllClients();
        validateClientsConfiguration(allClients);
        
        List<RegisteredClient> clients = buildRegisteredClients(allClients);
        
        logger.info("Total registered clients: {}", clients.size());
        return new InMemoryRegisteredClientRepository(clients);
    }
    
    private void validateClientsConfiguration(Map<String, Object> allClients) {
        if (allClients.isEmpty()) {
            String errorMessage = "No OAuth2 clients configured in clients.yml. " +
                "Application requires at least one client to be defined in the configuration file.";
            
            logger.error("ERROR: No clients found in configuration file!");
            logger.error("Please ensure clients.yml contains proper client entries.");
            logger.error("Application startup will be aborted.");
            
            throw new IllegalStateException(errorMessage);
        }
    }
    
    private List<RegisteredClient> buildRegisteredClients(Map<String, Object> allClients) {
        List<RegisteredClient> clients = new ArrayList<>();
        
        for (String clientName : allClients.keySet()) {
            try {
                RegisteredClient client = buildRegisteredClient(clientName);
                clients.add(client);
                logClientRegistration(clientName, client);
            } catch (Exception e) {
                logger.error("Failed to register client '{}': {}", clientName, e.getMessage());
                // Continue with other clients
            }
        }
        
        return clients;
    }
    
    private RegisteredClient buildRegisteredClient(String clientName) {
        ClientConfiguration config = extractClientConfiguration(clientName);
        
        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(config.clientId())
                .clientSecret(PASSWORD_ENCODER_PREFIX + config.clientSecret())
                .clientName(config.displayName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(config.tokenTtl())
                        .build());
        
        // Add scopes
        config.scopes().forEach(builder::scope);
        
        return builder.build();
    }
    
    private ClientConfiguration extractClientConfiguration(String clientName) {
        return new ClientConfiguration(
            clientsService.getClientId(clientName),
            clientsService.getClientSecret(clientName),
            clientsService.getClientDisplayName(clientName),
            clientsService.getClientScopes(clientName),
            clientsService.getAccessTokenTtl(clientName)
        );
    }
    
    private void logClientRegistration(String clientName, RegisteredClient client) {
        logger.info("Registered client '{}' ({}) with scopes: {}, TTL: {}min", 
            client.getClientId(),
            client.getClientName(),
            client.getScopes(),
            client.getTokenSettings().getAccessTokenTimeToLive().toMinutes()
        );
    }
    
    /**
     * Record to hold client configuration data
     */
    private record ClientConfiguration(
        String clientId,
        String clientSecret,
        String displayName,
        List<String> scopes,
        Duration tokenTtl
    ) {}
}