package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.factory.RegisteredClientFactory;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.model.ClientConfiguration;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.ClientsService;

/**
 * Configuration class for OAuth2 client repository management.
 * 
 * <p>This configuration is responsible for loading OAuth2 clients from external configuration
 * and registering them with Spring Security's OAuth2 authorization server. It follows the DRY
 * principle by delegating client creation to a dedicated factory and using shared configuration models.</p>
 * 
 * <h3>Key Responsibilities:</h3>
 * <ul>
 *   <li>Load client configurations from external YAML files via {@link ClientsService}</li>
 *   <li>Validate that at least one client is configured</li>
 *   <li>Transform client configurations into Spring Security RegisteredClient objects</li>
 *   <li>Handle registration errors based on configuration</li>
 *   <li>Provide comprehensive logging of the registration process</li>
 * </ul>
 * 
 * <h3>DRY Improvements:</h3>
 * <ul>
 *   <li><strong>Externalized Constants:</strong> Password encoder prefix moved to application.yml</li>
 *   <li><strong>Shared Model:</strong> Uses common ClientConfiguration model from model package</li>
 *   <li><strong>Factory Pattern:</strong> Delegates RegisteredClient creation to RegisteredClientFactory</li>
 *   <li><strong>Configurable Behavior:</strong> Error handling strategy externalized to configuration</li>
 * </ul>
 * 
 * <h3>Configuration Source:</h3>
 * <p>Client configurations are loaded from the file specified by the {@code clients.file.path}
 * property, defaulting to {@code classpath:clients.yml}.</p>
 * 
 * @author TsutomuNakamura
 * @since 0.0.1-SNAPSHOT
 * @see ClientsService
 * @see RegisteredClientFactory
 * @see ClientConfiguration
 */
@Configuration
public class ClientRepositoryConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(ClientRepositoryConfig.class);
    
    /**
     * Whether to fail fast when a client registration fails.
     * If true, application startup fails when any client cannot be registered.
     * If false, continues with other clients and logs errors.
     */
    @Value("${oauth2.client.fail-on-registration-error:false}")
    private boolean failOnRegistrationError;
    
    private final ClientsService clientsService;
    private final RegisteredClientFactory clientFactory;
    
    /**
     * Constructs the ClientRepositoryConfig with required dependencies.
     * 
     * @param clientsService the service for accessing client configurations from YAML
     * @param clientFactory the factory for creating RegisteredClient instances
     */
    public ClientRepositoryConfig(ClientsService clientsService, RegisteredClientFactory clientFactory) {
        this.clientsService = clientsService;
        this.clientFactory = clientFactory;
    }
    
    /**
     * Creates and configures the OAuth2 client repository.
     * 
     * <p>This bean is the central registry for all OAuth2 clients in the authorization server.
     * It loads client configurations from the external YAML file and transforms them into
     * Spring Security's RegisteredClient format using the client factory.</p>
     * 
     * <h4>Registration Process:</h4>
     * <ol>
     *   <li>Load all client configurations from YAML via ClientsService</li>
     *   <li>Validate that at least one client is configured</li>
     *   <li>Transform each client configuration into a RegisteredClient via factory</li>
     *   <li>Store all clients in an in-memory repository</li>
     * </ol>
     * 
     * <h4>Error Handling:</h4>
     * <ul>
     *   <li>If no clients are configured: Fails with IllegalStateException</li>
     *   <li>If a client registration fails: Behavior depends on fail-on-registration-error property</li>
     * </ul>
     * 
     * @return a RegisteredClientRepository containing all configured OAuth2 clients
     * @throws IllegalStateException if no clients are configured or if fail-on-registration-error
     *         is true and any client registration fails
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        logger.info("Initializing OAuth2 client repository...");
        
        Map<String, ClientDto> allClients = clientsService.getAllClients();
        validateClientsConfiguration(allClients);
        
        List<RegisteredClient> clients = buildRegisteredClients(allClients);
        validateRegisteredClients(clients, allClients.size());
        
        logger.info("Successfully registered {} OAuth2 client(s)", clients.size());
        return new InMemoryRegisteredClientRepository(clients);
    }
    
    /**
     * Validates that at least one client is configured.
     * 
     * @param allClients the map of all client configurations
     * @throws IllegalStateException if no clients are configured
     */
    private void validateClientsConfiguration(Map<String, ClientDto> allClients) {
        if (allClients.isEmpty()) {
            String errorMessage = "No OAuth2 clients configured in clients.yml. " +
                "Application requires at least one client to be defined in the configuration file.";
            
            logger.error("ERROR: No clients found in configuration file!");
            logger.error("Please ensure clients.yml contains proper client entries.");
            logger.error("Application startup will be aborted.");
            
            throw new IllegalStateException(errorMessage);
        }
    }
    
    /**
     * Builds RegisteredClient instances from client configurations.
     * 
     * @param allClients the map of all client configurations
     * @return a list of successfully registered clients
     */
    private List<RegisteredClient> buildRegisteredClients(Map<String, ClientDto> allClients) {
        List<RegisteredClient> clients = new ArrayList<>();
        
        for (String clientName : allClients.keySet()) {
            try {
                ClientConfiguration config = clientsService.getClientConfiguration(clientName);
                RegisteredClient client = clientFactory.createRegisteredClient(config);
                clients.add(client);
                logClientRegistration(clientName, client);
            } catch (Exception e) {
                handleRegistrationError(clientName, e);
            }
        }
        
        return clients;
    }
    
    /**
     * Validates that registered clients meet minimum requirements.
     * 
     * @param clients the list of registered clients
     * @param expectedCount the expected number of clients
     * @throws IllegalStateException if validation fails
     */
    private void validateRegisteredClients(List<RegisteredClient> clients, int expectedCount) {
        if (clients.isEmpty() && expectedCount > 0) {
            throw new IllegalStateException("No clients could be successfully registered");
        }
        
        if (clients.size() < expectedCount) {
            logger.warn("Only {} out of {} clients were successfully registered", 
                clients.size(), expectedCount);
        }
    }
    
    /**
     * Handles errors during client registration.
     * 
     * @param clientName the name of the client that failed to register
     * @param error the error that occurred
     * @throws IllegalStateException if fail-on-registration-error is true
     */
    private void handleRegistrationError(String clientName, Exception error) {
        String errorMessage = "Failed to register client '" + clientName + "': " + error.getMessage();
        
        if (failOnRegistrationError) {
            logger.error(errorMessage);
            throw new IllegalStateException(errorMessage, error);
        } else {
            logger.warn(errorMessage + " (continuing with other clients)");
        }
    }
    
    /**
     * Logs successful client registration with key details.
     * 
     * @param clientName the name of the client that was registered
     * @param client the registered client
     */
    private void logClientRegistration(String clientName, RegisteredClient client) {
        logger.info("Registered client '{}' ({}) with scopes: {}, TTL: {}min", 
            client.getClientId(),
            client.getClientName(),
            client.getScopes(),
            client.getTokenSettings().getAccessTokenTimeToLive().toMinutes()
        );
    }
}