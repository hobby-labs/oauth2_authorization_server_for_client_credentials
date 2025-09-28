package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/**
 * Data Transfer Object representing the complete clients configuration YAML file.
 * 
 * <p>This class provides type-safe access to the clients configuration structure,
 * eliminating the need for unchecked casts when parsing YAML configuration files.</p>
 * 
 * <p>Expected YAML structure:</p>
 * <pre>{@code
 * clients:
 *   my-client:
 *     client-id: "my-client-id"
 *     client-secret: "my-client-secret"
 *     client-name: "My Application"
 *     scopes: ["read", "write"]
 *     access-token-ttl: 60
 *     roles: ["CLIENT", "INTROSPECTOR"]
 * }</pre>
 * 
 * @author TsutomuNakamura
 * @since 1.0
 */
public class ClientsConfiguration {
    
    /** Map of client names to their configurations. */
    @JsonProperty("clients")
    private Map<String, ClientDto> clients;
    
    /**
     * Default constructor for Jackson deserialization.
     */
    public ClientsConfiguration() {
    }
    
    /**
     * Constructor with clients map.
     * 
     * @param clients the map of client configurations
     */
    public ClientsConfiguration(Map<String, ClientDto> clients) {
        this.clients = clients;
    }
    
    /**
     * Gets the clients map.
     * 
     * @return the map of client names to their configurations
     */
    public Map<String, ClientDto> getClients() {
        return clients;
    }
    
    /**
     * Sets the clients map.
     * 
     * @param clients the map of client configurations
     */
    public void setClients(Map<String, ClientDto> clients) {
        this.clients = clients;
    }
    
    @Override
    public String toString() {
        return "ClientsConfiguration{" +
                "clients=" + clients +
                '}';
    }
}