package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Data Transfer Object representing an individual client configuration in the YAML file.
 * 
 * <p>This class provides type-safe access to individual client configuration properties,
 * eliminating the need for unchecked casts when parsing client data from YAML.</p>
 * 
 * <p>This DTO corresponds to the individual client entries within the clients section:</p>
 * <pre>{@code
 * client-id: "my-client-id"
 * client-secret: "my-client-secret"
 * client-name: "My Application"
 * scopes: ["read", "write"]
 * access-token-ttl: 60
 * roles: ["CLIENT", "INTROSPECTOR"]
 * }</pre>
 * 
 * @author TsutomuNakamura
 * @since 1.0
 */
public class ClientDto {
    
    /** The OAuth2 client identifier. */
    @JsonProperty("client-id")
    private String clientId;
    
    /** The OAuth2 client secret. */
    @JsonProperty("client-secret")
    private String clientSecret;
    
    /** The human-readable client name. */
    @JsonProperty("client-name")
    private String clientName;
    
    /** The list of OAuth2 scopes. */
    @JsonProperty("scopes")
    private List<String> scopes;
    
    /** The access token time-to-live in minutes. */
    @JsonProperty("access-token-ttl")
    private Integer accessTokenTtl;
    
    /** The list of roles assigned to this client. */
    @JsonProperty("roles")
    private List<String> roles;
    
    /**
     * Default constructor for Jackson deserialization.
     */
    public ClientDto() {
    }
    
    /**
     * Constructor with all fields.
     * 
     * @param clientId the client ID
     * @param clientSecret the client secret
     * @param clientName the client display name
     * @param scopes the list of scopes
     * @param accessTokenTtl the token TTL in minutes
     * @param roles the list of roles
     */
    public ClientDto(String clientId, String clientSecret, String clientName, 
                     List<String> scopes, Integer accessTokenTtl, List<String> roles) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.clientName = clientName;
        this.scopes = scopes;
        this.accessTokenTtl = accessTokenTtl;
        this.roles = roles;
    }
    
    public String getClientId() {
        return clientId;
    }
    
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }
    
    public String getClientSecret() {
        return clientSecret;
    }
    
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
    
    public String getClientName() {
        return clientName;
    }
    
    public void setClientName(String clientName) {
        this.clientName = clientName;
    }
    
    public List<String> getScopes() {
        return scopes;
    }
    
    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }
    
    public Integer getAccessTokenTtl() {
        return accessTokenTtl;
    }
    
    public void setAccessTokenTtl(Integer accessTokenTtl) {
        this.accessTokenTtl = accessTokenTtl;
    }
    
    public List<String> getRoles() {
        return roles;
    }
    
    public void setRoles(List<String> roles) {
        this.roles = roles;
    }
    
    @Override
    public String toString() {
        return "ClientDto{" +
                "clientId='" + clientId + '\'' +
                ", clientSecret='" + clientSecret + '\'' +
                ", clientName='" + clientName + '\'' +
                ", scopes=" + scopes +
                ", accessTokenTtl=" + accessTokenTtl +
                ", roles=" + roles +
                '}';
    }
}