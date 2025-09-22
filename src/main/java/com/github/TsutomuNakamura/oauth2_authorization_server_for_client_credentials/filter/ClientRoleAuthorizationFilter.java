package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.filter;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.ClientsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter to enforce role-based authorization for OAuth2 token endpoint.
 * 
 * <p>This filter checks if the client making a request to the /oauth2/token endpoint
 * has the required "CLIENT" role as defined in the clients.yml configuration.</p>
 * 
 * <p>The filter performs the following checks:</p>
 * <ul>
 * <li>Extracts client credentials from Authorization header (Basic Auth)</li>
 * <li>Looks up the client configuration to retrieve roles</li>
 * <li>Verifies that the client has the "CLIENT" role</li>
 * <li>Returns HTTP 403 Forbidden if the client lacks the required role</li>
 * </ul>
 */
@Component
public class ClientRoleAuthorizationFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(ClientRoleAuthorizationFilter.class);
    
    private static final String TOKEN_ENDPOINT_PATH = "/oauth2/token";
    private static final String REQUIRED_ROLE = "CLIENT";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BASIC_AUTH_PREFIX = "Basic ";
    
    private final ClientsService clientsService;
    private final ObjectMapper objectMapper;
    
    public ClientRoleAuthorizationFilter(ClientsService clientsService) {
        this.clientsService = clientsService;
        this.objectMapper = new ObjectMapper();
    }
    
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, 
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        String requestPath = request.getRequestURI();
        String method = request.getMethod();
        
        // Only apply this filter to POST requests to the token endpoint
        if (!"POST".equals(method) || !TOKEN_ENDPOINT_PATH.equals(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }
        
        logger.debug("Checking client role authorization for token endpoint access");
        
        try {
            // Extract client credentials from Authorization header
            String clientId = extractClientIdFromRequest(request);
            
            if (clientId == null) {
                logger.warn("Client ID could not be extracted from request");
                sendForbiddenResponse(response, "Client authentication required");
                return;
            }
            
            // Find client name by client ID
            String clientName = findClientNameByClientId(clientId);
            
            if (clientName == null) {
                logger.warn("Client not found for client ID: {}", clientId);
                sendForbiddenResponse(response, "Invalid client credentials");
                return;
            }
            
            // Check if client has the required role
            List<String> clientRoles = clientsService.getClientRoles(clientName);
            
            if (!clientRoles.contains(REQUIRED_ROLE)) {
                logger.warn("Client '{}' (ID: {}) does not have required role '{}'. Client roles: {}", 
                    clientName, clientId, REQUIRED_ROLE, clientRoles);
                sendForbiddenResponse(response, "Insufficient privileges. CLIENT role required.");
                return;
            }
            
            logger.info("Client '{}' (ID: {}) authorized for token endpoint access with role '{}'", 
                clientName, clientId, REQUIRED_ROLE);
            
            // Client is authorized, continue with the request
            filterChain.doFilter(request, response);
            
        } catch (Exception e) {
            logger.error("Error during client role authorization: {}", e.getMessage(), e);
            sendForbiddenResponse(response, "Authorization check failed");
        }
    }
    
    /**
     * Extracts the client ID from the request.
     * Supports both Basic Authentication header and form parameters.
     */
    private String extractClientIdFromRequest(HttpServletRequest request) {
        // Try Basic Authentication header first
        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader != null && authHeader.startsWith(BASIC_AUTH_PREFIX)) {
            try {
                String base64Credentials = authHeader.substring(BASIC_AUTH_PREFIX.length());
                String credentials = new String(Base64.getDecoder().decode(base64Credentials));
                String[] parts = credentials.split(":", 2);
                if (parts.length == 2) {
                    return parts[0]; // client_id is the first part
                }
            } catch (Exception e) {
                logger.debug("Failed to parse Basic Auth header: {}", e.getMessage());
            }
        }
        
        // Fallback to form parameter
        return request.getParameter("client_id");
    }
    
    /**
     * Finds the client name (configuration key) by client ID.
     */
    private String findClientNameByClientId(String clientId) {
        var allClients = clientsService.getAllClients();
        
        for (String clientName : allClients.keySet()) {
            String configuredClientId = clientsService.getClientId(clientName);
            if (clientId.equals(configuredClientId)) {
                return clientName;
            }
        }
        
        return null;
    }
    
    /**
     * Sends a HTTP 403 Forbidden response with JSON error details.
     */
    private void sendForbiddenResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        var errorResponse = new ErrorResponse("access_denied", message);
        String jsonResponse = objectMapper.writeValueAsString(errorResponse);
        
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }
    
    /**
     * Error response structure for OAuth2 errors
     */
    private static class ErrorResponse {
        private final String error;
        private final String error_description;
        
        public ErrorResponse(String error, String errorDescription) {
            this.error = error;
            this.error_description = errorDescription;
        }
        
        public String getError() {
            return error;
        }
        
        public String getError_description() {
            return error_description;
        }
    }
}