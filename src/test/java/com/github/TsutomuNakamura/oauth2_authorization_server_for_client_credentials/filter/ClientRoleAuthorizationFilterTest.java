package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.filter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.dto.ClientDto;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.service.ClientsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ClientRoleAuthorizationFilterTest {

    private ClientRoleAuthorizationFilter filter;
    
    @Mock
    private ClientsService mockClientsService;
    
    @Mock
    private HttpServletRequest mockRequest;
    
    @Mock
    private HttpServletResponse mockResponse;
    
    @Mock
    private FilterChain mockFilterChain;
    
    @BeforeEach
    void setUp() {
        filter = new ClientRoleAuthorizationFilter(mockClientsService);
    }

    // ========== doFilterInternal() Tests ==========
    
    @Test
    @DisplayName("doFilterInternal() should allow request when client has required CLIENT role for token endpoint")
    void doFilterInternal_WithClientRoleForTokenEndpoint_ShouldAllowRequest() throws Exception {
        // Given: A POST request to /oauth2/token with valid client credentials and CLIENT role
        String clientId = "test-client-id";
        String clientSecret = "test-client-secret";
        String clientName = "test-client";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        
        when(mockRequest.getRequestURI()).thenReturn("/oauth2/token");
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getHeader("Authorization")).thenReturn(authHeader);
        
        // Set up mock clients service to return client with CLIENT role
        Map<String, ClientDto> allClients = new HashMap<>();
        ClientDto clientDto = new ClientDto();
        clientDto.setClientId(clientId);
        clientDto.setRoles(List.of("CLIENT"));
        allClients.put(clientName, clientDto);
        
        when(mockClientsService.getAllClients()).thenReturn(allClients);
        when(mockClientsService.getClientId(clientName)).thenReturn(clientId);
        when(mockClientsService.getClientRoles(clientName)).thenReturn(List.of("CLIENT"));
        
        // When: Filter processes the request
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);
        
        // Then: Request should be allowed to proceed through filter chain
        verify(mockFilterChain, times(1)).doFilter(mockRequest, mockResponse);
        verify(mockResponse, never()).setStatus(anyInt());
    }

    @Test
    @DisplayName("doFilterInternal() should call filterChain.doFilter(request, response) then return when requiredRole is null")
    void doFilterInternal_WhenRequiredRoleIsNull_ShouldCallFilterChainAndReturn() throws Exception {
        // Given: A request to an unprotected endpoint
        when(mockRequest.getRequestURI()).thenReturn("/unprotected/endpoint");
        when(mockRequest.getMethod()).thenReturn("GET");
        
        // When: Filter processes the request
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);
        
        // Then: Request should be allowed to proceed through filter chain
        verify(mockFilterChain, times(1)).doFilter(mockRequest, mockResponse);
        verify(mockResponse, never()).setStatus(anyInt());
    }

    @Test
    @DisplayName("doFilterInternal() should continue filter chain when method is not POST")
    void doFilterInternal_WhenMethodIsNotPost_ShouldContinueFilterChain() throws Exception {
        // Given: A GET request to a protected endpoint
        when(mockRequest.getRequestURI()).thenReturn("/oauth2/token");
        when(mockRequest.getMethod()).thenReturn("GET");
        
        // When: Filter processes the request
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);
        
        // Then: Request should be allowed to proceed through filter chain
        verify(mockFilterChain, times(1)).doFilter(mockRequest, mockResponse);
        verify(mockResponse, never()).setStatus(anyInt());
    }
}
