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

import java.io.PrintWriter;
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

    @Test
    @DisplayName("doFilterInternal() should send 403 response when client ID cannot be extracted")
    void doFilterInternal_WhenClientIdCannotBeExtracted_ShouldSendForbiddenResponse() throws Exception {
        // Given: A POST request to /oauth2/token without Authorization header
        when(mockRequest.getRequestURI()).thenReturn("/oauth2/token");
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getHeader("Authorization")).thenReturn(null);
        // Reponse writer mock setup. Mock writer for response
        PrintWriter mockWriter = mock(PrintWriter.class);
        when(mockResponse.getWriter()).thenReturn(mockWriter);
        
        // When: Filter processes the request
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);
        
        // Then: 403 Forbidden response should be sent
        verify(mockResponse, times(1)).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        verify(mockWriter, times(1)).write(contains("Client authentication required"));
    }

    @Test
    @DisplayName("doFilterInternal() should sent 403 response when client not found for given client ID")
    void doFilterInternal_WhenClientNotFound_ShouldSendForbiddenResponse() throws Exception {
        // Given: A POST request to /oauth2/token with invalid client credentials
        String clientId = "invalid-client-id";
        String clientSecret = "invalid-client-secret";

        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        
        when(mockRequest.getRequestURI()).thenReturn("/oauth2/token");
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getHeader("Authorization")).thenReturn(authHeader);
        // Set up mock clients service to return no clients
        when(mockClientsService.getAllClients()).thenReturn(new HashMap<>());
        // Reponse writer mock setup. Mock writer for response
        PrintWriter mockWriter = mock(PrintWriter.class);
        when(mockResponse.getWriter()).thenReturn(mockWriter);
        // When: Filter processes the request
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);
        // Then: 403 Forbidden response should be sent
        verify(mockResponse, times(1)).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        verify(mockWriter, times(1)).write(contains("Invalid client credentials"));
    }

    @Test
    @DisplayName("doFilterInternal() should send 403 response when client lacks required ADMIN role for admin endpoint")
    void doFilterInternal_WhenClientLacksRequiredRole_ShouldSendForbiddenResponse() throws Exception {
        // Given: A POST request to /oauth2/token with valid client credentials but missing ADMIN role
        String clientId = "introspector";
        String client = "Introspector";
        String clientSecret = "introspector-secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        
        when(mockRequest.getRequestURI()).thenReturn("/oauth2/token");
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getHeader("Authorization")).thenReturn(authHeader);
        // Set up mock clients service to return client without INTROSPECTOR role
        Map<String, ClientDto> allClients = new HashMap<>();
        ClientDto clientDto = new ClientDto();
        clientDto.setClientId(clientId);
        clientDto.setRoles(List.of("INTROSPECTOR")); // Missing INTROSPECTOR role
        allClients.put(client, clientDto);
        when(mockClientsService.getAllClients()).thenReturn(allClients);
        when(mockClientsService.getClientId(client)).thenReturn(clientId);
        when(mockClientsService.getClientRoles(client)).thenReturn(List.of("INTROSPECTOR"));
        // Reponse writer mock setup. Mock writer for response
        PrintWriter mockWriter = mock(PrintWriter.class);
        when(mockResponse.getWriter()).thenReturn(mockWriter);
        // When: Filter processes the request
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);
        // Then: 403 Forbidden response should be sent
        verify(mockResponse, times(1)).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        verify(mockWriter, times(1)).write(contains("{\"error\":\"access_denied\",\"error_description\":\"Insufficient privileges. CLIENT role required.\"}"));
    }

    @Test
    @DisplayName("doFilterInternal() should send 403 response when an exception occurs during processing")
    void doFilterInternal_WhenExceptionOccurs_ShouldSendForbiddenResponse() throws Exception {
        // Given: A POST request to /oauth2/token that causes an exception
        String clientId = "test-client-id";
        String clientSecret = "test-client-secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        
        when(mockRequest.getRequestURI()).thenReturn("/oauth2/token");
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getHeader("Authorization")).thenReturn(authHeader);
        // Set up mock clients service to throw exception
        when(mockClientsService.getAllClients()).thenThrow(new RuntimeException("Database error"));
        // Reponse writer mock setup. Mock writer for response
        PrintWriter mockWriter = mock(PrintWriter.class);
        when(mockResponse.getWriter()).thenReturn(mockWriter);
        // When: Filter processes the request
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);
        // Then: 403 Forbidden response should be sent
        verify(mockResponse, times(1)).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(mockFilterChain, never()).doFilter(mockRequest, mockResponse);
        verify(mockWriter, times(1)).write(contains("Authorization check failed"));
    }

    // ========== extractClientIdFromRequest() Tests ==========

    @Test
    @DisplayName("extractClientIdFromRequest() should return client ID from valid Basic Auth header")
    void extractClientIdFromRequest_WithValidBasicAuthHeader_ShouldReturnClientId() throws Exception {
        // Given: A request with valid Basic Auth header
        String clientId = "test-client-id";
        String clientSecret = "test-client-secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
        
        when(mockRequest.getHeader("Authorization")).thenReturn(authHeader);
        // When: Extracting client ID from request
        // Use reflection to access private method
        var method = ClientRoleAuthorizationFilter.class.getDeclaredMethod("extractClientIdFromRequest", HttpServletRequest.class);
        method.setAccessible(true);
        String result = (String) method.invoke(filter, mockRequest);
        // Then: The correct client ID should be returned
        assert result.equals(clientId);
    }

    @Test
    @DisplayName("extractClientIdFromRequest() should return client_id from request parameter when instructions in try block throws exception")
    void extractClientIdFromRequest_WhenExceptionInTryBlock_ShouldReturnClientIdFromParameter() throws Exception {
        // Given: A request with invalid Basic Auth header and client_id parameter
        String clientId = "param-client-id";
        String invalidAuthHeader = "Basic invalid-base64";
        
        when(mockRequest.getHeader("Authorization")).thenReturn(invalidAuthHeader);
        when(mockRequest.getParameter("client_id")).thenReturn(clientId);
        // When: Extracting client ID from request
        // Use reflection to access private method
        var method = ClientRoleAuthorizationFilter.class.getDeclaredMethod("extractClientIdFromRequest", HttpServletRequest.class);
        method.setAccessible(true);
        String result = (String) method.invoke(filter, mockRequest);
        // Then: The client_id parameter should be returned
        assert result.equals(clientId);
    }
}
