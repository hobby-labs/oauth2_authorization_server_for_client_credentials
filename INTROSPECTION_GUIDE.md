# OAuth2 Token Introspection Endpoint

## Overview

This OAuth2 Authorization Server now implements the **Token Introspection Endpoint** according to [RFC 7662](https://tools.ietf.org/html/rfc7662). This endpoint allows resource servers and authorized clients to obtain metadata about access tokens.

## Endpoint Details

### 🔍 Introspection Endpoint
- **URL**: `POST /oauth2/introspect`
- **Authentication**: HTTP Basic Authentication (client credentials)
- **Content-Type**: `application/x-www-form-urlencoded`

### ❤️ Health Check Endpoint
- **URL**: `POST /oauth2/introspect/health`
- **Authentication**: None required
- **Purpose**: Verify introspection service status

## Usage Examples

### 1. Basic Token Introspection

```bash
curl -X POST http://localhost:9000/oauth2/introspect \
  -u "mobile-app-client:mobile-app-client-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJhbGciOiJFUzI1NiIs...&token_type_hint=access_token"
```

### 2. Response Format

**Valid Token Response:**
```json
{
  "active": true,
  "client_id": "mobile-app-client",
  "username": "mobile-app-client",
  "scope": "read write profile",
  "token_type": "Bearer",
  "iat": 1642691400,
  "exp": 1642694400,
  "iss": "http://localhost:9000",
  "aud": ["mobile-app-client"],
  "client_name": "Mobile Application",
  "ver": "1",
  "revoked": false
}
```

**Invalid Token Response:**
```json
{
  "active": false
}
```

## Authentication Requirements

The introspection endpoint requires **HTTP Basic Authentication** using OAuth2 client credentials:

- **Username**: Client ID (e.g., `mobile-app-client`)
- **Password**: Client Secret (e.g., `mobile-app-client-secret`)

## Supported Features

### ✅ Implemented
- ✅ JWT token validation and parsing
- ✅ Token expiration checking
- ✅ Client authentication verification
- ✅ Standard RFC 7662 response format
- ✅ Cross-client introspection support
- ✅ Error handling for invalid tokens
- ✅ Health check endpoint

### 🔄 Future Enhancements
- 🔄 Token revocation status (currently always `false`)
- 🔄 Token usage tracking
- 🔄 Rate limiting
- 🔄 Audit logging

## Integration with Resource Servers

Resource servers can use this endpoint to validate tokens in two ways:

### Option 1: JWT Validation (Recommended for Performance)
```java
// Validate JWT locally using JWKS endpoint
JwtDecoder jwtDecoder = NimbusJwtDecoder
    .withJwkSetUri("http://localhost:9000/oauth2/jwks")
    .build();

Jwt jwt = jwtDecoder.decode(token);
```

### Option 2: Introspection (Recommended for Security)
```java
// Call introspection endpoint for centralized validation
RestTemplate restTemplate = new RestTemplate();
// ... implement introspection call
```

## Testing

Use the provided test script to verify functionality:

```bash
./test_introspection.sh
```

This script tests:
1. Health check endpoint
2. Token acquisition
3. Authenticated introspection
4. Unauthenticated introspection (should fail)
5. Invalid token handling
6. Cross-client introspection

## Security Considerations

1. **HTTPS Required**: In production, always use HTTPS
2. **Client Authentication**: Only authenticated clients can introspect tokens
3. **Token Privacy**: Introspection responses contain sensitive information
4. **Rate Limiting**: Consider implementing rate limiting for production use

## Architecture Benefits

With introspection endpoint, your OAuth2 server now supports:

- 🔄 **Hybrid Validation**: Resource servers can choose between local JWT validation or centralized introspection
- 🔒 **Enhanced Security**: Real-time token status checking
- 📊 **Compliance**: RFC 7662 compliant implementation
- 🎯 **Flexibility**: Supports different resource server architectures
