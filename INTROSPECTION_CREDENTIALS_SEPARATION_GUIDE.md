# Introspection Credentials Separation Guide

## Overview

This guide explains the security enhancement implemented for the OAuth2 introspection endpoint (`/oauth2/introspect`). The credentials for introspection services have been separated from regular OAuth2 clients to improve security isolation and follow the principle of least privilege.

## Security Architecture

### Before (Single Credential Store)
```
clients.yml
├── mobile-app (OAuth2 client + introspection access)
├── web-dashboard (OAuth2 client + introspection access)
├── api-service (OAuth2 client + introspection access)
└── analytics-service (OAuth2 client + introspection access)
```

All OAuth2 clients could potentially access the introspection endpoint, which violates the principle of least privilege.

### After (Separated Credential Stores)
```
clients.yml                          introspector.yml
├── mobile-app (OAuth2 only)         ├── resource-server
├── web-dashboard (OAuth2 only)      ├── api-gateway
├── api-service (OAuth2 only)        ├── monitoring-service
└── analytics-service (OAuth2 only)  └── admin-dashboard
```

- **clients.yml**: Contains regular OAuth2 clients for token issuance
- **introspector.yml**: Contains dedicated credentials for introspection services only

## Configuration Files

### introspector.yml Structure
```yaml
introspectors:
  service-name:
    client-id: "unique-introspector-id"
    client-secret: "secure-introspector-secret"
    client-name: "Human Readable Name"
    description: "Purpose of this introspection service"
```

### Example introspector.yml
```yaml
introspectors:
  resource-server:
    client-id: "resource-server-introspector"
    client-secret: "resource-server-introspect-secret-2024"
    client-name: "Resource Server Introspection Service"
    description: "Service for validating tokens on behalf of resource servers"
    
  api-gateway:
    client-id: "api-gateway-introspector"
    client-secret: "api-gateway-introspect-secret-2024"
    client-name: "API Gateway Introspection Service"
    description: "Service for API gateway token validation"
```

## Security Benefits

1. **Credential Isolation**: Introspection credentials are completely separate from OAuth2 client credentials
2. **Principle of Least Privilege**: Only dedicated introspection services can access the introspection endpoint
3. **Audit Trail**: Clear separation makes it easier to audit introspection access
4. **Role-Based Security**: Introspection clients get `ROLE_INTROSPECTION_CLIENT` role specifically
5. **Reduced Attack Surface**: OAuth2 clients cannot accidentally access introspection endpoint

## Implementation Details

### Components Added

1. **IntrospectionCredentialsService**: Manages credentials from `introspector.yml`
2. **IntrospectionAuthenticationProvider**: Custom authentication provider for introspection endpoints
3. **Enhanced Security Filter Chain**: Separate security configuration for introspection endpoints

### Authentication Flow

1. Client sends introspection request with Basic Auth header
2. `IntrospectionAuthenticationProvider` validates credentials against `introspector.yml`
3. If valid, client gets `ROLE_INTROSPECTION_CLIENT` role
4. Security filter chain allows access to `/oauth2/introspect` endpoint
5. Introspection controller processes the request

### Endpoint Security

- `/oauth2/introspect`: Requires `ROLE_INTROSPECTION_CLIENT` role
- `/oauth2/introspect/health`: Publicly accessible for health checks

## Usage Examples

### Valid Introspection Request
```bash
curl -X POST http://localhost:9000/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "resource-server-introspector:resource-server-introspect-secret-2024" \
  -d "token=eyJhbGciOiJFUzI1NiJ9..."
```

### Invalid Request (OAuth2 client credentials)
```bash
# This will fail with 401 Unauthorized
curl -X POST http://localhost:9000/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mobile-app-client:mobile-app-client-secret" \
  -d "token=eyJhbGciOiJFUzI1NiJ9..."
```

## Testing

Use the provided test script to verify the separation:
```bash
./test_introspection_separation.sh
```

This script tests:
- Regular OAuth2 token issuance works with clients.yml
- Introspection works with introspector.yml credentials
- Regular OAuth2 clients are rejected on introspection endpoint
- Invalid introspection credentials are rejected
- Health endpoint remains publicly accessible

## Best Practices

1. **Unique Secrets**: Use different, strong secrets for introspection services
2. **Minimal Services**: Only create introspection credentials for services that actually need them
3. **Regular Rotation**: Rotate introspection credentials regularly
4. **Monitoring**: Monitor introspection endpoint access for security audit
5. **Naming Convention**: Use descriptive names that identify the purpose of each introspection service

## Migration Notes

This is a backward-compatible change. Existing OAuth2 clients continue to work for token issuance, but they will no longer have access to the introspection endpoint. Services that need introspection access should be migrated to use dedicated introspection credentials from `introspector.yml`.
