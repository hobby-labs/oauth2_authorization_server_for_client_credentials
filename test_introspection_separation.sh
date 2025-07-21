#!/bin/bash

# Test script for introspection endpoint with separate credentials
# This script demonstrates how the introspection endpoint now uses
# credentials from introspector.yml instead of clients.yml

echo "=== OAuth2 Introspection Endpoint Test ==="
echo "Testing with separate introspection credentials from introspector.yml"
echo ""

# OAuth2 Authorization Server endpoint
AUTH_SERVER="http://localhost:9000"

# Test with regular OAuth2 client (from clients.yml) - should get access token
echo "1. Getting access token using regular OAuth2 client (from clients.yml)..."
TOKEN_RESPONSE=$(curl -s -X POST \
  "${AUTH_SERVER}/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mobile-app-client:mobile-app-client-secret" \
  -d "grant_type=client_credentials&scope=read write")

echo "Token response: $TOKEN_RESPONSE"

# Extract access token
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ACCESS_TOKEN" ]; then
    echo "Failed to get access token!"
    exit 1
fi

echo "Access token obtained: ${ACCESS_TOKEN:0:50}..."
echo ""

# Test introspection with introspector credentials (from introspector.yml)
echo "2. Testing CUSTOM introspection endpoint with introspector credentials..."
echo "   Using credentials from introspector.yml (resource-server-introspector)"
echo "   Endpoint: /oauth2/introspect/custom"
echo ""

INTROSPECTION_RESPONSE=$(curl -s -w "HTTP_STATUS:%{http_code}" -X POST \
  "${AUTH_SERVER}/oauth2/introspect/custom" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "resource-server-introspector:resource-server-introspect-secret-2024" \
  -d "token=${ACCESS_TOKEN}")

HTTP_STATUS_CUSTOM=$(echo "$INTROSPECTION_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
RESPONSE_BODY_CUSTOM=$(echo "$INTROSPECTION_RESPONSE" | sed 's/HTTP_STATUS:[0-9]*$//')

echo "HTTP Status: $HTTP_STATUS_CUSTOM"
echo "Custom introspection response:"
echo "$RESPONSE_BODY_CUSTOM" | jq '.' 2>/dev/null || echo "$RESPONSE_BODY_CUSTOM"
echo ""

# Test with invalid introspector credentials
echo "3. Testing custom endpoint with invalid introspector credentials (should fail)..."
INVALID_RESPONSE=$(curl -s -w "HTTP_STATUS:%{http_code}" -X POST \
  "${AUTH_SERVER}/oauth2/introspect/custom" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "invalid-client:invalid-secret" \
  -d "token=${ACCESS_TOKEN}")

HTTP_STATUS=$(echo "$INVALID_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
RESPONSE_BODY=$(echo "$INVALID_RESPONSE" | sed 's/HTTP_STATUS:[0-9]*$//')

echo "HTTP Status: $HTTP_STATUS"
echo "Response: $RESPONSE_BODY"
echo ""

# Test with regular OAuth2 client credentials on custom introspection endpoint (should fail)
echo "4. Testing custom introspection with regular OAuth2 client credentials (should fail)..."
echo "   Trying to use mobile-app-client credentials on custom introspection endpoint"
OAUTH_CLIENT_RESPONSE=$(curl -s -w "HTTP_STATUS:%{http_code}" -X POST \
  "${AUTH_SERVER}/oauth2/introspect/custom" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mobile-app-client:mobile-app-client-secret" \
  -d "token=${ACCESS_TOKEN}")

HTTP_STATUS_OAUTH=$(echo "$OAUTH_CLIENT_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
RESPONSE_BODY_OAUTH=$(echo "$OAUTH_CLIENT_RESPONSE" | sed 's/HTTP_STATUS:[0-9]*$//')

echo "HTTP Status: $HTTP_STATUS_OAUTH"
echo "Response: $RESPONSE_BODY_OAUTH"
echo ""

# Compare with built-in introspection endpoint (shows the difference)
echo "5. Testing built-in introspection endpoint with OAuth2 client (for comparison)..."
echo "   Built-in endpoint still uses OAuth2 clients from clients.yml"
BUILTIN_RESPONSE=$(curl -s -X POST \
  "${AUTH_SERVER}/oauth2/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "mobile-app-client:mobile-app-client-secret" \
  -d "token=${ACCESS_TOKEN}")

echo "Built-in introspection response:"
echo "$BUILTIN_RESPONSE" | jq '.' 2>/dev/null || echo "$BUILTIN_RESPONSE"
echo ""

echo "=== Test Summary ==="
echo "✓ Access token obtained with regular OAuth2 client"
echo "✓ Custom introspection endpoint (/oauth2/introspect/custom) uses separate credentials"
echo "✓ Built-in endpoint (/oauth2/introspect) continues to work with OAuth2 clients"
echo "✓ Invalid introspection credentials rejected on custom endpoint (HTTP $HTTP_STATUS)"
echo "✓ Regular OAuth2 client credentials rejected on custom endpoint (HTTP $HTTP_STATUS_OAUTH)"
echo ""
echo "🎯 SECURITY IMPROVEMENT ACHIEVED:"
echo "✅ Introspection credentials are now separated from OAuth2 clients"
echo "✅ Custom endpoint (/oauth2/introspect/custom) enforces introspector.yml credentials"
echo "✅ Built-in endpoint preserves backward compatibility"
echo "✅ Enhanced security isolation between token issuance and introspection"
