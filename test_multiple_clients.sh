#!/bin/bash

echo "=== Testing Multiple OAuth2 Clients ==="
echo

# Test each client configuration
declare -A clients=(
    ["mobile-app-client"]="mobile-app-secret-2025"
    ["web-dashboard-client"]="dashboard-secret-secure-2025"
    ["api-service-client"]="api-service-secret-key-2025"
    ["analytics-client"]="analytics-secret-2025"
)

# OAuth2 Token Endpoint
TOKEN_ENDPOINT="http://localhost:9000/oauth2/token"

echo "Token endpoint: $TOKEN_ENDPOINT"
echo

for client_id in "${!clients[@]}"; do
    client_secret="${clients[$client_id]}"
    
    echo "🔑 Testing client: $client_id"
    echo "   Secret: $client_secret"
    
    # Request access token using client credentials grant
    response=$(curl -s -X POST "$TOKEN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -u "$client_id:$client_secret" \
        -d "grant_type=client_credentials")
    
    # Check if request was successful
    if echo "$response" | grep -q "access_token"; then
        echo "   ✅ SUCCESS: Got access token"
        
        # Extract and display token info
        access_token=$(echo "$response" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
        token_type=$(echo "$response" | grep -o '"token_type":"[^"]*"' | cut -d'"' -f4)
        expires_in=$(echo "$response" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)
        
        echo "   📋 Token Type: $token_type"
        echo "   ⏰ Expires in: ${expires_in}s ($(($expires_in / 60))min)"
        echo "   🎫 Token (first 50 chars): ${access_token:0:50}..."
        
        # Verify token by calling JWKS endpoint
        jwks_response=$(curl -s "http://localhost:9000/oauth2/jwks")
        if echo "$jwks_response" | grep -q "keys"; then
            echo "   🔐 JWKS endpoint accessible"
        else
            echo "   ❌ JWKS endpoint failed"
        fi
        
    else
        echo "   ❌ FAILED: $response"
    fi
    
    echo
done

echo "=== Test completed ==="
