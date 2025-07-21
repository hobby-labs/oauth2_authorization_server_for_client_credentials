#!/bin/bash

echo "=== Testing OAuth2 Token Introspection Endpoint ==="
echo

# OAuth2 Token and Introspection Endpoints
TOKEN_ENDPOINT="http://localhost:9000/oauth2/token"
INTROSPECT_ENDPOINT="http://localhost:9000/oauth2/introspect"
HEALTH_ENDPOINT="http://localhost:9000/oauth2/introspect/health"

echo "🔗 Token endpoint: $TOKEN_ENDPOINT"
echo "🔍 Introspection endpoint: $INTROSPECT_ENDPOINT"
echo "❤️  Health endpoint: $HEALTH_ENDPOINT"
echo

# Test 1: Health check
echo "=== Test 1: Introspection Health Check ==="
health_response=$(curl -s -X POST "$HEALTH_ENDPOINT")
if echo "$health_response" | grep -q "healthy"; then
    echo "✅ Health check passed"
    echo "   Response: $health_response"
else
    echo "❌ Health check failed: $health_response"
fi
echo

# Test client credentials
CLIENT_ID="mobile-app-client"
CLIENT_SECRET="mobile-app-client-secret"

echo "=== Test 2: Get Access Token ==="
echo "🔑 Using client: $CLIENT_ID"

# Get access token
token_response=$(curl -s -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "grant_type=client_credentials")

if echo "$token_response" | grep -q "access_token"; then
    echo "✅ Successfully obtained access token"
    
    # Extract access token
    access_token=$(echo "$token_response" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    token_type=$(echo "$token_response" | grep -o '"token_type":"[^"]*"' | cut -d'"' -f4)
    expires_in=$(echo "$token_response" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)
    
    echo "   📋 Token Type: $token_type"
    echo "   ⏰ Expires in: ${expires_in}s ($(($expires_in / 60))min)"
    echo "   🎫 Token (first 50 chars): ${access_token:0:50}..."
    echo
    
    # Test 3: Introspect the token without authentication (should fail)
    echo "=== Test 3: Introspection Without Authentication ==="
    introspect_response_unauth=$(curl -s -X POST "$INTROSPECT_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=$access_token&token_type_hint=access_token")
    
    if echo "$introspect_response_unauth" | grep -q '"active":false'; then
        echo "✅ Correctly rejected introspection without authentication"
        echo "   Response: $introspect_response_unauth"
    else
        echo "⚠️  Unexpected response: $introspect_response_unauth"
    fi
    echo
    
    # Test 4: Introspect the token with authentication
    echo "=== Test 4: Introspection With Authentication ==="
    introspect_response=$(curl -s -X POST "$INTROSPECT_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -u "$CLIENT_ID:$CLIENT_SECRET" \
        -d "token=$access_token&token_type_hint=access_token")
    
    if echo "$introspect_response" | grep -q '"active":true'; then
        echo "✅ Token introspection successful!"
        echo "📋 Full introspection response:"
        echo "$introspect_response" | python3 -m json.tool 2>/dev/null || echo "$introspect_response"
        
        # Extract key information
        client_id=$(echo "$introspect_response" | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4)
        scope=$(echo "$introspect_response" | grep -o '"scope":"[^"]*"' | cut -d'"' -f4)
        exp=$(echo "$introspect_response" | grep -o '"exp":[0-9]*' | cut -d':' -f2)
        
        echo
        echo "🔍 Key introspection details:"
        echo "   Client ID: $client_id"
        echo "   Scope: $scope"
        echo "   Expires at: $exp ($(date -d @$exp 2>/dev/null || echo 'N/A'))"
        
    else
        echo "❌ Token introspection failed: $introspect_response"
    fi
    echo
    
    # Test 5: Introspect an invalid token
    echo "=== Test 5: Introspection With Invalid Token ==="
    invalid_token="invalid.jwt.token"
    introspect_invalid=$(curl -s -X POST "$INTROSPECT_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -u "$CLIENT_ID:$CLIENT_SECRET" \
        -d "token=$invalid_token&token_type_hint=access_token")
    
    if echo "$introspect_invalid" | grep -q '"active":false'; then
        echo "✅ Correctly identified invalid token as inactive"
        echo "   Response: $introspect_invalid"
    else
        echo "❌ Unexpected response for invalid token: $introspect_invalid"
    fi
    echo
    
    # Test 6: Test with different client
    echo "=== Test 6: Cross-Client Token Introspection ==="
    OTHER_CLIENT_ID="api-service-client"
    OTHER_CLIENT_SECRET="api-service-client-secret"
    
    introspect_cross=$(curl -s -X POST "$INTROSPECT_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -u "$OTHER_CLIENT_ID:$OTHER_CLIENT_SECRET" \
        -d "token=$access_token&token_type_hint=access_token")
    
    if echo "$introspect_cross" | grep -q '"active":true'; then
        echo "✅ Cross-client introspection successful"
        echo "   Different client can introspect token from another client"
    else
        echo "❌ Cross-client introspection failed: $introspect_cross"
    fi
    
else
    echo "❌ Failed to get access token: $token_response"
fi

echo
echo "=== Introspection Test Completed ==="

# Show all available endpoints
echo
echo "📚 Available endpoints:"
echo "   POST /oauth2/token                   - Get access token"
echo "   GET  /oauth2/jwks                    - JWT public keys"
echo "   POST /oauth2/introspect              - Token introspection (RFC 7662)"
echo "   POST /oauth2/introspect/health       - Introspection service health"
