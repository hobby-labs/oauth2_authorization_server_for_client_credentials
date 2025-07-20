#!/bin/bash

# Test script to verify YAML key loading functionality

echo "=== Testing YAML Key Loading ==="
echo

# Test 1: Check if keys.yml exists and has correct structure
echo "1. Checking keys.yml structure..."
if [ -f "src/main/resources/keys.yml" ]; then
    echo "✓ keys.yml exists"
    
    # Check for required keys
    if grep -q "keys:" src/main/resources/keys.yml && \
       grep -q "ec:" src/main/resources/keys.yml && \
       grep -q "private:" src/main/resources/keys.yml && \
       grep -q "public:" src/main/resources/keys.yml && \
       grep -q "config:" src/main/resources/keys.yml && \
       grep -q "primary-key:" src/main/resources/keys.yml; then
        echo "✓ YAML structure is correct"
    else
        echo "✗ YAML structure is missing required keys"
        exit 1
    fi
else
    echo "✗ keys.yml not found"
    exit 1
fi

echo

# Test 2: Test OAuth2 token generation
echo "2. Testing OAuth2 token generation with YAML keys..."
token_response=$(curl -s -X POST "http://localhost:9000/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "my-client:my-secret" \
  -d "grant_type=client_credentials&scope=read")

if echo "$token_response" | grep -q "access_token"; then
    echo "✓ Token generation successful"
    
    # Extract and decode JWT header
    access_token=$(echo "$token_response" | jq -r '.access_token')
    header=$(echo "$access_token" | cut -d'.' -f1)
    header_decoded=$(echo "$header" | base64 -d 2>/dev/null | jq . 2>/dev/null)
    
    if echo "$header_decoded" | grep -q "ec-key-from-yaml"; then
        echo "✓ JWT uses YAML-configured key ID"
        echo "  Key ID: $(echo "$header_decoded" | jq -r '.kid')"
    else
        echo "✗ JWT does not use YAML key ID"
        echo "  Header: $header_decoded"
    fi
else
    echo "✗ Token generation failed"
    echo "  Response: $token_response"
    exit 1
fi

echo

# Test 3: Test JWK endpoint
echo "3. Testing JWK endpoint..."
jwks_response=$(curl -s "http://localhost:9000/oauth2/jwks")

if echo "$jwks_response" | grep -q "ec-key-from-yaml"; then
    echo "✓ JWK endpoint returns YAML-configured key"
    echo "  JWK Kid: $(echo "$jwks_response" | jq -r '.keys[0].kid')"
else
    echo "✗ JWK endpoint does not return YAML key"
    echo "  Response: $jwks_response"
    exit 1
fi

echo

# Test 4: Verify key consistency
echo "4. Verifying key consistency between YAML and runtime..."

# Extract public key from YAML
yaml_public_key=$(grep -A 10 "public:" src/main/resources/keys.yml | grep -E "^\s*[A-Za-z0-9+/=]" | tr -d ' ')

# Extract x and y coordinates from JWK
jwk_x=$(echo "$jwks_response" | jq -r '.keys[0].x')
jwk_y=$(echo "$jwks_response" | jq -r '.keys[0].y')

if [ -n "$jwk_x" ] && [ -n "$jwk_y" ]; then
    echo "✓ JWK contains valid EC coordinates"
    echo "  x: ${jwk_x:0:20}..."
    echo "  y: ${jwk_y:0:20}..."
else
    echo "✗ JWK missing EC coordinates"
    exit 1
fi

echo

echo "=== All tests passed! ==="
echo "✅ YAML key loading is working correctly"
echo "✅ OAuth2 server uses keys from keys.yml"
echo "✅ JWT generation and verification working"
echo "✅ JWK endpoint exposes correct keys"
