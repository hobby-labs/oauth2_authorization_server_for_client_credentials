#!/bin/bash

echo "================================================"
echo "Testing Role-Based Authorization for OAuth2 Endpoints"
echo "================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base URL
BASE_URL="http://localhost:9000"

# Track test results
TOTAL_TESTS=0
PASSED_TESTS=0

# Function to test endpoint access
test_endpoint() {
    local endpoint=$1
    local client_id=$2
    local client_secret=$3
    local description=$4
    local expected_status=$5
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -n "Testing $description... "
    
    # Prepare the request based on endpoint
    if [ "$endpoint" = "/oauth2/token" ]; then
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -u "${client_id}:${client_secret}" \
            -d "grant_type=client_credentials&scope=read" \
            "${BASE_URL}${endpoint}")
    else
        # For introspect endpoint, we need a token
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -u "${client_id}:${client_secret}" \
            -d "token=dummy_token" \
            "${BASE_URL}${endpoint}")
    fi
    
    if [ "$response" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASSED${NC} (HTTP $response)"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED${NC} (Expected HTTP $expected_status, got HTTP $response)"
    fi
}

echo "================================================"
echo "Testing /oauth2/token endpoint (requires CLIENT role)"
echo "================================================"
echo ""

# Test clients with CLIENT role (should succeed)
test_endpoint "/oauth2/token" "client" "client-secret" \
    "Client Application (has CLIENT role)" "200"

test_endpoint "/oauth2/token" "administrator" "administrator-secret" \
    "Administrator (has CLIENT role)" "200"

# Test clients without CLIENT role (should be denied)
test_endpoint "/oauth2/token" "introspector" "introspector-secret" \
    "Introspector (no CLIENT role)" "403"

# Test invalid client
test_endpoint "/oauth2/token" "invalid" "invalid" \
    "Invalid client" "401"

echo ""
echo "================================================"
echo "Testing /oauth2/introspect endpoint (requires INTROSPECTOR role)"
echo "================================================"
echo ""

# Test clients with INTROSPECTOR role (should succeed)
test_endpoint "/oauth2/introspect" "introspector" "introspector-secret" \
    "Introspector (has INTROSPECTOR role)" "200"

test_endpoint "/oauth2/introspect" "administrator" "administrator-secret" \
    "Administrator (has INTROSPECTOR role)" "200"

# Test clients without INTROSPECTOR role (should be denied)
test_endpoint "/oauth2/introspect" "client" "client-secret" \
    "Client Application (no INTROSPECTOR role)" "403"

# Test invalid client
test_endpoint "/oauth2/introspect" "invalid" "invalid" \
    "Invalid client" "401"

echo ""
echo "================================================"
echo "Test Summary"
echo "================================================"
if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${GREEN}✓ All tests passed! ($PASSED_TESTS/$TOTAL_TESTS)${NC}"
else
    echo -e "${RED}✗ Some tests failed. Passed: $PASSED_TESTS/$TOTAL_TESTS${NC}"
fi
echo "================================================"