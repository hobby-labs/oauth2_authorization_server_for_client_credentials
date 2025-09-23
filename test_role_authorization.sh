#!/bin/bash

echo "================================================"
echo "Testing /oauth2/token Role-Based Authorization"
echo "================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base URL
BASE_URL="http://localhost:9000/oauth2/token"

# Track test results
TOTAL_TESTS=0
PASSED_TESTS=0

# Function to test client access
test_client() {
    local client_id=$1
    local client_secret=$2
    local description=$3
    local expected_status=$4
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo -n "Testing $description... "
    
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${client_id}:${client_secret}" \
        -d "grant_type=client_credentials&scope=read" \
        "${BASE_URL}")
    
    if [ "$response" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASSED${NC} (HTTP $response)"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAILED${NC} (Expected HTTP $expected_status, got HTTP $response)"
    fi
}

# Test clients with CLIENT role (should succeed)
test_client "client" "client-secret" \
    "Client Application (has CLIENT role)" "200"

test_client "administrator" "administrator-secret" \
    "Administrator (has CLIENT role)" "200"

# Test clients without CLIENT role (should be denied)
test_client "introspector" "introspector-secret" \
    "Introspector (no CLIENT role)" "403"

# Test invalid client
test_client "invalid-client" "invalid-secret" \
    "Invalid client credentials" "401"

echo ""
echo "================================================"
echo "Test Summary"
echo "================================================"
if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${GREEN}✓ All tests passed! ($PASSED_TESTS/$TOTAL_TESTS)${NC}"
else
    echo -e "${RED}✗ Some tests failed. Passed: $PASSED_TESTS/$TOTAL_TESTS${NC}"
fi