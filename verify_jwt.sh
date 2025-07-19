#!/bin/bash

# JWT ES256 Signature Verification Script
# Usage: ./verify_jwt.sh [JWT_TOKEN]

if [ $# -eq 0 ]; then
    # Use your provided JWT as default
    JWT="eyJ4NWMiOlsiTUlJQ2RUQ0NBaHVnQXdJQkFnSUpBT0V4YW1wbGUxLi4uIiwiTUlJQ2RUQ0NBaHVnQXdJQkFnSUpBT0V4YW1wbGUyLi4uIl0sImtpZCI6ImVjLWtleS1mcm9tLWZpbGUiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJteS1jbGllbnQiLCJhdWQiOiJteS1jbGllbnQiLCJ2ZXIiOiIxIiwibmJmIjoxNzUyOTM0NzYzLCJzY29wZSI6WyJyZWFkIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTc1MjkzNTA2MywiaWF0IjoxNzUyOTM0NzYzLCJjbGllbnRfbmFtZSI6ImIxNzM0ZmQ0LTM5ZmQtNGU4Yy1iNWQ0LTU0NDQ3OGNkNTcxNiIsImp0aSI6IjMzZDZlNmE5LTlkMmMtNDZiZS04MjIyLTU5Yjk0NGIwMzlkOSIsImNsaWVudF9pZCI6Im15LWNsaWVudCJ9.s24XP0O_7Dmq_cb3NaUqtIxketIQ3XFZFN0mkwJqHyyj9Eb_-NbfikBFR0ikecOc5USnRV9cV3VVi0FJGmsSqw"
else
    JWT="$1"
fi

PUBLIC_KEY="./src/main/resources/keys/ec-public-key_never-use-in-production.pem"

echo "=== JWT ES256 Signature Verification ==="
echo

# Check if public key exists
if [ ! -f "$PUBLIC_KEY" ]; then
    echo "❌ Error: Public key file not found: $PUBLIC_KEY"
    exit 1
fi

# Step 1: Split JWT into parts
IFS='.' read -r HEADER PAYLOAD SIGNATURE <<< "$JWT"

if [ -z "$SIGNATURE" ]; then
    echo "❌ Error: Invalid JWT format (missing signature)"
    exit 1
fi

echo "1. JWT Structure:"
echo "   Algorithm: ES256 (ECDSA with SHA-256)"
echo "   Header:    ${HEADER:0:50}..."
echo "   Payload:   ${PAYLOAD:0:50}..."
echo "   Signature: ${SIGNATURE:0:50}..."
echo

# Step 2: Prepare signing input (header.payload)
SIGNING_INPUT="${HEADER}.${PAYLOAD}"
echo "2. Signing input prepared (${#SIGNING_INPUT} characters)"

# Step 3: Create temporary files
echo -n "$SIGNING_INPUT" > "./signing_input"
echo -n "$SIGNING_INPUT" | base64 -d > "./signing_input.bin"

# Step 4: Decode URL-safe base64 signature
echo "3. Decoding signature..."

# Convert URL-safe base64 to standard base64
STANDARD_B64=$(echo "$SIGNATURE" | tr '_-' '/+')

# Add padding if needed
MOD=$((${#STANDARD_B64} % 4))
case $MOD in
    2) STANDARD_B64="${STANDARD_B64}==" ;;
    3) STANDARD_B64="${STANDARD_B64}=" ;;
esac

if [ $? -ne 0 ]; then
    echo "❌ Error: Failed to decode signature"
    exit 1
fi

SIG_SIZE=$(wc -c < "./signature.bin")
echo "   Signature decoded successfully ($SIG_SIZE bytes)"

# Step 5: Show public key info
echo
echo "4. Public Key Information:"
openssl ec -in "$PUBLIC_KEY" -pubin -text -noout 2>/dev/null | head -5
echo

# Step 6: Verify signature
echo "5. Verifying signature with OpenSSL..."

if openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "./signature.bin" "./signing_input" >/dev/null 2>&1; then
    echo "✅ SUCCESS: JWT signature is VALID!"
    echo "✅ The token was signed by the corresponding private key"
    echo "✅ The token integrity is verified - no tampering detected"
    RESULT=0
else
    echo "❌ FAILED: JWT signature is INVALID"
    echo "❌ Possible reasons:"
    echo "   - Token was not signed by the corresponding private key"
    echo "   - Token has been modified or corrupted"
    echo "   - Wrong public key being used"
    RESULT=1
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo
echo "=== Verification Complete ==="
exit $RESULT
