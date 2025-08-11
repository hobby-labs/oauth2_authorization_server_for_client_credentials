#!/usr/bin/env bash

# Certificate verification script for PKI infrastructure

set -e

BASE=pki
ROOT=${BASE}/root
INT=${BASE}/intermediate
EE=${BASE}/end-entities

echo "=== PKI Certificate Chain Verification ==="
echo

# Function to verify certificate chain
verify_chain() {
    local cert_name="$1"
    local intermediate_ca="$2"
    local ee_cert="$3"
    local int_cert="$4"
    local root_cert="$5"
    local ret
    
    echo "Verifying certificate chain for: ${cert_name}"
    echo "  End-entity: ${ee_cert}"
    echo "  Intermediate: ${int_cert}" 
    echo "  Root: ${root_cert}"
    echo
    
    # Method 1: Verify with full chain bundle
    set +e
    echo "Method 1: Using CA chain bundle"
    echo "Command: openssl verify -CAfile ${int_cert%/*}/ca-chain.cert.pem $ee_cert"
    openssl verify -CAfile "${int_cert%/*}/ca-chain.cert.pem" "$ee_cert" 2>/dev/null
    ret=$?
    if [ $ret -eq 0 ]; then
        echo "  ✅ VALID: Certificate verified with CA chain bundle"
    else
        echo "  ❌ INVALID: Certificate verification failed with CA chain bundle"
    fi
    echo
    
    # Method 2: Verify with separate root and intermediate
    echo "Method 2: Using separate root CA and intermediate CA"
    echo "Command: openssl verify -CAfile $root_cert -untrusted $int_cert $ee_cert"
    openssl verify -CAfile "$root_cert" -untrusted "$int_cert" "$ee_cert" 2>/dev/null
    ret=$?
    if [ $ret -eq 0 ]; then
        echo "  ✅ VALID: Certificate verified with separate CAs"
    else
        echo "  ❌ INVALID: Certificate verification failed with separate CAs"
    fi
    echo
    set -e
    
    # Show certificate details
    echo "Certificate Details:"
    echo "  Subject: $(openssl x509 -in "$ee_cert" -noout -subject 2>/dev/null || echo 'Failed to read')"
    echo "  Issuer:  $(openssl x509 -in "$ee_cert" -noout -issuer 2>/dev/null || echo 'Failed to read')"
    echo "  Serial:  $(openssl x509 -in "$ee_cert" -noout -serial 2>/dev/null || echo 'Failed to read')"
    echo "  Validity: $(openssl x509 -in "$ee_cert" -noout -dates 2>/dev/null | head -1 || echo 'Failed to read')"
    echo "  Key Usage: $(openssl x509 -in "$ee_cert" -noout -ext keyUsage,extendedKeyUsage 2>/dev/null | grep -E '(Key Usage|Extended Key Usage)' | tr '\n' ' ' || echo 'Failed to read')"
    echo
    echo "----------------------------------------"
    echo
}

# Function to show certificate chain structure
show_chain_structure() {
    local cert="$1"
    local depth="$2"
    local prefix="$3"
    
    if [[ ! -f "$cert" ]]; then
        echo "${prefix}❌ Certificate not found: $cert"
        return
    fi
    
    local subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/subject=//')
    local issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    
    echo "${prefix}📄 ${subject}"
    if [[ "$subject" != "$issuer" ]]; then
        echo "${prefix}   ↳ Issued by: ${issuer}"
    else
        echo "${prefix}   ↳ Self-signed (Root CA)"
    fi
}

echo "Certificate Chain Structure:"
echo "=============================="

# Check if PKI structure exists
if [[ ! -d "$BASE" ]]; then
    echo "❌ PKI directory not found. Run create_pki_infrastructures.sh first."
    exit 1
fi

# Show chain structures for each certificate type
for intermediate in trent pat; do
    echo
    echo "Intermediate CA: ${intermediate}"
    echo "----------------"
    
    root_ca="${ROOT}/ivan/certs/root-ca.cert.pem"
    int_ca="${INT}/${intermediate}/certs/intermediate-ca.cert.pem"
    
    if [[ -f "$root_ca" ]]; then
        show_chain_structure "$root_ca" 0 "  "
    fi
    if [[ -f "$int_ca" ]]; then
        show_chain_structure "$int_ca" 1 "    "
    fi
    
    # Check end-entity certificates under this intermediate
    for ee_dir in "${EE}"/*; do
        if [[ -d "$ee_dir" ]]; then
            ee_name=$(basename "$ee_dir")
            ee_cert="${ee_dir}/certs/${ee_name}.ee.example.com.cert.cert.pem"
            
            if [[ -f "$ee_cert" ]]; then
                show_chain_structure "$ee_cert" 2 "      "
                echo
                
                # Verify this certificate
                verify_chain "$ee_name" "$intermediate" "$ee_cert" "$int_ca" "$root_ca"
            fi
        fi
    done
done

echo "=== Verification Complete ==="
