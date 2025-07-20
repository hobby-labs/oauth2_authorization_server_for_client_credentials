#!/usr/bin/env bash

# Color of font red
FONT_COLOR_GREEN='\033[0;32m'
# Color of font red
FONT_COLOR_RED='\033[0;31m'
# Color of font end
FONT_COLOR_END='\033[0m'

main() {
    local response_body
    response_body="$(curl -u my-client:my-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token 2> /dev/null)"

    if [ "${response_body}" == "" ]; then
        echo "Error: No response received from the server http://localhost:9000/oauth2/token."
        return 1
    fi
    assert_result "${response_body}" || return 1

    return 0
}

assert_result() {
    local response_body="$1"
    local jwt jwt_header_b64 jwt_payload_b64 jwt_header jwt_payload jwt_signature_b64_urlsafe jwt_signature_b64 ret

    jwt=$(jq -r '.access_token' <<< "${response_body}")

    IFS='.' read -r jwt_header_b64 jwt_payload_b64 jwt_signature_b64_urlsafe <<< "$jwt"
    jwt_header=$(echo -n "${jwt_header_b64}" | base64 --decode)
    jwt_payload=$(echo -n "${jwt_payload_b64}" | base64 --decode)
    jwt_signature_b64=$(echo -n "${jwt_signature_b64_urlsafe}" | tr '_-' '/+')
    remainder=$((${#jwt_signature_b64} % 4))
    if [ $remainder -eq 2 ]; then
        jwt_signature_b64="${jwt_signature_b64}=="
    elif [ $remainder -eq 3 ]; then
        jwt_signature_b64="${jwt_signature_b64}="
    fi

    echo "# Result of Raw Response ###################################################"
    echo "${response_body}" | jq -r '.'

    echo "# Result of Header in JWT (decoded from base64) ############################"
    echo "${jwt_header}" | jq -r '.'

    echo "# Result of Header in JWT (decoded from base64) ############################"
    echo "${jwt_payload}" | jq -r '.'

    echo "# Result of Payload in JWT (base64) ########################################"
    echo "${jwt_signature_b64}"
    echo

    echo "# Result Signature Verification ############################################"
    verify_signature "${jwt_header_b64}" "${jwt_payload_b64}" "${jwt_signature_b64}" "./src/main/resources/keys/ec-public-key_never-use-in-production.pem"
    ret=$?
    if [ $ret -eq 0 ]; then
        echo -e "[${FONT_COLOR_GREEN}OK${FONT_COLOR_END}] Signature verification succeeded."
    else
        echo -e "[${FONT_COLOR_RED}NG${FONT_COLOR_END}] Signature verification failed."
    fi
}

verify_signature() {
    local jwt_header_b64="$1"
    local jwt_payload_b64="$2"
    local jwt_signature="$3"
    local path_public_key="$4"
    local temp_dir ret


    temp_dir="$(mktemp -d)"
    
    local file_signing_input="${temp_dir}/signing_input.txt"
    local file_signature_p1363="${temp_dir}/signature_p1363.bin"
    local file_signature_der="${temp_dir}/signature_der.bin"

    echo -n "${jwt_header_b64}.${jwt_payload_b64}" > "${file_signing_input}"
    echo -n "${jwt_signature}" | base64 --decode > "${file_signature_p1363}"

    convert_p1363_to_der "${file_signature_p1363}" "${file_signature_der}" "${temp_dir}"

    openssl dgst -sha256 -verify "${path_public_key}" -signature "${file_signature_der}" "${file_signing_input}"
    ret=$?

    return $ret
}


# Function to convert P1363 to DER.
# Created by GitHub Copilot
convert_p1363_to_der() {
    local input_file="$1"
    local output_file="$2"
    local temp_dir="$3"

    local size=$(wc -c < "$input_file")
    if [ "$size" -ne 64 ]; then
        echo "Expected 64-byte P1363 signature, got $size bytes in file \"${input_file}\""
        return 1
    fi

    # Extract r and s (32 bytes each)
    dd if="$input_file" of="${temp_dir}/r.bin" bs=1 count=32 2>/dev/null
    dd if="$input_file" of="${temp_dir}/s.bin" bs=1 skip=32 count=32 2>/dev/null

    # Convert to hex, remove leading zeros, add back if MSB set
    local r_hex=$(xxd -p ${temp_dir}/r.bin | tr -d '\n' | sed 's/^0*//')
    local s_hex=$(xxd -p ${temp_dir}/s.bin | tr -d '\n' | sed 's/^0*//')

    # Ensure at least one hex digit
    [ -z "$r_hex" ] && r_hex="00"
    [ -z "$s_hex" ] && s_hex="00"

    # Add leading zero if MSB is set (to ensure positive integers)
    local r_first=$((16#${r_hex:0:2}))
    local s_first=$((16#${s_hex:0:2}))

    [ "$r_first" -ge 128 ] && r_hex="00$r_hex"
    [ "$s_first" -ge 128 ] && s_hex="00$s_hex"

    # Calculate lengths
    local r_len=$((${#r_hex} / 2))
    local s_len=$((${#s_hex} / 2))
    local total_len=$((r_len + s_len + 4)) # +4 for the two INTEGER headers

    # Build DER: 30 <total_len> 02 <r_len> <r_hex> 02 <s_len> <s_hex>
    printf "30%02x02%02x%s02%02x%s" "$total_len" "$r_len" "$r_hex" "$s_len" "$s_hex" | xxd -r -p > "$output_file"

    local output_size=$(wc -c < "$output_file")

    # Clean up
    rm -f ${temp_dir}/r.bin ${temp_dir}/s.bin

    return 0
}

main "$@"
