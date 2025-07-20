#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

main() {
    local response_body

    cd "${SCRIPT_DIR}"

    response_body="$(curl -u my-client:my-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token 2> /dev/null)"

    if [ "${response_body}" == "" ]; then
        echo "Error: No response received from the server \"http://localhost:9000/oauth2/token\"."
        return 1
    fi
    assert_response "${response_body}" || return 1

    return 0
}

assert_response() {
    local response_body="$1"
    local jwt

    echo "# Result of Raw Response ###################################################"
    echo "${response_body}" | jq -r '.'

    jwt=$(jq -r '.access_token' <<< "${response_body}")

    assert_jwt "${jwt}" || return 1

    return 0
}

assert_jwt() {
    local jwt="$1"
    ./assert_jwt.sh "${jwt}" || return 1
}

main "$@"
