#!/usr/bin/env bash

main() {
    local response_body jwt jwt_header jwt_payload
    response_body="$(curl -u my-client:my-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token 2> /dev/null)"

    if [ "${response_body}" == "" ]; then
        echo "Error: No response received from the server http://localhost:9000/oauth2/token."
        return 1
    fi

    jwt=$(jq -r '.access_token' < <(curl -u my-client:my-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token))

    IFS='.' read -r jwt_header jwt_payload jwt_signature <<< "$jwt"
    jwt_header=$(echo -n "${jwt_header}" | base64 --decode)
    jwt_payload=$(echo -n "${jwt_payload}" | base64 --decode)
    #jwt_header=$(echo -n ${jwt} | cut -d '.' -f 1 | base64 --decode)
    #jwt_payload=$(echo -n ${jwt} | cut -d '.' -f 2 | base64 --decode)
    #jwt_signature=$(echo -n ${jwt} | cut -d '.' -f 3)
    echo "# Result of Raw Response ###################################################"
    echo "${response_body}" | jq -r '.'

    echo "# Result of Header in JWT (decoded from base64) ############################"
    echo "${jwt_header}" | jq -r '.'

    echo "# Result of Payload in JWT (base64) ########################################"
    echo "${jwt_signature}"

    return 0
}

main "$@"
