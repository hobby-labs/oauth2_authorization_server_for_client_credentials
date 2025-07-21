# oauth2_authorization_server_for_client_credentials

# Initialize project
```
curl https://start.spring.io/starter.zip \
  -d dependencies=web,security \
  -d type=maven-project \
  -d language=java \
  -d name=myproject \
  -d packageName=com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials \
  -d groupId=com.github.TsutomuNakamura \
  -d artifactId=myproject \
  -o myproject.zip
```

## Start the application
* For testing parposes only
```
$ ./mvnw spring-boot:run
```

* Specify the location of files of properties and secrets
```
$ ./mvnw spring-boot:run -Dspring-boot.run.arguments="--spring.config.additional-location=file:/path/to/application.yml --keys.file.path=/path/to/keys.yml --clients.file.path=./external-clients.yml"
```

## Testing with curl

```
$ curl -v -u mobile-app-client:mobile-app-client-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token
* Host localhost:9000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:9000...
* Connected to localhost (::1) port 9000
* using HTTP/1.x
* Server auth using Basic with user 'my-client'
> POST /oauth2/token HTTP/1.1
> Host: localhost:9000
> Authorization: Basic bXktY2xpZW50Om15LXNlY3JldA==
> User-Agent: curl/8.14.1
> Accept: */*
> Content-Length: 40
> Content-Type: application/x-www-form-urlencoded
>
* upload completely sent off: 40 bytes
< HTTP/1.1 200
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 0
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< Content-Type: application/json;charset=UTF-8
< Transfer-Encoding: chunked
< Date: Tue, 15 Jul 2025 00:23:49 GMT
<
* Connection #0 to host localhost left intact
{"access_token":"eyJ4NWMiOlsiTUlJQ2RUQ0NBaHVnQXdJQkFnSUpBT0V4YW1wbGUxLi4uIiwiTUlJQ2RUQ0NBaHVnQXdJQkFnSUpBT0V4YW1wbGUyLi4uIl0sImtpZCI6ImVjLWtleS0xZjY2YTJmMS0xODBiLTQxNzAtYTBkYy1hZDA4OTliMWM1ODIiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJteS1jbGllbnQiLCJhdWQiOiJteS1jbGllbnQiLCJ2ZXIiOiIxIiwibmJmIjoxNzUyNTM5MDI5LCJzY29wZSI6WyJyZWFkIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTc1MjUzOTMyOSwiaWF0IjoxNzUyNTM5MDI5LCJqdGkiOiIwZTFjODFhOS1jNTg4LTQwMDktYWUyZi1hYzU1OGFlZjgyZWQifQ.nXk4YfNE3_usGFnk31I1DPk6JL90BOem739llkuolT8FnNIT_m00dvQe402RqjNJ88H4dTlBkoqVsPQLR1E91A","scope":"read","token_type":"Bearer","expires_in":299}
```

```
$ response_body="$(curl -u mobile-app-client:mobile-app-client-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token)"
$ jwt=$(jq -r '.access_token' < <(curl -u mobile-app-client:mobile-app-client-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token))
$ jwt_header=$(echo -n ${jwt} | cut -d '.' -f 1 | base64 --decode)
$ jwt_payload=$(echo -n ${jwt} | cut -d '.' -f 2 | base64 --decode)
$ echo ${jwt_header} | jq
$ echo ${jwt_payload} | jq
```

Separate JWT.

| Key | Value |
| ---- | ---- |
| Header | eyJ4NWMiOlsiTUlJQ2RUQ0NBaHVnQXdJQkFnSUpBT0V4YW1wbGUxLi4uIiwiTUlJQ2RUQ0NBaHVnQXdJQkFnSUpBT0V4YW1wbGUyLi4uIl0sImtpZCI6ImVjLWtleS0xZjY2YTJmMS0xODBiLTQxNzAtYTBkYy1hZDA4OTliMWM1ODIiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9 |
| Payload | eyJzdWIiOiJteS1jbGllbnQiLCJhdWQiOiJteS1jbGllbnQiLCJ2ZXIiOiIxIiwibmJmIjoxNzUyNTM5MDI5LCJzY29wZSI6WyJyZWFkIl0sImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMCIsImV4cCI6MTc1MjUzOTMyOSwiaWF0IjoxNzUyNTM5MDI5LCJqdGkiOiIwZTFjODFhOS1jNTg4LTQwMDktYWUyZi1hYzU1OGFlZjgyZWQifQ |
| Signature | nXk4YfNE3_usGFnk31I1DPk6JL90BOem739llkuolT8FnNIT_m00dvQe402RqjNJ88H4dTlBkoqVsPQLR1E91A |


Decoded JWT.

| Key | Value |
| ---- | ---- |
| Header | {"x5c":["MIICdTCCAhugAwIBAgIJAOExample1...","MIICdTCCAhugAwIBAgIJAOExample2..."],"kid":"ec-key-1f66a2f1-180b-4170-a0dc-ad0899b1c582","typ":"JWT","alg":"ES256"} |
| Payload | {"sub":"my-client","aud":"my-client","ver":"1","nbf":1752539029,"scope":["read"],"iss":"http://localhost:9000","exp":1752539329,"iat":1752539029,"jti":"0e1c81a9-c588-4009-ae2f-ac558aef82ed"} |
| Signature | (Binary signature) |

## Testing with tool

```
$ ./test_request.sh
```

## Getting public keys for JWT verification

```
$ curl http://localhost:9000/oauth2/jwks | jq .
```

## Generate public key pair with OpenSSL which algorithm is ES256

```
$ resource_dir="./src/main/resources/keys"
$ mkdir -p "${resource_dir}"

$ # Generate a raw EC private key
$ openssl ecparam -genkey -name prime256v1 -noout -out ${resource_dir}/ec-private-key-raw_never-use-in-production.pem

$ # Convert the private key to PKCS#8 format
$ openssl pkcs8 -topk8 -nocrypt -in ${resource_dir}/ec-private-key-raw_never-use-in-production.pem -out ${resource_dir}/ec-private-key_never-use-in-production.pem

$ # Generate the public key from the private key
$ openssl ec -in ${resource_dir}/ec-private-key_never-use-in-production.pem -pubout -out ${resource_dir}/ec-public-key_never-use-in-production.pem
```

```

* [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
** [4.4 Client Credentials Grant - RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
** [4.4.2 Access Token Request - RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2)
** [4.4.3 Access Token Response - RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3)

* [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)

