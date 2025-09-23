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
* For testing purposes only
```
$ ./mvnw spring-boot:run
```

* Specify the location of files of properties and secrets
```
$ ./mvnw spring-boot:run -Dspring-boot.run.arguments="--spring.config.additional-location=file:/path/to/application.yml --keys.file.path=/path/to/keys.yml --clients.file.path=./external-clients.yml"
```

## Testing with curl

**Note: Role-Based Authorization is now enforced on OAuth2 endpoints:**
- `/oauth2/token` requires clients with "CLIENT" role
- `/oauth2/introspect` requires clients with "INTROSPECTOR" role

```
$ curl -v -u client:client-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token
* Host localhost:9000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:9000...
* Connected to localhost (::1) port 9000
* using HTTP/1.x
* Server auth using Basic with user 'client'
> POST /oauth2/token HTTP/1.1
> Host: localhost:9000
> Authorization: Basic Y2xpZW50OmNsaWVudC1zZWNyZXQ=
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
$ response_body="$(curl -u client:client-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token)"
$ jwt=$(jq -r '.access_token' < <(curl -u client:client-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token))
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
| Payload | {"sub":"client","aud":"client","ver":"1","nbf":1752539029,"scope":["read"],"iss":"http://localhost:9000","exp":1752539329,"iat":1752539029,"jti":"0e1c81a9-c588-4009-ae2f-ac558aef82ed"} |
| Signature | (Binary signature) |

## Testing with tool

```
$ ./test_request.sh
```

## Testing Role-Based Authorization

Test the role-based authorization for individual endpoints:

```bash
# Test only /oauth2/token endpoint authorization
$ ./test_role_authorization.sh

# Test both /oauth2/token and /oauth2/introspect endpoints
$ ./test_comprehensive_authorization.sh
```

The comprehensive test will verify:
- Clients with "CLIENT" role can access `/oauth2/token`
- Clients with "INTROSPECTOR" role can access `/oauth2/introspect`  
- Clients without required roles are properly denied access
- Invalid clients are rejected appropriately

# Endpoints

## Role-Based Authorization

This OAuth2 Authorization Server implements role-based access control for its endpoints. Client roles are defined in the `clients.yml` configuration file.

### Endpoint Access Requirements:

| Endpoint | Required Role | Description |
|----------|---------------|-------------|
| `/oauth2/token` | `CLIENT` | Obtain access tokens for client credentials flow |
| `/oauth2/introspect` | `INTROSPECTOR` | Introspect and validate access tokens |

### Current Client Configuration:

| Client Name | Client ID | Roles | Allowed Endpoints |
|-------------|-----------|-------|-------------------|
| Client Application | `client` | CLIENT | `/oauth2/token` |
| Introspector | `introspector` | INTROSPECTOR | `/oauth2/introspect` |
| Administrator | `administrator` | CLIENT, INTROSPECTOR | Both endpoints |

### Client Role Configuration Example:

```yaml
clients:
  mobile-app:
    client-id: "client"
    client-secret: "client-secret"
    client-name: "Client Application"
    scopes: ["read"]
    roles: ["CLIENT"]  # Can access /oauth2/token
    access-token-ttl: 15
    
  web-dashboard:
    client-id: "introspector" 
    client-secret: "introspector-secret"
    client-name: "Introspector"
    scopes: ["read"]
    roles: ["INTROSPECTOR"]  # Can only access /oauth2/introspect
    access-token-ttl: 30
    
  api-service:
    client-id: "administrator"
    client-secret: "administrator-secret"
    client-name: "Administrator"
    scopes: ["read", "write"]
    roles: ["CLIENT", "INTROSPECTOR"]  # Can access both endpoints
    access-token-ttl: 60
```

**Note:** Clients without the required role will receive HTTP 403 Forbidden responses with a descriptive error message.

## Get the access token

* /oauth2/token (Requires "CLIENT" role)
```
# Client with CLIENT role
$ curl -v -u client:client-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token

# Administrator with CLIENT role
$ curl -v -u administrator:administrator-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token

# This will fail with 403 (no CLIENT role)
$ curl -v -u introspector:introspector-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token
```

## Get the public key for verifying JWT signature

* /oauth2/jwks
```
$ curl http://localhost:9000/oauth2/jwks
```

## Introspect JWT tokens with introspection endpoint

* /oauth2/introspect (Requires "INTROSPECTOR" role)
```
# First, get a token with a client that has CLIENT role
$ JWT_TOKEN=$(curl -s -u client:client-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token | jq -r '.access_token')

# Introspect with a client that has INTROSPECTOR role
$ curl -v -X POST http://localhost:9000/oauth2/introspect \
    -u "introspector:introspector-secret" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=${JWT_TOKEN}&token_type_hint=access_token"

# Administrator can also introspect (has INTROSPECTOR role)
$ curl -v -X POST http://localhost:9000/oauth2/introspect \
    -u "administrator:administrator-secret" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=${JWT_TOKEN}&token_type_hint=access_token"

# This will fail with 403 (no INTROSPECTOR role)
$ curl -v -X POST http://localhost:9000/oauth2/introspect \
    -u "client:client-secret" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=${JWT_TOKEN}&token_type_hint=access_token"
```

* Q. Should introspection endpoint have authentication mechanisms like "-u introspector:introspector-secret"?
* A. Yes it should. In order to the section ["2.1.Introspection Request" in RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662#section-2.1) mentions below.

```
To prevent token scanning attacks, the endpoint MUST also require some form of authorization to access this endpoint, such as client authentication as described in OAuth 2.0 [RFC6749] or a separate OAuth 2.0 access token such as the bearer token described in OAuth2.0 Bearer Token Usage [RFC6750]. The methods of managing and validating these authentication credentials are out of scope of this specification.
```

**Note:** Our implementation adds an additional layer of role-based authorization. Only clients with the "INTROSPECTOR" role can access this endpoint, providing enhanced security beyond basic authentication.

# Keys to sign and verify JWT
## Generate public key pair with OpenSSL which algorithm is ES256

```
$ ./create_pki_infrastructures.sh
-> It will make CA certificates, intermediate CA certificates and end-entity certificates for testing.
   Do not use certificates and keys which already committed to the repository.
```

* [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
** [4.4 Client Credentials Grant - RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
** [4.4.2 Access Token Request - RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2)
** [4.4.3 Access Token Response - RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3)

* [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)

