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

```
./mvnw spring-boot:run
```

```
curl -v -u my-client:my-secret -d "grant_type=client_credentials&scope=read" http://localhost:9000/oauth2/token
```

* [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
   4.2.1
   response_type
         REQUIRED.  Value MUST be set to "token".

https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2


* [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)

