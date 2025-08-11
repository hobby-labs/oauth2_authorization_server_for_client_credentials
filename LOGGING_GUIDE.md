# OAuth2 Authorization Server - Logging Configuration Guide

## Overview

This OAuth2 Authorization Server uses SLF4J with Logback for comprehensive logging. The logging system provides flexible console/file output switching through transparent property-based configuration.

## Key Features

- **SLF4J Integration**: All application logging uses SLF4J with parameterized messages for performance
- **Flexible Output**: Switch between console and file logging via simple property change
- **Transparent Configuration**: Direct property mapping without opaque Spring profile pollution
- **Production Ready**: File logging includes rotation, compression, and retention policies
- **Performance Optimized**: Parameterized logging prevents string concatenation when log level is disabled

## Configuration

### Basic Setup

Configure logging behavior in `application.yml`:

```yaml
logging:
  appender:
    target: console  # Options: console, file
  level:
    com:
      github:
        TsutomuNakamura:
          '[oauth2_authorization_server_for_client_credentials]': INFO
    org:
      springframework:
        security:
          oauth2: INFO
```

### Console Logging

Set `logging.appender.target: console` for development and debugging:

```yaml
logging:
  appender:
    target: console
```

**Characteristics:**
- Real-time log output to terminal
- Colored output for better readability
- Immediate feedback during development
- Pattern: `%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n`

### File Logging

Set `logging.appender.target: file` for production deployments:

```yaml
logging:
  appender:
    target: file
```

**Characteristics:**
- Logs written to `logs/oauth2-server.log`
- Automatic file rotation at 10MB
- Keeps 30 days of history
- Compressed archived files (.gz)
- Pattern: `%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n`

## Implementation Details

### SLF4J Logger Usage

The application uses parameterized logging for optimal performance:

```java
// Correct - parameterized logging
log.info("Registered client '{}' ({}) with scopes: {}, TTL: {}min", 
         clientId, displayName, scopes, ttlMinutes);

// Avoided - string concatenation
log.info("Registered client '" + clientId + "' with scopes: " + scopes);
```

### Logback Configuration

The `logback-spring.xml` uses Janino conditional expressions for transparent behavior:

```xml
<if condition='property("logging.appender.target").equals("console")'>
    <then>
        <appender-ref ref="CONSOLE"/>
    </then>
</if>
<if condition='property("logging.appender.target").equals("file")'>
    <then>
        <appender-ref ref="FILE"/>
    </then>
</if>
```

## Log Levels and Content

### Application Logs (INFO Level)

- OAuth2 client registration details
- JWT key loading and rotation status
- Security filter chain initialization
- Token introspection configuration
- Primary key and algorithm information

### Security Logs (INFO/DEBUG Level)

- OAuth2 authentication flows
- Security filter processing
- JWT token validation details

### Framework Logs (WARN Level)

- Spring Boot actuator warnings
- Apache Catalina container logs
- Hibernate ORM warnings

## Switching Between Modes

### Development Mode (Console Logging)

1. Edit `src/main/resources/application.yml`
2. Set `logging.appender.target: console`
3. Restart the application
4. View logs in terminal output

### Production Mode (File Logging)

1. Edit `src/main/resources/application.yml`
2. Set `logging.appender.target: file`
3. Restart the application
4. Monitor logs at `logs/oauth2-server.log`

## Dependencies

### Required Dependencies

The logging system requires these Maven dependencies:

```xml
<!-- SLF4J (included with Spring Boot) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-logging</artifactId>
</dependency>

<!-- Janino for Logback conditionals -->
<dependency>
    <groupId>org.codehaus.janino</groupId>
    <artifactId>janino</artifactId>
</dependency>
```

## Best Practices

### Performance Considerations

1. **Use Parameterized Logging**: Always use `{}` placeholders instead of string concatenation
2. **Appropriate Log Levels**: Use INFO for business logic, DEBUG for detailed flow, ERROR for exceptions
3. **Avoid Expensive Operations**: Don't call expensive methods in log statements at inappropriate levels

### Production Deployment

1. **Set File Logging**: Use `logging.appender.target: file` for production
2. **Monitor Disk Space**: File rotation prevents unbounded growth but monitor `logs/` directory
3. **Log Level Optimization**: Consider reducing verbose framework logging in production
4. **Security**: Ensure log files don't contain sensitive information

### Development Workflow

1. **Console for Development**: Use `logging.appender.target: console` during development
2. **Test Both Modes**: Verify both console and file logging work before deployment
3. **Log Message Quality**: Write clear, informative log messages with sufficient context

## Troubleshooting

### Common Issues

**Issue: No log output visible**
- Check `logging.appender.target` value in `application.yml`
- Verify log level settings allow the messages to appear
- Ensure Janino dependency is present for conditional processing

**Issue: File not being created**
- Verify `logs/` directory permissions
- Check if `logging.appender.target` is set to `"file"`
- Confirm application has write access to the working directory

**Issue: Poor performance**
- Avoid string concatenation in log statements
- Use parameterized logging with `{}` placeholders
- Check if DEBUG level is enabled inappropriately in production

### Verification Commands

```bash
# Check current log file
tail -f logs/oauth2-server.log

# Monitor file rotation
ls -la logs/

# Verify console output
./mvnw spring-boot:run | grep "AuthorizationServerConfig"
```

## Architecture Benefits

### Transparency
- No opaque Spring profile pollution
- Direct property-to-behavior mapping
- Clear configuration without hidden magic

### Maintainability
- Single property controls logging destination
- Consistent logging patterns across application
- Easy switching between development and production modes

### Performance
- Parameterized logging prevents unnecessary string operations
- Conditional appender selection avoids runtime overhead
- Efficient file rotation and compression

This logging system provides a robust, transparent, and maintainable solution for both development and production environments.
