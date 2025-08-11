# Logging Configuration Guide

This application supports flexible logging configuration through the `logappender` parameter in `application.yml`.

## Configuration Options

### Console Logging (Development)
```yaml
logappender: console
```
- Logs are displayed in the console/terminal
- Useful for development and debugging
- Real-time log viewing

### File Logging (Production)
```yaml
logappender: file
```
- Logs are written to `logs/oauth2-server.log`
- File rotation enabled (10MB max size, 30 days retention, 1GB total cap)
- Useful for production environments
- Persistent log storage

## How It Works

1. The `logappender` property in `application.yml` sets the active Spring profile
2. Logback configuration (`logback-spring.xml`) uses Spring profiles to conditionally configure appenders:
   - `console` profile: activates console appender
   - `file` profile: activates file appender
3. All other logging configurations (levels, patterns, etc.) remain in the Logback XML file

## Usage Examples

### Switch to Console Logging
Edit `application.yml`:
```yaml
logappender: console
```
Restart the application to see logs in console.

### Switch to File Logging  
Edit `application.yml`:
```yaml
logappender: file
```
Restart the application. Logs will be written to `logs/oauth2-server.log`.

### View File Logs
```bash
# View latest log entries
tail -f logs/oauth2-server.log

# View last 50 lines
tail -50 logs/oauth2-server.log

# Search logs
grep "ERROR" logs/oauth2-server.log
```

## File Rotation Settings

When using file logging:
- **Max file size**: 10MB
- **Max history**: 30 days  
- **Total size cap**: 1GB
- **Compression**: Old files are gzipped
- **Pattern**: `logs/oauth2-server.YYYY-MM-DD.i.log.gz`

## Log Levels

Current log levels are configured in `logback-spring.xml`:
- Application classes: INFO
- Spring Security OAuth2: INFO
- Spring Web: WARN
- Apache Catalina: WARN
- Hibernate: WARN

## Benefits

1. **Easy switching**: Change one property to switch output destination
2. **Environment-specific**: Use console for dev, file for production
3. **No code changes**: Pure configuration-based
4. **Centralized**: All other logging config stays in Logback XML
5. **Production-ready**: File rotation and compression included
