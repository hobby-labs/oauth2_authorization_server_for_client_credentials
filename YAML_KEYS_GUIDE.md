# YAML Key Configuration Guide

This guide explains how to use YAML configuration for managing cryptographic keys in the OAuth2 Authorization Server.

## Overview

The application loads EC (Elliptic Curve) keys exclusively from a YAML configuration file (`keys.yml`) located in `src/main/resources/`. This approach provides:

- **Centralized key management**: All keys in one file
- **Key rotation support**: Multiple keys with primary key selection
- **Environment-specific configurations**: Different keys for dev/test/prod
- **Clean architecture**: YAML-only approach without fallback complexity

## Configuration Structure

### Basic Structure (`src/main/resources/keys.yml`)

```yaml
keys:
  ec:
    # EC P-256 key pair for JWT signing (ES256)
    private: |
      -----BEGIN PRIVATE KEY-----
      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0B5vUIKpkExxCzK7
      T04vaa8CcA2EtzNtpx+MTiYAvAKhRANCAATmBYWiTLeavnUPScDRLpYS5ayut0dB
      O3R8Fg2GgvnfeAqsm/WMSrw6cN6hNzSAWqWBEXBLzZxX7lGpYY9Qn2GO
      -----END PRIVATE KEY-----
    public: |
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5gWFoky3mr51D0nA0S6WEuWsrrdH
      QTt0fBYNhoL533gKrJv1jEq8OnDeoTc0gFqlgRFwS82cV+5RqWGPUJ9hjg==
      -----END PUBLIC KEY-----
    keyId: "ec-key-from-yaml"
    algorithm: "ES256"
    curve: "P-256"

config:
  primary-key: "ec"  # Which key to use as primary
  key-rotation: false  # Enable/disable key rotation
```

### Multiple Keys for Key Rotation

```yaml
keys:
  ec-primary:
    private: |
      -----BEGIN PRIVATE KEY-----
      # Primary key content
      -----END PRIVATE KEY-----
    public: |
      -----BEGIN PUBLIC KEY-----
      # Primary key content
      -----END PUBLIC KEY-----
    keyId: "ec-primary-2025"
    algorithm: "ES256"
    curve: "P-256"
    
  ec-backup:
    private: |
      -----BEGIN PRIVATE KEY-----
      # Backup key content
      -----END PRIVATE KEY-----
    public: |
      -----BEGIN PUBLIC KEY-----
      # Backup key content
      -----END PUBLIC KEY-----
    keyId: "ec-backup-2024"
    algorithm: "ES256"
    curve: "P-256"

config:
  primary-key: "ec-primary"  # Active key for signing
  key-rotation: true         # Enable key rotation
```

## Implementation Details

### Architecture

1. **KeysService**: Loads and parses the YAML configuration
2. **AuthorizationServerConfig**: Uses KeysService to configure JWK source
3. **Fallback mechanism**: Falls back to PEM files if YAML loading fails

### Key Components

#### 1. KeysService (`src/main/java/.../service/KeysService.java`)
- Loads `keys.yml` using SnakeYAML
- Provides methods to access primary key configuration
- Handles key pair creation from PEM strings

#### 2. AuthorizationServerConfig (Modified)
- Injects KeysService
- Loads primary key configuration
- Creates JWK with proper key ID and metadata

### Dependencies Added

```xml
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
</dependency>
```

## Usage Instructions

### 1. Basic Setup

1. Create or modify `src/main/resources/keys.yml` with your key configuration
2. Set the `primary-key` in the `config` section
3. Start the application - it will automatically load keys from YAML

### 2. Generating New Keys

You can generate new EC P-256 keys using OpenSSL:

```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out private-key.pem

# Generate public key
openssl ec -in private-key.pem -pubout -out public-key.pem

# Convert to PKCS#8 format (required)
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private-key.pem -out private-key-pkcs8.pem
```

### 3. Key Rotation

To rotate keys:

1. Add a new key pair to the `keys` section in YAML
2. Update `primary-key` to point to the new key
3. Keep old keys for a transition period to verify existing JWTs
4. Remove old keys after transition period

### 4. Environment-Specific Keys

Create different YAML files for different environments:

```
src/main/resources/
├── keys.yml              # Default/development
├── keys-staging.yml      # Staging environment
└── keys-production.yml   # Production environment
```

Use Spring profiles to load different configurations:

```yaml
# application-production.yml
spring:
  config:
    import: classpath:keys-production.yml
```

## Verification

### 1. Application Logs
Check the application startup logs for:
```
Successfully loaded keys.yml configuration
Loading EC keys from YAML configuration...
EC key pair loaded successfully from YAML
JWK Source initialized with EC key loaded from YAML
Key ID: ec-key-from-yaml
```

### 2. JWK Endpoint
Check the JWK endpoint to verify key loading:
```bash
curl http://localhost:9000/oauth2/jwks | jq .
```

Expected response:
```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "ec-key-from-yaml",
      "key_ops": ["verify", "sign"],
      "x": "...",
      "y": "...",
      "alg": "ES256"
    }
  ]
}
```

### 3. JWT Token
Generate a token and verify the header contains the correct key ID:
```bash
curl -X POST "http://localhost:9000/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "my-client:my-secret" \
  -d "grant_type=client_credentials&scope=read" | jq .access_token | cut -d'.' -f1 | base64 -d | jq .
```

Expected header:
```json
{
  "kid": "ec-key-from-yaml",
  "typ": "JWT",
  "alg": "ES256"
}
```

### 4. Automated Testing
Run the provided test script:
```bash
./test_yaml_keys.sh
```

## Troubleshooting

### Common Issues

1. **YAML Parsing Errors**
   - Check YAML indentation (use spaces, not tabs)
   - Ensure PEM blocks are properly formatted with `|` block scalar
   - Verify all required fields are present

2. **Key Format Issues**
   - Ensure private keys are in PKCS#8 format
   - Public keys should be in X.509 SubjectPublicKeyInfo format
   - Use `openssl pkcs8` to convert if needed

3. **Application Startup Failures**
   - Check application logs for specific error messages
   - Verify `keys.yml` is in the correct location
   - Ensure SnakeYAML dependency is included
   - Application will fail to start if YAML keys cannot be loaded

## Security Considerations

1. **Key Protection**: Keep private keys secure and never commit them to version control
2. **Key Rotation**: Implement regular key rotation policies
3. **Environment Separation**: Use different keys for different environments
4. **Backup**: Maintain secure backups of key configurations
5. **Access Control**: Restrict access to key configuration files

## Benefits

- **Simplified Management**: All key configuration in one file
- **Flexibility**: Easy to add/remove keys without code changes
- **Key Rotation**: Built-in support for multiple keys
- **Environment Agnostic**: Same configuration format across environments
- **Clean Architecture**: No fallback complexity, YAML-only approach
