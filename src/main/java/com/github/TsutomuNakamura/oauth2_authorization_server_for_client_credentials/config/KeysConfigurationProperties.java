package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.KeysConfig;

/**
 * Configuration to enable loading of keys.yml
 */
@Configuration
@EnableConfigurationProperties(KeysConfig.class)
public class KeysConfigurationProperties {
}
