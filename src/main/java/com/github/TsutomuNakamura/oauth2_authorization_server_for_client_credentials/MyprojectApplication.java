package com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.github.TsutomuNakamura.oauth2_authorization_server_for_client_credentials.util.KeysConfig;

@SpringBootApplication
@EnableConfigurationProperties(KeysConfig.class)
public class MyprojectApplication {

	public static void main(String[] args) {
		SpringApplication.run(MyprojectApplication.class, args);
	}

}
