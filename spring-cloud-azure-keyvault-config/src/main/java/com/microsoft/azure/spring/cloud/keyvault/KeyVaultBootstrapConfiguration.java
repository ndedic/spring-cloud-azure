package com.microsoft.azure.spring.cloud.keyvault;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(KeyVaultProperties.class)
@ConditionalOnProperty(prefix = "spring.cloud.azure.keyvault.config", name = "enabled", matchIfMissing = true)
public class KeyVaultBootstrapConfiguration {

    @Bean
    KeyVaultPropertySourceLocator keyVaultPropertySourceLocator(KeyVaultProperties properties, KeyVaultOperation operation) {
        return new KeyVaultPropertySourceLocator(properties, operation);
    }

    @Bean
    KeyVaultOperation keyVaultOperation(KeyVaultProperties properties) {
        String clientId = properties.getClientId();
        String clientSecret = properties.getClientSecret();
        return new KeyVaultTemplate(properties.getClientId(), properties.getClientSecret());
    }
}
