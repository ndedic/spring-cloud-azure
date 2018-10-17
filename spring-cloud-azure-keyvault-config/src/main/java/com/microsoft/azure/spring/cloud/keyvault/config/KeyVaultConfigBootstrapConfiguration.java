/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.keyvault.config;

import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.spring.cloud.context.core.api.CredentialsProvider;
import com.microsoft.azure.spring.cloud.context.core.impl.DefaultCredentialsProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * Spring Cloud Bootstrap Configuration for setting up an {@link KeyVaultPropertySourceLocator}.
 */
@Slf4j
@Configuration
@EnableConfigurationProperties(KeyVaultConfigProperties.class)
@ConditionalOnProperty(name = KeyVaultConfigProperties.ENABLED, matchIfMissing = true)
public class KeyVaultConfigBootstrapConfiguration {

    @Bean
    public KeyVaultClient keyVaultClient(KeyVaultConfigProperties properties) {
        CredentialsProvider credentialsProvider = new DefaultCredentialsProvider(properties);
        ApplicationTokenCredentials credentials = credentialsProvider.getCredentials();
        return new KeyVaultClient(new KeyVaultCredentials() {
            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {
                try {
                    return credentials.getToken(resource);
                } catch (Exception e) {
                    log.error("Failed to authenticate with Azure Key Vault.", e);
                }
                return "";
            }
        });
    }

    @Bean
    public KeyVaultPropertySourceLocator keyVaultPropertySourceLocator(KeyVaultConfigProperties properties) {
        return new KeyVaultPropertySourceLocator(properties);
    }
}
