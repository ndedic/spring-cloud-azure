/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.autoconfigure.context;

import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.AzureResponseBuilder;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.resources.fluentcore.utils.ProviderRegistrationInterceptor;
import com.microsoft.azure.management.resources.fluentcore.utils.ResourceManagerThrottlingInterceptor;
import com.microsoft.azure.serializer.AzureJacksonAdapter;
import com.microsoft.azure.spring.cloud.autoconfigure.telemetry.TelemetryCollector;
import com.microsoft.azure.spring.cloud.context.core.api.ResourceManagerProvider;
import com.microsoft.azure.spring.cloud.context.core.config.AzureProperties;
import com.microsoft.azure.spring.cloud.context.core.api.CredentialsProvider;
import com.microsoft.azure.spring.cloud.context.core.impl.AzureResourceManagerProvider;
import com.microsoft.azure.spring.cloud.context.core.impl.DefaultCredentialsProvider;
import com.microsoft.rest.RestClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

/**
 * Auto-config to provide default {@link CredentialsProvider} for all Azure services
 *
 * @author Warren Zhu
 */
@Configuration
@EnableConfigurationProperties(AzureProperties.class)
@ConditionalOnClass(Azure.class)
@ConditionalOnProperty(prefix = "spring.cloud.azure", value = {"credential-file-path", "resource-group", "region"})
public class AzureContextAutoConfiguration {
    private static final String PROJECT_VERSION =
            AzureContextAutoConfiguration.class.getPackage().getImplementationVersion();
    private static final String SPRING_CLOUD_USER_AGENT = "spring-cloud-azure/" + PROJECT_VERSION;

    @Bean
    @ConditionalOnMissingBean
    public ResourceManagerProvider resourceManagerProvider(Azure azure, AzureProperties azureProperties) {
        return new AzureResourceManagerProvider(azure, azureProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CredentialsProvider credentialsProvider(AzureProperties azureProperties) {
        return new DefaultCredentialsProvider(azureProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public Azure azure(CredentialsProvider credentialsProvider) throws IOException {
        ApplicationTokenCredentials credentials = credentialsProvider.getCredentials();
        TelemetryCollector.getInstance().setSubscription(credentials.defaultSubscriptionId());
        RestClient restClient = new RestClient.Builder()
                .withBaseUrl(credentials.environment(), AzureEnvironment.Endpoint.RESOURCE_MANAGER)
                .withCredentials(credentials).withSerializerAdapter(new AzureJacksonAdapter())
                .withResponseBuilderFactory(new AzureResponseBuilder.Factory())
                .withInterceptor(new ProviderRegistrationInterceptor(credentials))
                .withInterceptor(new ResourceManagerThrottlingInterceptor()).withUserAgent(SPRING_CLOUD_USER_AGENT)
                .build();

        return Azure.authenticate(restClient, credentials.domain()).withDefaultSubscription();
    }

}
