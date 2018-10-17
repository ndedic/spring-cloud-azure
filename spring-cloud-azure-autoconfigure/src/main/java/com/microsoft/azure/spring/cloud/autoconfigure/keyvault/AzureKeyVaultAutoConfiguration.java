/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.autoconfigure.keyvault;

import com.microsoft.aad.adal4j.AsymmetricKeyCredential;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.spring.cloud.autoconfigure.context.AzureContextAutoConfiguration;
import com.microsoft.azure.spring.cloud.autoconfigure.telemetry.TelemetryAutoConfiguration;
import com.microsoft.azure.spring.cloud.autoconfigure.telemetry.TelemetryCollector;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.concurrent.Future;
import java.util.function.BiFunction;

/**
 * An auto-configuration for Azure Key Vault.
 */
@Slf4j
@Configuration
@AutoConfigureBefore(TelemetryAutoConfiguration.class)
@AutoConfigureAfter(AzureContextAutoConfiguration.class)
@ConditionalOnClass(KeyVaultClient.class)
@ConditionalOnProperty(name = "spring.cloud.azure.keyvault.enabled", matchIfMissing = true)
@EnableConfigurationProperties(AzureKeyVaultProperties.class)
public class AzureKeyVaultAutoConfiguration {

    private static final String KEY_VAULT = "KeyVault";

    @PostConstruct
    public void collectTelemetry() {
        TelemetryCollector.getInstance().addService(KEY_VAULT);
    }

    @Bean
    @ConditionalOnMissingBean
    public KeyVaultClient keyVaultClient(final AzureKeyVaultProperties properties) {

        KeyVaultCredentials keyVaultCredentials = new KeyVaultCredentials() {
            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {
                try {
                    return AuthUtils.getAccessToken(authorization, resource, createGetAccessTokenFunction(properties));
                } catch (Exception e) {
                    log.error("Failed to authenticate with Azure Key Vault.", e);
                }

                return "";
            }
        };
        return new KeyVaultClient(keyVaultCredentials);
    }

    private BiFunction<AuthenticationContext, String, Future<AuthenticationResult>> createGetAccessTokenFunction(AzureKeyVaultProperties properties)
            throws OperatorCreationException, CertificateException, PKCSException, IOException {
        final String clientId = properties.getClientId();
        final String pemCertPath = properties.getPemCertPath();
        final String pemCertPassword = properties.getPemCertPassword();

        if (!StringUtils.isEmpty(pemCertPath)) {
            final KeyCert certificateKey = AuthUtils.readPemCertificate(pemCertPath, pemCertPassword);
            AsymmetricKeyCredential asymmetricKeyCredential = AsymmetricKeyCredential.create(clientId, certificateKey.getKey(), certificateKey.getCertificate());
            return (context, resource) -> context.acquireToken(resource, asymmetricKeyCredential, null);
        }

        final String clientSecret = properties.getClientSecret();
        if (!StringUtils.isEmpty(clientSecret)) {
            final ClientCredential clientCredential =  new ClientCredential(clientId, clientSecret);
            return (context, resource) -> context.acquireToken(resource, clientCredential, null);
        }
    }
}
