/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.keyvault;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.net.MalformedURLException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Credential used for Key Vault call. This class just fetch token by provided
 * {@code clientId} and {@code clientSecret}. This should be provided by Azure SDK
 */
@Slf4j
@AllArgsConstructor
public class AzureKeyVaultCredential extends KeyVaultCredentials {
    private final String clientId;
    private final String clientSecret;

    @Override
    public String doAuthenticate(String authorization, String resource, String scope) {
        try {
            AuthenticationContext context =
                    new AuthenticationContext(authorization, false, Executors.newSingleThreadExecutor());

            Future<AuthenticationResult> future =
                    context.acquireToken(resource, new ClientCredential(this.clientId, this.clientSecret), null);
            return future.get().getAccessToken();
        } catch (MalformedURLException | InterruptedException | ExecutionException e) {
            log.error("Failed to authenticate with Azure Key Vault.", e);
            throw new IllegalStateException("Failed to authenticate with Azure Key Vault.", e);
        }
    }
}
