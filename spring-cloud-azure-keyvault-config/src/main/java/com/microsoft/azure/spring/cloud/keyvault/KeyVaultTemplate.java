/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.keyvault;

import java.util.Collection;

public class KeyVaultTemplate implements KeyVaultOperation {
    @Override
    public String getSecret(String keyVaultName, String secretName, boolean fromCache) {
        return null;
    }

    @Override
    public Collection<String> listSecrets(String keyVaultName, boolean fromCache) {
        return null;
    }
}
