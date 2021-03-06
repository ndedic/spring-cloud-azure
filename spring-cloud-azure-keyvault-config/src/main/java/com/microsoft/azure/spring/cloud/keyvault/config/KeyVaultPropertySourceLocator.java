/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.keyvault.config;

import org.springframework.cloud.bootstrap.config.PropertySourceLocator;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;

/**
 * Builds a {@link KeyVaultPropertySource} instance based on application name and active profiles.
 */
public class KeyVaultPropertySourceLocator implements PropertySourceLocator {

    private final KeyVaultConfigProperties properties;

    public KeyVaultPropertySourceLocator(KeyVaultConfigProperties properties) {

        this.properties = properties;
    }

    @Override
    public PropertySource<?> locate(Environment environment) {
        return null;
    }
}
