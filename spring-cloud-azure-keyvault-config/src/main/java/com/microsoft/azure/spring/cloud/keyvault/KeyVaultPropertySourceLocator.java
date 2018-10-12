/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.keyvault;

import org.springframework.cloud.bootstrap.config.PropertySourceLocator;
import org.springframework.core.env.CompositePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;

/**
 * Builds a {@link CompositePropertySource} with various {@link KeyVaultPropertySource} instances based on
 * active profiles, application name and default context permutations.
 */
public class KeyVaultPropertySourceLocator implements PropertySourceLocator {
    private KeyVaultProperties properties;

    public KeyVaultPropertySourceLocator(KeyVaultProperties properties) {

        this.properties = properties;
    }

    @Override
    public PropertySource<?> locate(Environment environment) {
        return null;
    }
}
