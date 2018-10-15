/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.keyvault;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.bootstrap.config.PropertySourceLocator;
import org.springframework.core.env.CompositePropertySource;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.util.ReflectionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builds a {@link CompositePropertySource} with various {@link KeyVaultPropertySource} instances based on
 * active profiles, application name and default context permutations.
 */
@Slf4j
public class KeyVaultPropertySourceLocator implements PropertySourceLocator {
    private KeyVaultProperties properties;
    private KeyVaultOperation keyVaultOperation;
    private List<String> keyVaultList = new ArrayList<>();

    public KeyVaultPropertySourceLocator(KeyVaultProperties properties, KeyVaultOperation keyVaultOperation) {

        this.properties = properties;
        this.keyVaultOperation = keyVaultOperation;
    }

    @Override
    public PropertySource<?> locate(Environment environment) {
        if (!(environment instanceof ConfigurableEnvironment)) {
            return null;
        }

        ConfigurableEnvironment env = (ConfigurableEnvironment) environment;

        initKeyVaultList(env);

        return loadPropertySources();
    }

    private void initKeyVaultList(ConfigurableEnvironment env) {
        String appName = properties.getName();

        if (appName == null) {
            appName = env.getProperty("spring.application.name");
        }

        // Add the default key vault
        keyVaultList.add(appName);

        // Add key vault names for active profiles
        List<String> profiles = Arrays.asList(env.getActiveProfiles());
        for (String profile : profiles) {
            keyVaultList.add(appName + KeyVaultProperties.PROFILE_SEPARATOR + profile);
        }
    }

    private CompositePropertySource loadPropertySources() {
        CompositePropertySource composite = new CompositePropertySource("azure-key-vault");

        for (String keyVault : this.keyVaultList) {
            loadPropertySource(composite, keyVault);
        }

        return composite;
    }

    private void loadPropertySource(CompositePropertySource composite, String name) {
        try {
            KeyVaultPropertySource propertySource = new KeyVaultPropertySource(name, keyVaultOperation);
            propertySource.init();
            composite.addPropertySource(propertySource);
        } catch (Exception e) {
            processException(e, name);
        }
    }

    private void processException(Exception e, String name) {
        if (this.properties.isFailFast()) {
            log.error("Fail fast is set and there was an error reading configuration from Azure Key Vault:\n"
                    + e.getMessage());
            ReflectionUtils.rethrowRuntimeException(e);
        } else {
            log.warn("Unable to load config from Azure Key Vault: " + name, e);
        }
    }
}
