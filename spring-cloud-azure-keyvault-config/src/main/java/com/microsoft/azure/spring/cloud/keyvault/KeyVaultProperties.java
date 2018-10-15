/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.keyvault;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotEmpty;

/**
 * Configuration properties for the Azure Key Vault integration.
 */
@ConfigurationProperties("spring.cloud.azure.keyvault.config")
@Validated
public class KeyVaultProperties {
    // https://github.com/Azure/azure-rest-api-specs/blob/master/specification/keyvault/resource-manager/Microsoft.KeyVault/stable/2018-02-14/keyvault.json#L34
    // Pattern of valid key vault name is "^[a-zA-Z0-9-]{3,24}$" as documented in above link.
    // So hard code the profile separator as "-".
    public static final String PROFILE_SEPARATOR = "-";

    @Getter @Setter
    private boolean enabled = true;

    @Getter @Setter
    private boolean failFast = true;

    @Getter @Setter
    private String name;

    @Getter @Setter
    private String activeProfile;

    @Getter @Setter
    @NotEmpty
    private String clientId;

    @Getter @Setter
    @NotEmpty
    private String clientSecret;
}
