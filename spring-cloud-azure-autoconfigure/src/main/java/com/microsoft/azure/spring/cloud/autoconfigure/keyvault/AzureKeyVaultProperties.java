/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.autoconfigure.keyvault;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotEmpty;

@Getter
@Setter
@Validated
@ConfigurationProperties(AzureKeyVaultProperties.CONFIG_PREFIX)
public class AzureKeyVaultProperties {
    public static final String CONFIG_PREFIX = "spring.cloud.azure.keyvault";

    @NotEmpty
    private String clientId;

    private String pemCertPath;

    private String pemCertPassword = "";

    private String clientSecret;
}
