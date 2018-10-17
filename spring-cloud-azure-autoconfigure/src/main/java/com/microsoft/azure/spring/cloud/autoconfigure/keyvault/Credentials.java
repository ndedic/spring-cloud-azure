/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.autoconfigure.keyvault;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Credentials {

    private String clientId;

    private String clientSecret;

    private String clientCertificate = "";

    private String clientCertificatePassword;
}
