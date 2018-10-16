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
import com.microsoft.azure.spring.cloud.autoconfigure.storage.AzureStorageProperties;
import com.microsoft.azure.spring.cloud.autoconfigure.telemetry.TelemetryAutoConfiguration;
import com.microsoft.azure.spring.cloud.autoconfigure.telemetry.TelemetryCollector;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * An auto-configuration for Azure Key Vault.
 */
@Slf4j
@Configuration
@AutoConfigureBefore(TelemetryAutoConfiguration.class)
@AutoConfigureAfter(AzureContextAutoConfiguration.class)
@ConditionalOnClass(KeyVaultClient.class)
@ConditionalOnProperty(name = "spring.cloud.azure.keyvault.enabled", matchIfMissing = true)
@EnableConfigurationProperties(AzureStorageProperties.class)
public class AzureKeyVaultAutoConfiguration {

    private static final String KEY_VAULT = "KeyVault";

    @PostConstruct
    public void collectTelemetry() {
        TelemetryCollector.getInstance().addService(KEY_VAULT);
    }

    @Bean
    @ConditionalOnMissingBean
    public KeyVaultClient keyVaultClient(AzureKeyVaultProperties properties)
            throws OperatorCreationException, CertificateException, PKCSException, IOException {
        final String clientId = properties.getClientId();
        final String clientSecret = properties.getClientSecret();
        final String pemCertPath = properties.getPemCertPath();
        final String pemCertPassword = properties.getPemCertPassword();

        KeyVaultClient client = null;

        // Read PEM Cert
        final KeyCert certificateKey = readPemCertificate(pemCertPath, pemCertPassword);
        final PrivateKey privateKey = certificateKey.getKey();
        client = new KeyVaultClient(new KeyVaultCredentials() {
            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {
                try {
                    AuthenticationContext context = new AuthenticationContext(authorization, false, Executors.newFixedThreadPool(1));
                    AsymmetricKeyCredential asymmetricKeyCredential = AsymmetricKeyCredential.create(clientId,
                            privateKey, certificateKey.getCertificate());
                    // pass null value for optional callback function and acquire access token
                    AuthenticationResult result = context.acquireToken(resource, asymmetricKeyCredential, null).get();

                    return result.getAccessToken();
                } catch (Exception e) {
                    log.error("Failed to authenticate with Azure Key Vault.", e);
                }
                return "";
            }
        });

        // Using ADAL to authenticate
        client = new KeyVaultClient(new KeyVaultCredentials() {
            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {
                AuthenticationResult authResult;
                try {
                    authResult = getAccessToken(clientId, clientSecret, authorization, resource);
                    return authResult.getAccessToken();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return "";
            }
        });

        return client;
    }

    private static KeyCert readPemCertificate(String path, String password)
            throws IOException, CertificateException, OperatorCreationException, PKCSException {

        Security.addProvider(new BouncyCastleProvider());
        PEMParser pemParser = new PEMParser(new FileReader(new File(path)));
        PrivateKey privateKey = null;
        X509Certificate cert = null;
        Object object = pemParser.readObject();

        while (object != null) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (object instanceof X509CertificateHolder) {
                cert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) object);
            }
            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                PKCS8EncryptedPrivateKeyInfo pinfo = (PKCS8EncryptedPrivateKeyInfo) object;
                InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());
                PrivateKeyInfo info = pinfo.decryptPrivateKeyInfo(provider);
                privateKey = converter.getPrivateKey(info);
            }
            if (object instanceof PrivateKeyInfo) {
                privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
            }
            object = pemParser.readObject();
        }

        KeyCert keycert = new KeyCert(null, null);
        keycert.setCertificate(cert);
        keycert.setKey(privateKey);
        pemParser.close();
        return keycert;
    }

    /**
     * Private helper method that gets the access token for the authorization and resource depending on which variables are supplied in the environment.
     *
     * @param authorization
     * @param resource
     * @return
     * @throws ExecutionException
     * @throws InterruptedException
     * @throws MalformedURLException
     * @throws Exception
     */
    private static AuthenticationResult getAccessToken(String clientId, String clientSecret, String authorization, String resource)
            throws InterruptedException, ExecutionException, MalformedURLException {

        AuthenticationResult result = null;

        //Starts a service to fetch access token.
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            AuthenticationContext context = new AuthenticationContext(authorization, false, service);

            Future<AuthenticationResult> future = null;

            //Acquires token based on client ID and client secret.
            if (clientSecret != null && clientSecret != null) {
                ClientCredential credentials = new ClientCredential(clientId, clientSecret);
                future = context.acquireToken(resource, credentials, null);
            }

            result = future.get();
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new RuntimeException("Authentication results were null.");
        }
        return result;
    }
}

@Getter
@Setter
@AllArgsConstructor
class KeyCert {

    private X509Certificate certificate;

    private PrivateKey key;
}
