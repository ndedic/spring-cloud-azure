/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE in the project root for
 * license information.
 */

package com.microsoft.azure.spring.cloud.autoconfigure.keyvault;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
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
import java.util.function.BiFunction;

public class AuthUtils {
    public static KeyCert readPemCertificate(String path, String password)
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

    public static String getAccessToken(String authorization, String resource, BiFunction<AuthenticationContext, String, Future<AuthenticationResult>> func)
            throws ExecutionException, InterruptedException, MalformedURLException {
        AuthenticationResult result = null;

        //Starts a service to fetch access token.
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            AuthenticationContext context = new AuthenticationContext(authorization, false, service);

            result = func.apply(context, resource).get();
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new RuntimeException("Authentication results were null.");
        }

        return result.getAccessToken();
    }
}
