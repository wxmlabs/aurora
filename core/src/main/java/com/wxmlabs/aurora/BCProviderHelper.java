package com.wxmlabs.aurora;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

class BCProviderHelper extends BCJcaJceHelper {
    static final BCProviderHelper INSTANCE = new BCProviderHelper();

    Provider getProvider() {
        return provider;
    }

    /*
     * @see org.bouncycastle.operator.jcajce.OperatorHelper.convertCertificate
     */
    public X509Certificate convertCertificate(X509CertificateHolder certHolder) throws CertificateException {
        try {
            CertificateFactory certFact = INSTANCE.createCertificateFactory("X.509");
            return (X509Certificate) certFact.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
        } catch (IOException e) {
            throw new CertificateException("cannot get encoded form of certificate: " + e.getMessage(), e);
        }
    }
}
