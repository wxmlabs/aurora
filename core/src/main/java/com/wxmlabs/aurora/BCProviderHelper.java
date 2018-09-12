package com.wxmlabs.aurora;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;

import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class BCProviderHelper extends BCJcaJceHelper {
    static final BCProviderHelper INSTANCE = new BCProviderHelper();
    private static JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();

    static {
        certificateConverter.setProvider(INSTANCE.getProvider());
    }

    Provider getProvider() {
        return provider;
    }

    X509Certificate convertCertificate(X509CertificateHolder certificateHolder) throws CertificateException {
        return certificateConverter.getCertificate(certificateHolder);
    }
}
