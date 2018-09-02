package com.wxmlabs.aurora;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.text.SimpleDateFormat;

class LoggerUtil {
    private static SimpleDateFormat ISO8601_FORMAT = new SimpleDateFormat("yyyy-mm-dd'T'HH:MM:ssZ");

    static String certInfo(Certificate cert) {
        if (cert instanceof X509Certificate) {
            return x509CertInfo((X509Certificate) cert);
        }

        return cert.toString();
    }

    private static String x509CertInfo(X509Certificate x509Cert) {
        return String.format("[SerialNumber: %s, Subject: \"%s\", Issuer: \"%s\", NotBefore: %s, NotAfter: %s, Key: %s]",
            x509Cert.getSerialNumber().toString(16),
            x509Cert.getSubjectX500Principal().getName(),
            x509Cert.getIssuerX500Principal().getName(),
            ISO8601_FORMAT.format(x509Cert.getNotBefore()),
            ISO8601_FORMAT.format(x509Cert.getNotAfter()),
            keyInfo(x509Cert.getPublicKey())
        );
    }

    static String keyInfo(Key key) {
        if (key instanceof RSAKey) {
            return rsaKeyInfo((RSAKey) key);
        }
        if (key instanceof ECKey) {
            return ecKeyInfo((ECKey) key);
        }
        return key.toString();
    }

    private static String rsaKeyInfo(RSAKey rsaKey) {
        return String.format("RSA %d bits", rsaKey.getModulus().bitLength());
    }

    private static String ecKeyInfo(ECKey ecKey) {
        return String.format("EC %s", ECParameterSpecUtil.toString(ecKey.getParams()));
    }
}
