package com.wxmlabs.aurora;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;

class BCProviderHelper {
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static {
        Security.addProvider(PROVIDER);
    }

    static BouncyCastleProvider getProvider() {
        return PROVIDER;
    }

    static Signature getSignatureInstance(String algorithm) throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm, PROVIDER);
    }
}
