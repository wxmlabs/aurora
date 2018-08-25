package com.wxmlabs.aurora;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;

public class BCProviderHelper {
    private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    static {
        Security.addProvider(PROVIDER);
    }

    public static BouncyCastleProvider getProvider() {
        return PROVIDER;
    }

    public static Signature getSignatureInstance(String algorithm) throws NoSuchAlgorithmException {
        return Signature.getInstance(algorithm, PROVIDER);
    }
}
