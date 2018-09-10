package com.wxmlabs.aurora;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface SignatureManager {
    Signer addSigner(String name, Signer signer);

    Signer addCMSSigner(String name, PrivateKey signerKey, X509Certificate signerCert, DigestAlgorithm defaultDigestAlg);

    Signer removeSigner(String name);

    Verifier addVerifier(String name, Verifier verifier);

    Verifier addCMSVerifier(String name, X509Certificate signerCert);

    Verifier removeVerifier(String name);
}
