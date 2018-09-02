package com.wxmlabs.aurora;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface CMSSignatureService extends SignatureService {
    Signer addCMSSigner(String name, PrivateKey signerKey, X509Certificate signerCert, DigestAlgorithm defaultDigestAlg);

    Verifier addCMSVerifier(String name, X509Certificate signerCert);
}
