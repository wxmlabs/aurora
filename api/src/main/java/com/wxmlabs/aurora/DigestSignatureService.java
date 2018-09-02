package com.wxmlabs.aurora;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface DigestSignatureService extends SignatureService {
    Signer addSigner(String name, PrivateKey signerKey, DigestAlgorithm defaultDigestAlg);

    Verifier addVerifier(String name, PublicKey signerPub, DigestAlgorithm defaultDigestAlg);
}
