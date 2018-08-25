package com.wxmlabs.aurora;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SignatureService {
    Signer findSignerByName(String name);

    Verifier findVerifierByName(String name);

    Signer addSigner(String name, PrivateKey privateKey, DigestAlgorithm defaultDigestAlg);

    Signer removeSigner(String name);

    Verifier addVerifier(String name, PublicKey publicKey, DigestAlgorithm defaultDigestAlg);

    Verifier removeVerifier(String name);

}
