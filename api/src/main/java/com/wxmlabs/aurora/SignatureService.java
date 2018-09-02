package com.wxmlabs.aurora;

import java.util.Collection;

public interface SignatureService {
    Collection<String> listSigner();

    Collection<String> listVerifier();

    Signer findSignerByName(String name);

    Verifier findVerifierByName(String name);

    Signer addSigner(String name, Signer signer);

    Signer removeSigner(String name);

    Verifier addVerifier(String name, Verifier verifier);

    Verifier removeVerifier(String name);

}
