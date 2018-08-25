package com.wxmlabs.aurora;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MemorySignatureService implements SignatureService {
    private Map<String, Signer> signerMap;
    private Map<String, Verifier> verifierMap;

    public MemorySignatureService() {
        signerMap = new ConcurrentHashMap<String, Signer>();
        verifierMap = new ConcurrentHashMap<String, Verifier>();
    }

    @Override
    public Signer findSignerByName(String name) {
        return signerMap.get(name);
    }

    @Override
    public Verifier findVerifierByName(String name) {
        return verifierMap.get(name);
    }

    @Override
    public Signer addSigner(String name, PrivateKey privateKey, DigestAlgorithm defaultDigestAlg) {
        return signerMap.put(name, new SimpleSigner(privateKey, defaultDigestAlg));
    }

    @Override
    public Signer removeSigner(String name) {
        return signerMap.remove(name);
    }

    @Override
    public Verifier addVerifier(String name, PublicKey publicKey, DigestAlgorithm defaultDigestAlg) {
        return verifierMap.put(name, new SimpleVerifier(publicKey, defaultDigestAlg));
    }

    @Override
    public Verifier removeVerifier(String name) {
        return verifierMap.remove(verifierMap);
    }
}
