package com.wxmlabs.aurora;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class MemorySignatureService implements SignatureService, DigestSignatureService, CMSSignatureService {
    private Map<String, Signer> signerMap;
    private Map<String, Verifier> verifierMap;

    public MemorySignatureService() {
        signerMap = new ConcurrentHashMap<String, Signer>();
        verifierMap = new ConcurrentHashMap<String, Verifier>();
    }

    @Override
    public Collection<String> listSigner() {
        return signerMap.keySet();
    }

    @Override
    public Collection<String> listVerifier() {
        return verifierMap.keySet();
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
    public Signer addSigner(String name, Signer signer) {
        return signerMap.put(name, signer);
    }

    @Override
    public Signer addSigner(String name, PrivateKey signerKey, DigestAlgorithm defaultDigestAlg) {
        return signerMap.put(name, new SimpleDigestSigner(signerKey, defaultDigestAlg));
    }

    @Override
    public Signer removeSigner(String name) {
        return signerMap.remove(name);
    }

    @Override
    public Verifier addVerifier(String name, Verifier verifier) {
        return verifierMap.put(name, verifier);
    }

    @Override
    public Verifier addVerifier(String name, PublicKey signerPub, DigestAlgorithm defaultDigestAlg) {
        return verifierMap.put(name, new SimpleDigestVerifier(signerPub, defaultDigestAlg));
    }

    @Override
    public Verifier removeVerifier(String name) {
        return verifierMap.remove(name);
    }

    @Override
    public Signer addCMSSigner(String name, PrivateKey signerKey, X509Certificate signerCert, DigestAlgorithm defaultDigestAlg) {
        return signerMap.put(name, new SimpleCMSSigner(signerKey, signerCert, defaultDigestAlg));
    }

    @Override
    public Verifier addCMSVerifier(String name, X509Certificate signerCert) {
        return verifierMap.put(name, new SimpleCMSVerifier(signerCert));
    }
}
