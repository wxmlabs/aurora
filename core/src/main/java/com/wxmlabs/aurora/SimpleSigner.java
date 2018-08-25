package com.wxmlabs.aurora;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import static com.wxmlabs.aurora.SignatureAlgorithmNameGenerator.getSignatureAlg;

public class SimpleSigner implements Signer {
    private PrivateKey privateKey;
    private DigestAlgorithm defaultDigestAlg;

    public SimpleSigner(PrivateKey privateKey, DigestAlgorithm defaultDigestAlg) {
        this.privateKey = privateKey;
        this.defaultDigestAlg = defaultDigestAlg;
    }

    @Override
    public byte[] sign(byte[] plaintext) {
        try {
            Signature verifier = BCProviderHelper.getSignatureInstance(getSignatureAlg(defaultDigestAlg, privateKey));
            verifier.initSign(privateKey);
            verifier.update(plaintext);
            return verifier.sign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }
}
