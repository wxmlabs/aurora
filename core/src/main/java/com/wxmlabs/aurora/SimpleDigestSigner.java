package com.wxmlabs.aurora;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import static com.wxmlabs.aurora.SignatureAlgorithmNameGenerator.getSignatureAlg;

public class SimpleDigestSigner implements DigestSigner {
    private PrivateKey signerKey;
    private DigestAlgorithm defaultDigestAlg;

    public SimpleDigestSigner(PrivateKey signerKey, DigestAlgorithm defaultDigestAlg) {
        this.signerKey = signerKey;
        this.defaultDigestAlg = defaultDigestAlg;
    }

    @Override
    public byte[] sign(byte[] plaintext) {
        return sign(plaintext, defaultDigestAlg);
    }

    @Override
    public byte[] sign(byte[] plaintext, DigestAlgorithm digestAlgorithm) {
        try {
            Signature verifier = BCProviderHelper.getSignatureInstance(getSignatureAlg(digestAlgorithm, signerKey));
            verifier.initSign(signerKey);
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
