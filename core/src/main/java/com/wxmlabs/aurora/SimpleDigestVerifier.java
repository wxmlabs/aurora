package com.wxmlabs.aurora;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;


public class SimpleDigestVerifier implements DigestVerifier {
    private PublicKey signerPub;
    private DigestAlgorithm defaultDigestAlg;

    public SimpleDigestVerifier(PublicKey signerPub, DigestAlgorithm defaultDigestAlg) {
        this.signerPub = signerPub;
        this.defaultDigestAlg = defaultDigestAlg;
    }

    @Override
    public boolean verify(byte[] plaintext, byte[] signature) {
        return verify(plaintext, signature, defaultDigestAlg);
    }

    @Override
    public boolean verify(byte[] plaintext, byte[] signature, DigestAlgorithm digestAlgorithm) {
        try {
            Signature verifier = BCProviderHelper.getSignatureInstance(SignatureAlgorithmNameGenerator.getSignatureAlg(digestAlgorithm, signerPub));
            verifier.initVerify(signerPub);
            verifier.update(plaintext);
            return verifier.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }
}
