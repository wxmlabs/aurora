package com.wxmlabs.aurora;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;


public class SimpleVerifier implements Verifier {
    private PublicKey publicKey;
    private DigestAlgorithm defaultDigestAlg;

    public SimpleVerifier(PublicKey publicKey, DigestAlgorithm defaultDigestAlg) {
        this.publicKey = publicKey;
        this.defaultDigestAlg = defaultDigestAlg;
    }

    @Override
    public boolean verify(byte[] plaintext, byte[] signature) {
        try {
            Signature verifier = BCProviderHelper.getSignatureInstance(SignatureAlgorithmNameGenerator.getSignatureAlg(defaultDigestAlg, publicKey));
            verifier.initVerify(publicKey);
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
