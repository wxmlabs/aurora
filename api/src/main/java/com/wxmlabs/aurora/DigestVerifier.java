package com.wxmlabs.aurora;

public interface DigestVerifier extends Verifier {
    boolean verify(byte[] plaintext, byte[] signature, DigestAlgorithm digestAlgorithm);
}
