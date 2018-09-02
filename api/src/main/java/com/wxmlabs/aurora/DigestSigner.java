package com.wxmlabs.aurora;

public interface DigestSigner extends Signer {
    byte[] sign(byte[] plaintext, DigestAlgorithm digestAlgorithm);
}
