package com.wxmlabs.aurora;

public interface Verifier {
    boolean verify(byte[] plaintext, byte[] signature);
}
