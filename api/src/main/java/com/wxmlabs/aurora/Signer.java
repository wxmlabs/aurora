package com.wxmlabs.aurora;

public interface Signer {
    byte[] sign(byte[] plaintext);
}
