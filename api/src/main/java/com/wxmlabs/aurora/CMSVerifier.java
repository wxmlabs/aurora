package com.wxmlabs.aurora;

public interface CMSVerifier extends Verifier {
    /**
     * Verify the signature - content with detached signature.
     *
     * @param signedContent the content that was signed.
     * @param sigData       the signature object.
     * @return true if every signer information is verified.
     */
    boolean verify(byte[] signedContent, byte[] sigData);

    /**
     * Verify the signature - with encapsulated content
     *
     * @param sigData the signature object.
     * @return true if every signer information is verified.
     */
    boolean verify(byte[] sigData);
}
