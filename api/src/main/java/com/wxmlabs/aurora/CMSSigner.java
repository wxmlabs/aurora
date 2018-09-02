package com.wxmlabs.aurora;

public interface CMSSigner extends Signer {
    /**
     * Generate a CMS Signed Data carrying a detached CMS signature.
     *
     * @param content the content to be signed.
     * @return the ASN.1 encoded representation of the CMS Signed Data
     */
    byte[] sign(byte[] content);

    /**
     * Generate a CMS Signed Data which can be carrying a detached CMS signature, or have encapsulated data, depending on the value
     * of the encapsulated parameter.
     *
     * @param content     the content to be signed.
     * @param encapsulate true if the content should be encapsulated in the signature, false otherwise.
     * @return the ASN.1 encoded representation of the CMS Signed Data
     */
    byte[] sign(byte[] content, boolean encapsulate);

    // TODO append signature to the exist CMS Signed Data
}
