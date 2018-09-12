package com.wxmlabs.aurora

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.operator.DigestCalculator

/**
 * @see org.bouncycastle.cms.test.SHA1DigestCalculator
 */
@SuppressWarnings("GroovyDocCheck")
class SHA1DigestCalculator
    implements DigestCalculator
{
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream()

    AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)
    }

    OutputStream getOutputStream()
    {
        return bOut
    }

    byte[] getDigest()
    {
        byte[] bytes = bOut.toByteArray()

        bOut.reset()

        Digest sha1 = new SHA1Digest()

        sha1.update(bytes, 0, bytes.length)

        byte[] digest = new byte[sha1.getDigestSize()]

        sha1.doFinal(digest, 0)

        return digest
    }
}
