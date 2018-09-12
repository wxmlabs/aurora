package com.wxmlabs.aurora

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSignerId
import org.bouncycastle.util.Selector
import spock.lang.Specification

import java.security.KeyPair
import java.security.cert.X509Certificate

class SimpleCMSSignerSpec extends Specification {
    private static byte[] content

    private static String _origDN
    private static KeyPair _origKP
    private static X509Certificate _origCert

    private static String _signDN
    private static KeyPair _signKP
    private static X509Certificate _signCert

    private static KeyPair _signEcDsaKP
    private static X509Certificate _signEcDsaCert

    private static KeyPair _signEcSm2KP
    private static X509Certificate _signEcSm2Cert


    void setupSpec() {
        content = "hello, world".bytes

        _origDN = "O=WXM Labs, C=CN"
        _origKP = CMSTestUtil.makeKeyPair()
        _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _origKP, _origDN, true)

        _signDN = "CN=Anna, OU=Sales, O=WXM Labs, C=CN"
        _signKP = CMSTestUtil.makeKeyPair()
        _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _origKP, _origDN)

        _signEcDsaKP = CMSTestUtil.makeEcDsaKeyPair()
        _signEcDsaCert = CMSTestUtil.makeCertificate(_signEcDsaKP, _signDN, _origKP, _origDN)

        _signEcSm2KP = CMSTestUtil.makeEcSm2KeyPair()
        _signEcSm2Cert = CMSTestUtil.makeCertificate(_signEcSm2KP, _signDN, _origKP, _origDN)
    }

    void "make RSA detached signed data"() {
        given: "a signer"
        CMSSigner signer = new SimpleCMSSigner(_signKP.private, _signCert, SignatureAlgorithmNameGenerator.getDefaultDigestAlg(_signKP.private))
        when: "sign detached signed data"
        byte[] signedData = signer.sign(content)
        then:
        CMSSignedData s = new CMSSignedData(signedData)
        Selector signerId = new JcaSignerId(_signCert)
        SignerInformation signerInfo = s.getSignerInfos().get(signerId)

        s.getSignedContent() == null
        s.getCertificates().getMatches(signerId).size() == 1
        signerInfo != null
        signerInfo.signedAttributes != null
        signerInfo.signedAttributes.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null
    }
}
