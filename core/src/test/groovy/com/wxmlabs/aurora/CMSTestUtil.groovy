package com.wxmlabs.aurora

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509ExtensionUtils
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import javax.crypto.KeyGenerator
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey

/**
 * @see org.bouncycastle.cms.test.CMSTestUtil
 */
@SuppressWarnings("GroovyDocCheck")
class CMSTestUtil {
    public static SecureRandom rand
    public static KeyPairGenerator kpg

    public static KeyPairGenerator ecDsaKpg
    public static KeyPairGenerator ecSm2Kpg
    public static KeyGenerator aes192kg
    public static KeyGenerator desede128kg
    public static KeyGenerator desede192kg
    public static KeyGenerator rc240kg
    public static KeyGenerator rc264kg
    public static KeyGenerator rc2128kg
    public static KeyGenerator aesKg
    public static KeyGenerator seedKg
    public static KeyGenerator camelliaKg
    public static BigInteger serialNumber

    private static Provider provider = BCProviderHelper.INSTANCE.getProvider()

    static {
        try {

            rand = new SecureRandom()

            kpg = KeyPairGenerator.getInstance("RSA", provider)
            kpg.initialize(2048, rand)

            ecDsaKpg = KeyPairGenerator.getInstance("EC", provider)
            ecDsaKpg.initialize(new ECNamedCurveGenParameterSpec("prime256v1"))

            ecSm2Kpg = KeyPairGenerator.getInstance("EC", provider)
            ecSm2Kpg.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"))

            aes192kg = KeyGenerator.getInstance("AES", provider)
            aes192kg.init(192, rand)

            desede128kg = KeyGenerator.getInstance("DESEDE", provider)
            desede128kg.init(112, rand)

            desede192kg = KeyGenerator.getInstance("DESEDE", provider)
            desede192kg.init(168, rand)

            rc240kg = KeyGenerator.getInstance("RC2", provider)
            rc240kg.init(40, rand)

            rc264kg = KeyGenerator.getInstance("RC2", provider)
            rc264kg.init(64, rand)

            rc2128kg = KeyGenerator.getInstance("RC2", provider)
            rc2128kg.init(128, rand)

            aesKg = KeyGenerator.getInstance("AES", provider)

            seedKg = KeyGenerator.getInstance("SEED", provider)

            camelliaKg = KeyGenerator.getInstance("Camellia", provider)

            serialNumber = new BigInteger("1")
        } catch (Exception ex) {
            throw new RuntimeException(ex.toString())
        }
    }

    static KeyPair makeKeyPair() {
        return kpg.generateKeyPair()
    }


    static KeyPair makeEcDsaKeyPair() {
        return ecDsaKpg.generateKeyPair()
    }

    static KeyPair makeEcSm2KeyPair() {
        return ecSm2Kpg.generateKeyPair()
    }

    static X509Certificate makeCertificate(KeyPair _subKP,
                                           String _subDN, KeyPair _issKP, String _issDN)
        throws GeneralSecurityException, IOException, OperatorCreationException {
        return makeCertificate(_subKP, _subDN, _issKP, _issDN, false)
    }

    static X509Certificate makeCertificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN, boolean _ca)
        throws GeneralSecurityException, IOException, OperatorCreationException {

        PublicKey subPub = subKP.getPublic()
        PrivateKey issPriv = issKP.getPrivate()
        PublicKey issPub = issKP.getPublic()

        X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
            new X500Name(_issDN),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)),
            new X500Name(_subDN),
            subPub)

        JcaContentSignerBuilder contentSignerBuilder = makeContentSignerBuilder(issPub)

        v3CertGen.addExtension(
            Extension.subjectKeyIdentifier,
            false,
            createSubjectKeyId(subPub))

        v3CertGen.addExtension(
            Extension.authorityKeyIdentifier,
            false,
            createAuthorityKeyId(issPub))

        v3CertGen.addExtension(
            Extension.basicConstraints,
            false,
            new BasicConstraints(_ca))

        X509Certificate _cert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)))

        _cert.checkValidity(new Date())
        _cert.verify(issPub)

        return _cert
    }

    private static JcaContentSignerBuilder makeContentSignerBuilder(PublicKey issPub) {
        JcaContentSignerBuilder contentSignerBuilder
        if (issPub instanceof RSAPublicKey) {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSA")
        } else if (issPub.getAlgorithm() == "ECDSA") {
            contentSignerBuilder = new JcaContentSignerBuilder("SHA256withECDSA")
        } else {
            contentSignerBuilder = new JcaContentSignerBuilder("SM3withSM2")
        }

        contentSignerBuilder.setProvider(provider)

        return contentSignerBuilder
    }

    private static final X509ExtensionUtils extUtils = new X509ExtensionUtils(new SHA1DigestCalculator())

    private static AuthorityKeyIdentifier createAuthorityKeyId(
        PublicKey _pubKey)
        throws IOException {
        return extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(_pubKey.getEncoded()))
    }

    static SubjectKeyIdentifier createSubjectKeyId(
        PublicKey _pubKey)
        throws IOException {
        return extUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(_pubKey.getEncoded()))
    }

    private static BigInteger allocateSerialNumber() {
        BigInteger _tmp = serialNumber
        serialNumber = serialNumber.add(BigInteger.ONE)
        return _tmp
    }
}
