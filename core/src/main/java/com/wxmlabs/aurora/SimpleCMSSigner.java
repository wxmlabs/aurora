package com.wxmlabs.aurora;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static com.wxmlabs.aurora.SignatureAlgorithmNameGenerator.getSignatureAlg;

public class SimpleCMSSigner implements CMSSigner {
    private PrivateKey signerKey;
    private X509Certificate signerCert;
    private DigestAlgorithm defaultDigestAlg;
    private boolean directSignature;

    public SimpleCMSSigner(PrivateKey signerKey, X509Certificate signerCert, DigestAlgorithm defaultDigestAlg) {
        this.signerKey = signerKey;
        this.signerCert = signerCert;
        this.defaultDigestAlg = defaultDigestAlg;
        this.directSignature = false;
    }

    public SimpleCMSSigner(PrivateKey signerKey, X509Certificate signerCert, DigestAlgorithm defaultDigestAlg, boolean directSignature) {
        this.signerKey = signerKey;
        this.signerCert = signerCert;
        this.defaultDigestAlg = defaultDigestAlg;
        this.directSignature = directSignature;
    }

    @Override
    public byte[] sign(byte[] content) {
        return sign(content, false);
    }

    @Override
    public byte[] sign(byte[] content, boolean encapsulate) {
        try {
            List<X509Certificate> certList = new ArrayList<X509Certificate>();
            CMSTypedData msg = new CMSProcessableByteArray(content);

            certList.add(signerCert);

            Store certs = new JcaCertStore(certList);

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            ContentSigner contentSigner = new JcaContentSignerBuilder(getSignatureAlg(defaultDigestAlg, signerKey)).setProvider(BCProviderHelper.getProvider()).build(signerKey);

            gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(BCProviderHelper.getProvider()).build())
                    .setDirectSignature(directSignature)
                    .build(contentSigner, signerCert));

            gen.addCertificates(certs);

            CMSSignedData sigData = gen.generate(msg, encapsulate);
            return sigData.getEncoded();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
