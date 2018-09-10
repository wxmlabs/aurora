package com.wxmlabs.aurora;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSVerifierCertificateNotValidException;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerId;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Selector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

public class SimpleCMSVerifier implements CMSVerifier {
    private static Logger log = LoggerFactory.getLogger(SimpleCMSVerifier.class);
    private final X509Certificate signerCert;

    public SimpleCMSVerifier() {
        this.signerCert = null;
    }

    public SimpleCMSVerifier(X509Certificate signerCert) {
        this.signerCert = signerCert;
    }

    @Override
    public boolean verify(byte[] signedContent, byte[] sigData) {
        try {
            return verify(new CMSSignedData(new CMSProcessableByteArray(signedContent), sigData));
        } catch (CMSException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean verify(byte[] sigData) {
        try {
            return verify(new CMSSignedData(sigData));
        } catch (CMSException e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean verify(CMSSignedData sigData) {
        SignerInformationStore signerStore = sigData.getSignerInfos();
        Collection<SignerInformation> signers;
        if (signerCert == null) {
            signers = signerStore.getSigners();
        } else {
            SignerId signerId = new JcaSignerId(signerCert);
            signers = signerStore.getSigners(signerId);
        }

        int total = signers.size();
        int verified = 0;
        for (SignerInformation signer : signers) {
            X509Certificate verifier;
            if (signerCert != null) {
                verifier = signerCert;
            } else {
                @SuppressWarnings("unchecked") Selector<X509CertificateHolder> selector = signer.getSID();
                Collection<X509CertificateHolder> certCollection = sigData.getCertificates().getMatches(selector);
                Iterator<X509CertificateHolder> certIt = certCollection.iterator();
                X509CertificateHolder cert = certIt.next();
                try {
                    verifier = BCProviderHelper.INSTANCE.convertCertificate(cert);
                } catch (CertificateException e) {
                    log.error("parsing CMS SignedData Certificate failed: " + e.getMessage(), e);
                    break;
                }
            }
            try {
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BCProviderHelper.INSTANCE.getProvider()).build(verifier))) {
                    verified++;
                }
            } catch (CMSVerifierCertificateNotValidException e) {
                log.info("verifier certificate not valid: " + LoggerUtil.certInfo(verifier) + " cause: " + e.getMessage());
            } catch (CMSException e) {
                e.printStackTrace();
            } catch (OperatorCreationException e) {
                e.printStackTrace();
            }
        }
        return verified == total;
    }
}
