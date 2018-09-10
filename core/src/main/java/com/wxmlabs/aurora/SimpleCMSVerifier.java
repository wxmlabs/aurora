package com.wxmlabs.aurora;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Collection;

public class SimpleCMSVerifier implements CMSVerifier {
    public static Logger log = LoggerFactory.getLogger(SimpleCMSVerifier.class);
    private X509Certificate signerCert;

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
        SignerId signerId = new JcaSignerId(signerCert);
        SignerInformationStore signerStore = sigData.getSignerInfos();
        Collection<SignerInformation> signers = signerStore.getSigners(signerId);
        int total = signers.size();
        int verified = 0;
        for (SignerInformation signer : signers) {
            try {
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BCProviderHelper.INSTANCE.getProvider()).build(signerCert))) {
                    verified++;
                }
            } catch (CMSVerifierCertificateNotValidException e) {
                log.info(e.getMessage() + "\n  verifier: " + LoggerUtil.certInfo(signerCert));
            } catch (CMSException e) {
                e.printStackTrace();
            } catch (OperatorCreationException e) {
                e.printStackTrace();
            }
        }
        return verified == total;
    }
}
