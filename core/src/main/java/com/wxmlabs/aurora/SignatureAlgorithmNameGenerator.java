package com.wxmlabs.aurora;

import java.security.Key;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class SignatureAlgorithmNameGenerator {
    private final Map<String, String> encryptionAlgs = new HashMap<String, String>();
    static final SignatureAlgorithmNameGenerator INSTANCE = new SignatureAlgorithmNameGenerator();

    SignatureAlgorithmNameGenerator() {
        // ANSI X9.57 algorithm
        encryptionAlgs.put("1.2.840.10040.4.1", "DSA"); // esa
        // PKCS #1
        encryptionAlgs.put("1.2.840.113549.1.1.1", "RSA"); // rsaEncryption
        // ANSI X9.62 public key type
        encryptionAlgs.put("1.2.840.10045.2.1", "EC"); // ecPublicKey
        // China GM Standards Committee
        encryptionAlgs.put("1.2.156.10197.1.301 ", "SM2"); // sm2ECC
    }

    public String getSignatureName(DigestAlgorithm digestAlg, Key asymmetricKey) {
        return digestAlg.name() + "with" + getEncryptionAlgName(asymmetricKey);
    }

    private String getEncryptionAlgName(Key asymmetricKey) {
        String keyAlg = asymmetricKey.getAlgorithm();
        String encryptionAlg;
        if (asymmetricKey instanceof ECKey) {
            ECParameterSpec spec = ((ECKey) asymmetricKey).getParams();
            if (ECParameterSpecUtil.isSM2ECC(spec)) {
                encryptionAlg = "SM2";
            } else {
                throw new UnsupportedKeyException("Unsupported ECParameterSpec: " + ECParameterSpecUtil.getCurveName(spec));
            }
        } else {
            encryptionAlg = encryptionAlgs.get(keyAlg);
        }
        if (encryptionAlg == null) encryptionAlg = keyAlg;
        return encryptionAlg;

    }

    public DigestAlgorithm getDefaultDigestAlgorithm(Key asymmetricKey) {
        String encryptionAlgName = getEncryptionAlgName(asymmetricKey);
        if ("SM2".equals(encryptionAlgName)) {
            return DigestAlgorithm.SM3;
        } else {
            return DigestAlgorithm.SHA256;
        }
    }

    public static String getSignatureAlg(DigestAlgorithm digestAlg, Key asymmetricKey) {
        return INSTANCE.getSignatureName(digestAlg, asymmetricKey);
    }

    public static DigestAlgorithm getDefaultDigestAlg(Key asymmetricKey) {
        return INSTANCE.getDefaultDigestAlgorithm(asymmetricKey);
    }
}
