package com.wxmlabs.aurora;

import java.lang.reflect.Method;
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
            if (isSM2ECC(spec)) {
                encryptionAlg = "SM2";
            } else {
                throw new UnsupportedKey("Unsupported ECParameterSpec: " + getCurveName(spec));
            }
        } else {
            encryptionAlg = encryptionAlgs.get(keyAlg);
        }
        if (encryptionAlg == null) encryptionAlg = keyAlg;
        return encryptionAlg;

    }

    private boolean isSM2ECC(ECParameterSpec spec) {
        return spec.getCurve().getField().getFieldSize() == 256
            && spec.getCurve().getA().toString().equals("115792089210356248756420345214020892766250353991924191454421193933289684991996") // c
            && spec.getCurve().getB().toString().equals("18505919022281880113072981827955639221458448578012075254857346196103069175443") // g
            && spec.getGenerator().getAffineX().toString().equals("22963146547237050559479531362550074578802567295341616970375194840604139615431") // g
            && spec.getGenerator().getAffineY().toString().equals("85132369209828568825618990617112496413088388631904505083283536607588877201568") // g
            && spec.getOrder().toString().equals("115792089210356248756420345214020892766061623724957744567843809356293439045923") // n
            && spec.getCofactor() == 1; // h

    }

    private String getCurveName(ECParameterSpec spec) {
        try {
            Method m = spec.getClass().getDeclaredMethod("getName");
            if (m != null) {
                Object name = m.invoke(spec);
                if (name instanceof String) {
                    return (String) name;
                }
            }
        } catch (Exception ignore) {
        }
        return "unknown";
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
