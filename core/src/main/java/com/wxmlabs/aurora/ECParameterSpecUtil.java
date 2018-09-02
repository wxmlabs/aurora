package com.wxmlabs.aurora;

import java.lang.reflect.Method;
import java.security.spec.ECParameterSpec;

public class ECParameterSpecUtil {
    static boolean isSM2ECC(ECParameterSpec spec) {
        return spec.getCurve().getField().getFieldSize() == 256
            && spec.getCurve().getA().toString().equals("115792089210356248756420345214020892766250353991924191454421193933289684991996") // c
            && spec.getCurve().getB().toString().equals("18505919022281880113072981827955639221458448578012075254857346196103069175443") // g
            && spec.getGenerator().getAffineX().toString().equals("22963146547237050559479531362550074578802567295341616970375194840604139615431") // g
            && spec.getGenerator().getAffineY().toString().equals("85132369209828568825618990617112496413088388631904505083283536607588877201568") // g
            && spec.getOrder().toString().equals("115792089210356248756420345214020892766061623724957744567843809356293439045923") // n
            && spec.getCofactor() == 1; // h
    }

    static String getCurveName(ECParameterSpec spec) {
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
        return null;
    }

    static String toString(ECParameterSpec spec) {
        String params;
        String curveName = getCurveName(spec);
        if (curveName != null) {
            params = curveName;
        } else {
            params = String.format(
                "Curve[Field: %d, A: %s, B: %s], Generator[AffineX: %s, AffineY: %s], Order: %s, Cofactor: %d",
                spec.getCurve().getField().getFieldSize(),
                spec.getCurve().getA().toString(),
                spec.getCurve().getB().toString(),
                spec.getGenerator().getAffineX().toString(),
                spec.getGenerator().getAffineY().toString(),
                spec.getOrder().toString(),
                spec.getCofactor()
            );
        }
        return params;
    }
}
