package com.wxmlabs.aurora;

import org.bouncycastle.jcajce.util.BCJcaJceHelper;

import java.security.Provider;

class BCProviderHelper extends BCJcaJceHelper {
    static final BCProviderHelper INSTANCE = new BCProviderHelper();

    Provider getProvider() {
        return provider;
    }
}
