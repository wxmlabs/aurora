package com.wxmlabs.aurora.compatible;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.wxmlabs.aurora.DigestAlgorithm;
import com.wxmlabs.aurora.MemorySignatureService;
import com.wxmlabs.aurora.SignatureAlgorithmNameGenerator;
import com.wxmlabs.aurora.SignatureService;
import com.wxmlabs.aurora.SimpleCMSSigner;
import com.wxmlabs.aurora.SimpleCMSVerifier;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class TCACompatibleSignatureService {
    public static SignatureService getInstance(String json) {
        MemorySignatureService signatureService = new MemorySignatureService();

        JsonObject tcaConfig = new JsonParser().parse(json).getAsJsonObject();
        JsonArray keyStoreCfgArray = tcaConfig.getAsJsonArray("keyStore");
        for (JsonElement element : keyStoreCfgArray) {
            JsonObject keyStoreCfg = element.getAsJsonObject();
            String name = keyStoreCfg.get("name").getAsString();
            String type = keyStoreCfg.get("type").getAsString();
            String keyStorePath = keyStoreCfg.get("keyStorePath").getAsString();
            char[] password = keyStoreCfg.get("password").getAsString().toCharArray();

            try {
                KeyStore ks = KeyStore.getInstance(type);
                ks.load(new FileInputStream(keyStorePath), password);
                Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        PrivateKey signerKey = (PrivateKey) ks.getKey(alias, password);
                        X509Certificate signerCert = (X509Certificate) ks.getCertificate(alias);
                        String serial = signerCert.getSerialNumber().toString(16);
                        DigestAlgorithm defaultDigestAlg = SignatureAlgorithmNameGenerator.getDefaultDigestAlg(signerKey);
                        signatureService.addSigner(name + "_" + serial, new SimpleCMSSigner(signerKey, signerCert, defaultDigestAlg, true));
                        signatureService.addCMSVerifier(name + "_" + serial, signerCert);
                    }
                }
            } catch (KeyStoreException e1) {
                e1.printStackTrace();
            } catch (CertificateException e1) {
                e1.printStackTrace();
            } catch (NoSuchAlgorithmException e1) {
                e1.printStackTrace(); // type错误
            } catch (FileNotFoundException e1) {
                e1.printStackTrace(); // 文件不存在
            } catch (IOException e1) {
                e1.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace(); // 无法还原Key
            }
        }
        signatureService.addVerifier("CMSVerifier", new SimpleCMSVerifier()); // 不指定证书进行验证
        return signatureService;
    }
}
