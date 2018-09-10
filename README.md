# aurora
电子签名

#### Release - v1.0

1. PKCS1格式签名验签
2. CMS格式签名验签

Example:

```java
DigestAlgorithm defaultDigestAlg = SignatureAlgorithmNameGenerator.getDefaultDigestAlg(signerKey);
Signer signer = new SimpleDigestSigner(signerKey, defaultDigestAlg);
byte[] signature = signer.sign(plaintext);
```

```java
DigestAlgorithm defaultDigestAlg = SignatureAlgorithmNameGenerator.getDefaultDigestAlg(verifierKey);
Verifier verifier = new SimpleDigestVerifier(verifierKey, defaultDigestAlg);
boolean verified = verifier.verify(plaintext, signature);
```

```java
DigestAlgorithm defaultDigestAlg = SignatureAlgorithmNameGenerator.getDefaultDigestAlg(signerKey);
CMSSigner signer = new SimpleCMSSigner(signerKey, signerCert, defaultDigestAlg); // default contract - contains signingTime attribute
byte[] cmsSignedData = signer.sign(content); // default sign - content detached
```

```java
DigestAlgorithm defaultDigestAlg = SignatureAlgorithmNameGenerator.getDefaultDigestAlg(signerKey);
CMSSigner signer = new SimpleCMSSigner(signerKey, signerCert, defaultDigestAlg, true); // no signed attributes will be included
byte[] cmsSignedData = signer.sign(content, true); // the content should be encapsulated in the signature
```

```java
CMSVerifier verifier = new SimpleCMSVerifier(signerCert);
boolean verified = verifier.verify(content, cmsSignedData); // verify detached signature
```

```java
CMSVerifier verifier = new SimpleCMSVerifier(signerCert);
boolean verified = verifier.verify(cmsSignedData); // verify encapsulated signature
```

Maven
```xml
<dependency>
    <groupId>com.wxmlabs</groupId>
    <artifactId>aurora-core</artifactId>
    <version>1.0</version>
</dependency>
```

Gradle
```groovy
compile("com.wxmlabs:aurora-core:1.0")
```
