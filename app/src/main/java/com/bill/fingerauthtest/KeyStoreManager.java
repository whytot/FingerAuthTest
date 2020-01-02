package com.bill.fingerauthtest;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import androidx.annotation.RequiresApi;

import static com.bill.fingerauthtest.Constants.GOOGLE_ROOT_CERTIFICATE;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * @author Bill.WangBW
 */
@RequiresApi(api = Build.VERSION_CODES.M)
public class KeyStoreManager {
    private static final String TAG = "KeyStoreManager";
    private static byte[] IV = "1234123412341234".getBytes();
    private KeyStore mKeyStore;
    private KeyStore mCAStore;

    private static class KeyStoreManagerInstance {
        private static final KeyStoreManager sKeyStoreManager = new KeyStoreManager();
    }

    public static KeyStoreManager getInstance() {
        return KeyStoreManagerInstance.sKeyStoreManager;
    }

    public KeyStoreManager() {
        try {
            initKeyStore();
            initCAStore();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void initKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        mKeyStore.load(null);
    }

    private void initCAStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        mCAStore = KeyStore.getInstance("AndroidCAStore");
        mCAStore.load(null);
    }

    public void test() {
        try {
            createRSAKey(getTestAliasName());
            verifyRSAKey(getTestAliasName());
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    public Cipher getTestCipher(int opmode, String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        if (!hasAlias(alias)) {
            Log.e(TAG, "getTestKey: " + alias + " 不存在!");
            return null;
        }
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA + "/" + KeyProperties.BLOCK_MODE_ECB + "/" + KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
        if (opmode == KeyProperties.PURPOSE_ENCRYPT) {
            cipher.init(opmode, keyStore.getCertificate(alias).getPublicKey());
        } else {
            cipher.init(opmode, keyStore.getKey(alias, null));
        }
        return cipher;
    }

    public Signature getTestKey(int opmode, String alias) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        if (!hasAlias(alias)) {
            Log.e(TAG, "getTestKey: " + alias + " 不存在!");
            return null;
        }
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

//        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
//        Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
//        cipher.init(opmode, keyStore.getCertificate(alias).getPublicKey());
//        return cipher;
        Signature signature = Signature.getInstance("SHA256withECDSA");
        if (opmode == KeyProperties.PURPOSE_SIGN) {
            signature.initSign((PrivateKey) keyStore.getKey(alias, null));
        } else {
            signature.initVerify(keyStore.getCertificate(alias).getPublicKey());
        }
        return signature;

    }

    private void verifyRSAKey(String alias) throws CertificateException, NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchProviderException, SignatureException {
        if (!hasAlias(alias)) {
            Log.e(TAG, "verifyRSAKey: " + alias + " 不存在!");
            return;
        }
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            Certificate[] certificates = keyStore.getCertificateChain(alias);
            if (certificates == null || certificates.length == 0) {
                Log.e(TAG, "verifyRSAKey: " + alias + " 没有证书链!");
            } else {
                verifyCertificateChain(certificates);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private boolean isInsideSecurityHardware(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            PrivateKey key = (PrivateKey) ks.getKey(alias, null);
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = factory.getKeySpec(key, KeyInfo.class);
            if (keyInfo.isInsideSecureHardware()) {
                return true;
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }


    private void createRSAKey(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (hasAlias(alias)) {
            Log.e(TAG, "createRSAKey: " + alias + " 已存在！");
            return;
        }
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(512, RSAKeyGenParameterSpec.F4))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.M) {
            byte[] challenge = genChallenge();
            builder.setAttestationChallenge(challenge);
        }
        kpGenerator.initialize(builder.build());
        kpGenerator.generateKeyPair();
        Log.e(TAG, "createRSAKey: " + alias + " 创建完成！");
    }

    /**
     * 官方提供的校验方法，但应在服务端处理
     * <p>
     * https://github.com/google/android-key-attestation/blob/master/server/src/main/java/com/android/example/KeyAttestationExample.java
     */
    private static void verifyCertificateChain(Certificate[] certs)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException, IOException {
        final X509Certificate[] x509Certificates = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            x509Certificates[i] = (X509Certificate) certs[i];
            Log.e(TAG, "PublicKey : " + x509Certificates[i].getPublicKey().toString());
        }

        X509Certificate parent = x509Certificates[x509Certificates.length - 1];
        for (int i = certs.length - 1; i >= 0; i--) {
            X509Certificate cert = x509Certificates[i];
            // Verify that the certificate has not expired.
            cert.checkValidity();
            cert.verify(parent.getPublicKey());
            parent = cert;
//            try {
//                CertificateRevocationStatus certStatus = CertificateRevocationStatus
//                        .fetchStatus(cert.getSerialNumber());
//                if (certStatus != null) {
//                    throw new CertificateException(
//                            "Certificate revocation status is " + certStatus.status.name());
//                }
//            } catch (IOException e) {
//                throw new IOException("Unable to fetch certificate status. Check connectivity.");
//            }
        }

        // If the attestation is trustworthy and the device ships with hardware-
        // level key attestation, Android 7.0 (API level 24) or higher, and
        // Google Play services, the root certificate should be signed with the
        // Google attestation root key.
        X509Certificate secureRoot =
                (X509Certificate)
                        CertificateFactory.getInstance("X.509")
                                .generateCertificate(
                                        new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes(UTF_8)));
        if (Arrays.equals(
                secureRoot.getTBSCertificate(), x509Certificates[x509Certificates.length - 1].getTBSCertificate())) {
            Log.e(TAG,
                    "The root certificate is correct, so this attestation is trustworthy, as long as none of"
                            + " the certificates in the chain have been revoked. A production-level system"
                            + " should check the certificate revocation lists using the distribution points that"
                            + " are listed in the intermediate and root certificates.");
        } else {
            Log.e(TAG,
                    "The root certificate is NOT correct. The attestation was probably generated by"
                            + " software, not in secure hardware. This means that, although the attestation"
                            + " contents are probably valid and correct, there is no proof that they are in fact"
                            + " correct. If you're using a production-level system, you should now treat the"
                            + " properties of this attestation certificate as advisory only, and you shouldn't"
                            + " rely on this attestation certificate to provide security guarantees.");
        }
        verifyCertificate(x509Certificates[0]);
    }

    private static void verifyCertificate(X509Certificate x509Certificate) {
        byte[] extensionValue = x509Certificate.getExtensionValue(Constants.KEY_DESCRIPTION_OID);
        Log.e(TAG, "verifyCertificate: 获取扩展名");
    }

    private static byte[] genChallenge() {
        SecureRandom random = new SecureRandom();
        byte[] challenge = new byte[32];
        random.nextBytes(challenge);
        return challenge;
    }

    private void createClientCert() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        String alias = "cert1";
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        //存
        X509Certificate clientCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Constants.CLIENT_1_CERTIFICATE.getBytes(UTF_8)));
        keyStore.setCertificateEntry(alias, clientCertificate);
        Certificate[] certificates = keyStore.getCertificateChain(alias);
        Log.e(TAG, "certificates " + (certificates == null ? 0 : certificates.length));
        //取 & 验证
        Certificate certificate = keyStore.getCertificate(alias);
        if (certificate != null) {
            X509Certificate secureRoot = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes(UTF_8)));
            X509Certificate x509Certificate = (X509Certificate) clientCertificate;
            x509Certificate.checkValidity();
            try {
                secureRoot.verify(x509Certificate.getPublicKey());
//                x509Certificate.verify(secureRoot.getPublicKey());
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (SignatureException e) {
                e.printStackTrace();
            }
            boolean result = Arrays.equals(secureRoot.getTBSCertificate(), x509Certificate.getTBSCertificate());
            Log.e(TAG, "verify result: " + result);
        }
    }

    public void printAllAliases(KeyStore keyStore) {
        try {
            keyStore.load(null);
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Log.e(TAG, alias);
                Certificate certificate = mCAStore.getCertificate(alias);
                verify(certificate);
//                Log.e(TAG, "certificate " + certificate);
//                Certificate[] certificates = mCAStore.getCertificateChain(alias);
//                Log.e(TAG, "certificates " + (certificates == null ? 0 : certificates.length));
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Log.e(TAG, "------------------- " + keyStore.getType() + " -------------------");
    }

    private void verify(Certificate certificate) {
        if (certificate == null) {
            return;
        }
        try {
            X509Certificate secureRoot = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes(UTF_8)));
            ;
            Log.e(TAG, "verify : " + mCAStore.getCertificateAlias(secureRoot));
            X509Certificate x509Certificate = (X509Certificate) certificate;
            x509Certificate.checkValidity();
            x509Certificate.verify(secureRoot.getPublicKey());
            boolean result = Arrays.equals(secureRoot.getTBSCertificate(), x509Certificate.getTBSCertificate());
            Log.e(TAG, "verify result: " + result);
//            x509Certificate.verify(certificateFactory.generateCertificate(App.getInstance().getResources().openRawResource(R.raw.google_cer)).getPublicKey());
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    private boolean hasAlias(String aliasName) {
        try {
            return mKeyStore.containsAlias(aliasName);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 生成对称密钥
     * TODO: 按照我的理解应该有一个第三方入口创建alias，因为既然是为了安全，那么创建alias的代码就不该暴露
     */
    private void createSecretKey(String aliasName) {
        if (hasAlias(aliasName)) {
            Log.e(TAG, "createSecretKey: " + aliasName + " has been created !");
            return;
        }
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
            try {
                KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(aliasName, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//                        .setUserAuthenticationRequired(true)
                        ;
//                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
//                    builder.setAttestationChallenge("Bill".getBytes());
//                }
                keyGenerator.init(builder.build());
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
            SecretKey key = keyGenerator.generateKey();
            Log.e(TAG, "createSecretKey: SecretKey - " + key);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String getTestAliasName() {
        return "test";
    }

    public SecretKey getTestSecretKey() {
        return getSecretKey(getTestAliasName());
    }

    private SecretKey getSecretKey(String aliasName) {
        SecretKey result = null;
        try {
            result = (SecretKey) mKeyStore.getKey(aliasName, null);
            Log.e(TAG, "getSecretKey: SecretKey - " + result);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return result;
    }

    public Cipher getCipher(int opmode, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        byte[] bytes = cipher.getIV();
        if (iv == null) {
            cipher.init(opmode, key);
        } else {
            cipher.init(opmode, key, new IvParameterSpec(iv));
        }
        IV = cipher.getIV();
        return cipher;
    }

    private byte[] encryptBySecretKey(byte[] source, String aliasName, byte[] iv) {
        byte[] result = null;
        SecretKey secretKey = getSecretKey(aliasName);
        if (secretKey == null) {
            Log.e(TAG, "encryptBySecretKey: SecretKey - " + aliasName + " not exist!");
            return result;
        }
        try {
            result = getCipher(Cipher.ENCRYPT_MODE, secretKey, iv).doFinal(source);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return result;
    }

    private byte[] decryptBySecretKey(byte[] source, String aliasName, byte[] iv) {
        byte[] result = null;
        SecretKey secretKey = getSecretKey(aliasName);
        if (secretKey == null) {
            Log.e(TAG, "decryptBySecretKey: SecretKey - " + aliasName + " not exist!");
            return result;
        }
        try {
            result = getCipher(Cipher.DECRYPT_MODE, secretKey, iv).doFinal(source);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 生成非对称密钥
     * TODO: 按照我的理解应该有一个第三方入口创建alias，因为既然是为了安全，那么创建alias的代码就不该暴露
     */
    private void createKeyPair(String aliasName) {
        if (hasAlias(aliasName)) {
            Log.e(TAG, "createKeyPair: " + aliasName + " has been created !");
            return;
        }
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(aliasName, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .build());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Log.e(TAG, "createKeyPair>>PrivateKey:" + keyPair.getPrivate() + ",PublicKey:" + keyPair.getPublic());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    private KeyPair getKeyPair(String aliasName) {
        try {
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(aliasName, null);
            PublicKey publicKey = entry.getCertificate().getPublicKey();
            PrivateKey privateKey = entry.getPrivateKey();
            Log.e(TAG, "getTargetKeyPair>>privateKey:" + privateKey + ",publicKey:" + publicKey);
            return new KeyPair(publicKey, privateKey);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        }
        return null;
    }

}
