package com.bill.fingerauthtest.auth;

import android.content.DialogInterface;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.bill.fingerauthtest.App;
import com.bill.fingerauthtest.KeyStoreManager;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import androidx.annotation.RequiresApi;

/**
 * @author Bill.WangBW
 */
@RequiresApi(api = Build.VERSION_CODES.P)
class BiometricAuthManager implements BaseAuthManager {
    private static final String TAG = "BiometricAuthManager";
    private BiometricPrompt mBiometricPrompt;
    private CancellationSignal mCancellationSignal;
    private byte[] testResultBytes = null;
    private byte[] testResultIv = null;

    BiometricAuthManager() {
        mBiometricPrompt = new BiometricPrompt.Builder(App.getInstance())
                .setTitle("我是标题")
                .setSubtitle("我是副标题")
                .setDescription("我是描述描述")
                .setNegativeButton("我是取消按钮", App.getInstance().getMainExecutor(), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        Log.e(TAG, "点击取消");
                    }
                })
//                    .setConfirmationRequired(true)
                .build();
        mCancellationSignal = new CancellationSignal();
    }

    @Override
    public void init() {
        // do nothing
    }

    @Override
    public void requestAuth() {
        try {
            Cipher object = KeyStoreManager.getInstance().getTestCipher(testResultBytes == null ? KeyProperties.PURPOSE_ENCRYPT : KeyProperties.PURPOSE_DECRYPT, KeyStoreManager.getInstance().getTestAliasName());
            testResultBytes = doEnc(object, "Bill".getBytes());
            object = KeyStoreManager.getInstance().getTestCipher(testResultBytes == null ? KeyProperties.PURPOSE_ENCRYPT : KeyProperties.PURPOSE_DECRYPT, KeyStoreManager.getInstance().getTestAliasName());
//            final Signature object = KeyStoreManager.getInstance().getTestKey(testResultBytes == null ? KeyProperties.PURPOSE_SIGN : KeyProperties.PURPOSE_VERIFY, KeyStoreManager.getInstance().getTestAliasName());
            BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(object);
            mBiometricPrompt.authenticate(cryptoObject, new CancellationSignal(), App.getInstance().getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
//                    Signature signature1 = cryptoObject.getSignature();
//                    if (testResultBytes == null) {
//                        try {
//                            signature1.update("Bill".getBytes());
//                            testResultBytes = signature1.sign();
//                        } catch (SignatureException e) {
//                            e.printStackTrace();
//                        }
//                    } else {
//                        try {
//                            signature1.update("Bill".getBytes());
//                            boolean verifyResult = signature1.verify(testResultBytes);
//                            Log.e(TAG, "onAuthenticationSucceeded 0: " + verifyResult);
//                        } catch (SignatureException e) {
//                            e.printStackTrace();
//                        }
//                        testResultBytes = null;
//                    }
                    Cipher cipher = cryptoObject.getCipher();
                    Log.e(TAG, "onAuthenticationSucceeded 0: " + cryptoObject.getCipher());
                    if (cipher == null) {
                        return;
                    }
                    if (testResultBytes == null) {
                        testResultBytes = doEnc(cipher, "Bill".getBytes());
                        testResultIv = cipher.getIV();
                    } else {
                        doDec(cipher, testResultBytes, testResultIv);
                        testResultBytes = null;
                        testResultIv = null;
                    }
                }

                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    Log.e(TAG, "onAuthenticationError: " + errorCode + " - " + errString);
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    Log.e(TAG, "onAuthenticationFailed");
                }

                @Override
                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                    super.onAuthenticationHelp(helpCode, helpString);
                    Log.e(TAG, "onAuthenticationHelp: " + helpCode + " - " + helpString);
                }
            });
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    private byte[] doDec(Cipher cipher, byte[] bytes, byte[] iv) {
        try {
            byte[] resultBytes = cipher.doFinal(bytes);
            Log.e(TAG, "result: " + new String(resultBytes));
            return resultBytes;
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] doEnc(Cipher cipher, byte[] bytes) {
        try {
            byte[] resultBytes = cipher.doFinal(bytes);
            Log.e(TAG, "length: " + resultBytes.length);
            return resultBytes;
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    private Cipher getSimpleCipher() {
        try {
            return KeyStoreManager.getInstance().getCipher(testResultBytes == null ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, KeyStoreManager.getInstance().getTestSecretKey(), testResultIv);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void unregisterAuth() {
        if (!mCancellationSignal.isCanceled()) {
            mCancellationSignal.cancel();
        }
    }
}