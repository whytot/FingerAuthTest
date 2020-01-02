package com.bill.fingerauthtest.auth;

import android.os.Build;
import android.os.Handler;
import android.util.Log;

import com.bill.fingerauthtest.App;

import androidx.annotation.RequiresApi;
import androidx.core.hardware.fingerprint.FingerprintManagerCompat;
import androidx.core.os.CancellationSignal;

/**
 * @author Bill.WangBW
 */
@RequiresApi(api = Build.VERSION_CODES.M)
class FingerprintAuthManager implements BaseAuthManager {
    private static final String TAG = "FingerprintAuthManager";
    private FingerprintManagerCompat mFingerprintManagerCompat;
    private CancellationSignal mCancellationSignal;

    FingerprintAuthManager() {
        mFingerprintManagerCompat = FingerprintManagerCompat.from(App.getInstance());
        mCancellationSignal = new CancellationSignal();
    }

    @Override
    public void init() {
        // do nothing
    }

    @Override
    public void requestAuth() {
        mFingerprintManagerCompat.authenticate(null, 0, mCancellationSignal, new FingerprintManagerCompat.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errMsgId, CharSequence errString) {
                super.onAuthenticationError(errMsgId, errString);
                Log.e(TAG, "onAuthenticationError: " + errMsgId + " - " + errString);
            }

            @Override
            public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                super.onAuthenticationHelp(helpMsgId, helpString);
                Log.e(TAG, "onAuthenticationHelp: " + helpMsgId + " - " + helpString);
            }

            @Override
            public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                FingerprintManagerCompat.CryptoObject cryptoObject = result.getCryptoObject();
                Log.e(TAG, "onAuthenticationSucceeded 0: " + cryptoObject);
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Log.e(TAG, "onAuthenticationFailed");
            }
        }, new Handler());
    }

    @Override
    public void unregisterAuth() {
        if (!mCancellationSignal.isCanceled()) {
            mCancellationSignal.cancel();
        }
    }
}
