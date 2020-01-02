package com.bill.fingerauthtest.auth;

import android.os.Build;

/**
 * @author Bill.WangBW
 */
public class AuthManager implements BaseAuthManager {
    private static class AuthManagerInstance {
        private static final AuthManager sAuthManager = new AuthManager();
    }

    public static AuthManager getInstance() {
        return AuthManagerInstance.sAuthManager;
    }

    private BaseAuthManager mBaseAuthManager;

    private AuthManager() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            mBaseAuthManager = new BiometricAuthManager();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mBaseAuthManager = new FingerprintAuthManager();
        }
        mBaseAuthManager = new SoterAuthManager();
    }

    @Override
    public void init() {
        mBaseAuthManager.init();
    }

    @Override
    public void requestAuth() {
        mBaseAuthManager.requestAuth();
    }

    @Override
    public void unregisterAuth() {
        mBaseAuthManager.unregisterAuth();
    }
}
