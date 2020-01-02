package com.bill.fingerauthtest;

import android.app.Application;

import com.bill.fingerauthtest.auth.AuthManager;

public class App extends Application {
    private static App sInstance;

    public static App getInstance() {
        return sInstance;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        sInstance = this;
        AuthManager.getInstance().init();
    }
}
