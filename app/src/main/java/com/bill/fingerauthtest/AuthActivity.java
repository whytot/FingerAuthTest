package com.bill.fingerauthtest;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.bill.fingerauthtest.auth.AuthManager;

public class AuthActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth);
    }

    @Override
    protected void onStart() {
        super.onStart();
        AuthManager.getInstance().requestAuth();
    }

    @Override
    protected void onPause() {
        super.onPause();
        AuthManager.getInstance().unregisterAuth();
    }
}
