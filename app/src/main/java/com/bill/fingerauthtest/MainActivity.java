package com.bill.fingerauthtest;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.View;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "Main";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void onClick0(View view) {
        startActivity(new Intent(this, AuthActivity.class));
    }

    public void onClick1(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyStoreManager.getInstance().test();
        }
    }
}
