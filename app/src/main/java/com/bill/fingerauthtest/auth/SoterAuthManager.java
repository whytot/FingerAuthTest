package com.bill.fingerauthtest.auth;

import android.util.Log;

import com.bill.fingerauthtest.App;
import com.tencent.soter.core.model.ConstantsSoter;
import com.tencent.soter.wrapper.SoterWrapperApi;
import com.tencent.soter.wrapper.wrap_biometric.SoterBiometricStateCallback;
import com.tencent.soter.wrapper.wrap_callback.SoterProcessAuthenticationResult;
import com.tencent.soter.wrapper.wrap_callback.SoterProcessCallback;
import com.tencent.soter.wrapper.wrap_callback.SoterProcessKeyPreparationResult;
import com.tencent.soter.wrapper.wrap_callback.SoterProcessNoExtResult;
import com.tencent.soter.wrapper.wrap_task.AuthenticationParam;
import com.tencent.soter.wrapper.wrap_task.InitializeParam;

import androidx.annotation.NonNull;

class SoterAuthManager implements BaseAuthManager {
    private static final String TAG = "SoterAuthManager";

    SoterAuthManager() {
    }

    @Override
    public void init() {
        InitializeParam param = new InitializeParam.InitializeParamBuilder()
                // 场景值常量，后续使用该常量进行密钥生成或指纹认证
                .setScenes(0)
                .build();
        SoterWrapperApi.init(App.getInstance(),
                new SoterProcessCallback<SoterProcessNoExtResult>() {
                    @Override
                    public void onResult(@NonNull SoterProcessNoExtResult result) {
                        Log.e(TAG, "init onResult: " + result);
                        SoterWrapperApi.prepareAuthKey(new SoterProcessCallback<SoterProcessKeyPreparationResult>() {
                            @Override
                            public void onResult(@NonNull SoterProcessKeyPreparationResult result) {
                                Log.e(TAG, "prepareAuthKey onResult: " + result);
                            }
                        }, false, true, 0, null, null);
                    }
                },
                param);
    }

    @Override
    public void requestAuth() {
        AuthenticationParam param = new AuthenticationParam.AuthenticationParamBuilder()
                .setScene(0)
                .setContext(App.getInstance())
                // fingerprint
//                .setBiometricType(ConstantsSoter.FINGERPRINT_AUTH)
                // faceid
                .setBiometricType(ConstantsSoter.FACEID_AUTH)
                .setSoterBiometricCanceller(null)
                .setPrefilledChallenge("test challenge")
                .setSoterBiometricStateCallback(new SoterBiometricStateCallback() {
                    @Override
                    public void onStartAuthentication() {
                        Log.e(TAG, "onStartAuthentication");
                    }

                    @Override
                    public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                        Log.e(TAG, "onAuthenticationHelp: " + helpCode + " - " + helpString);
                    }

                    @Override
                    public void onAuthenticationSucceed() {
                        Log.e(TAG, "onAuthenticationSucceed");
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        Log.e(TAG, "onAuthenticationFailed");
                    }

                    @Override
                    public void onAuthenticationCancelled() {
                        Log.e(TAG, "onAuthenticationCancelled");
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errorString) {
                        Log.e(TAG, "onAuthenticationError: " + errorCode + " - " + errorString);
                    }
                }).build();
        SoterWrapperApi.requestAuthorizeAndSign(new SoterProcessCallback<SoterProcessAuthenticationResult>() {
            @Override
            public void onResult(@NonNull SoterProcessAuthenticationResult result) {
                Log.e(TAG, "requestAuthorizeAndSign onResult: " + result);
            }
        }, param);
    }

    @Override
    public void unregisterAuth() {
//        SoterWrapperApi.release();
    }
}
