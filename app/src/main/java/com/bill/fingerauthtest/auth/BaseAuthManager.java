package com.bill.fingerauthtest.auth;

/**
 * @author Bill.WangBW
 */
public interface BaseAuthManager {
    void init();

    void requestAuth();

    void unregisterAuth();
}
