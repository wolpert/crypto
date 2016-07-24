package com.codeheadsystems.crypto.password;

/**
 * BSD-Style License 2016
 */
public interface ExpirationHandler {

    /**
     * This causes the timer to be reset
     */
    void touch();
}
