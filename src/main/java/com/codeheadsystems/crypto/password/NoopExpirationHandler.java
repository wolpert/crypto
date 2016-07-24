package com.codeheadsystems.crypto.password;

/**
 * BSD-Style License 2016
 */
public class NoopExpirationHandler implements ExpirationHandler {
    @Override
    public void touch() {
    }
}
