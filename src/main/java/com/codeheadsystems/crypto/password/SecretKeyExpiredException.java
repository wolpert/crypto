package com.codeheadsystems.crypto.password;

/**
 * Only used if the secretKey expired in session
 * <p/>
 * BSD-Style License 2016
 */
public class SecretKeyExpiredException extends Exception {

    public SecretKeyExpiredException() {
        super("The secret key has expired");
    }
}
